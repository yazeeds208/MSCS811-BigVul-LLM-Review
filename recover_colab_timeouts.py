"""Recover timed-out MSCS811 cases into a separate, auditable run folder.

No original runner, prompt, sample, model, or source result is edited.
Only cases with transport timeouts/blocked reviews are repeated, as full A/B/C
triplets. All complete source triplets are copied byte-for-byte.
"""
import argparse
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def complete(record):
    return all(record['conditions'][m]['status'] == 'ok' for m in ('A', 'B', 'C'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project-dir', type=Path, required=True)
    parser.add_argument('--source-run', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--model', type=Path)
    parser.add_argument('--server', type=Path)
    parser.add_argument('--timeout', type=int, default=600)
    parser.add_argument('--max-cases', type=int, help='Checkpoint after this many new triplets; resume with the same command.')
    parser.add_argument('--verify-only', action='store_true', help='Validate and recompute the source results; no inference.')
    args = parser.parse_args()
    if args.timeout <= 90 or (args.max_cases is not None and args.max_cases < 1):
        parser.error('Use a timeout above 90 seconds and a positive max-cases value.')

    root = args.project_dir.resolve()
    sys.path.insert(0, str(root))
    import run_mscs811_pilot as pilot
    import run_mscs811_evaluation as evaluation

    source = (args.source_run or root / 'evaluation_runs/my_run').resolve()
    output = (args.output or root / 'evaluation_runs/my_run_timeout600').resolve()
    if output == source or source in output.parents or output in source.parents:
        raise ValueError('Source and output must be separate, non-nested folders.')
    archive = root / 'MSCS811_BigVul_Evaluation.zip'
    archive_hash, protocol, prompts, setup = evaluation.load_configuration(archive)
    manifest_path = source / 'run_manifest.json'
    source_manifest = json.loads(manifest_path.read_text())
    expected = {
        'archive_sha256': archive_hash,
        'model_sha256': protocol['model_sha256'],
        'runner_sha256': pilot.digest(root / 'run_mscs811_evaluation.py'),
        'pilot_runner_sha256': pilot.digest(root / 'run_mscs811_pilot.py'),
        'prompts_sha256': protocol['prompts_sha256'],
        'generation': protocol['generation'],
        'server_arguments': protocol['server_arguments'],
        'repetitions': 3,
    }
    for key, value in expected.items():
        if source_manifest[key] != value:
            raise ValueError(f'Source configuration mismatch: {key}')
    samples = pilot.archive_rows(archive, 'model_inputs.jsonl')
    if len(samples) != 100 or source_manifest['sample_ids'] != [s['sample_id'] for s in samples]:
        raise ValueError('Source sample IDs differ from the frozen sample.')

    source_records, source_hashes, rerun_ids, scores, runs = {}, {}, {}, [], []
    timeouts = 0
    for repetition in range(1, 4):
        records, pending = {}, []
        for sample in samples:
            key = sample['sample_id']
            path = source / f'repetition_{repetition}/records/{key}.json'
            record = json.loads(path.read_text())
            if record['sample_id'] != key or set(record['conditions']) != set(pilot.CONDITIONS):
                raise ValueError(f'Invalid record: {path}')
            source_hashes[str(path.relative_to(source))] = pilot.digest(path)
            records[key] = record
            if not complete(record):
                if not any(v['status'] == 'error' for v in record['conditions'].values()):
                    raise ValueError(f'Unexpected blocked-only record: {path}')
                for value in record['conditions'].values():
                    if value['status'] == 'error':
                        if value.get('error') != 'timed out':
                            raise ValueError(f'Non-timeout failure needs separate diagnosis: {path}')
                        timeouts += 1
                    elif value['status'] not in ('ok', 'blocked'):
                        raise ValueError(f'Unexpected status: {path}')
                pending.append(key)
        source_records[repetition] = records
        rerun_ids[str(repetition)] = pending
        mapped = {key: record['conditions'] for key, record in records.items()}
        score = evaluation.score_repetition(archive, samples, mapped, prompts)
        saved = json.loads((source / f'repetition_{repetition}/scores.json').read_text())
        if score != saved:
            raise ValueError(f'Archived scores do not recompute for repetition {repetition}')
        scores.append(score)
        runs.append(mapped)
        print(f'Source R{repetition}: {score["paired_scored_samples"]}/100 complete; {len(pending)} triplets to repeat.', flush=True)
    if evaluation.aggregate(scores, runs) != json.loads((source / 'aggregate.json').read_text()):
        raise ValueError('Source aggregate does not recompute.')
    print(f'All source scores verified. {timeouts} timed-out requests; no other recorded error type.', flush=True)
    if args.verify_only:
        return

    model = (args.model or root / 'model/qwen.gguf').resolve()
    if args.server:
        server = args.server.resolve()
    else:
        candidates = list(Path('/content/mscs811_runtime').rglob('llama-server'))
        if len(candidates) != 1:
            raise ValueError('Provide --server pointing to the b12263 llama-server executable.')
        server = candidates[0]
    if pilot.digest(model) != protocol['model_sha256']:
        raise ValueError('Model checksum differs from the frozen protocol.')
    version = subprocess.check_output([str(server), '--version'], text=True, stderr=subprocess.STDOUT, timeout=15).strip()
    if version.splitlines()[0] != protocol['runtime_version'].splitlines()[0]:
        raise ValueError('Runtime version differs from the frozen protocol.')

    plan = {
        'kind': 'timeout_recovery_with_inherited_complete_cases',
        'recovery_script_sha256': pilot.digest(Path(__file__)),
        'source_manifest_sha256': pilot.digest(manifest_path),
        'source_record_sha256': source_hashes,
        'source_run': str(source),
        'source_manifest': source_manifest,
        'request_timeout_seconds': args.timeout,
        'recovered_case_ids': rerun_ids,
        'runtime_version_for_retries': version,
        'note': 'Complete source cases are inherited. Incomplete cases are repeated as full A/B/C triplets. This is a recovered run, not a fresh independent repetition. Timings exclude earlier failed attempts; retain the source run for total-cost accounting.',
    }
    output.mkdir(parents=True, exist_ok=True)
    plan_path = output / 'recovery_manifest.json'
    if plan_path.exists():
        if json.loads(plan_path.read_text()) != plan:
            raise ValueError('Recovery folder belongs to a different source or recovery configuration.')
    elif any(output.iterdir()):
        raise ValueError('Use an empty output folder for a new recovery.')
    else:
        evaluation.atomic_json(plan_path, plan)

    # Only generation uses a 90-second open timeout; leave health checks unchanged.
    original_http = pilot.LOCAL_HTTP
    class LongerWait:
        def open(self, request, timeout=None):
            return original_http.open(request, timeout=args.timeout if timeout == 90 else timeout)
    pilot.LOCAL_HTTP = LongerWait()

    generated, all_results, all_scores = 0, [], []
    for repetition in range(1, 4):
        folder = output / f'repetition_{repetition}'
        records_dir = folder / 'records'
        records_dir.mkdir(parents=True, exist_ok=True)
        missing = []
        for sample in samples:
            key = sample['sample_id']
            path = records_dir / f'{key}.json'
            original = source / f'repetition_{repetition}/records/{key}.json'
            if complete(source_records[repetition][key]):
                if path.exists() and pilot.digest(path) != source_hashes[str(original.relative_to(source))]:
                    raise ValueError(f'Inherited record was changed: {path}')
                if not path.exists():
                    shutil.copyfile(original, path)
            elif not path.exists() or not complete(json.loads(path.read_text())):
                missing.append(sample)
        print(f'Recovery R{repetition}: {len(missing)} triplets remain.', flush=True)
        if missing:
            with pilot.local_server(server, model, setup, folder) as endpoint:
                for sample in missing:
                    if args.max_cases is not None and generated >= args.max_cases:
                        print('Checkpoint saved. Rerun the same command to continue; omit --max-cases for all remaining cases.', flush=True)
                        return
                    key = sample['sample_id']
                    path = records_dir / f'{key}.json'
                    if path.exists():
                        history = folder / 'previous_recovery_attempts'
                        history.mkdir(exist_ok=True)
                        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
                        shutil.copyfile(path, history / f'{key}_{stamp}.json')
                    conditions = {}
                    pilot.evaluate_sample(endpoint, setup['model']['alias'], prompts, sample, lambda m, r: conditions.__setitem__(m, r))
                    record = {'sample_id': key, 'conditions': conditions}
                    evaluation.atomic_json(path, record)
                    generated += 1
                    print(f'R{repetition} {key}: ' + ', '.join(f'{m}={conditions[m]["status"]}' for m in pilot.CONDITIONS), flush=True)
                    if not complete(record):
                        raise RuntimeError(f'Retry still failed for R{repetition}/{key}. Saved for diagnosis; source is untouched.')
        results = {s['sample_id']: json.loads((records_dir / f'{s["sample_id"]}.json').read_text())['conditions'] for s in samples}
        with (folder / 'predictions.jsonl').open('w', encoding='utf-8') as stream:
            for sample in samples:
                key = sample['sample_id']
                for method in pilot.CONDITIONS:
                    stream.write(json.dumps({'sample_id': key, 'condition': method, **results[key][method]}, ensure_ascii=False) + '\n')
        score = evaluation.score_repetition(archive, samples, results, prompts)
        evaluation.atomic_json(folder / 'scores.json', score)
        all_results.append(results)
        all_scores.append(score)
        print(f'R{repetition} scored {score["paired_scored_samples"]}/100 paired cases.', flush=True)
    result = evaluation.aggregate(all_scores, all_results)
    result['recovery_note'] = plan['note']
    evaluation.atomic_json(output / 'aggregate.json', result)
    print(f'Recovery complete. Results: {output}', flush=True)


if __name__ == '__main__':
    main()
