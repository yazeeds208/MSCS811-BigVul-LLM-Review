"""Run the frozen MSCS811 evaluation on 100 archived BigVul functions."""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from statistics import mean
from zipfile import ZipFile

from run_mscs811_pilot import (
    CONDITIONS, archive_rows, digest, evaluate_sample, local_server, summarize, write_json,
)


ROOT = Path(__file__).resolve().parent
EXPECTED_ARCHIVE_SHA256 = 'dedb29d5de3bf8f7761aa2e23443116db060fc08c3bbefb6b1eff2fdc896a7b3'


def load_configuration(archive_path):
    archive_hash = digest(archive_path)
    if archive_hash != EXPECTED_ARCHIVE_SHA256:
        raise ValueError('The archive differs from the frozen evaluation sample.')
    with ZipFile(archive_path) as archive:
        protocol = json.loads(archive.read('evaluation_protocol.json'))
        prompt_bytes = archive.read('config/MSCS811_Experiment_Prompts.json')
        setup_bytes = archive.read('config/MSCS811_Model_Setup.json')
    if hashlib.sha256(prompt_bytes).hexdigest() != protocol['prompts_sha256']:
        raise ValueError('Prompt configuration does not match the frozen protocol.')
    if hashlib.sha256(setup_bytes).hexdigest() != protocol['setup_sha256']:
        raise ValueError('Model configuration does not match the frozen protocol.')
    prompts, setup = json.loads(prompt_bytes), json.loads(setup_bytes)
    assert prompts['version'] == protocol['prompt_version']
    assert prompts['generation'] == protocol['generation']
    assert setup['runtime']['server_arguments'] + ['--no-cache-prompt'] == protocol['server_arguments']
    assert setup['model']['revision'] == protocol['model_revision']
    assert setup['model']['sha256'] == protocol['model_sha256']
    return archive_hash, protocol, prompts, setup


def atomic_json(path, data):
    temporary = path.with_suffix('.tmp')
    write_json(temporary, data)
    temporary.replace(path)


def run_repetition(output, server, model, setup, prompts, samples, repetition):
    output.mkdir(exist_ok=True)
    records_dir = output / 'records'
    records_dir.mkdir(exist_ok=True)
    results = {}
    missing = []
    for row in samples:
        sample_id = row['sample_id']
        path = records_dir / f'{sample_id}.json'
        if path.is_file():
            record = json.loads(path.read_text())
            assert record['sample_id'] == sample_id and set(record['conditions']) == set(CONDITIONS)
            results[sample_id] = record['conditions']
        else:
            missing.append(row)
    print(f'Repetition {repetition}: {len(results)} saved, {len(missing)} remaining', flush=True)
    if missing:
        with local_server(server, model, setup, output) as endpoint:
            for sample in missing:
                records = {}

                def save(method, record):
                    records[method] = record

                evaluate_sample(endpoint, setup['model']['alias'], prompts, sample, save)
                sample_id = sample['sample_id']
                atomic_json(records_dir / f'{sample_id}.json', {'sample_id': sample_id, 'conditions': records})
                results[sample_id] = records
                statuses = ', '.join(f'{m}={records[m]["status"]}' for m in CONDITIONS)
                print(f'R{repetition} {len(results)}/{len(samples)} {sample_id}: {statuses}', flush=True)
    with (output / 'predictions.jsonl').open('w', encoding='utf-8') as log:
        for sample in samples:
            key = sample['sample_id']
            for method in CONDITIONS:
                log.write(json.dumps({
                    'sample_id': key, 'condition': method, **results[key][method],
                }, ensure_ascii=False) + '\n')
    return results


def score_repetition(data_path, samples, results, prompts):
    scores = summarize(data_path, samples, results, prompts)
    labels = {r['sample_id']: r['vul'] for r in archive_rows(data_path, 'reference_labels.jsonl')}
    mapping = prompts['verdict_to_reference_label']
    paired = scores['paired_scored_sample_ids']
    changes = {}
    for before, after in [('A', 'B'), ('A', 'C'), ('B', 'C')]:
        improved, regressed = [], []
        for key in paired:
            original = mapping[results[key][before]['output']['verdict']]
            revised = mapping[results[key][after]['output']['verdict']]
            if original != revised:
                (improved if revised == labels[key] else regressed).append(key)
        changes[f'{before}_to_{after}'] = {
            'improved_sample_ids': improved, 'regressed_sample_ids': regressed,
            'unchanged': len(paired) - len(improved) - len(regressed),
        }
    scores['decision_changes'] = changes
    return scores


def average_defined(values):
    values = [x for x in values if x is not None]
    return mean(values) if values else None


def aggregate(scores, repeated_results):
    avg = {}
    for method in CONDITIONS:
        rows = [score['conditions'][method] for score in scores]
        avg[method] = {
            'mean_' + name: average_defined([row['metrics'][name] for row in rows])
            for name in ('accuracy', 'precision', 'recall', 'f1', 'fp', 'fn')
        }
        for key in ('mean_total_request_seconds', 'mean_total_tokens'):
            avg[method][key] = average_defined([row[key] for row in rows])
        avg[method]['valid_per_repetition'] = [row['valid'] for row in rows]
    deltas = []
    for score in scores:
        b = score['conditions']['B']['metrics']['f1']
        c = score['conditions']['C']['metrics']['f1']
        deltas.append(c - b if b is not None and c is not None else None)
    first = repeated_results[0]
    stability = {}
    for method in CONDITIONS:
        status_and_verdict = lambda r: (r['status'], (r['output'] or {}).get('verdict'))
        stability[method] = [
            sum(status_and_verdict(run[k][method]) == status_and_verdict(first[k][method]) for k in first)
            for run in repeated_results[1:]
        ]
    return {
        'repetitions': len(scores), 'samples_per_repetition': len(first),
        'paired_scored_samples_per_repetition': [x['paired_scored_samples'] for x in scores],
        'by_condition': avg, 'f1_delta_C_minus_B_per_repetition': deltas,
        'mean_f1_delta_C_minus_B': average_defined(deltas),
        'status_and_verdict_matches_to_repetition_1': stability,
        'note': 'Repetitions reuse the same functions. Means are descriptive, with no increase in independent sample size.',
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, default=ROOT / 'MSCS811_BigVul_Evaluation.zip')
    parser.add_argument('--output', type=Path, required=True, help='Run folder, reusable to resume a matching run')
    parser.add_argument('--model', type=Path)
    parser.add_argument('--server', type=Path)
    args = parser.parse_args()

    data_path = args.archive.resolve()
    archive_hash, protocol, prompts, setup = load_configuration(data_path)
    tag = setup['runtime']['release_tag']
    model = (args.model or ROOT / '.mscs811-work/model' / setup['model']['filename']).resolve()
    server = (args.server or ROOT / '.mscs811-work' / f'llama-{tag}' / f'llama-{tag}' / 'llama-server').resolve()
    if digest(model) != protocol['model_sha256']:
        raise ValueError('Model checksum does not match the frozen protocol.')
    version = subprocess.check_output([server, '--version'], text=True, stderr=subprocess.STDOUT, timeout=15).strip()
    if version.splitlines()[0] != protocol['runtime_version'].splitlines()[0]:
        raise ValueError('Runtime build does not match the frozen protocol.')

    samples = archive_rows(data_path, 'model_inputs.jsonl')
    assert len(samples) == len({row['sample_id'] for row in samples}) == 100
    assert all(set(row) == {'sample_id', 'code'} for row in samples)
    assert protocol['planned_repetitions'] == 3

    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    manifest_path = output / 'run_manifest.json'
    manifest = {
        'archive_sha256': archive_hash, 'model_sha256': protocol['model_sha256'],
        'runner_sha256': digest(Path(__file__)), 'pilot_runner_sha256': digest(ROOT / 'run_mscs811_pilot.py'),
        'runtime_version': version, 'server_arguments': protocol['server_arguments'],
        'model_revision': protocol['model_revision'], 'generation': protocol['generation'],
        'prompt_version': protocol['prompt_version'], 'prompts_sha256': protocol['prompts_sha256'],
        'repetitions': protocol['planned_repetitions'],
        'sample_ids': [row['sample_id'] for row in samples],
    }
    if manifest_path.exists():
        if json.loads(manifest_path.read_text()) != manifest:
            raise ValueError('Run folder was created with different inputs or settings.')
    else:
        if any(output.iterdir()):
            raise ValueError('Use an empty output folder for a new run.')
        atomic_json(manifest_path, manifest)

    all_scores, repeated_results = [], []
    for repetition in range(1, protocol['planned_repetitions'] + 1):
        folder = output / f'repetition_{repetition}'
        results = run_repetition(folder, server, model, setup, prompts, samples, repetition)
        scores = score_repetition(data_path, samples, results, prompts)
        atomic_json(folder / 'scores.json', scores)
        all_scores.append(scores)
        repeated_results.append(results)
        atomic_json(output / 'aggregate.json', aggregate(all_scores, repeated_results))
        print(f'R{repetition} scored {scores["paired_scored_samples"]}/100 paired cases.', flush=True)
    print(f'Completed all three repetitions. Results: {output}', flush=True)


if __name__ == '__main__':
    main()
