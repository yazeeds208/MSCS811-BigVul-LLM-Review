"""Prepare the frozen MSCS811 evaluation sample from the pinned BigVul test split."""
import argparse
import hashlib
import json
import random
import re
import zipfile
from collections import Counter
from pathlib import Path

import pyarrow.parquet as pq


REVISION = '4d8647a9b52fdd2ae42343c60fd6c7c48bbff25e'
SOURCE_URL = f'https://huggingface.co/datasets/bstee615/bigvul/resolve/{REVISION}/data/test-00000-of-00001-d20b0e7149fa6eeb.parquet'
SEED = 81104
N_PER_LABEL = 50
MAX_PER_PROJECT = 5
DUPLICATE_THRESHOLD = 0.8
FIELDS = ['func_before', 'func_after', 'vul', 'lang', 'project', 'commit_id', 'CVE ID', 'CWE ID', 'codeLink']


def sha256(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def token_seq(code):
    return re.findall(r'[A-Za-z_][A-Za-z_0-9]*|\d+|[^\s]', code)


def shingles(code):
    seq = token_seq(code)
    return set(zip(seq, seq[1:], seq[2:], seq[3:], seq[4:]))


def jsonl_rows(archive, name):
    return [json.loads(line) for line in archive.read(name).splitlines() if line.strip()]


def jsonl(records):
    return ''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in records)


def candidate_rows(path, pilot_labels):
    pilot_commits = {row['commit_id'] for row in pilot_labels}
    pilot_cves = {row['cve_id'] for row in pilot_labels if row['cve_id']}
    rows = pq.read_table(path, columns=FIELDS).to_pylist()
    by_label = {0: [], 1: []}
    for index, row in enumerate(rows):
        label = row['vul']
        code = row['func_before']
        after = row['func_after']
        cve = row['CVE ID']
        if row['lang'] != 'C' or label not in by_label or not isinstance(code, str):
            continue
        if not 100 <= len(code.strip()) <= 4000 or not code.rstrip().endswith('}'):
            continue
        if not row['project'] or not row['commit_id'] or not isinstance(after, str) or not after.strip():
            continue
        if row['commit_id'] in pilot_commits or (cve and cve in pilot_cves):
            continue
        if label == 1 and not (cve or '').startswith('CVE-'):
            continue
        if (token_seq(code) != token_seq(after)) != bool(label):
            continue
        row['source_row'] = index
        by_label[label].append(row)
    return len(rows), by_label


def select_rows(candidates, pilot_inputs):
    rng = random.Random(SEED)
    selected = []
    used_commits, used_cves = set(), set()
    projects = Counter()
    code_shingles = [shingles(row['code']) for row in pilot_inputs]

    def add(row):
        if row['commit_id'] in used_commits or (row['CVE ID'] and row['CVE ID'] in used_cves):
            return False
        if projects[row['project']] >= MAX_PER_PROJECT:
            return False
        code = shingles(row['func_before'])
        if any(len(code & prev) / max(1, len(code | prev)) >= DUPLICATE_THRESHOLD for prev in code_shingles):
            return False
        selected.append(row)
        code_shingles.append(code)
        used_commits.add(row['commit_id'])
        if row['CVE ID']:
            used_cves.add(row['CVE ID'])
        projects[row['project']] += 1
        return True

    positives = candidates[1][:]
    rng.shuffle(positives)
    for row in positives:
        add(row)
        if len(selected) == N_PER_LABEL:
            break
    if len(selected) != N_PER_LABEL:
        raise ValueError('Insufficient positive examples for the planned sample')
    for row in selected[:]:
        ranked = sorted(candidates[0], key=lambda other: abs(len(other['func_before']) - len(row['func_before'])))
        if not any(add(control) for control in ranked):
            raise ValueError('Insufficient matched negative examples for the planned sample')
    rng.shuffle(selected)
    return selected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project-dir', type=Path, default=Path.cwd())
    parser.add_argument('--test-parquet', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    project = args.project_dir
    pilot_path = project / 'MSCS811_BigVul_Pilot.zip'
    results_path = project / 'MSCS811_Pilot_Results.zip'
    prompts_path = project / 'MSCS811_Experiment_Prompts.json'
    setup_path = project / 'MSCS811_Model_Setup.json'
    with zipfile.ZipFile(pilot_path) as pilot:
        pilot_inputs = jsonl_rows(pilot, 'model_inputs.jsonl')
        pilot_labels = jsonl_rows(pilot, 'reference_labels.jsonl')
        pilot_manifest = json.loads(pilot.read('source_manifest.json'))
    assert pilot_manifest['revision'] == REVISION and pilot_manifest['split'] == 'validation'
    with zipfile.ZipFile(results_path) as results:
        pilot_run = json.loads(results.read('run_manifest.json'))
        decisions = json.loads(results.read('paired_analysis.json'))['decision_changes']
        predictions = {(r['sample_id'], r['condition']): r['output'] for r in jsonl_rows(results, 'predictions.jsonl')}
    assert pilot_run['prompts_sha256'] == sha256(prompts_path)
    assert pilot_run['setup_sha256'] == sha256(setup_path)
    assert pilot_run['pilot_sha256'] == sha256(pilot_path)
    prompts = json.loads(prompts_path.read_text())
    setup = json.loads(setup_path.read_text())

    total_rows, candidates = candidate_rows(args.test_parquet, pilot_labels)
    if total_rows != 33050:
        raise ValueError(f'Expected 33050 rows in the pinned test partition, found {total_rows}')
    chosen = select_rows(candidates, pilot_inputs)
    inputs, labels = [], []
    for index, row in enumerate(chosen, 1):
        sample_id = f'E{index:03d}'
        code = row['func_before']
        inputs.append({'sample_id': sample_id, 'code': code})
        labels.append({
            'sample_id': sample_id, 'vul': row['vul'], 'language_tag': row['lang'],
            'project': row['project'], 'cve_id': row['CVE ID'], 'cwe_id': row['CWE ID'],
            'commit_id': row['commit_id'], 'source_commit_url': row['codeLink'],
            'source_row_zero_based': row['source_row'], 'code_chars': len(code),
            'code_sha256': hashlib.sha256(code.encode('utf-8')).hexdigest(),
        })

    assert Counter(row['vul'] for row in labels) == {0: N_PER_LABEL, 1: N_PER_LABEL}
    assert len({row['commit_id'] for row in labels}) == len(labels)
    assert len({row['code_sha256'] for row in labels}) == len(labels)
    for key in ('commit_id', 'cve_id', 'code_sha256'):
        assert not {r[key] for r in labels if r[key]} & {r[key] for r in pilot_labels if r[key]}
    manifest = {
        'dataset': 'bstee615/bigvul', 'distribution': 'unofficial mirror of BigVul',
        'original_paper_doi': '10.1145/3379597.3387501', 'revision': REVISION,
        'partition': 'test', 'source_url': SOURCE_URL, 'source_sha256': sha256(args.test_parquet),
        'source_rows': total_rows, 'eligible_rows_by_label': {k: len(v) for k, v in candidates.items()},
        'chosen_rows_by_label': dict(Counter(r['vul'] for r in labels)),
        'unique_projects': len({r['project'] for r in labels}), 'seed': SEED,
        'filters': {
            'dataset_language_tag': 'C', 'trimmed_code_character_range': [100, 4000],
            'max_per_project': MAX_PER_PROJECT, 'one_sample_per_commit_and_per_nonempty_cve': True,
            'exclude_pilot_commits_and_nonempty_cves': True,
            'reject_token_five_gram_jaccard_at_or_above': DUPLICATE_THRESHOLD,
            'compare_duplicates_with_pilot_and_within_sample': True,
            'positive': 'source label 1, tokenized before/after differ, CVE ID present',
            'negative': 'source label 0, tokenized before/after identical',
            'matching': 'each selected positive is matched to the closest eligible negative by code character count',
        },
        'pilot_archive_sha256': pilot_run['pilot_sha256'],
    }
    protocol = {
        'status': 'frozen_before_evaluation',
        'model_repository': setup['model']['repository'], 'model_revision': setup['model']['revision'],
        'model_sha256': setup['model']['sha256'], 'runtime_version': pilot_run['server_version'],
        'server_arguments': pilot_run['server_arguments'],
        'prompt_version': prompts['version'], 'prompts_sha256': pilot_run['prompts_sha256'],
        'setup_sha256': pilot_run['setup_sha256'], 'generation': pilot_run['generation'],
        'conditions': prompts['conditions'], 'planned_repetitions': 3,
        'primary_comparison': 'C versus B on the same functions, using F1 difference and paired corrections/regressions',
        'secondary_comparison': 'B and C versus A for precision, recall, F1, accuracy, and end-to-end time/tokens',
        'scoring': 'Use all three methods on each sample. Compare scores on their shared valid cases and report validity coverage per condition. Use BigVul labels as references after inference. Report each repetition and descriptive averages; repetitions reuse the same functions and are not independent samples.',
        'timing': 'Keep prompt caching disabled. Include the initial analysis and review request in B and C totals.',
        'pilot_decision': 'Keep the same prompts and model as the pilot for the held-out classification comparison. Record explanation completeness separately; a valid verdict can coexist with an incomplete explanation.',
        'pilot_decision_changes': decisions,
    }

    changed = sorted({
        sample_id
        for change in decisions.values()
        for direction in ('improved', 'regressed')
        for sample_id in change[direction]
    })
    assert changed == ['P03', 'P13', 'P17']
    pilot_reference = {row['sample_id']: row['vul'] for row in pilot_labels}
    verdict_mapping = prompts['verdict_to_reference_label']
    notes = {
        'P03': 'Both reviews changed the verdict to match the reference label. The reason differs from A only in trailing punctuation and ends mid-thought.',
        'P13': 'C agreed with the reference label while B raised an alert. All three reasons were identical. The explanation assumed an input other than a Boolean without support from the Boolean parameter declaration.',
        'P17': 'Both reviews changed a correct A verdict to a false alert relative to the reference label. All three reasons were identical.',
    }
    lines = [
        '# MSCS811 pilot case review', '',
        'These were the only pilot functions on which the predicted verdict changed across A, B, and C. The reference is the BigVul label.', '',
        '| Sample | Reference | A | B | C | Observation |',
        '|---|---:|---:|---:|---:|---|',
    ]
    for sample_id in changed:
        a, b, c = [predictions[sample_id, method] for method in 'ABC']
        assert len({r['reason'].rstrip(' ,.').strip() for r in (a, b, c)}) == 1
        values = [verdict_mapping[r['verdict']] for r in (a, b, c)]
        lines.append(f"| {sample_id} | {pilot_reference[sample_id]} | {values[0]} | {values[1]} | {values[2]} | {notes[sample_id]} |")
    lines.extend([
        '', 'A change in verdict on these cases did not correspond to a substantive change in the recorded reason. Keep verdict performance and explanation quality separate.',
        '', 'The evaluation set is a balanced, held-out sample drawn from the mirror test split. The recorded tag C is a dataset metadata filter. Some projects can be present in both partitions, and the balance does not represent operational prevalence.',
        '', 'Frozen prompts, model configuration, row identifiers, hashes, and the sampler are included in the archive. Send only model_inputs.jsonl code to the model. Use reference_labels.jsonl for scoring.',
    ])

    with zipfile.ZipFile(args.output, 'x', compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('model_inputs.jsonl', jsonl(inputs))
        archive.writestr('reference_labels.jsonl', jsonl(labels))
        archive.writestr('source_manifest.json', json.dumps(manifest, indent=2) + '\n')
        archive.writestr('evaluation_protocol.json', json.dumps(protocol, indent=2) + '\n')
        archive.writestr('pilot_case_review.md', '\n'.join(lines) + '\n')
        archive.write(prompts_path, 'config/' + prompts_path.name)
        archive.write(setup_path, 'config/' + setup_path.name)
        archive.write(__file__, 'prepare_evaluation.py')
    print(json.dumps({k: manifest[k] for k in ('source_rows', 'eligible_rows_by_label', 'chosen_rows_by_label', 'unique_projects')}, indent=2))


if __name__ == '__main__':
    main()
