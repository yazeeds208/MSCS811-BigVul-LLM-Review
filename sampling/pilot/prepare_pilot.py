import hashlib
import json
import random
import re
import zipfile
from collections import Counter
from pathlib import Path

import pyarrow.parquet as pq


SEED = 811
ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / 'bigvul_validation.parquet'
DATASET = 'bstee615/bigvul'
REVISION = '4d8647a9b52fdd2ae42343c60fd6c7c48bbff25e'
SOURCE_FILE = 'data/validation-00000-of-00001-d21ad392180d1f79.parquet'
SOURCE_URL = f'https://huggingface.co/datasets/{DATASET}/resolve/{REVISION}/{SOURCE_FILE}'
FIELDS = ['func_before', 'func_after', 'vul', 'lang', 'project', 'commit_id', 'CVE ID', 'CWE ID', 'codeLink']


def tokens(code):
    return re.findall(r'[A-Za-z_][A-Za-z_0-9]*|\d+|[^\s]', code)


def shingles(code):
    sequence = tokens(code)
    return set(zip(sequence, sequence[1:], sequence[2:], sequence[3:], sequence[4:]))


def candidate_rows():
    rows = pq.read_table(SOURCE, columns=FIELDS).to_pylist()
    candidates = {0: [], 1: []}
    for row_index, row in enumerate(rows):
        code = row['func_before']
        label = row['vul']
        if row['lang'] != 'C' or label not in candidates or not isinstance(code, str):
            continue
        if not 100 <= len(code.strip()) <= 4000 or not row['commit_id'] or not row['project']:
            continue
        if not code.rstrip().endswith('}'):
            continue
        after = row['func_after']
        if not isinstance(after, str) or not after.strip():
            continue
        changed = tokens(code) != tokens(after)
        if changed != bool(label):
            continue
        if label == 1 and not (row['CVE ID'] or '').startswith('CVE-'):
            continue
        row['source_row'] = row_index
        candidates[label].append(row)
    return len(rows), candidates


def choose_samples(candidates):
    rng = random.Random(SEED)
    selected = []
    commits = set()
    cves = set()
    project_counts = Counter()

    def eligible(row):
        if row['commit_id'] in commits or (row['CVE ID'] and row['CVE ID'] in cves):
            return False
        if project_counts[row['project']] >= 3:
            return False
        a = shingles(row['func_before'])
        for other in selected:
            b = other['shingles']
            if len(a & b) / max(1, len(a | b)) >= 0.8:
                return False
        return True

    def add(row):
        row['shingles'] = shingles(row['func_before'])
        selected.append(row)
        commits.add(row['commit_id'])
        if row['CVE ID']:
            cves.add(row['CVE ID'])
        project_counts[row['project']] += 1

    positives = candidates[1][:]
    rng.shuffle(positives)
    for row in positives:
        if eligible(row):
            add(row)
        if len(selected) == 10:
            break
    if len(selected) != 10:
        raise ValueError('Could not select ten eligible positive rows')
    for row in selected[:]:
        ranked = sorted(
            candidates[0], key=lambda control: abs(len(control['func_before']) - len(row['func_before']))
        )
        closest = next((control for control in ranked if eligible(control)), None)
        if closest is None:
            raise ValueError('Could not select ten eligible controls')
        add(closest)
    rng.shuffle(selected)
    return selected


def jsonl(records):
    return ''.join(json.dumps(record, ensure_ascii=False) + '\n' for record in records)


def main():
    total_rows, candidates = candidate_rows()
    selected = choose_samples(candidates)
    inputs, reference = [], []
    for index, row in enumerate(selected, 1):
        sample_id = f'P{index:02d}'
        code = row['func_before']
        inputs.append({'sample_id': sample_id, 'code': code})
        reference.append({
            'sample_id': sample_id, 'vul': row['vul'], 'language': row['lang'],
            'project': row['project'], 'cve_id': row['CVE ID'], 'cwe_id': row['CWE ID'],
            'commit_id': row['commit_id'], 'source_commit_url': row['codeLink'],
            'source_row_zero_based': row['source_row'], 'code_chars': len(code),
            'code_sha256': hashlib.sha256(code.encode('utf-8')).hexdigest(),
        })
    counts = Counter(row['vul'] for row in reference)
    assert counts == {0: 10, 1: 10}
    assert len({row['commit_id'] for row in reference}) == 20
    assert len({row['code_sha256'] for row in reference}) == 20
    with SOURCE.open('rb') as source_file:
        source_hash = hashlib.file_digest(source_file, 'sha256').hexdigest()
    metadata = {
        'dataset': DATASET, 'distribution': 'unofficial mirror of BigVul',
        'revision': REVISION, 'split': 'validation', 'source_url': SOURCE_URL,
        'original_paper_doi': '10.1145/3379597.3387501',
        'parquet_rows': total_rows, 'eligible_rows_by_label': {key: len(value) for key, value in candidates.items()},
        'pilot_rows_by_label': dict(counts), 'unique_projects': len({row['project'] for row in reference}),
        'source_sha256': source_hash,
        'random_seed': SEED,
    }
    archive = ROOT.parent / 'MSCS811_BigVul_Pilot.zip'
    with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as package:
        package.writestr('model_inputs.jsonl', jsonl(inputs))
        package.writestr('reference_labels.jsonl', jsonl(reference))
        package.writestr('source_manifest.json', json.dumps(metadata, indent=2) + '\n')
        package.write(ROOT / 'README.md', 'README.md')
        package.write(__file__, 'prepare_pilot.py')
    print(json.dumps(metadata, indent=2))
    print(archive)


if __name__ == '__main__':
    main()
