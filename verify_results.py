"""Recompute archived scores without downloading a model or starting a server."""
import json
import math
from pathlib import Path
from run_mscs811_pilot import archive_rows, digest, summarize, PILOT_SHA256
from run_mscs811_evaluation import load_configuration, score_repetition, aggregate

ROOT = Path(__file__).resolve().parent

def check(actual, expected, location):
    if isinstance(expected, dict):
        if actual.keys() != expected.keys():
            raise ValueError(f"Different fields at {location}")
        for key in expected:
            check(actual[key], expected[key], f"{location}.{key}")
    elif isinstance(expected, list):
        if len(actual) != len(expected):
            raise ValueError(f"Different lengths at {location}")
        for index, (left, right) in enumerate(zip(actual, expected)):
            check(left, right, f"{location}[{index}]")
    elif isinstance(expected, float):
        if not math.isclose(actual, expected, rel_tol=1e-12, abs_tol=1e-12):
            raise ValueError(f"Numeric mismatch at {location}")
    elif actual != expected:
        raise ValueError(f"Mismatch at {location}")

def records(path):
    result = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        sample, method = row["sample_id"], row["condition"]
        if method in result.setdefault(sample, {}):
            raise ValueError(f"Duplicate response for {sample}/{method}")
        result[sample][method] = row
    return result

def main():
    archive = ROOT / "MSCS811_BigVul_Evaluation.zip"
    _, protocol, prompts, setup = load_configuration(archive)
    manifest = json.loads((ROOT / "results/evaluation/run_manifest.json").read_text())
    for name, field in (("run_mscs811_evaluation.py", "runner_sha256"),
                        ("run_mscs811_pilot.py", "pilot_runner_sha256")):
        if digest(ROOT / name) != manifest[field]:
            raise ValueError(f"Changed original runner: {name}")
    sample = archive_rows(archive, "model_inputs.jsonl")
    scores, runs = [], []
    for number in range(1, 4):
        folder = ROOT / "results/evaluation" / f"repetition_{number}"
        run = records(folder / "predictions.jsonl")
        score = score_repetition(archive, sample, run, prompts)
        check(score, json.loads((folder / "scores.json").read_text()), f"run{number}")
        print(f"Repetition {number}: all 100 cases and archived scores match")
        scores.append(score)
        runs.append(run)
    check(aggregate(scores, runs),
          json.loads((ROOT / "results/evaluation/aggregate.json").read_text()), "aggregate")
    pilot = ROOT / "MSCS811_BigVul_Pilot.zip"
    if digest(pilot) != PILOT_SHA256:
        raise ValueError("Changed original pilot archive")
    run = records(ROOT / "results/pilot/predictions.jsonl")
    score = summarize(pilot, archive_rows(pilot, "model_inputs.jsonl"), run, prompts)
    check(score, json.loads((ROOT / "results/pilot/scores.json").read_text()), "pilot")
    print("Pilot scores and final aggregate match the archived results.")

if __name__ == "__main__":
    main()
