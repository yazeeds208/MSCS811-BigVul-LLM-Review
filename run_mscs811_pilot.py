#!/usr/bin/env python3
"""Run the MSCS811 BigVul pilot using the prepared files and a local llama.cpp server.

Place the pilot ZIP and the two MSCS811 JSON configuration files beside this
script. It uses Python 3.10+ and the standard library. Pass --model and --server
when the pinned GGUF and llama-server are stored outside the project workspace.
Use --limit 1 for a setup check or omit it to process all twenty pilot functions.

The output folder contains the run manifest, raw and parsed per-call records,
the server log, and scores on samples with valid results for all three methods.
"""
import argparse
import hashlib
import json
import socket
import subprocess
import time
import urllib.error
import urllib.request
import zipfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean


ROOT = Path(__file__).resolve().parent
PILOT_SHA256 = "ee4a3a505fb6fb6ce57497b6aa884e825334ee00b4de855924e4a3d697d10694"
CONDITIONS = ("A", "B", "C")
LOCAL_HTTP = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def digest(path):
    sha = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            sha.update(block)
    return sha.hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def archive_rows(path, member):
    with zipfile.ZipFile(path) as archive:
        return [json.loads(line) for line in archive.read(member).splitlines() if line.strip()]


@contextmanager
def local_server(executable, model, setup, output_dir):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    base_url = f"http://127.0.0.1:{port}"
    args = [
        str(executable), "--model", str(model), "--alias", setup["model"]["alias"],
        "--host", "127.0.0.1", "--port", str(port),
        *setup["runtime"]["server_arguments"], "--no-cache-prompt",
    ]
    with (output_dir / "llama-server.log").open("w", encoding="utf-8") as log:
        process = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError("llama-server exited during startup. See llama-server.log.")
                try:
                    with LOCAL_HTTP.open(base_url + "/health", timeout=2) as response:
                        if json.load(response).get("status") == "ok":
                            break
                except (urllib.error.URLError, TimeoutError):
                    time.sleep(0.25)
            else:
                raise TimeoutError("llama-server did not become ready. See llama-server.log.")
            yield base_url + setup["runtime"]["chat_endpoint"]
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


def generate(endpoint, model_alias, protocol, prefix, task, user_message):
    system = "\n".join([prefix, protocol["common_system_instruction"], task])
    payload = {
        "model": model_alias,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user_message},
        ],
        **protocol["generation"],
        "response_format": protocol["response_format"],
    }
    request = urllib.request.Request(
        endpoint, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    record = {"status": "error", "raw_response": None, "output": None, "finish_reason": None, "usage": None}
    start = time.perf_counter()
    try:
        with LOCAL_HTTP.open(request, timeout=90) as response:
            result = json.load(response)
    except (OSError, ValueError) as exc:
        record["error"] = str(exc)
    else:
        try:
            choice = result["choices"][0]
            record["raw_response"] = choice["message"]["content"]
            record["finish_reason"] = choice.get("finish_reason")
            record["usage"] = result.get("usage")
            if record["finish_reason"] != "stop":
                raise ValueError(f"Completion ended with {record['finish_reason']!r}.")
            parsed = json.loads(record["raw_response"])
            if not isinstance(parsed, dict) or set(parsed) != {"reason", "verdict"}:
                raise ValueError("Response does not have the required fields.")
            verdict = parsed["verdict"]
            reason = parsed["reason"]
            if not isinstance(verdict, str) or verdict not in protocol["verdict_to_reference_label"]:
                raise ValueError("Response verdict is outside the allowed values.")
            if not isinstance(reason, str) or not 1 <= len(reason.strip()) <= 200:
                raise ValueError("Response reason is empty or exceeds 200 characters.")
            record.update(status="ok", output=parsed)
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            record["error"] = str(exc)
    record["elapsed_seconds"] = round(time.perf_counter() - start, 6)
    return record


def evaluate_sample(endpoint, alias, protocol, sample, save):
    code = sample["code"]
    initial = protocol["initial_analysis"]
    a = generate(endpoint, alias, protocol, initial["system_prefix"],
                 initial["task_instruction"], json.dumps({"code": code}, ensure_ascii=False))
    save("A", a)
    review = protocol["review"]
    if a["status"] != "ok":
        for condition in ("B", "C"):
            save(condition, {"status": "blocked", "error": "Initial assessment is invalid.",
                             "raw_response": None, "output": None, "finish_reason": None,
                             "usage": None, "elapsed_seconds": None})
        return
    user_message = json.dumps({"code": code, "initial_assessment": a["output"]}, ensure_ascii=False)
    for condition, prefix_key in (
        ("B", "self_review_system_prefix"), ("C", "separate_reviewer_system_prefix")
    ):
        result = generate(endpoint, alias, protocol, review[prefix_key],
                          review["shared_task_instruction"], user_message)
        save(condition, result)


def classification_metrics(pairs):
    tp = sum(truth == prediction == 1 for truth, prediction in pairs)
    tn = sum(truth == prediction == 0 for truth, prediction in pairs)
    fp = sum(truth == 0 and prediction == 1 for truth, prediction in pairs)
    fn = sum(truth == 1 and prediction == 0 for truth, prediction in pairs)
    return {
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "accuracy": (tp + tn) / len(pairs) if pairs else None,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None,
    }


def summarize(data_path, samples, results, protocol):
    labels = {row["sample_id"]: row for row in archive_rows(data_path, "reference_labels.jsonl")}
    for sample in samples:
        label = labels[sample["sample_id"]]
        sha = hashlib.sha256(sample["code"].encode("utf-8")).hexdigest()
        if label["code_sha256"] != sha or label["vul"] not in (0, 1):
            raise ValueError(f"Reference label failed validation for {sample['sample_id']}.")
    eligible = [
        sample["sample_id"] for sample in samples
        if all(results[sample["sample_id"]][method]["status"] == "ok" for method in CONDITIONS)
    ]
    mapping = protocol["verdict_to_reference_label"]
    by_condition = {}
    for method in CONDITIONS:
        pairs = [
            (labels[key]["vul"], mapping[results[key][method]["output"]["verdict"]])
            for key in eligible
        ]
        stages = ("A",) if method == "A" else ("A", method)
        durations, token_totals = [], []
        for key in eligible:
            calls = [results[key][stage] for stage in stages]
            durations.append(sum(call["elapsed_seconds"] for call in calls))
            token_counts = [(call["usage"] or {}).get("total_tokens") for call in calls]
            if all(type(count) is int for count in token_counts):
                token_totals.append(sum(token_counts))
        by_condition[method] = {
            "valid": sum(row[method]["status"] == "ok" for row in results.values()),
            "invalid": sum(row[method]["status"] != "ok" for row in results.values()),
            "metrics": classification_metrics(pairs),
            "mean_total_request_seconds": mean(durations) if durations else None,
            "mean_total_tokens": mean(token_totals) if token_totals else None,
            "cases_with_token_usage": len(token_totals),
        }
    return {
        "attempted_samples": len(samples),
        "paired_scored_samples": len(eligible),
        "paired_scored_sample_ids": eligible,
        "paired_positive_labels": sum(labels[key]["vul"] == 1 for key in eligible),
        "paired_negative_labels": sum(labels[key]["vul"] == 0 for key in eligible),
        "conditions": by_condition,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--project-dir", type=Path, default=ROOT)
    parser.add_argument("--model", type=Path, help="Path to the pinned Qwen GGUF file")
    parser.add_argument("--server", type=Path, help="Path to the pinned llama-server executable")
    parser.add_argument("--output", type=Path, help="New folder for run results")
    parser.add_argument("--limit", type=int, choices=range(1, 21), metavar="1-20")
    args = parser.parse_args()

    project = args.project_dir.resolve()
    setup_path = project / "MSCS811_Model_Setup.json"
    prompts_path = project / "MSCS811_Experiment_Prompts.json"
    data_path = project / "MSCS811_BigVul_Pilot.zip"
    setup = json.loads(setup_path.read_text(encoding="utf-8"))
    protocol = json.loads(prompts_path.read_text(encoding="utf-8"))
    model = (args.model or project / ".mscs811-work/model" / setup["model"]["filename"]).resolve()
    tag = setup["runtime"]["release_tag"]
    executable = (args.server or project / ".mscs811-work" / f"llama-{tag}" / f"llama-{tag}" / "llama-server").resolve()
    pilot_hash = digest(data_path)
    if pilot_hash != PILOT_SHA256:
        raise ValueError("The pilot archive differs from the pinned MSCS811 archive.")
    model_hash = digest(model)
    if model_hash != setup["model"]["sha256"]:
        raise ValueError("The GGUF file differs from the verified model.")
    version = subprocess.check_output([executable, "--version"], text=True, stderr=subprocess.STDOUT, timeout=15).strip()
    if version.splitlines()[0] != setup["runtime"]["version_output"].splitlines()[0]:
        raise ValueError("llama-server version differs from the pinned release.")

    samples = archive_rows(data_path, "model_inputs.jsonl")
    if len(samples) != 20 or len({sample["sample_id"] for sample in samples}) != 20:
        raise ValueError("The pilot must contain twenty uniquely identified samples.")
    if args.limit is not None:
        samples = samples[:args.limit]
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output = (args.output or project / "pilot_runs" / timestamp).resolve()
    output.mkdir(parents=True, exist_ok=False)
    write_json(output / "run_manifest.json", {
        "run_id": timestamp, "partial_run": len(samples) != 20,
        "sample_ids": [sample["sample_id"] for sample in samples],
        "pilot_sha256": pilot_hash, "model_sha256": model_hash,
        "model_revision": setup["model"]["revision"], "server_version": version,
        "setup_sha256": digest(setup_path), "prompts_sha256": digest(prompts_path),
        "protocol_version": protocol["version"], "generation": protocol["generation"],
        "server_arguments": [*setup["runtime"]["server_arguments"], "--no-cache-prompt"],
    })

    results = {}
    with local_server(executable, model, setup, output) as endpoint:
        with (output / "predictions.jsonl").open("x", encoding="utf-8") as log:
            for index, sample in enumerate(samples, 1):
                key = sample["sample_id"]
                results[key] = {}

                def save(method, record):
                    results[key][method] = record
                    log.write(json.dumps({"sample_id": key, "condition": method, **record}, ensure_ascii=False) + "\n")
                    log.flush()

                evaluate_sample(endpoint, setup["model"]["alias"], protocol, sample, save)
                statuses = ", ".join(f"{method}={results[key][method]['status']}" for method in CONDITIONS)
                print(f"{index}/{len(samples)} {key}: {statuses}", flush=True)

    scores = summarize(data_path, samples, results, protocol)
    write_json(output / "scores.json", scores)
    print(f"Paired scored samples: {scores['paired_scored_samples']}/{len(samples)}")
    print(f"Output: {output}")


if __name__ == "__main__":
    main()
