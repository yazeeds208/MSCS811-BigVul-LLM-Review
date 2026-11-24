# Pair Programming–Inspired LLM Review for Vulnerability Detection on BigVul

MSCS811, Taibah University  
Yazeed Sami Qashqary (4714384)  
Supervisor: Dr. Abdulmajeed Aljuhani

This experiment compares the same Qwen2.5-Coder-1.5B-Instruct model in three conditions.
A retains the initial assessment. B reviews it as the original analyst. C reviews it as a second reviewer.
B and C receive identical function text and initial assessment in separate fresh requests.
The held-out sample contains 100 C functions (50 per reference class) from 60 projects.
Three repetitions reuse those 100 functions. A separate pilot uses 20 functions.
Reference labels enter scoring after inference.

## Files

| Path | Purpose |
|---|---|
| run_mscs811_pilot.py | Original pilot runner and common generation/scoring functions |
| run_mscs811_evaluation.py | Original evaluation runner, three repetitions, resume support |
| run_portable_evaluation.py | Recommended entry point: 600-second client wait, recorded separately |
| recover_colab_timeouts.py | Optional recovery of timed-out triplets into a separate folder |
| verify_results.py | Recompute archived scores without downloading a model |
| MSCS811_Experiment_Prompts.json | Exact executed prompts and generation settings |
| MSCS811_Model_Setup.json | Model URL, revision, checksum, runtime configuration |
| MSCS811_BigVul_Pilot.zip | Original pilot sample |
| MSCS811_BigVul_Evaluation.zip | Original held-out sample and frozen protocol |
| MSCS811_Pilot_Results.zip | Pilot results read by the evaluation sampler |
| sampling/ | Original preparation scripts and source manifests |
| results/pilot/ | Saved pilot predictions and scores |
| results/evaluation/ | All 900 responses, per-run scores, aggregate and provenance |
| docs/ | Report, PowerPoint with Arabic speaker notes, Arabic Colab guide |

Extract the repository ZIP before using these instructions.
Run commands from the repository root.

## Verify the submitted results

Requires Python 3.11 or later. This command uses the Python standard library.

~~~bash
python verify_results.py
~~~

It calls the original scoring functions on saved responses and compares every pilot score, evaluation score, and aggregate.
It also verifies evaluation archive and runner hashes. It works independently of model availability.

## New model inference

Use Python 3.11+, the GGUF listed in MSCS811_Model_Setup.json, and llama.cpp release b12263.
The original environment used a Linux x86_64 CPU with six inference threads.
Runners validate model checksums and runtime version before generation.
Keep the original ZIP and JSON inputs intact.

Download the approximately 1.12 GB model from the download_url field of MSCS811_Model_Setup.json.
Get the runtime from https://github.com/ggml-org/llama.cpp/releases/tag/b12263

Linux/Colab setup:

~~~bash
mkdir -p model llama
MODEL_URL=$(python -c 'import json; print(json.load(open("MSCS811_Model_Setup.json"))["model"]["download_url"])')
curl -fL --retry 3 "$MODEL_URL" -o model/qwen.gguf
curl -fL --retry 3 https://github.com/ggml-org/llama.cpp/releases/download/b12263/llama-b12263-bin-ubuntu-x64.tar.gz -o llama.tar.gz
tar -xzf llama.tar.gz -C llama
SERVER=$(find "$PWD/llama" -type f -name llama-server -print -quit)
"$SERVER" --version
~~~

Start with a single pilot function:

~~~bash
python run_mscs811_pilot.py --model model/qwen.gguf --server "$SERVER" --limit 1
~~~

Look for A=ok, B=ok, C=ok and Paired scored samples: 1/1.
Omit --limit 1 to run all 20 pilot functions.
Run the full three-repetition evaluation as follows:

~~~bash
python -u run_portable_evaluation.py --archive MSCS811_BigVul_Evaluation.zip --model model/qwen.gguf --server "$SERVER" --output evaluation_runs/new_run
~~~

Reuse that output path with identical inputs to resume an interrupted evaluation.
Pilot runs require a new output directory each time if using --output.
The runners start and stop their own local llama-server.

Windows examples (install the b12263 Windows CPU package and retain its DLLs):

~~~powershell
py run_mscs811_pilot.py --model "C:\models\qwen.gguf" --server "C:\llama\llama-server.exe" --limit 1
py run_portable_evaluation.py --model "C:\models\qwen.gguf" --server "C:\llama\llama-server.exe" --output evaluation_runs/new_run
~~~

Fresh inference passed on Linux x86_64 during packaging: one pilot function completed A, B, and C with valid outputs.
Windows execution was not tested.
The original CPU times describe the recorded environment. New devices may give different times and predictions.


## Client timeout on slower CPUs (2026-11-24 update)

The original runner waits 90 seconds for each generation request. A complete Colab rerun
encountered 43 transport timeouts and 36 dependent blocked reviews; its paired score counts
were 89, 90, and 90. All 821 valid verdicts matched their counterparts in the original run.
This is a separate rerun. Its metrics use incomplete paired subsets and should not replace
the report's results as if the samples were identical.

Use run_portable_evaluation.py for a new run. It increases only the client wait to 600 seconds
and records that change in client_settings.json. It leaves the original scripts and protocol
unchanged. The exact original entry point remains available for a compatible environment.
Windows execution and a complete 900-response run with this wrapper have not been tested.
The wrapper's timeout forwarding and resume guards were checked, and the recovery script
completed a real E003 A/B/C retry on Linux with the same extended wait mechanism.

A limited timeout is not a guarantee: slow or failed requests can still time out after 600 seconds.
Check paired_scored_samples in every scores.json; a full run should have 100 in each repetition.

Existing Colab run recovery (optional, do not repeat the full dataset unnecessarily):

~~~bash
python -u recover_colab_timeouts.py --project-dir . --server "$SERVER" --timeout 600
~~~

This reads evaluation_runs/my_run and writes evaluation_runs/my_run_timeout600.
It repeats only triplets containing a timeout or blocked review, without using reference labels
to select retries. It copies complete triplets byte-for-byte and preserves source records.
It records inherited and repeated cases in recovery_manifest.json. These recovered results
are not independent new repetitions. Their response times exclude earlier failed attempts;
retain the original run for total-cost accounting. Stop and inspect any new failure.
Use --max-cases 1 for a one-case checkpoint, then resume with the same settings without that flag.
Use --verify-only to verify the source scores without inference.

## Recorded results

| Condition | Accuracy | Precision | Recall | F1 | Mean total request time |
|---|---:|---:|---:|---:|---:|
| A | 56.0% | 54.3% | 76.0% | 63.3% | 8.19 s |
| B | 53.0% | 51.8% | 88.0% | 65.2% | 16.96 s |
| C | 55.0% | 53.1% | 86.0% | 65.6% | 17.10 s |

The F1 difference C minus B is approximately 0.46 percentage points using unrounded scores.
C removes three false alerts and misses one additional positive relative to B.
B and C costs include the initial assessment and their respective review requests.

## Rebuild sample selection (optional)

~~~bash
python -m pip install -r requirements.txt
~~~

The pilot sampler expects bigvul_validation.parquet and its supplied README.md beside it in sampling/pilot/.
Download the pinned Parquet using source_url in sampling/pilot/source_manifest.json.

~~~bash
python sampling/pilot/prepare_pilot.py
~~~

It writes sampling/MSCS811_BigVul_Pilot.zip. ZIP timestamps can change on regeneration.
Use the original root data archive for inference with the frozen runners.

For the evaluation sampler, download the pinned test Parquet using sampling/evaluation/source_manifest.json.
It reads the original root pilot archive, pilot results, and JSON configuration files.

~~~bash
python sampling/evaluation/prepare_evaluation.py --project-dir . --test-parquet /path/to/bigvul_test.parquet --output evaluation_sample_rebuilt.zip
~~~

Use a new output filename. The root archives preserve the original hashes needed by the frozen runners.

## Sources and document provenance

BigVul paper: https://doi.org/10.1145/3379597.3387501  
Unofficial dataset distribution: https://huggingface.co/datasets/bstee615/bigvul  
Dataset revision: 4d8647a9b52fdd2ae42343c60fd6c7c48bbff25e  
Model: https://huggingface.co/Qwen/Qwen2.5-Coder-1.5B-Instruct-GGUF

Dataset excerpts retain the rights and terms of their source projects.
The reference records retain original commit URLs and row IDs.

The bundled report is the user's version (5). Its common-instruction paragraph paraphrases the executed prompt.
For exact reproduction use MSCS811_Experiment_Prompts.json.
The Colab guide links to the original ChatGPT files. Root files supply those same inputs.

## Verification during packaging

The runners and sample archives match the original recorded checksums.
Pilot scores, all three evaluation score sets, and the aggregate were recomputed successfully from saved responses.
All Python files passed syntax checks. Both inference CLI entry points passed --help checks.
A fresh one-function pilot passed with the pinned model checksum and b12263 runtime on 2026-11-19.
All three conditions returned status ok; paired scored samples: 1/1.
The new smoke-test logs are in docs/packaging_smoke_test/, separate from the original research results.
The complete 900-response evaluation was not rerun during packaging.
The optional Parquet sample-rebuilding scripts passed syntax checks but were not executed during packaging.
Fresh inference requires external model and runtime downloads.
