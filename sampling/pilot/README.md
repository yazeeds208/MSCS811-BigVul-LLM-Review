# MSCS811 BigVul pilot data

This package contains 20 historical C functions for a pilot evaluation of LLM-assisted defensive code review. It uses BigVul's dataset labels as the reference for this experiment. The labels were not independently audited and a zero label does not establish that the function has no security flaws.

| File | Use |
|---|---|
| `model_inputs.jsonl` | Present each `code` field to the model separately. Use the same 20 samples in all three conditions. |
| `reference_labels.jsonl` | Join predictions by `sample_id` for scoring. Keep labels, links, and identifiers out of the model inputs. |
| `source_manifest.json` | Dataset revision, checksum, source URL, and sampling counts. |
| `prepare_pilot.py` | Reproduce the selection from the same Parquet snapshot. |

The input field is `func_before`. The comparison label is `vul` from the same row, where 1 denotes a vulnerable function and 0 denotes a function labeled non-vulnerable by the dataset. `func_after` is used for a consistency check during selection. Each selected positive has a nonempty changed version and a CVE ID. Each selected negative has an unchanged version. These checks do not prove label correctness.

The source is the `validation` partition of the unofficial `bstee615/bigvul` distribution, pinned to the revision in `source_manifest.json`. Selection uses C-labeled functions with 100–4,000 characters after trimming outer whitespace, one sample per commit, a maximum of three per project, and at most one sample per nonempty CVE ID. A fixed seed selects ten positives. Each is matched to a similarly sized negative. Candidates with token five-gram Jaccard similarity of 0.8 or more to a previously selected function are excluded. The sample order is then shuffled. This balanced pilot supports a feasibility check and does not estimate performance at the original dataset's class prevalence.

Use different samples for final evaluation. Exclude these pilot rows and check for overlapping commits, CVEs, and similar code when selecting the final samples. Freeze model instructions and settings after the pilot. Record the model version and original responses for each condition.

To reproduce, save the Parquet file referenced by `source_url` as `bigvul_validation.parquet` next to `prepare_pilot.py` and `README.md`. Run the script with Python 3.11 or later and PyArrow installed. It writes the pilot archive to the parent folder.

BigVul source paper: Fan, J., Li, Y., Wang, S., & Nguyen, T. N. (2020). *A C/C++ Code Vulnerability Dataset with Code Changes and CVE Summaries*. MSR 2020. https://doi.org/10.1145/3379597.3387501
