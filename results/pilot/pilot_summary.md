# MSCS811 BigVul pilot results

The run attempted 20 C functions from the pinned BigVul pilot archive, with 10 per reference class. All methods produced a valid verdict on 20 samples. The scores below use those shared samples.

| Method | Valid | TP | TN | FP | FN | Precision | Recall | F1 | Mean seconds | Mean tokens |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| A Single pass | 20 | 8 | 3 | 7 | 2 | 53.3% | 80.0% | 64.0% | 2.51 | 569.60 |
| B Self-review | 20 | 9 | 1 | 9 | 1 | 50.0% | 90.0% | 64.3% | 5.17 | 1218.65 |
| C Separate reviewer role | 20 | 9 | 2 | 8 | 1 | 52.9% | 90.0% | 66.7% | 5.11 | 1219.70 |

Precision, recall, and F1 are undefined when their respective denominators are zero. Time and tokens for B and C include their shared initial analysis plus the corresponding review call.

| Comparison | Corrected | Made incorrect | Unchanged |
|---|---:|---:|---:|
| A to B | 1 | 2 | 17 |
| A to C | 1 | 1 | 18 |
| B to C | 1 | 0 | 19 |

22 of 60 reasons reached the 200-character limit. The metrics score the verdict field. Review explanation completeness separately.

The fixed 20-sample pilot checks feasibility and provides descriptive results for this run. Performance estimates for the study require a separate evaluation sample. The scores measure agreement with BigVul reference labels.

The archive includes the raw and parsed responses, score calculations, paired decision changes, and run configuration.
