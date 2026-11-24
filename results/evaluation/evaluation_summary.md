# MSCS811 final held-out evaluation

Three repetitions were completed on the same 100 BigVul functions from 60 projects. Each repetition used 50 functions per reference class and the frozen model, prompts, and generation settings.

| Method | Mean accuracy | Mean precision | Mean recall | Mean F1 | Mean seconds | Mean tokens |
|---|---:|---:|---:|---:|---:|---:|
| A Single pass | 56.0% | 54.3% | 76.0% | 63.3% | 8.19 | 617.97 |
| B Self-review | 53.0% | 51.8% | 88.0% | 65.2% | 16.96 | 1319.91 |
| C Separate reviewer role | 55.0% | 53.1% | 86.0% | 65.6% | 17.10 | 1320.97 |

Time and tokens for B and C include the shared initial call and their corresponding review call. Metrics use common valid cases per repetition.

| Repetition | Paired cases | F1 A | F1 B | F1 C | C minus B (pp) | C corrections | C regressions | Identical reasons on B/C flips |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 100 | 63.3% | 65.2% | 65.6% | +0.46 | 3 | 1 | 4 |
| 2 | 100 | 63.3% | 65.2% | 65.6% | +0.46 | 3 | 1 | 4 |
| 3 | 100 | 63.3% | 65.2% | 65.6% | +0.46 | 3 | 1 | 4 |

Status and verdict matches against repetition 1, in order for repetitions 2 and 3: {'A': [100, 100], 'B': [100, 100], 'C': [100, 100]}.
Response status counts: {'ok': 900}.

These are descriptive results for one balanced sample and one fixed model. Repetition assesses stability on the same functions. It does not increase the number of independent samples. BigVul labels serve as the reference for all classification metrics.
