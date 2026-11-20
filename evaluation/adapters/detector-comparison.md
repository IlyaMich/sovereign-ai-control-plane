# Stage 3 — reproducible detector comparison

Stage 3 is **developer-only**. It adds a **stock Presidio baseline** and a paired
comparison command. It does not alter the production detector, enforcement,
OPA policy, audit storage, or signed release. The frozen dataset v1 is unchanged:
`766980e0e02f92931dac747a36bcddf915d8ef597e267d9c552fce03a4c74109`.

## What the baseline measures

`--adapter presidio-stock` uses Presidio's **built-in recognizers only**,
without the Sovereign `rules.json` custom patterns, `FindingAggregator`, or
candidate safety guard. It uses `presidio-analyzer==2.2.366`, the pinned
`en_core_web_sm==3.8.0` model, English NLP, and `score_threshold=0.5`. To
match the control plane's *evaluation input scope*, the adapter returns
`UNKNOWN` for non-ASCII prompts; this is an **evaluation wrapper** and not
native Presidio abstention behavior. Unlike the control-plane aggregator, stock
Presidio does not automatically abstain on low-confidence raw candidates.

Only built-in supported categories are requested from the stock analyzer; all
other categories in the frozen nine-category ground truth remain in the
**full-taxon denominator** and can contribute false negatives. A run's
`adapter_metadata.supported_categories` and `unsupported_categories` identify
this coverage limitation. This comparison evaluates detection quality, **not**
complete policy or egress safety. Never interpret a `NO_PRIVATE_DETECTED`
baseline result as an externally authorized request.

Like Stage 1, all model calls are local, the spaCy model must be installed in
advance, and Presidio's tldextract suffix lookup is disabled at runtime.

## Installation and commands (PowerShell)

Use the same `.venv` for comparable runs and do **not** change the frozen
benchmark dataset or scoring specification.

```powershell
# From the repository root; existing Stage 1 prerequisites also apply
.\.venv\Scripts\python.exe -m evaluation.cli validate
.\.venv\Scripts\python.exe -m pytest -q tests/evaluation

# Run stock Presidio against all 1,200 synthetic cases
.\.venv\Scripts\python.exe -m evaluation.cli detect --adapter presidio-stock --split all
```

Copy the resulting `run_dir` from the console. The following comparisons use
previously recorded run directories. Adjust them if yours differ:

```powershell
$original = "evaluation\runs\20261120T020050Z-907dc614"
$remediated = "evaluation\runs\20261120T031724Z-efddf754"
$stock = "evaluation\runs\REPLACE_WITH_NEW_STOCK_RUN_ID"

# Check original-to-remediated detection changes without rerunning either model
.\.venv\Scripts\python.exe -m evaluation.cli compare `
  --baseline $original --candidate $remediated

# Compare native stock Presidio with your remediated control-plane detector
.\.venv\Scripts\python.exe -m evaluation.cli compare `
  --baseline $stock --candidate $remediated
```

The `compare` command refuses different dataset SHA-256 values, dataset
versions, run splits, scoring specifications, missing/duplicate prediction case
IDs, invalid spans, or saved metrics inconsistent with re-scoring the stored
predictions. Both runs **must include** `run.json` and `predictions.jsonl`.
It does not overwrite historical run files.

The comparison output directory is under `evaluation/runs/comparison-...` and
contains:

- `comparison.json`: run identities and environment, aggregate deltas, fixed/new
  unsafe-negative classifications, and warning about detection-only scope.
- `categories.csv`: exact-span TP/FP/FN, precision/recall/F1 for each entity
  category, and per-category deltas.
- `changed_cases.csv`: IDs and classification/span-count differences, **no
  prompt contents**.
- `comparison.html`: self-contained human-readable comparative report.

A metric's delta is **candidate minus baseline**. For unsafe-negative and
false-positive rates, a negative delta is an improvement. Missing/undefined
precision or F1 is represented as `null` in JSON and `N/A` in HTML.

## Interpreting results

- **Exact entity F1** tests category and span equality; **overlap F1** accepts
  any same-category character overlap but does not prove complete redaction.
- **Unsafe-negative rate** is the proportion of *sensitive* ground-truth prompts
  classified `NO_PRIVATE_DETECTED`. This is **not** the number of actual
  unauthorized external forwards; use Stage 2 to measure that.
- **UNKNOWN** and **ERROR** are separate, not successful detection decisions.
- Stock Presidio may have a narrower entity taxonomy than the control-plane
  recognizers. Review the recorded supported categories before comparing
  aggregate results; never discard missed categories to inflate recall.
- p50/p95/p99 latency and throughput include local Python adapter overhead and
  vary by run environment, CPU state, Python version, and cold/warm model setup.
  Compare performance only in controlled matched environments.
- The dataset has repeated templates and deliberately fake tokens. It measures
  this benchmark, not real-world prevalence or regulatory compliance.
- Keep the `development`/`validation`/`evaluation` splits frozen; do not tune
  future recognizer improvements against held-out labels.

## Verification boundaries

The comparator re-scores every case from archived predictions; it does not
rerun old detector versions or cryptographically authenticate their recorded
metadata. The `adapter_metadata` for stock Presidio records category coverage,
threshold, dependency/model version, and configuration digest. Historical
control-plane runs may lack `adapter_metadata` or a detector artifact digest.
They are valid developer comparisons but not evidence of a signed deployed
release. Stage 4 will add CI and benchmark automation separately.
