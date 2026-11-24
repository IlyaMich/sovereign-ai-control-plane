# Detection evaluation in GitHub Actions

The [Detection Evaluation workflow](../.github/workflows/detection-evaluation.yml)
executes the existing synthetic detector evaluation on a **GitHub-hosted Ubuntu
runner with Python 3.12**. Unlike the [manual performance workflow](../.github/workflows/performance.yml),
it needs **no self-hosted Podman runner, signed release, policy server, API key, or
running application**, because it evaluates detector adapters directly.

## When it runs

- Automatically for pull requests to `main` and pushes to `main` that touch
  detection code, evaluation sources/tests, model/dependency configuration,
  or this workflow/documentation.
- Manually from **Actions → Detection Evaluation → Run workflow**, including
  when you want an unchanged codebase checked again.
- The existing `CI` workflow still validates the dataset and runs the normal
  Python test suite; this workflow adds **real detector execution and paired
  stock-Presidio comparison**.

The job uses read-only repository permissions, unprivileged GitHub-hosted
runners, and no deployment/production secrets. No simulator, external provider,
OPA runtime, or release activation is started. Only the synthetic benchmark is
used; the spaCy model is installed from its version-pinned release URL, matching
[the existing CI setup](../.github/workflows/ci.yml).

## What it runs

1. Install project `.[dev]` dependencies and `en_core_web_sm==3.8.0`.
2. Run the detection framework's unit tests and validate the frozen dataset.
3. Execute all **1,200 cases** with the `presidio-stock` adapter and the
   `control-plane` adapter, using the **same code revision and runner**.
4. Re-score the saved predictions and produce the paired Stage 3 comparison.
5. Apply `evaluation.ci_gate` checks and upload **aggregate-only artifacts**.

The following rules fail the workflow:

- The dataset is not frozen v1 (`1200` cases, manifest SHA-256
  `766980e0e02f92931dac747a36bcddf915d8ef597e267d9c552fce03a4c74109`).
- Either detector reports execution errors or produces incomplete run metadata.
- The candidate classifies any known-sensitive synthetic prompt as
  `NO_PRIVATE_DETECTED` (unsafe negative), or introduces a new unsafe negative
  relative to stock Presidio.
- Candidate **exact F1** or **exact recall** falls below the same-run stock
  Presidio baseline.
- The paired comparator rejects case IDs, dataset identity, scoring results,
  or other integrity checks.

There is **no hard-coded minimum F1**, fixed latency threshold, or prohibition
against `UNKNOWN`: uncertain detection may be fail-closed and needs separate
review. F1/recall are relative to **stock Presidio on the same commit**, not a
historical approved control-plane release. If you want a gate against an earlier
approved control-plane run, that requires a separately maintained and reviewed
baseline artifact; Actions artifacts are not release attestations.

## Results and privacy

The job summary contains aggregate F1/recall, unsafe-negative rate, unknown
rate, and gate outcomes. The Actions artifact (retained for 14 days) contains
`stock-run.json`, `candidate-run.json`, their `categories.csv`,
`paired-comparison.json`, `paired-categories.csv`, `paired-comparison.html`,
`gate.json`, and `summary.md`.

**Do not upload** the synthetic dataset itself, `predictions.jsonl`,
`cases.csv`, `changed_cases.csv`, raw request/response text, or any operational
audit evidence in Actions artifacts. This workflow creates full evaluator
outputs only under the runner's temporary directory, then exports a strict
aggregate allowlist. Job console output contains summaries only.

A passing detector-only benchmark **does not** prove safe external forwarding,
complete redaction, signed audit verification, or production release readiness.
Use the separate Stage 2 enforcement replay, release controls, and signed
performance benchmark for those claims. The GitHub-hosted runner's timing is
**diagnostic**, not a stable capacity benchmark; use your controlled
self-hosted performance runner for repeatable load comparisons.

## Local reproduction

From the repository root in an environment with the pinned model installed:

```powershell
python -m pytest -q tests/evaluation/test_detection_ci_gate.py
python -m evaluation.cli validate
python -m evaluation.cli detect --adapter presidio-stock --split all --output-dir evaluation/runs/ci-stock
python -m evaluation.cli detect --adapter control-plane --split all --output-dir evaluation/runs/ci-candidate
python -m evaluation.cli compare --baseline evaluation/runs/ci-stock --candidate evaluation/runs/ci-candidate --output-dir evaluation/runs/ci-paired
python -m evaluation.ci_gate --stock evaluation/runs/ci-stock --candidate evaluation/runs/ci-candidate --comparison evaluation/runs/ci-paired --aggregate-dir evaluation/runs/ci-aggregate
```

Use fresh output directory names for subsequent local reproductions. The
aggregate directory and individual run folders are ignored under
`evaluation/runs/`.
