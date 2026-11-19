# Detection Evaluation — Stage 1

This is an **additive, developer-only benchmark** for the Sovereign AI Control Plane.
It does **not** change the production detector, OPA policy, signed release artifacts,
model gateway, or audit database. It is **not** an enforcement/egress benchmark (Stage 2),
a detector comparison (Stage 3), or a load/CI benchmark (Stage 4).

## Dataset v1

`datasets/v1/cases.jsonl` contains **1,200 deterministic synthetic prompts**, with
labels as exact character offsets into the original Python string, entity category,
expected detection status, scenario group, and dataset split.

| Group | Cases | Intended behavior |
| --- | ---: | --- |
| Standard sensitive | 350 | Find single labeled entities |
| Clean | 250 | Avoid false positives |
| Hard negative | 200 | Distinguish resembling/non-sensitive text |
| Mixed entities | 150 | Detect multiple labeled spans |
| Adversarial ASCII | 150 | Measure brittleness on modified formats |
| Unsupported/non-ASCII | 100 | Return `UNKNOWN`, as the current detector requires |
| **Total** | **1,200** | |

Splits: `development` 240; `validation` 240; held-out `evaluation` 720.
The default `--split all` processes all 1,200 cases; use `--split evaluation`
for the untouched holdout when comparing an improved detector.

The fixture uses fictional names, reserved `example.com`, `555-01xx` phone examples,
public payment-card/IBAN examples, and deliberately invalid token/key material.
Synthetic examples **must never be assumed to represent the true prevalence or
complexity of production sensitive data**. In particular, the `PRIVATE_KEY` cases
mostly test syntactically recognizable PEM-like material, not the detection of all
cryptographic secrets. `PERSON`, `LOCATION`, and obfuscated tokens may require
human review of ambiguous labels before publication of formal benchmark claims.

`manifest.json` stores a SHA-256 of the exact UTF-8 JSONL bytes. The loader
validates this digest, unique IDs/text, required fields, spans, split counts,
category names and input scope before benchmarking. This detects *accidental*
changes; it is **not a signed data-source attestation**. Protect benchmark
releases with reviewed Git commits/tags. Do not edit a released v1 dataset in
place to improve scores: create v2 instead.

## Requirements

Run from the **repository root**, with Python 3.12+ and the project's dev dependencies:

```powershell
python -m pip install -e ".[dev]"
```

The real detector also needs the exact spaCy model specified by
`deploy/Containerfile`. For a standalone developer environment (never on a
sensitive request path), install the pinned release:

```powershell
python -m pip install "https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl"
```

The existing production image does not include `evaluation/`. Keep this
benchmark in a separate developer environment; do **not** rebuild or modify
a signed production image just to run it. `ControlPlaneAdapter.create()` uses
`PresidioDetector.create()` in **standalone** mode without loading an
operational detector artifact manifest. Production enforcement provenance
therefore remains separate from this benchmark's source/config fingerprints.

## Commands

```powershell
# Verify the exact 1,200-case dataset before any model execution
python -m evaluation.cli validate

# Run every case and save reports in an automatically named evaluation/runs directory
python -m evaluation.cli detect --split all

# Test only the held-out 720-case split and choose a stable output path
python -m evaluation.cli detect --split evaluation --output-dir evaluation/runs/v1-holdout

# Regenerate the HTML report from a prior run.json
python -m evaluation.cli report --run evaluation/runs/v1-holdout

# Check evaluation logic (no Presidio/spaCy model required)
python -m pytest -q tests/evaluation
```

The **fixture generator** can reproduce `datasets/v1/` byte-for-byte with
`python -m evaluation.generate_dataset`. Do not execute it against an already
published dataset in the repository during routine benchmark runs.

## Output files

- `run.json`: metrics, run ID, dataset digest/version, adapter, Git commit,
  detector config/artifact identities (if provided), source/rules SHA-256,
  selected package/runtime versions and sequential-call latency percentiles.
- `predictions.jsonl`: one normalized detector result per case, **no prompt text**.
- `cases.csv`: case IDs, expected vs observed labels, span-match counts,
  reason codes and timing; **no prompt text**.
- `categories.csv`: exact-span entity precision, recall and F1 per category.
- `report.html`: self-contained summary/dashboard with category and group tables.

The reports intentionally omit raw input and exception messages. The synthetic
cases themselves still contain test PII-like strings, so share datasets only
as appropriate. `evaluation/runs` is gitignored.

## Scoring rules and interpretation

**Exact span matching** requires equality of category, start and end. **Overlap
matching** allows any same-category intersection but uses one-to-one maximum
matching to prevent double-counting. Both metrics are produced; do not treat
overlap recall as proof of safe redaction. Cross-category mismatches count as
one FP and one FN in the relevant categories.

The benchmark measures **prompt status** separately from entity accuracy:
`PRIVATE`, `NO_PRIVATE_DETECTED`, and `UNKNOWN` are three distinct states.
In-scope `UNKNOWN` and adapter `ERROR` cannot earn true positives in the
**full** entity recall; this avoids inflated safety/quality claims. Selective
exact entity scores (only definitive classifications) and in-scope `UNKNOWN`
rate are reported separately. Out-of-scope non-ASCII cases are excluded from
entity scores; their expected `UNKNOWN` frequency is reported separately.

`unsafe_negative_rate` here means **known-sensitive input classified
`NO_PRIVATE_DETECTED`**, not a confirmed external data leak. Stage 2 will
exercise OPA and actual forwarding and measure unsafe egress independently.

Latency is a sequential per-call diagnostic in Stage 1, **not a throughput or
concurrency benchmark**. Performance/load calibration belongs to Stage 4.

## Release-safety invariants

- No changes to `app/`, `policies/`, `policy-active/`, `release-active/`,
  `release-archive/`, `detector-active/`, `deploy/` or audit volumes.
- No remote inference or model invocation; detector calls remain local.
- Test fixtures are synthetic; never import operational audit data.
- Failing detector calls are marked `ERROR`, not silently scored as clean.
- No benchmark pass/fail thresholds are hard-coded until baseline measurement
  and ground-truth review have been completed.
