# Stage 1 diagnostics + Stage 2 enforcement evaluation

All commands below run from the **repository root**. They do not edit `app/`,
`policies/`, `policy-active/`, `release-*`, signed detector manifests, or the
control-plane deployment. They use **synthetic** prompts only. Recorded model
calls are intercepted in memory, and the evaluation audit database and signing
keys exist only inside a temporary directory. Do not point these tools at an
operational audit database or model endpoint.

## 1. Analyze the saved Stage 1 baseline

```powershell
python -m evaluation.diagnostics --run "evaluation\runs\20261120T020050Z-907dc614"
```

Requires that run folder's `run.json` and `predictions.jsonl` and the frozen
`evaluation/datasets/v1` dataset. The user-uploaded `run.json` alone is **not
sufficient** for case-level diagnosis. If `predictions.jsonl` was not retained,
rerun `python -m evaluation.cli detect --split all` before diagnostics.

Outputs under `<run>/diagnostics/`: `diagnostics.json`, `entity_errors.csv`, and `prediction_errors.csv`.
They contain case IDs, categories, offsets and span-coverage fractions, **not
prompt strings or recognized values**. Error types distinguish exact matches,
partial-coverage overlaps, boundary mismatch with full coverage, wrong-category
matches, `UNKNOWN`, detector error, unsafe negative and other unmatched entities.
The report **cannot** infer why Presidio candidates were low confidence or
suppressed without additional controlled recognizer instrumentation.

## 2. Controlled, network-free orchestration suite

```powershell
python -m evaluation.enforcement.cli --mode controlled
python -m pytest -q tests/evaluation
```

Runs 21 declared scenarios using the real `RequestOrchestrator`,
`EnforcementPlanner`, redaction routine and temporary `SQLiteAuditStore`, but
**fixture classification and fixture policy**. Asserts request outcomes,
forbidden model calls, decision precommit order, redaction-rescan denial,
unregistered routes, audit failure semantics, and release failure semantics.
This measures enforcement plumbing; **it is not evidence that live OPA, API
admission, or a signed production release was tested**.

## 3. Reproduce policy decisions with the actual OPA executable

Install/use an appropriate **local OPA 1.8.x CLI** (`opa version`). Without
calling the production OPA HTTP service, the suite verifies the existing
`policy-active` snapshot and its archive, then evaluates it through `opa eval`.
It does not modify, rebuild, or re-sign any active release.

```powershell
python -m evaluation.enforcement.cli --mode controlled --policy opa-cli --opa-bin opa
```

When this mode is used, the synthetic detector fixture advertises the current
`presidio-spacy-v1` classification contract to exercise the **real Rego rules**.
This deliberately bypasses runtime detector-manifest and signed-release
verification; signed-release integrity remains covered by existing M6 tests.
OPA evaluation failures produce failed scenarios rather than silently falling back to fixtures.

## 4. Replay against the real detector, targeting simulated external routing

Run this with Presidio and the pinned spaCy English model installed in the
active virtual environment. No live network egress occurs. The same model
payload never leaves the Python process; only case IDs and test outcomes are
written to the evaluation run directory.

```powershell
# Short smoke run with fixture policy
python -m evaluation.enforcement.cli --mode replay --split development --limit 20

# Entire 1,200-case dataset, real detector, actual pinned Rego snapshot
python -m evaluation.enforcement.cli --mode replay --split all --policy opa-cli --opa-bin opa
```

Each original test prompt is submitted to `RequestOrchestrator` with the
`external-simulator` destination and a recorder instead of an HTTP gateway.
The harness independently checks all labeled ground-truth spans against the
**spans actually redacted** before forwarding. A synthetic prompt classified
`NO_PRIVATE_DETECTED` can be permitted by policy; if its ground truth is
sensitive and the model recorder receives it, the report records
`UNSAFE_EXTERNAL_FORWARD`. An `UNKNOWN` that is blocked is **not counted as
an unsafe forward**.

Results: `run.json` (aggregate), `cases.jsonl` and `cases.csv` (case IDs only).
A non-zero exit code from replay indicates a measured invariant violation or
an unassessed execution failure; this is a **finding**, not an infrastructure
failure. Compared with the Stage 1 baseline, cases may be classified differently
if runtime versions or detector artifacts differ. Compare detector and dataset
identities before interpreting changes. Baseline tests from a standalone model
cannot prove approved image identity; use your M6 release verification for that.

## Boundaries and pending work

* No external network or real provider is contacted. The simulated outbound
  gateway is an in-memory spy, so these results are not proof of network
  isolation or geographically sovereign egress.
* `fixture` policy mode cannot claim actual OPA correctness. Prefer
  `--policy opa-cli` for Rego policy evidence.
* Neither mode verifies the production signed-release trust chain, API-key
  authentication, concurrency admission or audit durability under process kill.
  Continue to use the existing runtime/M6 tests for those assertions.
* Synthetic ground truth may need manual review before treating rate estimates
  as real-world risk estimates. No detector or policy tuning is done here.
* Input strings exist **in memory and in the synthetic dataset**. Reports are
  value-free, and temporary SQLite event records contain only structural
  classification findings and HMACs, not the raw prompts.
