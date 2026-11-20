# Response-side DLP evaluation

This is an **additive evaluation extension** to the existing Stage 1 detector and
Stage 2 enforcement benchmarks. It exercises the **real RequestOrchestrator's
output stage**, not a reimplementation of DLP decisions. The test model
returns deterministic synthetic responses from memory. **No HTTP inference,
production audit database, release signing key, running OPA service, or
external egress is used.** All audit keys, SQLite events, checkpoint and
evidence ZIP exist only in a temporary test directory and are deleted on exit.

## Run

Use the project Python environment with development requirements installed.
Run from the repository root.

```powershell
# Controlled safety/fail-closed cases with a fixture detector/policy.
python -m evaluation.output.cli --mode controlled

# Controlled cases with the real Rego policy evaluated locally by OPA CLI.
python -m evaluation.output.cli --mode controlled --policy opa-cli --opa-bin opa

# Turn frozen 1,200-case synthetic prompts into model-response payloads.
# Uses the real standalone Presidio/spaCy detector, NOT an installed approved
# artifact manifest. Pinned en_core_web_sm 3.8.0 is required.
python -m evaluation.output.cli --mode dataset --split development --limit 20
python -m evaluation.output.cli --mode dataset --split evaluation

# Recheck the benchmark and its negative controls.
python -m pytest -q tests/evaluation/test_output_evaluation.py
```

`--output-dir evaluation/runs/<unique-name>` selects a new run directory;
existing directories are never overwritten. By default a unique
`evaluation/runs/output-...` directory is created. For an OPA CLI run,
the harness builds an isolated content-addressed snapshot from **source**
`policies/` in its temporary directory, and independently replays all recorded
input and output decisions against that snapshot. It never uses or modifies
`.runtime/`, live Compose services or the actual release-trust store.

## Local OPA CLI on Windows (optional)

The `--policy opa-cli` mode launches a host executable through
`subprocess.run()`. The running Compose OPA container does **not** make an
`opa.exe` command available to Windows. To match `deploy/compose.yaml`,
install the official OPA **v1.8.0** Windows x64 release in a folder outside
the repository (example: `$env:LOCALAPPDATA\\Programs\\OPA\\1.8.0`).
Pass the absolute path using `--opa-bin`; no PATH modification is required.
Verify the binary checksum against the official GitHub release asset before
execution. Do not download the unpinned `latest` binary for reproducible
benchmark comparisons.

A missing executable now yields an explicit setup error and exit code 2.
Do not edit `.runtime/` or rebuild the OPA container to run this check.

## Diagnose nonzero dataset results

`run.json` contains `metrics.issues`, `metrics.false_block_count`,
`metrics.unsafe_sensitive_release_count` and detailed detection metrics.
`cases.csv` includes `issues`, expected versus actual response outcome,
classification and policy reason codes, without output content. A dataset
run with nonzero `failed` and zero `unsafe_sensitive_release_count`
still deserves review: false-positive blocks, wrong policy reasons or
unavailable classifications may explain the difference. Do not assume the
signatures are defective simply because some benchmark cases fail.

## Initial measured synthetic baseline (2026-11-20)

A Windows evaluation of the pinned 1,200-case fixture reported 1,190
expected outcomes, 10 unnecessary blocks, 440 released responses, 760 blocked
responses, **zero ground-truth sensitive releases** and 2,400 verified
temporary signed audit events. All 10 unexpected cases were
`HARD_NEGATIVE-0009`, `-0029`, ... `-0189`: repeated occurrences of
the hard-negative template `The instruction says BEGIN KEY, not a PEM private key.`
The output detector returned `PRIVATE`, so the output policy correctly
blocked each result *given the classification*. Direct inspection of
`HARD_NEGATIVE-0009` found `PERSON` from `SpacyRecognizer` at confidence
`0.85`, offset `[46, 55)`, matching the literal phrase `BEGIN KEY`.
The output describes a schema-like instruction, not an actual person's name.
This is a spaCy NER false positive on one repeated hard-negative template;
the other nine have the same template but were not independently inspected for
their matching spans. The false-block rate is **10/450 (2.22%)** of labeled
benign responses, not an estimate of real-world false positives.

No response policy or detector rule was changed: a `PRIVATE` classification
must continue to fail closed, and this frozen ground truth should remain
untouched. If detector precision is improved later, compare a fresh evaluation
to this documented baseline and use the approved signing/release workflow for
any production detector changes.

The local OPA 1.8.0 CLI controlled run also passed all 15 scenarios, with
29 independently verified temporary audit events and seven output-policy
decisions replayed.

A nonzero dataset CLI exit caused by false blocks is a **measured quality
finding**, not an evaluation-code crash. Preserve the frozen dataset labels;
do not loosen fail-closed response policy just to get a zero exit code.
For category/recognizer diagnosis, case-level reports created by this change
include `observed_categories` and `observed_recognizers` identifiers but
not extracted text, and earlier runs still retain per-category counts in
`run.json -> metrics.output_detection.entities_exact_full.by_category`.

## Controlled cases

The default suite includes two safe outputs; email, telephone, mixed entities,
API credential and PEM-header output; unsupported text; injected detector
`UNKNOWN` and exception; output-policy exception; empty/oversized output;
model timeout; and failure committing the output OUTCOME event.

All known-private responses must be blocked and withheld from the returned
`ProcessedRequest.output`. Expected failure modes must fail closed.
The output-audit failure must raise before any response is released; the
pre-model input decision remains signed. The model invocation must occur only
after the input DECISION event has been committed.

The benchmark's regression tests additionally inject (a) a detector false
negative that **releases a labeled synthetic secret** and (b) a detector false
positive that blocks benign text. These are intentional **negative controls**:
they prove that safety metrics notice unsafe releases and unnecessary blocks,
even when the audit signature itself remains valid. A third negative
control writes an internally contradictory output-release flag **with a valid
temporary audit signature**; independent evidence replay must reject it.

## Frozen-dataset mode: detection vs safety

`--mode dataset` reuses the existing digest-validated Stage 1 synthetic ground
truth as **model output**, while feeding the orchestrator a single fixed safe
input prompt. Every model result is intercepted before leaving the process.

Scoring uses `evaluation.scoring.score` to preserve exact-span and overlap
matching, status confusion, unknown rates and false-positive/false-negative
definitions. It is **not a new frozen response-specific dataset**; some source
prompts contain instructions rather than typical model outputs, so interpret
the numbers as synthetic response testing, not as production prevalence.

The measured release safety metrics are **separate** from detector metrics:

| Measurement | Definition |
| --- | --- |
| Output detection | Exact-/overlap-span precision, recall, F1, status confusion, false-positive rate, unsafe negative rate and sequential output detection p50/p95 latency |
| Released | Responses actually returned by the orchestrator |
| Output blocked | Responses withheld with `OUTPUT_BLOCKED` |
| Execution/audit errors | Model or audit failures with no released response |
| Unsafe sensitive release | Ground-truth-labeled sensitive output returned to the caller |
| False block | Benign output expected to be released but marked `OUTPUT_BLOCKED` |
| Output fail-closed | Explicit `UNKNOWN`, detector/policy failures, empty, oversized and audit-outcome failures do not release response text |
| Signed evidence | Independent Ed25519 audit chain verification, HMAC linkage, decision-before-model order, input and output policy replay, and outcome consistency |

CLI exit codes: `0` for a clean run, `1` for measured
safety/expectation violations (including an unsafe release), and `2` for setup,
verification or execution failures. Never interpret a run that failed
verification as a passing benchmark.

## Evidence verification and limitations

Each run creates its **own temporary Ed25519 audit authority** and an
immutable event chain. It verifies the audit chain using the corresponding
public key, exports a portable evidence ZIP, and passes a separate copy of the
public key and its audit head to `verify_package`. The verifier independently
replays input and output decisions with either the declared fixture evaluator
or the actual OPA 1.8 CLI.

A **fixture policy replay** confirms recording/serialization consistency and
cryptographic signatures, **not correctness of real OPA Rego**.
`--policy opa-cli` is required to claim that the local policy source
produces the recorded decisions.

The audit key and checkpoint are *pinned outside the generated ZIP*, but are
generated within the **same evaluation run**: they are not externally
witnessed production trust anchors, and do not prove resistance to an attacker
who controls the benchmark process. The benchmark does **not** verify a
production-signed release, actual detector-manifest provenance, real network
isolation, API authentication or operational SQLite recovery. Continue to use
the M6 signed-release workflow and offline reviewer for those controls.

The returned report records `release_signer_trusted_externally=false` on
purpose, to prevent misrepresenting temporary test evidence as production
release-approval evidence. The benchmark does not consume real audit records.

## Reports and privacy

Each run writes `run.json`, `cases.jsonl`, `cases.csv` and `report.html`.
These contain only case IDs, synthetic scenario labels, classification statuses,
entity counts, output outcomes, policy reason codes, issue codes and aggregate
metrics—not generated response strings, prompt text, extracted findings,
private keys, audit event payloads, or raw exception messages. The in-memory
response and temporary evidence bundle are never persisted under
`evaluation/runs/`. Do not repurpose the harness for real/private prompts.

Successful controlled fixture runs should report **15 cases, 2 released,
11 output-blocked, 2 model/audit errors, zero unsafe releases**, and
**29 signed audit events** independently verified. Seven policy-evaluated
outputs are replayed; six output denials are authenticated as local fail-closed
decisions. If this expected baseline changes, inspect the case-level report
before accepting a new benchmark definition.

## Remaining follow-up

For production-representative assurance, add a distinct offline approved-image
test using a test-only signed release and detector manifest, with intentionally
tampered release approval, altered detector digest and missing output evidence
negative controls. Do not run these against production signing keys or audit
volumes.

Latency here measures sequential response inspection, not throughput or concurrent admission.
Synthetic benchmark audit pins must never be substituted for independent
production signing authorities.
