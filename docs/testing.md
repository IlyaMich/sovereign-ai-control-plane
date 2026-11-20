# Testing and verification - signed releases, M7 operations and detection evaluation

The project has unit/integration tests for detection, policy parsing, enforcement, audit integrity, policy replay, detector provenance, signed releases, idempotency, bounded executors/admission, upload deadlines, runtime logging/metrics and concurrent release publication. The **runtime** verification path is Windows PowerShell + Podman Compose.

## Prerequisites

From the repository root: `.env` with a strong `CONTROL_PLANE_API_KEY`; Podman + Compose provider; Python 3.12+; for M6 a properly provisioned **separate release signing key** and activated signed release. Preserve audit volumes and signing material; never use `compose down -v` on existing evidence.

The local runtime is intentionally English ASCII-only and simulated models are used for inference. External model integration is not tested by the simulated egress profile.

## Candidate response-side DLP verification

The proposed output policy has a new Rego entrypoint and revision, but the
checked-in active snapshot remains signed for the old release. Do **not**
overwrite active policy or release files merely to run a test.

~~~powershell
python -m pytest -q tests/enforcement/test_output_dlp.py tests/api/test_output_dlp_api.py
python -m tools.test_output_policy --opa-bin opa
~~~

The policy test helper builds a disposable policy snapshot and evaluates both
request-side and output-side Rego tests. See
[response-side DLP](response-side-dlp.md) for the output audit contract and
required successor release procedure.

## Python tests

~~~powershell
python -m pip install -e '.[dev]'
python -m pytest -q
~~~

`tests/integration/test_presidio_real_integration.py` is skipped if the NLP installation is absent; install the pinned spaCy English model in a dedicated environment to run it. The production image intentionally omits pytest. `make test` is available when Make is installed and the virtual environment has been set up.

CI installs the patched OPA CLI before the complete Python suite and treats
Python warnings as errors. Local signed-runtime integration tests require
`OPA_BINARY` to name an OPA executable; the symlink test also requires host support.

CI security scans freeze installed dependencies to `requirements.txt`, retain
`trivy-filesystem.json`, and fail if that report does not include the Python
requirements. Bandit blocks all unreviewed severities. Narrow `nosec` annotations
cover only the necessary external OPA/Git subprocess boundaries: executable paths
are resolved without searching the checkout, shell launchers are rejected, shells
are disabled, stdin is closed, and executions have deadlines. Internal signing and
profiling calls use Python APIs; no scanner rule is disabled globally.

Tests are grouped by subsystem under `tests/api/`, `tests/application/`,
`tests/audit/`, `tests/detection/`, `tests/enforcement/`, `tests/infrastructure/`,
`tests/policy/`, `tests/release/`, and `tests/tools/`. Cross-component tests live
with the subsystem whose behavior they verify. Tests exercising real Presidio
or a signed runtime with the OPA CLI live in `tests/integration/`; dependency-based
skips still apply. The existing `tests/evaluation/`, `tests/performance/`,
`tests/rego/`, and `tests/rego_output/` suites keep their dedicated folders.

Shared fixtures and test doubles remain in `tests/conftest.py`. Each Python test
folder is a package so cross-suite helper imports remain explicit. The default
`python -m pytest -q` command discovers all Python suites, including integration
tests. Run an individual subsystem from the repository root, for example:

~~~powershell
python -m pytest -q tests/api
python -m pytest -q tests/detection tests/enforcement
python -m pytest -q tests/integration
~~~

Key areas:

| Test area | Files / checks |
| --- | --- |
| Detection normalization, unknown/overlap behavior | `tests/detection/test_detection_aggregation.py`, `tests/detection/test_presidio_adapter.py`, `tests/integration/test_presidio_real_integration.py` |
| API, authorization and sanitized errors | `tests/api/test_api.py` |
| Audit sequencing, tamper/truncation | `tests/audit/test_audit_integrity.py` |
| Decision-before-forwarding and fail-closed orchestration | `tests/application/test_orchestrator.py`, `tests/enforcement/test_redaction_and_egress.py` |
| OPA parsing and Rego | `tests/policy/test_policy_adapter.py`, `tests/rego/decision_test.rego` |
| Policy integrity, archive replay | `tests/policy/test_policy_snapshots.py`, `tests/policy/test_policy_replay.py`, `tests/policy/test_policy_integrity_enforcement.py` |
| Detector provenance and portable evidence | `tests/audit/test_provenance_and_evidence_packages.py` |
| Signed releases, anti-rollback workflow | `tests/release/test_release_approvals.py`, `tests/release/test_runtime_release.py` |
| Idempotency, restart and cancellation behavior | `tests/audit/test_idempotency.py` |
| Admission, ingress and upload deadlines | `tests/api/test_request_admission.py`, `tests/api/test_ingress_bounds.py`, `tests/api/test_upload_deadline.py` |
| Bounded detector/audit/integrity workers | `tests/application/test_detector_executor.py`, `tests/audit/test_audit_executor.py`, `tests/audit/test_audit_capacity_bounds.py`, `tests/infrastructure/test_integrity_executor.py`, `tests/infrastructure/test_integrity_runtime.py` |
| Runtime diagnostics and logging | `tests/infrastructure/test_runtime_metrics.py`, `tests/infrastructure/test_logging.py`, `tests/infrastructure/test_logging_runtime.py` |
| Atomic publication and activation races | `tests/infrastructure/test_atomic_publication.py`, `tests/release/test_release_activation_concurrency.py` |
| Profiling and overload tool logic | `tests/tools/test_concurrency_performance.py`, `tests/tools/test_overload_and_audit_lookup.py` |
| Synthetic evaluation validation, scoring and reports | `tests/evaluation/` |

## Runtime and Rego checks

Run after installing/activating the **approved** release image; do not rebuild it after signing.

~~~powershell
podman compose -f deploy/compose.yaml --env-file .env up --no-build --force-recreate -d
Invoke-RestMethod http://127.0.0.1:8000/health/ready -Headers @{"X-API-Key"=$env:CONTROL_PLANE_API_KEY}
podman compose -f deploy/compose.yaml --env-file .env exec control-plane python -m tools.smoke_detection
podman compose -f deploy/compose.yaml --env-file .env run --rm opa test /policies /policy-tests
python -m tools.verify_policy_snapshot
python -m tools.verify_release
.\Verify-SignedReleaseWorkflow.ps1
~~~

The documented M6 validation on Windows produced `RELEASE_VERIFIED`, Rego `PASS: 14/14`, `READY`, an approved signed request, and an offline evidence report with `REPLAY_VERIFIED`. Test counts reflect that run and are not a hard-coded guarantee for future test additions.

The additional historical `Verify-RedactionAndEgress.ps1`, `Verify-PolicyEvidenceAndReplay.ps1` and `Verify-DetectorProvenanceAndEvidence.ps1` scripts cover redaction/network isolation, policy snapshot replay and detector provenance; they are useful regression checks, but **the current signed-release startup and activation procedure supersedes their older `up --build` commands**.

### Optional simulated external egress

Set `ENABLE_EXTERNAL_SIMULATOR=true` and start the `egress-test` profile using an approved prebuilt image. `Verify-RedactionAndEgress.ps1` exercises redaction digest equivalence, blocked destinations, network separation, gateway outage and cryptographic audit verification. Use synthetic PII only. The gateway is not a real external cloud or proof of geographic residency.

## Offline evidence interpretation

A valid verification may report:

- `RELEASE_VERIFIED`: active policy/detector tuple matches signed release approval.
- `EVIDENCE_PACKAGE_SELF_CONSISTENT` and `audit.status=REPLAY_VERIFIED`: package hashes, event chain and eligible Rego decisions reproduce using keys/checkpoints from the package.
- `release_signer_trusted_externally=true`: independent release public key was used for approval authentication.
- `public_key_trusted_externally=false` / `checkpoint_trusted_externally=false`: **audit history itself is not independently anchored**.
- `classification_replayed=0`: expected; plaintext input/model weights are not exported.

For stronger audit authentication, supply independent `--trusted-public-key` and `--trusted-checkpoint` to `tools.verify_evidence_package`. Current scripts do **not** automate periodic external checkpoint witnessing.

## Detection evaluation and concurrency profiling

The developer-only [Stage 1 detection evaluation](../evaluation/README.md)
provides a versioned 1,200-case synthetic dataset and detector scoring/reporting.
Validate the fixture without loading the NLP model:

```powershell
python -m evaluation.cli validate
python -m pytest -q tests/evaluation
```

Actual detection evaluation requires the pinned local spaCy model; follow the
evaluation README. It does not exercise OPA, model forwarding or live egress.

[M7.9 profiling](concurrency-performance-profiling.md) and the
[live overload/lookup follow-up](overload-and-audit-lookup.md) exercise an approved
running simulator deployment with signed-audit checks. They require the separately
supplied, Git-ignored `benchmarks/` kit and cannot be reproduced from a fresh
checkout without that dependency. Tool unit tests do not establish live capacity,
resolve a performance regression, or satisfy the documented M7 acceptance criteria.
The historical M6 results above do not validate later M7 changes.

## Gaps not covered by current automated tests

Real enterprise identity/tenant isolation, real local-model inference quality, external provider identity/residency, mTLS and authenticated egress, output DLP, distributed audit durability, production-scale capacity/SLO guarantees, full supply-chain attestation, audit signer compromise recovery, and periodic external checkpoint witnessing.

See [current architecture](architecture.md), [threat model](threat-model.md) and [Milestone 6](signed-release-workflow.md).
