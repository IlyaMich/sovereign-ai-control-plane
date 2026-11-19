# Testing and verification — current Milestone 6

The project has unit/integration tests for detection, policy parsing, enforcement, audit integrity, policy replay, detector provenance and signed release approval. The **runtime** verification path is Windows PowerShell + Podman Compose.

## Prerequisites

From the repository root: `.env` with a strong `CONTROL_PLANE_API_KEY`; Podman + Compose provider; Python 3.12+; for M6 a properly provisioned **separate release signing key** and activated signed release. Preserve audit volumes and signing material; never use `compose down -v` on existing evidence.

The local runtime is intentionally English ASCII-only and simulated models are used for inference. External model integration is not tested by the simulated egress profile.

## Python tests

~~~powershell
python -m pip install -e '.[dev]'
python -m pytest -q
~~~

`tests/test_presidio_real_integration.py` is skipped if the NLP installation is absent; install the pinned spaCy English model in a dedicated environment to run it. The production image intentionally omits pytest. `make test` is available when Make is installed and the virtual environment has been set up.

Key areas:

| Test area | Files / checks |
| --- | --- |
| Detection normalization, unknown/overlap behavior | `tests/test_detection_aggregation.py`, `test_presidio_adapter.py`, `test_presidio_real_integration.py` |
| API, authorization and sanitized errors | `tests/test_api.py` |
| Audit sequencing, tamper/truncation | `tests/test_audit_integrity.py` |
| Decision-before-forwarding and fail-closed orchestration | `tests/test_orchestrator.py`, `test_redaction_and_egress.py` |
| OPA parsing and Rego | `tests/test_policy_adapter.py`, `tests/rego/decision_test.rego` |
| Policy integrity, archive replay | `tests/test_policy_snapshots.py`, `test_policy_replay.py`, `test_policy_integrity_enforcement.py` |
| Detector provenance and portable evidence | `tests/test_provenance_and_evidence_packages.py` |
| Signed releases, anti-rollback workflow | `tests/test_release_approvals.py` |

## Runtime and Rego checks

Run after installing/activating the **approved** release image; do not rebuild it after signing.

~~~powershell
podman compose -f deploy/compose.yaml --env-file .env up --no-build --force-recreate -d
Invoke-RestMethod http://127.0.0.1:8000/health/ready
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

## Gaps not covered by current automated tests

Real enterprise identity/tenant isolation, real local-model inference quality, external provider identity/residency, mTLS and authenticated egress, output DLP, distributed audit durability, load/performance testing, full supply-chain attestation, audit signer compromise recovery, and periodic external checkpoint witnessing.

See [current architecture](architecture.md), [threat model](threat-model.md) and [Milestone 6](signed-release-workflow.md).
