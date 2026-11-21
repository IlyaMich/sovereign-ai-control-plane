# Operator and developer tools

Run module commands from the **repository root** in Python 3.12+. Host operator tools use the Git-ignored `.runtime/` state by default; **container commands use container paths** and may require Compose. Read `--help` for exact options. Never direct an evaluation tool at a production audit database or assume a Git-tracked example is a trusted live release.

| Command/module | Role | Side effects and safe use |
| --- | --- | --- |
| `tools.build_policy_snapshot` | Hash, archive and publish policy source | **Mutates** active/archive policy; use only in a coordinated release window or pass explicit disposable `--archive`/`--active` paths for CI |
| `tools.verify_installation` | Unified read-only host policy/release verification; optionally check detector bytes, signed audit chain (external checkpoint optional) and loopback API readiness via `--runtime` | Read-only; run from the operator checkout, never changes state |
| `tools.verify_policy_snapshot` | Verify policy active/archive consistency | Read-only |
| `tools.build_detector_manifest` | Generate detector provenance after build | **Writes** manifest; intended for image build, not a live approved container |
| `tools.verify_detector_manifest` | Recompute installed detector identity | Read-only; must run where pinned NLP/model files exist |
| `tools.generate_release_key` | Create development Ed25519 signer keypair; `--recover-public` can reconstruct public key | **Writes key files**; private key stays outside Git; never replace an existing deployment's authority |
| `tools.sign_release` | Offline sign a release candidate | **Writes approval JSON**, requires private key, exact policy snapshot and detector digest; never run on the API host |
| `tools.activate_release` | Verify and activate an approved release and policy | **Mutates** `.runtime` active/archive state under lock; stop services and preserve history |
| `tools.verify_release` | Authenticate signed release and policy identity | Read-only; uses trust state, not private signing key |
| `tools.verify_runtime_release` | Verify mounted release against installed image | Read-only; invoked by `make release-check` before starting the approved image |
| `tools.migrate_operator_state` | Preflight legacy-to-`.runtime` migration | Default **read-only preflight**; `--apply` copies/publishes verified state, refusing overwrite |
| `tools.verify_audit` | Verify local signed audit chain | Read-only; requires `--db` and `--public-key`; optional externally retained checkpoint |
| `tools.export_checkpoint` | Save signed-chain head to a separate file | **Writes checkpoint**; protect it externally if using as a trusted witness |
| `tools.export_evidence_package` | Export portable audit and provenance ZIP | **Writes output ZIP**; may read running SQLite, policy/detector/release archives; use bounded export controls |
| `tools.verify_evidence_package` | Network-free verify ZIP and eligible replay | Read-only; use external `--trusted-public-key`, `--trusted-checkpoint` and release trust for independent authentication |
| `tools.replay_decisions` | Replay recorded OPA decisions from a verified audit DB and policy archive | Read-only; requires trusted audit public key and OPA executable |
| `tools.inspect_request_lifecycle` | Report unresolved idempotency claims | Read-only; does not retry, rewrite or synthesize outcomes |
| `tools.smoke_detection` | Real local Presidio/spaCy smoke check | Synthetic in-process check; no cloud inference |
| `tools.smoke_idempotency` | Idempotency smoke check | **Writes synthetic audit events**; run inside a suitable approved test container, not against evidence to be preserved untouched |
| `tools.test_output_policy` | Build temporary source policy snapshot and run Rego tests | Temporary files only; requires `--opa-bin` resolving to a compatible OPA binary |
| `tools.run_control_plane` | Start validated Uvicorn API | **Starts server**; deployment entrypoint, not a document verification utility |
| `tools.concurrency_performance` | Capture/report M7.9 diagnostics with external reviewer kit | **Generates synthetic requests, signed audit events and local result files**; loopback-only test deployment |
| `tools.overload_and_audit_lookup` | Measure live overload and evidence lookup | **Generates test traffic, audit records and results**; loopback-only, safe test deployment |

The [performance CLI](../performance/README.md) offers `python -m performance.cli list|run|report|compare`; the [evaluation CLI](../evaluation/README.md) provides detector benchmarks and `evaluation.output.cli` evaluates response DLP. Both are **developer/test** tools; use their guides for synthetic datasets, optional model requirements and limits.

## Root PowerShell scripts

| Script | Intended use |
| --- | --- |
| `Approve-And-ActivateRelease.ps1` | **Mutating operator procedure**: build/verify intended image, sign and activate generation N+1 with the existing key, or bootstrap an independently isolated new authority |
| `Verify-SignedReleaseWorkflow.ps1` | Operator signed release, runtime and evidence verification; runs synthetic requests and may append audit events |
| `Verify-RedactionAndEgress.ps1` | Historical redaction/egress regression; inspect startup commands before use, never allow an obsolete `up --build` to replace approved images |
| `Verify-PolicyEvidenceAndReplay.ps1` | Historical policy/evidence replay regression, with the same startup caveat |
| `Verify-DetectorProvenanceAndEvidence.ps1` | Historical detector provenance/evidence regression, with the same startup caveat |

For safe order of operations and key custody, see [operator-state migration](operator-state-migration.md), [signed-release workflow](signed-release-workflow.md) and [testing](testing.md). `make build` is **not** equivalent to `make up`: a rebuilt detector/image must be approved before use.
