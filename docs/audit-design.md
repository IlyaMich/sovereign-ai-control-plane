# Audit integrity, provenance and independent review — Milestone 6

**Current scope:** A single SQLite writer persists tamper-evident evidence for each admitted policy decision, before any model invocation. See [architecture](architecture.md), [policy design](policy-design.md) and [Milestone 6](signed-release-workflow.md).

## Commit order and failure semantics

1. Ingress creates an authenticated `PromptCommand` and a unique request ID.
2. The detector emits a normalized classification; OPA evaluates structured metadata and returns a content-bound policy decision.
3. The enforcement planner validates `REDACT`/`ROUTE` obligations and, when needed, redacts and rescans.
4. The orchestrator **durably appends and signs `DECISION` before calling any model**. A decision-commit failure prevents forwarding.
5. A denial appends `OUTCOME` with `BLOCKED` and `model_invoked=false`; a successful call appends `COMPLETED`. A model exception appends `UNKNOWN` execution status because the request could have reached the destination.
6. An outcome-write failure or process crash can leave an unresolved/pending decision. Missing outcomes are **not** evidence that the model was never invoked.

This guarantee covers **admitted policy decisions**. Rejected authentication, malformed pre-validation HTTP traffic or audit-store outages may prevent durable entry creation. The system does not currently reconcile unresolved executions using an idempotency protocol.

## Event fields and privacy

The SQLite record stores a schema version, sequence, event/request/tenant IDs, event type, timestamp, previous/current hashes, Ed25519 signature and JSON payload. The signed `DECISION` payload includes:

- Trusted principal ID and HMAC fingerprint of original input (not plaintext).
- Exact structured `policy_input`, normalized detection status, categories, scores, spans, detector/configuration identities.
- Final `decision` and, if evaluated, original `policy_evaluation`, exact `policy_snapshot` digest and revision.
- Optional `detector_snapshot` artifact digest (M5+) and `release_snapshot` release identity/approved digests (M6+).
- Transformation `applied` flag, output HMAC and second-scan metadata when redaction occurred.

The signed `OUTCOME` records execution status, destination/model ID and transformation flag. Raw prompts, matched text, model output and private keys are not copied into normal audit entries or evidence ZIPs. **Metadata still has privacy implications** (principal IDs, finding categories, offsets and operational history); restrict exports.

The input HMAC is for within-installation correlation. In the current design its key is derived from local audit key material rather than an independently managed tenant secret.

## Integrity construction

For this bounded v1 schema, serialized JSON uses deterministic Python JSON: sorted keys, compact separators, UTF-8, `allow_nan=False`. **It is not RFC 8785/JCS**.

~~~text
hash_i = SHA256(
  "sovereign-audit-event-v1\0"
  || previous_hash_bytes
  || uint64_be(sequence)
  || canonical_json(event)
)
signature_i = Ed25519_sign(audit_private_key, hash_i)
~~~

`BEGIN IMMEDIATE` serializes append transactions. SQLite uses WAL with `synchronous=FULL`. One local SQLite sequencer is assumed; no distributed ordering guarantee is claimed.

`tools.verify_audit` recomputes hashes, checks continuity and verifies every event using an audit public key. A forged or edited record is detectable without the private key. **Tail deletion can preserve a valid signed prefix** unless an earlier, independently retained chain-head checkpoint is available.

The exporter uses SQLite's backup API and changes only the **copied snapshot** to `journal_mode=DELETE`, so the network-disabled, read-only reviewer need not create WAL sidecar files.

## Portable evidence and verification levels

`tools.export_evidence_package` creates a ZIP with the consistent database snapshot, audit public key, checkpoint, referenced Rego snapshots, detector manifests and signed release approvals. `tools.verify_evidence_package` validates ZIP hashes, audit-chain signatures, detector manifest references, eligible Rego decision replays and release approval signatures.

| Reviewer claim | Required independent input | What it means |
| --- | --- | --- |
| `EVIDENCE_PACKAGE_SELF_CONSISTENT` | None; ZIP's own keys/checkpoint | Internally consistent, **not** independently authentic |
| `release_signer_trusted_externally=true` | Public release signing key supplied outside ZIP | Release approvals verify against that key; does **not** authenticate audit history |
| `public_key_trusted_externally=true` | Independently pinned audit public key | Audit signatures are checked against a pre-trusted key |
| `checkpoint_trusted_externally=true` | Independently retained checkpoint | Exact witnessed head is checked; strengthens completeness/truncation evidence |
| `REPLAY_VERIFIED` | Archived policy bytes + OPA binary | Eligible historical structured policy decisions reproduce |

The bundle's checkpoint generated during export is **not** an independent witness. A checkpoint needs to have been stored under separate authority *before* a potential compromise. The current verifier expects an exact checkpoint for the provided snapshot, not a general proof of later extension from an older checkpoint.

Example reviewer CLI (paths must exist in reviewer environment):

~~~powershell
python -m tools.verify_evidence_package --bundle evidence.zip --trusted-public-key trusted-audit-key.pub.pem --trusted-checkpoint witnessed-checkpoint.json --trusted-release-public-key trusted-release-key.pub.pem
~~~

The standard `Verify-SignedReleaseWorkflow.ps1` intentionally pins only the **release** public key outside the bundle; its observed result remains `EVIDENCE_PACKAGE_SELF_CONSISTENT` with authenticated release approvals until independent audit anchors are provided.

## Replay limits and history compatibility

- **M1–M3:** Audit signature integrity only; no archived source digest with which to replay exact old Rego.
- **M4+:** Eligible policy decisions can be reevaluated with archived Rego. Local fail-closed overrides are reported separately, not misrepresented as OPA replay.
- **M5+:** Detector manifest identity can be checked, **but original NLP classification cannot be reproduced** without original prompt/model artifacts.
- **M6+:** Archived release approvals can be authenticated with an out-of-bundle release signer key.

The release authority is **separate from** the audit signer. Host compromise remains a material threat: the audit key and SQLite volume are locally managed, and independently witnessed audit checkpoints are **not yet automated**.

## Next security work

Independent audit public-key pinning, periodic checkpoint witnessing to a separate trust domain, protected audit signing (KMS/HSM), recovery/rotation, audited evidence export access controls and an explicit unresolved-request reconciliation workflow. Do not imply GDPR/PCI certification or forensic completeness beyond the tested scope.
