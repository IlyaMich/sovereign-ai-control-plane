# Threat model and sovereignty - signed releases and M7 operations

**System under review:** A single-host, local AI policy gateway running FastAPI, Presidio/spaCy, OPA, a local model simulator and SQLite audit chain on Podman Compose. Optional `egress-test` services are **simulated**. This is a reference implementation, not evidence of certification, production isolation, or regional residency.

## Assets and boundaries

- Sensitive prompt text and recognizer findings; integrity of classification and transformed payload.
- Approved policy/detector bytes, release trust root and permitted model destinations.
- Signed audit events, signing keys, archived policy/detector/release artifacts and external witness checkpoints.
- Authenticated request identities and eventually tenant/role boundaries.

The client and request body are untrusted. OPA inputs derive from trusted application-side classification, not the client's claims. The local host, Podman/Compose runtime, base images, installed dependencies and OPA engine are **within the current trusted computing base**; malicious compromise of those components exceeds the prototype's effective enforcement boundary.

The **release signer private key** is kept outside runtime containers/repository. The **audit signing private key** is still locally managed with its SQLite audit volume. The release and audit key roles are not interchangeable.

## Controls implemented and exercised

| Threat / failure | Current defensive behavior | Limit |
| --- | --- | --- |
| Client attempts URL injection or changes tenant claims | Request accepts only fixed destination ID; principal comes from API-key authentication | Single static tenant, not real enterprise IAM |
| Prompt injection attempts to alter the policy | Prompt is data; Rego receives structured classification, not instructions | Downstream model may still be vulnerable to prompt injection |
| Detector crashes, unsupported input, incomplete coverage | `UNKNOWN` or exception becomes local deny; no model call | False-negative entities can still be missed |
| Secret markers detected | Current Rego `CREDENTIAL_BLOCKED` for configured formats | Not exhaustive secret recognition |
| OPA unavailable or malformed decision | Local fail-closed denial and audited reason | Audit writer must still be writable |
| Rego source replaced or old policy loaded | Active snapshot digest checked against OPA answer and signed release | Compromised runtime binary/host can evade local checks |
| Release signer untrusted or wrong detector artifact | Startup, readiness and request validation fail closed | Local monotonic generation isn't hardware-backed |
| External simulated route with PII | Mandatory redaction plan, second scan, fixed gateway and no direct model connection | Second scan is best-effort; no real external egress attestation |
| Audit unavailable before model | Precommit fails; no invocation | Rejected request may not be durably recorded |
| Audit row edited / chain gap | Hash/Ed25519 verification rejects tampering | Tail truncation needs independent prior checkpoint |
| Archive or release manifest tampered | Content digests and signed release verification reject mismatch | Does not attest entire image or host |
| Model call timeout | Outcome `UNKNOWN` rather than falsely claiming block; an opt-in durable idempotency claim prevents another gateway admission for the same key | No automatic outcome recovery or exactly-once provider execution |
| Retry after lost response | Tenant/principal-scoped durable key claim; matching retry returns 409 with original request ID | Claim table is unsigned; output is not cached; unkeyed requests can execute again |
| Slow upload or capacity exhaustion | Body deadline, HTTP/prompt admission bounds and bounded worker jobs/waiters | Per-process bounds; health probes may be rejected; this is not a global rate limit |

Default `sovereign-internal` network is private; API published only on loopback. The optional test profile routes through an explicit gateway into a second **private** simulator network. Podman networking differs across Windows VM/rootless environments and does not replace tested host firewall rules, mTLS or workload identity.

## Residual risks and unimplemented security controls

1. **Audit trust:** The standard evidence ZIP supplies its own audit public key and checkpoint; this proves internal consistency but not independent authenticity or completeness. Periodic checkpoint witnessing to external storage is not implemented. Local audit key compromise threatens reconstructed history.
2. **Real model sovereignty:** No real inference server, provider residency attestation, authenticated real external egress or RAG/attachment scanning. Model responses are scanned and blocked if private or unknown; classification may miss private content and masking is opt-in v5 only after release approval.
3. **Identity/governance:** One API key maps to `local-tester` / `local-tenant`. No OIDC/JWT, tenant-aware admin policies, authorization workflows, RBAC or tenant isolation at scale.
4. **Detection limits:** English ASCII, best-effort recognizers and limited patterns; entity overlap/threshold handling does not guarantee complete sensitivity detection.
5. **Supply chain and releases:** Selected model/source bytes are hashed and independently approved, but not the full image, OS and dependency closure. Python versions are not fully hash-locked; release key is an unencrypted development PEM; local generation checks can be subverted by host administrators.
6. **Operational resilience:** Single local SQLite sequencer with bounded per-process admission and worker queues. Durable opt-in idempotency and a read-only lifecycle inspector exist, but automatic recovery, cached responses, exactly-once inference, global rate limits, distributed sequencing, streaming, production monitoring and disaster recovery remain unimplemented. See [idempotency](idempotency-and-request-lifecycle.md) and [configuration](configuration.md).

## Evidence interpretation

- Signed audit events prove internal append-chain integrity **relative to a trusted key**; a self-contained ZIP is not an independent proof of origin.
- Archived Rego and signed policy-input metadata enable deterministic replay of **eligible** decisions (M4+), not original model inference or classifier correctness.
- Detector artifact digests (M5+) identify enumerated classifier bytes; they do not reproduce classification without prompt/model artifacts.
- Release signatures (M6+) prove approval by an externally trusted signer for an artifact tuple; they do not prove policy correctness, legal compliance, live host integrity or destination residency.
- A checkpoint witnessed outside the writer's trust domain is necessary to resist plausible tail rewrite/truncation by a compromised local signer.

## Priority improvements

Independent audit trust and periodic checkpoint witnessing; protected audit/release keys; real local inference and authenticated egress; broader DLP channels and real-runtime tests; OIDC/multi-tenant policy governance; then deployment hardening and measured performance improvements. Existing [profiling and overload tools](concurrency-performance-profiling.md) support investigation; their presence does not establish completed performance acceptance.

See [audit design](audit-design.md), [architecture](architecture.md), [Milestone 6](signed-release-workflow.md) and the [release workflow](policy-design.md).
