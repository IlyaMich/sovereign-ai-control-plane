# Milestone 3: verified transformations and simulated model egress

## Invariants

1. Untrusted request data never determines a URL or a model hostname.
2. OPA returns an ordered obligation list; only zero or one `REDACT` followed by exactly one `ROUTE` is supported.
3. Destination registry is authoritative and unavailable destinations are denied.
4. For external targets, private findings require redaction of every detected category.
5. Transformation uses non-overlapping original offsets, stable placeholders, and a second full detection pass.
6. The second pass must report `NO_PRIVATE_DETECTED` to proceed.
7. Audit commits the final decision, original input HMAC, redacted input HMAC, and verification metadata **before** any model invocation.
8. Direct outbound internet traffic is not implemented; optional egress is simulated on a separate Podman network.

## Limitations and future design

- `POST /v1/prompts` is synchronous, with no streaming, attachment or RAG support.
- Re-scanning catches detectable remnants, not false negatives present in both passes.
- Return values from models are not inspected for data leakage.
- The simulated gateway does not independently attest the redaction; an actual boundary would need mTLS/workload identity and authorization tokens tied to the verified payload digest and decision receipt.
- Policy revision pinning is enforced operationally by readiness, but in-flight atomic policy version pinning and signed policy bundle archival remain future work.
- Real networks and destination residency require stronger validation than Podman profiles.
- Operator-controlled keys/host remain trusted. Signed audit checkpoints should be copied to independent storage.
