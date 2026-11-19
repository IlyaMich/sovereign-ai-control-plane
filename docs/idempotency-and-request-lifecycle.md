# M7.4 — Durable Idempotency and Request-Lifecycle Visibility

## Motivation and trust boundary

A client can time out after the server has already recorded a signed decision and
outcome, as happened in the M6 credential-denial benchmark. Replaying the same
prompt as a new request can have a second effect. Client-provided idempotency
keys are an **opt-in, durable correlation and at-most-one-gateway-admission**
mechanism, not a guarantee of exactly-once inference at a remote provider.

M7.4 keeps the signed audit schema, policies, detector models, and existing
SQLite `BEGIN IMMEDIATE` + WAL writer unchanged. Its auxiliary
`request_idempotency` table is stored in the **same persistent audit volume**,
but the table itself is not independently signed. The signed DECISION / OUTCOME
events remain the authoritative historical evidence.

## HTTP contract

- `POST /v1/prompts` accepts an optional `Idempotency-Key` header: 8–128 ASCII
  characters, matching `[A-Za-z0-9][A-Za-z0-9._:-]{7,127}`. Supply a new,
  unpredictable value for each logical operation and reuse it only on retries.
- A new key is durably claimed (scoped to authenticated tenant and principal)
  **before detection or inference**; the request proceeds normally. If the
  claim cannot be durably stored, return HTTP 503 with no model invocation.
- A retry of the same key with the same prompt/destination/purpose returns
  **HTTP 409** `IDEMPOTENCY_ALREADY_ACCEPTED` plus the original `request_id`,
  and **never invokes the model a second time**. A reused key with different
  input returns HTTP 409 `IDEMPOTENCY_KEY_CONFLICT` without disclosing the
  original request ID.
- If the header is omitted, the API retains its M7.3 behavior; existing
  benchmarks do not exercise idempotency unless explicitly modified.
- `GET /v1/idempotency/status` requires the same authentication and key in
  HTTP headers. It returns `request_id`, `audit_state`, and `execution_status`
  (when an OUTCOME exists). States: `OUTCOME_RECORDED`, `UNRESOLVED` (no
  signed events or DECISION without OUTCOME), or `INVALID_AUDIT_LIFECYCLE`.
- `GET /v1/requests/{request_id}` remains the authenticated evidence API.
  M7.4 does **not** cache or recover the original model output; a lost output
  cannot be recreated without replaying inference.

Both the key and the input (prompt, destination and purpose) are stored only as
purpose-separated HMAC-SHA256 digests derived from the existing audit store's
HMAC mechanism. Plaintext prompts and raw keys are not written to the claim
registry. Keep keys out of URL paths and query parameters.

## Crash/cancellation behavior

- If a client disconnects after a claim but before a decision is recorded,
  retries are blocked, and status reports `UNRESOLVED`. The request may still
  be in flight or may have crashed. **Do not automatically retry it.**
- If DECISION exists without OUTCOME, the model effect may be ambiguous,
  especially if cancellation happened during or after invocation.
- If OUTCOME exists, the signed audit shows what was recorded, though a
  provider may still have executed after a network timeout.
- On process restart, new workers read the same durable claim registry.
- No automatic expiration or deletion of keys is performed. Naive TTL-based
  eviction could permit a duplicate execution. Retention and trusted operator
  recovery remain an explicit future policy decision.

The current non-idempotent request path remains supported. M7.4 does not change
model cancellation behavior or pretend to complete a missing OUTCOME. The
read-only inspector is for reconciliation, not repair.

## Operator reconciliation

Run from an environment that can read the database and independent trusted
public key, preferably using a **consistent SQLite snapshot** when the source
volume is mounted read-only. The existing benchmark snapshot tooling can
create a WAL-safe backup for offline review.

```powershell
podman compose -f deploy/compose.yaml --env-file .env `
  exec -T control-plane python -m tools.inspect_request_lifecycle `
  --db /var/lib/sovereign/audit.sqlite `
  --public-key /var/lib/sovereign/audit-key.pub.pem `
  --min-age-seconds 60
```

The inspector first checks the complete signed audit chain using the public
key supplied. An independent externally pinned public key and checkpoint are
needed for stronger trust than the local exported key alone. The inspector
reports request IDs and status metadata only. **It never deletes claims,
retries inference, rewrites audit history, or fabricates outcomes.**

## Known limitations

- Single-host shared SQLite volume is required for coordination between API
  workers; the existing per-process admission limit remains separate.
- An idempotency claim is an extra durable SQLite write for keyed requests;
  the M7.3 audit executor is reused to bound that work. Benchmark it separately.
- A request can be admitted and its claim persisted even when later detection,
  policy, audit, or inference fails. This conservative behavior prevents replay.
- More complete recovery of results would require protected, size-bounded
  response storage and provider-supported idempotent inference operations.
- Signed audit verification, not the auxiliary registry's contents, is the
  forensic authority for past decisions and outcomes.
- M7.3 performance is still under investigation: a single run showed reduced
  throughput versus M7.2. Functional correctness is not a latency claim.
