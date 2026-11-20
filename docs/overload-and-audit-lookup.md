# M7.9 final follow-up — live overload and evidence-lookup limit

This is **diagnostic only**: no changes to the control plane, SQLite durability,
OPA, model, release signing, key storage or audit format. The local Git-ignored
`benchmarks/` kit remains the independent reviewer of Ed25519 signed audit
history. Only run against the existing **approved** single-host Podman simulator.
Do not rebuild or delete volumes for this test.

## Run

Keep other benchmark clients and audit-producing processes idle. From the repo
root, with the approved stack running and `.env` configured:

```powershell
python -m pytest -q tests/tools/test_overload_and_audit_lookup.py
python -m tools.overload_and_audit_lookup --label-prefix m7-9-overload-16 --clients 16 --duration 20 --lookup-rounds 12
```

The tool first invokes `tools.concurrency_performance capture --allow-overload` using
`benchmarks.suite` for a single **16-client, 20-second local_permit** scenario.
The existing kit performs independent before/after audit-chain verification,
checks exact two-event pairs for admitted responses and recognizes correct 429
pre-admission rejection contracts. The tool **requires at least one real 429**;
otherwise the workload did not exercise application admission and the result
fails as inconclusive. A 503 is *not* automatically accepted as proper overload.

It then uses up to 32 accepted request receipts from the signed-verified run
for two isolated evidence lookup phases, 4 and 8 concurrent lookups, 12 rounds
each. `GET /v1/requests/{id}` must match the original decision and outcome
receipts. Only the known `AUDIT_UNAVAILABLE` 503 contract is retried, up to
8 times. The 4-way phase should have **zero** audit-capacity rejections; the
8-way phase may show transient rejections as it exceeds the configured
`MAX_AUDIT_AUXILIARY_JOBS=4`. It reports `REPRODUCED` only when both the observed
503s and the audit capacity rejection counter increase. `NOT_REPRODUCED`
means the load did not trigger that behavior, not that the cap is removed.

Result files:

- `bench-results/m7-9-overload-16-r01/*`: signed-audit benchmark, request records,
  profile and full existing verification assertions. The existing `benchmarks/`
  kit may contain request IDs and receipts; keep this directory private.
- `bench-results/m7-9-overload-16-followup.json`: only aggregated counts and
  outcomes; no API key, prompts, request IDs, output or audit payloads.

To retry lookup analysis without adding another set of signed audit events:

```powershell
python -m tools.overload_and_audit_lookup --label-prefix m7-9-overload-16 --existing-run --lookup-rounds 12
```

## Interpretation / acceptance

- **Pass overload:** at least one admitted HTTP 200 and one valid HTTP 429,
  no unexpected HTTP status/transport errors, no functional or evidence failures,
  signed chain delta and per-request evidence checks pass, and process
  admission counter reflects the rejections.
- **Pass 4-way lookups:** no 503 or capacity counter increment; every GET
  matches its signed-run receipt pair.
- **Confirm 8-way contention:** transient, recognized audit-capacity 503s,
  matching capacity counter increase, and eventual successful evidence GETs.
- If any checks fail, do not call M7 complete. If the eight-way phase is
  `NOT_REPRODUCED` but returns valid evidence, the cause is not demonstrated
  by this particular workload and the earlier M7.9 phase timing remains
  circumstantial evidence.
- This test is **not** a maximum capacity measurement, cannot verify external
  residency, and does not replace crash/recovery or slow-upload tests.

The audit lookup requests are separate from the 20-second performance interval;
do not attribute their queue delays to the latency of prompt processing.
