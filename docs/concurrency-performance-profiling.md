# M7.9 — Repeatable concurrency profiling and integrity-gated review

This is a **measurement increment**, not a change to policy, detector artifacts,
Ed25519 signatures, SQLite durability, release activation, or executor sizing.
The previously observed M7.2→M7.3 goodput regression is a hypothesis to
investigate, **not** proof that the audit executor is its cause.

The repository deliberately ignores the separately delivered `benchmarks/` kit.
Install/retain your existing kit (the one providing `python -m benchmarks.suite`
and `python -m benchmarks.compare`) in the repository checkout. M7.9 calls that
kit: its reviewer verifies the signed audit chain before and after every
scenario, and its response/evidence assertions remain authoritative.

## Prerequisites

- Approved, **already built** control-plane image, OPA and model simulator are
  running. `GET http://127.0.0.1:8000/health/ready` returns `READY`.
- The benchmark suite and its audit-reviewer dependencies are installed. Keep
  `.env` outside Git, with a real `CONTROL_PLANE_API_KEY`. An existing
  `BENCH_API_KEY` environment variable takes precedence over `.env`.
- Use **synthetic** benchmark prompts only. Do not use production traffic or
  run against real inference endpoints. This tool accepts only loopback HTTP.
- Do not rebuild the approved image or reset the audit volume to benchmark.
  Stop other audit-producing clients to satisfy the benchmark's exclusive-writer
  audit-delta assertion. Preserve the signed audit history across runs.

## Baseline / current-runtime collection

Run from the repository root in PowerShell:

```powershell
python -m tools.concurrency_performance capture `
  --label-prefix m7-9-8clients `
  --runs 3 `
  --clients 8 `
  --duration 60 `
  --interval 0.75
```

This runs the existing three scenarios (`local_permit`, `credential_deny`, and
`unsupported_input`) **three times each**, with a fresh benchmark label per
repetition. It may take considerably longer than 3 × 60 seconds because each
run includes all three scenarios, offline chain checks, and reviewer setup.

Every repetition writes:

- `bench-results/m7-9-8clients-r01/suite.json`, scenario `summary.json` and
  `assertions.json` from the **existing benchmark kit**.
- `bench-results/m7-9-8clients-r01/m7_9_diagnostics.json`, containing only
  allowlisted process-local counters, current queue activity and rolling
  timing summaries sampled from `/v1/diagnostics/concurrency`.

The tool refuses to overwrite existing benchmark directories and stops on a
failed reviewer assertion, failed benchmark process, unavailable diagnostic
endpoint, a diagnostic gap, or a process-counter reset. No prompt, request ID,
model output, access token or API key is written into the M7.9 profiles.
The existing `benchmarks/` suite retains its own privacy and evidence rules.

Produce an integrity-gated report:

```powershell
python -m tools.concurrency_performance report `
  --label-prefix m7-9-8clients `
  --runs 3 `
  --out bench-results/m7-9-report.md
```

A nonzero exit means **do not declare M7.9 stabilized**. Reported medians and
ranges describe closed-loop client results at the configured clients/duration,
not maximum sustainable requests per second. A run without signed-chain
assertions cannot pass the report's correctness gate.

To compare against the original single M7.2 reference, also use the existing
benchmark comparison for each **individual** M7.9 repetition:

```powershell
python -m benchmarks.compare `
  --baseline bench-results/m7-2-8clients `
  --improved bench-results/m7-9-8clients-r01 `
  --out bench-results/m7-9-vs-m7-2-r01.md
```

The M7.2 reference was one run, so treat this as descriptive rather than a
statistically reliable performance gate. Gather comparable repeated runs of the
same code/configuration before applying strict latency or throughput thresholds.

## Reading the diagnostics

The `phase` field marks which scenario was running when each sample was taken.
Review `detector.queue_wait.p95_ms`, `audit.queue_wait.p95_ms`,
`audit.processing.p95_ms`, `event_loop.p95_ms`, `integrity.active_jobs`, and
`audit_limits.waiting_for_slot`. Each p95 is the API's **rolling sample-window
p95 at poll time**, not a p95 recomputed over the entire benchmark scenario.
Counter deltas reflect **this one API process**; do not interpret them as
cluster totals. M7.9 refuses profiles if counters reset midrun.

Investigate bottlenecks in this order:

1. High **event-loop lag** alongside stable detector/audit service times:
   investigate remaining loop work and host scheduling.
2. High **detector queue wait** with long detector processing: inspect NLP CPU
   contention and verification overhead. Do not assume more Presidio threads
   are safe without proving analyzer concurrency.
3. High **audit queue wait** but low audit service time: inspect executor
   contention and auxiliary queries. High audit **processing** time: inspect
   SQLite/WAL fsync latency and host storage instead.
4. Integrity executor saturation: inspect policy/release verification frequency
   and disk pressure, without caching approvals or weakening fail-closed checks.
5. Capacity rejections: benchmark the overload contract separately, rather
   than counting deliberate 429/503 responses as successful inference.

## Overload/cancellation checks

Run the already implemented regression tests against a safe test database:

```powershell
python -m pytest -q `
  tests/api/test_ingress_bounds.py `
  tests/audit/test_audit_capacity_bounds.py `
  tests/infrastructure/test_integrity_executor.py `
  tests/infrastructure/test_integrity_runtime.py `
  tests/audit/test_audit_executor.py `
  tests/api/test_request_admission.py
```

These cover ingress saturation, audit waiter/auxiliary limits, cancellation,
precommit-before-inference, and fail-closed integrity behavior. They are not a
replacement for a controlled **live** overload test with connection-count,
CPU/RAM and audit-history inspection. The older benchmark kit's
`--allow-overload` recognizes pre-admission HTTP 429; M7.6's outer limit and
Uvicorn may instead emit HTTP 503. Do not interpret every 503 as a correct
rejection or loosen the signed-audit assertion to make a stress test pass.

## Acceptance before M8

- At least three comparable runs for each default scenario, with complete
  signed audit assertions, no unexpected transport errors, and no evidence
  validation failures.
- No unexplained counter resets or diagnostics-poll gaps.
- Investigate a persistent goodput regression or growing p95 before tuning
  `MAX_AUDIT_JOBS`, `MAX_INTEGRITY_JOBS`, or SQLite durability.
- Capture OS, Podman, resource limits, policy/detector/release identities and
  model configuration separately when interpreting results.

Only after reviewing those numbers can we identify and measure a targeted
performance optimization. **M7.9 is not automatically complete because the
capture tool passes its unit tests.**
