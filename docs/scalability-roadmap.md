# Scalability implementation roadmap

Status: Phase 1, incremental measurement-only work. This is an engineering
roadmap, not evidence that the current deployment can scale horizontally.

## Scope and invariants

Keep the modular-monolith security contract intact:
- Signed DECISION must be durably committed **before** any model invocation.
- Signed OUTCOME must cover execution and response-side DLP results.
- Invalid/unknown detection, unverified releases, policy errors, and unavailable
  audit persistence fail closed.
- Preserve durable idempotency claims and unresolved-outcome semantics.
- Evidence must remain independently verifiable, including the full signed chain.
- Only synthetic workloads on the local simulator; no live egress or real secrets.

## Phase 1 — Baseline and bottleneck measurement

Implemented: existing evidence-gated baseline/saturation profiles and the
`mixed-traffic` closed-loop profile. It interleaves ordinary permits, synthetic
credential denies, and unsupported-input denies concurrently, retaining the
true scenario for each request's functional and evidence assertions. This
exercise includes response-side DLP for successful local permits **only when
the installed signed release has that capability active**. Output-blocking,
masking, and real inference are not independently benchmarked.

Capture at least three compatible repetitions, compare both medians and ranges,
and inspect raw scenario counts, offline audit verification, queue wait,
processing time, event-loop lag, and integrity execution activity. The
HTML report and CSV include per-process sampled diagnostic maxima (not
whole-run latency distributions or cluster utilization).

Remaining Phase 1 work:
- Open-loop scheduled arrival rate, bounded client-side backpressure, separate
  offered/accepted/completed/goodput rates, and explicit overload contracts.
- Deterministic output-DLP blocking/masking fixtures with signed evidence gates.
- Per-stage resource utilization and repeatable host/runtime manifest,
  including signed generation and OCI image digest.
- Failure injection and recovery baselines with strict state/evidence checks.

Acceptance: no missing signed events, invalid receipts, unauthorized
forwarding, unexpected transport errors, or audit verification failures.
Measure a throughput/latency saturation curve; do not infer a maximum RPS from
the current closed-loop client count.

## Phase 2 — Improve the single-host data path

Prototype per-process detector isolation and compare one vs multiple detector
workers on the same resources. Profile audit commit/write contention and
integrity verification before changing code. Never relax SQLite durability,
signatures, release verification, or fail-closed enforcement to improve scores.

Acceptance: repeatable goodput/latency improvement at identical workload,
resource allocation, and signed release configuration, with security tests
and independent audit verification passing.

## Phase 3 — Safe multi-replica foundation

Introduce an explicit authoritative audit and idempotency service; define
atomic sequence/hash/sign/commit and leader fencing before adding replicas.
Pin policy and detector releases consistently. Validate retries, crashes,
duplicate requests, and unresolved outcomes before allowing inference.

Acceptance: verified chain consistency and correct request ownership across
replicas under failure and recovery, without double invocation.

## Phase 4 — Distributed operations

Add independent scaling for API, detector, OPA, and sovereign inference,
coordinated admission, rollout/drain procedures, failover, and region-aware
placement within permitted data sovereignty boundaries.

Acceptance: controlled availability under faults, bounded resource usage and
queuing, verified evidence, and reproducible per-replica/cluster telemetry.

## Operator constraints

The manual GitHub Actions performance workflow targets an already-approved,
self-hosted Podman installation. The checkout SHA identifies benchmark code,
**not** the running signed image. Never run the benchmark against sensitive
production prompts, reset the audit volume to achieve clean numbers, or publish
raw evidence artifacts. See [performance guide](../performance/README.md) and
[runner setup](performance-github-actions.md).
