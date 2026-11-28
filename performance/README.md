# Phase 1: reusable, evidence-gated performance benchmarking

This **operator-only** package extends the existing M7.9 tools. It does **not** change
`app/`, detector artifacts, OPA policy, the approved container image, signed releases,
SQLite settings, or audit semantics. Only synthetic prompts and the local simulator
are supported. Never use real secrets, production requests or live egress.

## Requirements

Run commands from the repository root with Python 3.12+, `httpx`, a running
**approved** Podman Compose stack and the source-controlled `benchmarks/suite.py`
kit. It remains an independent offline signed-audit reviewer.
Do not rebuild the approved image, delete volumes, or use `podman compose down -v`.
No fallback reviewer is provided: missing or failed signed-audit assertions fail the run.
Leave competing writers idle for the kit's exclusive audit-delta assertions.

```powershell
python -m performance.cli list
python -m performance.cli run --profile smoke --environment-tag my-host-fixed-config
python -m performance.cli run --profile baseline --environment-tag my-host-fixed-config
python -m performance.cli run --profile saturation --environment-tag my-host-fixed-config
python -m performance.cli run --profile scenario-catalog --environment-tag my-host-fixed-config
python -m performance.cli run --profile mixed-traffic --environment-tag my-host-fixed-config
```

`smoke` is a brief end-to-end file-retention and correctness check (one client, 15 seconds per scenario); it is not a capacity benchmark.

`scenario-catalog` is a **sequential** set of scenarios, *not simultaneous mixed
traffic*. Its `external_redaction` scenario requires the existing enabled
simulated-egress profile. The benchmark client itself is closed-loop. The `mixed-traffic` profile instead
interleaves synthetic local permits, credential denies and unsupported-input
denies *concurrently* inside each load interval, retains the actual per-request
scenario for signed receipt and evidence assertions, and reports per-scenario
request/success counts. It does not require external egress. Local permits
execute response-side DLP when the approved installed release supports it;
this profile does not prove output blocking or masking functionality. Saturation
rejections are expected and checked by the underlying reviewer; saturation is
not a maximum sustainable-throughput measurement.

Results are in `performance/results/<run-id>/` (ignored by Git):
`manifest.json`, `summary.json`, `metrics.csv`, `report.html`, and immutable
raw suite artifacts, independent evidence assertions, diagnostic samples, and
best-effort `resources.json` files. The latter capture only allowlisted Podman
CPU percentages and memory usage for known services; unavailable sampling is
explicitly marked unavailable. Other host metrics remain deferred. Mixed traffic is still closed-loop; an
open-loop arrival-rate generator, explicit output-blocking fixtures and
multi-replica benchmarks remain future Phase 1 increments.

Generate reports and compare separate commits:

```powershell
python -m performance.cli report --run performance/results/<baseline-run-id>
python -m performance.cli compare --baseline performance/results/<baseline-run-id> --candidate performance/results/<candidate-run-id> --out performance/results/comparison.json
python -m pytest -q tests/performance benchmarks/tests
```

Comparison **revalidates signed evidence** from both runs and rejects mismatched
profile digests, levels, durations, scenarios, repeats, operator environment tags,
platform fingerprints, and identical commits. Ensure policy/release/detector images,
Podman limits, test host and audit DB state are comparable; the environment tag is
operator-supplied and does not cryptographically prove equivalence. Compare latency
medians and ranges as diagnostic statistics, not statistical significance.
A 10% goodput decrease or p95 increase produces a warning and exit code **2**;
it is not a hard correctness failure. Exit code **1** indicates invalid/incomplete
results or configuration. An intact run returns **0**. The report records maxima
of sampled rolling component p95 windows; those are not entire-run percentiles.

The runner records no API keys, prompts or model outputs in its own reports.
The legacy raw suite may contain request IDs and receipts. **Keep all results
private** and do not publish them without review. The original kit's existing
security and privacy rules continue to apply.

When changing detector/policy/runtime code, deploy through the existing signed
release process. Never alter production behavior merely to make a benchmark pass.

**Submission status:** no versioned performance result archive is committed here.
The runner, profiles and `benchmarks/` source are now version-controlled, but
reproduction of a live performance test still requires an approved image,
trusted signed operator state, and a controlled benchmark host. The [submission evidence matrix](../docs/submission-evidence.md)
records required metadata; historical M7.9 profiling is described in
[concurrency profiling](../docs/concurrency-performance-profiling.md), with
[live overload checks](../docs/overload-and-audit-lookup.md).

## GitHub Actions

A **manual** [`Performance Benchmark`](../.github/workflows/performance.yml) workflow
can run the existing signed-evidence suite on a dedicated, approved **self-hosted**
Podman performance runner. It cannot run a live signed benchmark from a bare hosted checkout because the
approved signed deployment and its private runtime state are not tracked. Configure
and operate it using [the runner guide](../docs/performance-github-actions.md).
Only aggregate reports are uploaded to Actions; raw evidence stays on the host.

## Phase 1 scalability measurement guidance

1. Capture baseline and `mixed-traffic` profiles on the **same** approved
   simulator deployment, with no other audit-producing clients. Never compare
   different profile digests as a before/after performance result.
2. Record the approved image digest, detector/policy/release generation, host
   CPU/RAM, Podman limits, and output DLP activation alongside each run.
   A Git SHA alone identifies the benchmark harness, not the runtime.
3. Inspect the new HTML diagnostic table and `metrics.csv`: detector/audit
   queue delays, integrity active/waiting jobs, and event-loop lag. These
   process-local sampled signals are clues, not proof of a bottleneck.
4. Retain independent audit assertions and review the raw results privately
   before changing executor or audit settings.

`mixed_traffic` deterministically rotates synthetic request types per client.
It is not a statistical model of production demand, an open-loop stress test,
or a test of geographic data residency.
