# M7 baseline benchmark kit — Sovereign AI Control Plane

This source-controlled benchmark kit targets the local Sovereign AI Control Plane API and Podman Compose configuration. It remains a separate **offline-audit evidence reviewer**: no application code, signed release, policy, or detector model is modified. Use it from the repository root, against an approved, already-running deployment. It does not establish independent trust in a signed release without the separately pinned public keys and approved image.

**Safety:** send only synthetic prompts to the loopback-bound local API. No prompt text, API key, or model output is written to results. Use a dedicated nonproduction deployment and preserve its audit history. Never run `podman compose down -v` as part of benchmarking. Run against the local simulators, not a real external model. This is a **closed-loop** workload: eight client tasks each submit their next request only after the previous finishes. It does not measure open-loop overload or maximum RPS.

## Prerequisites

- Windows PowerShell, Python 3.12+, Podman + Compose, working `.env`, trusted local signing setup, and an *already approved image* for the current release.
- Run commands from the repository root. Use the exact approved image; **do not rebuild the control plane after release signing.** The suite only builds the separate offline `audit-reviewer` image.
- Install `httpx>=0.27,<1`, and `pytest` for local harness tests.
- Ensure the local service responds `{"status":"READY"}` at `http://127.0.0.1:8000/health/ready`.
- The `audit-reviewer` profile must have access to the `audit-data` named volume, with no network access; this is already the existing `deploy/compose.yaml` design.
- Stop all other traffic; the audit event-count delta assumes the benchmark is the only writer. Do not activate a release during a run.

## PowerShell setup

```powershell
# Start your already-approved M6 image and leave the audit volume intact.
podman compose -f deploy/compose.yaml --env-file .env up --no-build --force-recreate -d
Invoke-RestMethod http://127.0.0.1:8000/health/ready

# The kit can run in your existing Python environment (no spaCy needed on load-generator host).
python -m pip install "httpx>=0.27,<1" "pytest>=8,<10"
python -m pytest -q benchmarks/tests

# Use a process-only environment variable, not a command-line --api-key parameter.
$line = Get-Content .env | Where-Object { $_ -match '^CONTROL_PLANE_API_KEY=' } | Select-Object -First 1
if (-not $line) { throw 'CONTROL_PLANE_API_KEY missing in .env' }
$env:BENCH_API_KEY = ($line -split '=', 2)[1].Trim().Trim('"').Trim("'")

# Optional: identify the container name for resource samples.
podman ps --format "{{.Names}}"
```

If `BENCH_API_KEY` is managed outside `.env`, set it from your secure secret source instead. Keep it out of source control and result files.

## Capture baseline — 8 concurrent clients × 60 seconds each scenario

```powershell
python -m benchmarks.suite --label baseline --clients 8 --duration 60
```

This runs three scenarios sequentially, each lasting **60 seconds of request starts**, followed by draining remaining requests, checking each returned receipt against `GET /v1/requests/{request_id}`, and validating the full SQLite hash/signature chain **outside the load interval**:

| Scenario | Synthetic request | Expected |
|---|---|---|
| `local_permit` | Ordinary ASCII policy question to `sovereign-model` | 200, `COMPLETED`, `PERMIT`, two signed events |
| `credential_deny` | Fake `-----BEGIN PRIVATE KEY-----` marker to `sovereign-model` | 403, `BLOCKED`, `CREDENTIAL_BLOCKED`, no model invocation |
| `unsupported_input` | Synthetic `café` unsupported character | 403, `BLOCKED`, `DETECTION_UNKNOWN`, no model invocation |

For **optional** redaction / simulated external egress (requires opt-in egress-test profile and `ENABLE_EXTERNAL_SIMULATOR=true` *before startup*), run an independent tagged suite:

```powershell
# With the approved image deployed in the optional egress-test configuration:
python -m benchmarks.suite --label external-baseline --scenarios external_redaction --clients 8 --duration 60
```

This expects the synthetic email address at `example.com` to be redacted before forwarding to `external-simulator`. It does not make an internet request. If your local detection model classifies the prompt unexpectedly, the scenario fails instead of silently accepting a different behavior.

### Optional resource statistics

Collect best-effort Podman CPU/RAM samples for a named container *during* the timed interval; stats are stored verbatim in `podman-stats.jsonl` for inspection. Determine the name with `podman ps --format "{{.Names}}"` first.

```powershell
python -m benchmarks.suite --label baseline --clients 8 --duration 60 --stats-container <your-control-plane-container-name>
```

Podman stats formats differ by OS/Podman version; inspect these raw records and document CPU%, memory, and any sampling failures. Run with and without monitoring to estimate its overhead if necessary. Also capture host/Podman CPU count, RAM, Podman version, service container limits, and whether the host was otherwise idle. Keep these conditions the same for improved runs. Note that a Podman Machine VM can affect measurements on Windows.

## Improved run and A/B comparison

After implementing, testing, building and **approving** the intended new runtime image under the existing release procedure, deploy it with `--no-build`. Re-run the exact same benchmark settings and conditions:

```powershell
python -m benchmarks.suite --label improved --clients 8 --duration 60
python -m benchmarks.compare --baseline bench-results/baseline --improved bench-results/improved --out bench-results/comparison.md
```

Do not compare measurements across different scenarios, client counts, durations, host CPU resources, simulator behavior or network profiles. Set the same `--stats-container` sampling approach for both runs if gathering resources. A throughput improvement is not acceptable if audit assertions regress. Avoid running two suites at the same time. Existing result directories cannot be overwritten; use a new label or move the old results.

If the improved gateway intentionally rejects excess traffic as **HTTP 429 before admission**, add `--allow-overload` to *both* suites being compared. `429` responses are counted as overload rejections, not admitted requests, and have no required audit receipt. **HTTP 503 is never silently classified as successful backpressure**, because it can indicate an audit failure. Distinguish total responses/sec from useful admitted-request **goodput/sec**. For a strict no-overload comparison, do not use this flag.

## What exactly is verified?

1. **HTTP contracts:** expected `200/403` responses; status, policy effect, model ID, explicit reason code (where relevant), and valid-looking receipt fields; unique request IDs.
2. **Per-request evidence:** `GET /v1/requests/{id}` returns exactly one `DECISION` and one `OUTCOME` (in this version), with the original response receipts, correct request ID / tenant, effect and outcome, and increasing sequence numbers.
3. **Offline chain:** runs the existing `python -m tools.verify_audit` inside the network-disabled `audit-reviewer` container before and after each scenario. It cryptographically checks every event's SHA-256 chain predecessor and Ed25519 signature, including all historic events. This is separate from the HTTP evidence endpoint.
4. **Audit growth:** for an exclusive benchmark writer, total event count after minus before **must equal twice the number of complete receipt-bearing responses**. This catches unexpected missing outcomes / extra events / unknown-result requests (subject to the explicitly stated single-writer assumption). Failed or timed-out requests without a response ID are visible as transport/validation failures; they may still have committed an event, and this count assertion will then fail.
5. **Timing:** evidence checks, reviewer runs and postrun drain are not counted as benchmark response-time samples. Every request is started before the 60-second deadline, but an in-flight request may complete after it. `responses_per_test_second` counts only responses completed during the window; `goodput_per_test_second` counts functionally correct responses completed during the window.

**Trust caveat:** By default the verifier uses the public key in the same audit volume, so its result demonstrates internally valid signatures and chain continuity, **not independent proof of origin or completeness**. To enforce an independently pinned audit public key, pass `--trusted-audit-public-key path/to/previously-pinned-audit-public-key.pem` to `benchmarks.suite`. That key must have been retained independently *before* this benchmark; do not create a supposed trust anchor from the same data after a suspected compromise. Even an independently pinned key does not prevent tail truncation without an independently retained earlier checkpoint.

## Results

Each scenario writes:

```text
bench-results/
  baseline/
    environment.json
    suite.json
    local_permit/
      before.json         # Network-disabled full-chain verification summary
      requests.jsonl      # Status, latency, request ID, receipt metadata — no prompt/output
      summary.json        # Throughput, goodput, p50/p95/p99, counters
      after.json          # Full-chain verification summary after test
      assertions.json     # Chain-growth check and invariants
      podman-stats.jsonl  # Optional Podman resource samples
    credential_deny/
    unsupported_input/
  improved/
  comparison.md
```

**Pass/fail policy:** every supported scenario must have at least one functional success; unexpected response codes, transport failures, missing evidence, duplicate request IDs, invalid decision/outcome order, verifier failure or audit-count mismatch are failures. A performance regression is reported numerically, not automatically judged against an arbitrary RPS threshold. The suite returns a nonzero exit status on correctness failures.

`requests.jsonl` includes event hashes/signatures, IDs, and timing; those can be sensitive operational metadata. Protect them appropriately, despite the absence of plaintext prompts.

## Constraints and follow-up reliability tests

A closed-loop eight-client run alone cannot prove a maximum throughput or absence of event-loop blocking. Follow up with (1) low-rate latency baseline at one client, (2) overload test with an admission capacity deliberately below eight, (3) cancellation/timeout injection, (4) concurrent release activation only as an explicitly coordinated maintenance test, and (5) thread/process audit-writer regression tests. The M7 implementation plan in `M7_IMPLEMENTATION_PLAN.md` sets out those steps.

To run the generator alone without reviewer orchestration (for troubleshooting):

```powershell
python -m benchmarks.load --scenario local_permit --clients 8 --duration 60 --label manual --out-dir bench-results/manual
```

The standalone generator checks returned evidence via the API but **does not** run the independent chain verifier; use `benchmarks.suite` for full correctness checks.

The benchmark source and offline unit tests are tracked in Git. Raw outputs (`bench-results/`), live `.env`/`.runtime` state, audit receipts and signing keys remain excluded. The [GitHub Actions workflow](../docs/performance-github-actions.md) uses this checked-in kit on a dedicated performance host rather than fetching an untracked copy.
