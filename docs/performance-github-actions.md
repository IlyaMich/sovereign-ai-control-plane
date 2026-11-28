# GitHub Actions performance benchmarking

[Performance Benchmark](../.github/workflows/performance.yml) runs the existing
`performance.cli` framework on a **dedicated self-hosted Linux x86-64 runner**
against a **previously approved, already-running Podman deployment**.
It does not build or sign the application image, modify OPA, or reset audit storage.

## Why not a default GitHub-hosted load job?

The independent `benchmarks/` source and tests are now checked in. Full load
verification still requires an approved signed release, trusted policy/state,
and a live SQLite audit volume. A fresh GitHub-hosted checkout cannot
reproduce that deployment. Shared runner CPU/IO also makes performance
threshold comparisons unreliable. Existing CI runs both
`tests/performance/` and `benchmarks/tests/` on GitHub-hosted runners.

## One-time trusted runner setup

1. Install a dedicated GitHub Actions self-hosted runner on Linux x86-64.
   Give it the labels `self-hosted`, `linux`, `x64`, and `sovereign-performance`.
   **Never use the isolated `release-signer` runner for this job.** Do not grant
   the performance runner a release-signing or audit-signing private key.
2. Install rootless Podman, a working `podman compose` provider, Git, and
   Python 3.12 support. The Actions runner user must own or be authorized to
   use the *same* Podman machine, active approved containers, and audit volume
   as the signed deployment.
3. Preinstall the independently verified signed release and keep it running on
   `http://127.0.0.1:8000`. The performance tool invokes an independent
   reviewer image and uses `podman compose` to access the running project.
   Its project name must match the one used when the approved stack started.
4. Keep the approved install (including `.env` and `.runtime`) in a
   protected directory outside the GitHub runner workspace. The workflow uses
   the **reviewed, committed** `benchmarks/` kit from `main`, including its
   patched `load.py` and regression tests. No separate kit installation or
   unsigned download is required.
5. In **Settings → Environments**, create `performance-benchmark`. Restrict
   deployments to `main`; an optional required reviewer protects manual
   executions. Configure these four repository **Actions variables** (not secrets):

   | Variable | Example |
   | --- | --- |
   | `PERF_OPERATOR_ROOT` | `/srv/sovereign/approved-install` (contains `.env` and `.runtime`) |
   | `PERF_RESULTS_DIR` | `/srv/sovereign/benchmark-results` (private, persistent, writable) |
   | `PERF_ENVIRONMENT_TAG` | `fixed-perf-host-signed-g2` |
   | `PERF_COMPOSE_PROJECT` | `sovereign-review` (match the actual running Compose project) |

The existing `.env` supplies the HTTP API key to the Python benchmark
process; do not put the API key in GitHub workflow input, variables, or logs.
The runner accesses operator state using local filesystem links in its
temporary workspace and removes those links after execution. Protect host
access accordingly.

## Execute the tests

Open **Actions → Performance Benchmark → Run workflow**, select **main**, and
choose a profile:

- `smoke` (default): one client, 15 seconds per scenario; quick full
  request and signed-evidence verification, **not** a capacity test.
- `baseline`: three repetitions at 1, 2, 4 and 8 clients; 60 seconds per
  sequential scenario, for a controlled throughput/latency curve.
- `saturation`: above-admission-limit test; only fully verified intentional
  429 rejections count as expected overload.
- `scenario-catalog`: sequential scenarios including simulated external
  redaction. Requires the running approved stack to be configured with
  `egress-test` and `ENABLE_EXTERNAL_SIMULATOR=true`.

The workflow runs both framework and benchmark-kit unit tests, followed by
the **independent signed-evidence verification** benchmark. Missing or invalid receipts, failed audit
chains, correctness errors, or missing diagnostic artifacts fail the job.

Only `manifest.json`, `summary.json`, `metrics.csv`, and `report.html`
are uploaded to Actions (14-day retention). These are aggregate outputs and
may be visible to other repository members. **Raw** `requests.jsonl`,
receipts, diagnostics, and other sensitive audit artifacts remain in the
private `PERF_RESULTS_DIR` on the benchmark host. Manage that directory's
retention and access separately. If a run fails before generating aggregate
reports, inspect its private results and job logs; do not relax audit
validation.

## Comparison and provenance limitations

This workflow benchmarks the *deployed, approved runtime*, **not necessarily
the source code at the checked-out `main` commit**. The run manifest's Git SHA
identifies the benchmark tool revision, not a verified runtime-image digest.
Record the installed signed-release generation, OCI image digests, policy and
detector identity, machine and resource limits alongside each run when
comparing changes. Use `performance.cli compare` against two compatible
privately preserved runs; do not treat hosted-runner differences as a
regression verdict.

The workflow is **manual only** to avoid unexpected benchmark traffic or
audit database growth. Run it with other audit writers idle: the independent
reviewer expects exclusive signed event deltas. Never attach a
`pull_request` trigger to the trusted self-hosted runner, share it with the
release signer, or use `podman compose down -v` to reset the audit history.

### Mixed-traffic scalability profile

The manual workflow also offers `mixed-traffic`. It exercises local permits
(including output DLP if active in the approved release), credential denies,
and unsupported-input denies concurrently across closed-loop clients. Every
response uses its own type-specific contract and audit-evidence validation.
It does not require optional external egress. The aggregate HTML report now
includes sampled per-process queue, detector, audit and integrity workload
signals; these are not cluster metrics or whole-run p95 measurements.

### Fixed-rate scalability profiles

The workflow supports `open-loop-4`, `open-loop-8`, and `open-loop-16`.
Each schedules fixed-rate synthetic arrivals (4, 8 or 16 requests/s) rather
than waiting for a previous response to complete, with a 32-request client
concurrency cap. Three repetitions are verified independently using the same
read-only offline audit reviewer as the baseline benchmark. Client-capacity
drops, missing evidence or unexpected server failures make the run fail.
Review the offered-versus-issued and 429 counts in the aggregate report; a
successful suite does **not** imply every offered request was admitted.
Never run these loads on a production system or against a real inference model.
