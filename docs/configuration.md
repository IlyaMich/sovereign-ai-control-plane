# Configuration

Copy `.env.example` to `.env`. Compose interpolates these settings and passes application
settings into the relevant services. Direct Python deployments read process environment
variables; they do not automatically load `.env`.

| Setting | Default | Purpose |
| --- | --- | --- |
| `MAX_PROMPT_BYTES` | 8192 | Maximum ingress prompt size in UTF-8 bytes |
| `MAX_REQUEST_BODY_BYTES` | 16384 | Maximum complete ingress request, including JSON overhead |
| `MAX_FORWARDED_PROMPT_BYTES` | 8192 | Maximum prompt accepted by all model simulators and egress gateway |
| `OUTPUT_MASKING_ENABLED` | false | Opt-in v5-only selective email/phone masking, followed by mandatory clean rescan and signed outcome |
| `MAX_INFLIGHT_REQUESTS` | 8 | Maximum admitted prompt requests per API process (1-1024), fail-fast 429 |
| `MAX_ACTIVE_HTTP_REQUESTS` | 32 | Active HTTP ASGI scopes per process, before reading the body; 503 on saturation |
| `BODY_READ_TIMEOUT_SECONDS` | 10 | Total body-read deadline for POST/PUT/PATCH; 408 on expiry, releasing ingress capacity |
| `UVICORN_LIMIT_CONCURRENCY` | 96 | Outer Uvicorn connection/task pressure bound; 503 on saturation |
| `UVICORN_KEEPALIVE_SECONDS` | 5 | Idle HTTP keep-alive timeout |
| `MAX_DETECTOR_JOBS` | 8 | Per process, maximum detector submissions running or queued (1-1024) |
| `DETECTOR_QUEUE_WAIT_SECONDS` | 1 | Max wait to reserve a detector submission slot, not an NLP execution deadline |
| `MAX_AUDIT_JOBS` | 16 | Max in-flight/queued SQLite audit operations per API process |
| `MAX_INTEGRITY_JOBS` | 8 | Request-time filesystem/signature verification submissions per API process |
| `MAX_INTEGRITY_WAITERS` | 8 | Additional callers allowed to wait for request-time integrity capacity |
| `INTEGRITY_QUEUE_WAIT_SECONDS` | 1 | Max wait for a verification job slot; not a verification deadline |
| `MAX_AUDIT_WAITERS` | 8 | Additional coroutines waiting for audit submission capacity; excess fails fast |
| `MAX_AUDIT_AUXILIARY_JOBS` | 4 | Bound outstanding status/read/probe/idempotency jobs separately |
| `AUDIT_QUEUE_WAIT_SECONDS` | 1 | Max wait for audit submission capacity, not a commit timeout |
| `LOOP_LAG_INTERVAL_SECONDS` | 0.25 | Event-loop delay sampling interval, 0.05–5 seconds |
| `METRICS_SAMPLE_WINDOW` | 512 | Recent queue/service/lag timings retained per process, 1–4096 |
| `OPA_TIMEOUT_SECONDS` | 2 | OPA evaluation HTTP timeout |
| `MODEL_TIMEOUT_SECONDS` | 10 | Model invocation HTTP timeout |
| `READINESS_TIMEOUT_SECONDS` | 1 | Timeout for each readiness HTTP probe |
| `SIMULATOR_EGRESS_TIMEOUT_SECONDS` | 5 | Gateway-to-external-simulator HTTP timeout |
| `API_HOST` | 127.0.0.1 | Published API host address |
| `API_PORT` | 8000 | Published API host port; container port stays 8000 |
| `SIMULATOR_UPSTREAM_URL` | http://external-simulator:9000 | Operator-controlled HTTP(S) origin; gateway appends `/generate` |

Limits must be positive integers. The body limit must exceed the ingress prompt limit.
Admission uses a separate 1-1024 integer limit and rejects with a sanitized HTTP 429
(`Retry-After: 1`) after authentication and request validation, but before any
detection, audit or model work. Rejected requests have no audit receipt because
they were never admitted; client retries must use backoff. This limit applies
per Uvicorn worker, not globally across multiple processes. It does not cap
HTTP body buffering, event-loop CPU work or the model server's queue.

M7.2 submits both the initial and post-redaction detection passes to a
single-worker thread executor per API process. Submissions are bounded by
`MAX_DETECTOR_JOBS` (including the running job). Excess work waits for
up to `DETECTOR_QUEUE_WAIT_SECONDS`, then fails closed with signed
`DETECTION_UNKNOWN` / `DETECTION_CAPACITY_EXCEEDED` evidence when possible.
The detector's queue bound is separate from M7.1 request admission.
Cancellation of a request does not release an underlying detector job
until the worker future actually finishes or is cancelled. No parallel
Presidio access is attempted. Graceful shutdown waits for real detector
work to finish; a permanently hung recognizer can delay shutdown.
M7.3 offloads the existing SQLite operations through a bounded, single-worker
audit executor. The durable signed DECISION commit must finish successfully
before model invocation; OUTCOME commits are awaited before returning a
successful HTTP response. Database errors or exhausted audit capacity
fail with a sanitized 503; no model call occurs when precommit fails.
The request-history endpoint and audit readiness probe also use the
executor. Cancellation after submitting a commit does not cancel its
thread: it can leave an unresolved DECISION requiring M7.4 reconciliation.
Graceful shutdown drains submitted audit operations. SQLite still
serializes cross-process writers through BEGIN IMMEDIATE and WAL.
Request-time policy and release verification now runs off the event loop through
the M7.7 integrity executor; readiness uses a separate full-scan lane (see below).
Prompt fingerprint calculation remains synchronous in the orchestrator.
Timeouts must be positive and finite; HTTPX applies them to individual network operations,
not to the entire request lifecycle. Invalid values fail startup. Character counts in
OpenAPI are a preliminary bound; UTF-8 byte validation also applies. Each API app instance
has its own limit and OpenAPI schema.

If increasing the ingress limit, also increase the body and forwarded limits as needed.
Redaction can expand text, so the forwarded allowance can be larger than the ingress
allowance. The simulator still validates UTF-8 bytes and rejects blank prompts.

`OPA_URL`, `MODEL_URL`, `EGRESS_GATEWAY_URL`, all existing policy/release/audit paths,
and the detector manifest/archive paths can be overridden through Compose. The simulator
upstream remains operator-controlled; API callers cannot supply a URL. Existing network
isolation and destination model-ID checks remain active.

`ACTIVE_POLICY_PATH`, `POLICY_ARCHIVE_PATH`, `RELEASE_ARCHIVE_PATH`, and
`RELEASE_TRUST_PATH` also move their corresponding container mount targets. Change
`RELEASE_ACTIVE_DIR` to move the release directory mount and default active release file.
An explicit `RELEASE_ACTIVE_PATH` must reference `release.json` within that mounted directory.
Change `AUDIT_DATA_DIR` to move the writable audit volume; default database, signing-key,
and detector-archive paths follow it. Explicit file/archive overrides must remain within
that writable volume. Host source directories are unchanged. Reviewer CLI arguments and
historical PowerShell verification scripts must use the chosen paths and API address.

`DETECTOR_MANIFEST_PATH` is also passed as an image build argument, so generated provenance
is written to the runtime path. The manifest build/verification CLI tools also respect
this environment variable; explicit CLI path arguments take precedence. Changing it
requires rebuilding and approving the image.
Recreate services to apply runtime environment changes. Never rebuild an image after
signing its detector digest; use the existing M6 initialization/signing/activation workflow.

## Detector rules

`app/detection/rules.json` is the single configuration source for:

- `threshold`: minimum accepted finding confidence, between 0 and 1. Lower-confidence
  findings produce `UNKNOWN`; they are never discarded as evidence of public text.
- `entity_categories`: unique entity identifiers requested from Presidio.
- `required_coverage`: nonempty required recognizers, all included in selected entities.
- `sensitivity_mapping`: exactly one `MEDIUM` or `HIGH` entry per selected entity.
- `patterns`: category-to-list mapping of `[name, regex, score]` custom recognizers.

The file is packaged with Python and copied into the image. It is validated at startup
and its actual installed bytes are hashed into the detector manifest. The same parsed
configuration drives aggregation and the classification configuration digest. Managed
requests reject rules changed after initialization. Existing archived manifests remain
verifiable; changed detector source/rules require a newly built, signed, activated release.
Do not edit generated manifests or historical approvals.

To change detection behavior, edit the JSON, run the checks, then run
`Approve-And-ActivateRelease.ps1` (with the existing signing key) and recreate services using
`--no-build`. Coordinate coverage/category changes with `policies/decision.rego`, regenerate
the policy snapshot if needed, and obtain approval for both artifacts. The existing
English/ASCII restriction remains in effect.

## M7.5 — Process-local concurrency diagnostics

`GET /v1/diagnostics/concurrency` requires the existing `X-API-Key` and returns
`Cache-Control: no-store`. It reports active/rejected admissions, detector and
audit queue wait/processing time distributions (p50/p95 and max), operation counts,
and event-loop scheduling lag. All values are counters or aggregate durations: no
raw prompts, keys, model outputs, request identifiers or tenant details are stored.

Metrics start at zero when a control-plane worker starts. They are not shared across
processes, and distributions are bounded rolling windows, not complete histories.
`queue_wait` includes capacity waiting and pending time behind the executor worker;
`processing` measures only work inside that worker. Job counts include cancelled
requests until the underlying worker future really finishes.

When comparing M7.2 and M7.3 throughput, collect diagnostics before and after each
load scenario, ideally with an isolated single-worker deployment, unchanged
Podman resources and a reproducible workload. Look for growing audit queue wait
versus audit worker processing; this instrumentation does not itself determine
the regression's cause. The diagnostics endpoint does not provide production
monitoring, global admission accounting or external telemetry exports.

## Upload deadline

`BODY_READ_TIMEOUT_SECONDS` must be a finite positive number. The deadline starts
when body buffering begins and spans all chunks, including chunked requests without
Content-Length. Sending occasional bytes does not reset it. Expiry returns a
sanitized HTTP 408 before authentication, detection, audit, or model work and releases
the HTTP ingress slot. HTTP/1.x timeout responses close the connection because the
body may be incomplete. Disconnects and external cancellation also release capacity.
The deadline ends when the body is buffered; it does not limit policy/model processing
or response transmission. It does not cover time spent receiving HTTP headers.
Recreate the control-plane service to apply changes.

## M7.6 — HTTP ingress and audit waiter limits

The original `MAX_INFLIGHT_REQUESTS` admission (429) still applies *after*
authentication and JSON validation. An outer ASGI middleware now caps active
HTTP scopes *before* body buffering and FastAPI parsing (503, Retry-After: 1).
The limit is process-local and includes readiness, lookups, diagnostics, and
slow body uploads. A separate Uvicorn `limit_concurrency` setting caps server
connection/task pressure even when a client has not finished sending a body.
Uvicorn may return its own 503 when saturated; it counts connections and
server tasks, so the numeric limit is not equal to request goodput.

`MAX_AUDIT_JOBS` still bounds submitted/running audit work. `MAX_AUDIT_WAITERS`
adds a hard cap on coroutines waiting for a slot. Requests above this total
capacity fail immediately instead of joining a larger wait queue; existing
waiters still have `AUDIT_QUEUE_WAIT_SECONDS` as a deadline. Auxiliary
readiness, audit read, and idempotency DB calls share one separate quota
(`MAX_AUDIT_AUXILIARY_JOBS`) whose permits are released on actual thread
completion, not HTTP cancellation. For `MAX_AUDIT_JOBS` above 1, the effective
auxiliary cap is at most `MAX_AUDIT_JOBS - 1`, preventing auxiliary operations
alone from occupying every job slot. This is **not strict write priority**:
an auxiliary job already ahead in the single-worker queue still runs first.

Both new limits are per-process. No HTTP middleware can guarantee a cap on
kernel sockets without also configuring Uvicorn or the edge proxy. The HTTP
limits can reject readiness checks during overload: liveness/readiness should
be interpreted accordingly. Neither the audit event schema nor signed-release
verification is changed. Blocking filesystem checks and release activation
races are handled in the subsequent M7.7 and M7.8 increments.

## M7.7 — Nonblocking integrity verification

Policy snapshot and signed release checks performed during request processing
run in a dedicated bounded two-worker thread pool. The original checks still
run *before and after* OPA evaluation and in the orchestrator before audit and
model execution. Results are **not cached** between requests. If verification
cannot complete or its queue is exhausted, requests fail closed and cannot
invoke the model before a durable signed decision.

Readiness runs the original full detector live-file scan, release verification,
and policy snapshot validation in a separate single-worker lane. Overlapping
readiness probes share only the **in-progress** scan; the next probe after
completion checks the real artifact bytes again. The readiness lane does not
consume request-time verification capacity. A cancelled HTTP caller cannot
cancel work already submitted to either lane. Running verification is not
forcibly interrupted: an indefinitely blocked filesystem can delay graceful
shutdown. Neither an in-flight shared readiness check nor this process-local
worker isolation provides atomicity against concurrent release activation;
M7.8 addresses that separate operator-side race.

`MAX_INTEGRITY_JOBS` bounds submitted and queued request-time verifications;
`MAX_INTEGRITY_WAITERS` bounds additional slot waiters. The asynchronous
verification limits are per process, not global across multiple Uvicorn workers.
The authenticated concurrency diagnostics endpoint reports request verification
capacity and coalesced readiness scan counts without storing request data.

## DLP-specific diagnostics and optional masking

`GET /v1/diagnostics/dlp` requires `X-API-Key` and returns no-store,
process-local counts for input/output classifications, released, withheld,
masked and failed responses, with a bounded p50/p95 output-inspection latency
window. Counters reset on process restart and cannot prove zero leakage or
replace durable signed events. No text, matched values, request IDs, principal
identities, or arbitrary recognition labels are emitted.

New-source `OUTPUT_MASKING_ENABLED=false` preserves allow/block DLP. Set it
true only after activating a signed **v5** policy+detector release that permits
only explicit `REDACT` obligations for email and phone outputs. The setting is
trusted operator configuration, not client-controlled. Invalid flag values
fail startup. A masked response is returned only after replacing every recorded
span, verifying the transformed bytes remain within the output limit, a
second detector result is clean, the detector identity stays unchanged and
signed OUTCOME evidence is committed. Production signed v4 continues to be
valid until the operator explicitly activates the reviewed successor release.
