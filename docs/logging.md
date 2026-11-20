# Operational logging

The control-plane API emits JSON Lines to stdout. `LOG_LEVEL` defaults to `INFO`;
use `DEBUG` for successful audit operations and gateway timings. Set it before
process startup. No additional runtime dependency or network collector is needed.
Use `make logs` or `podman compose -f deploy/compose.yaml --env-file .env logs -f control-plane`.

Every HTTP response passing through the request middleware includes a generated
`X-Correlation-ID`. The same ID appears on request events, including authentication,
validation, capacity and body-size rejection. Accepted prompt processing also adds
the generated `request_id`, linking operational events to signed audit evidence.
Caller-provided correlation headers are ignored. Request routes use known templates;
raw paths, query strings and headers are excluded.

Events include request completion, rejection, policy and detection failures,
redaction/enforcement failures, release integrity failures, audit errors, uncertain
model execution, startup stages, verified release identities and shutdown. Readiness
logs report state/component transitions rather than every poll. Authentication and
capacity warnings and selected rejection events are limited to one per event type
per ten seconds per process; the next emitted event includes `suppressed`.

Only allowlisted primitive fields are accepted. Prompt/model content, detection
matches, credentials, idempotency keys, request/response bodies, full audit payloads,
exception messages and tracebacks are excluded, including at DEBUG. Configured
Uvicorn, HTTPX, HTTP Core, Presidio and spaCy logger messages use a sanitized runtime
envelope rather than their arbitrary message text. Do not enable raw HTTP/body
logging in surrounding infrastructure. Additional third-party loggers need explicit
review before being enabled.

A 2048-record process-local queue delivers events to stdout on a background thread.
A full queue drops operational events; logging errors do not change request outcomes.
The authenticated `/v1/diagnostics/concurrency` endpoint exposes `logging.dropped_events`
and `logging.output_errors`. DEBUG events may be dropped under load. Tail events may
be lost on abrupt termination. The application does not write rotating log files;
configure bounded retention and access controls in the local container log collector.
No log export outside the deployment is configured.

Signed SQLite DECISION/OUTCOME events remain the evidence source. Operational logs
neither replace nor satisfy the durable decision precommit. A model failure remains
UNKNOWN where execution cannot be established; cancellation may leave a decision
without an outcome. Audit executor events report actual completion even when a
caller was cancelled, with captured correlation metadata. They do not perform
reconciliation or authorize retrying inference.

Logging changes do not edit signed classifier source files. Follow the normal image
build and runtime release verification procedure before deploying. Changes to signed
detector files still require their existing manifest/release approval workflow.


## Overload and integrity diagnostics

HTTP ingress saturation emits `http_ingress_rejected` with
`HTTP_INGRESS_CAPACITY_EXCEEDED`, including on health routes. This warning replaces
the ordinary request summary for that rejection and is rate-limited per process.
The HTTP correlation header is still returned. The outer Uvicorn connection limit
emits `server_capacity_exceeded` with `UVICORN_CAPACITY_EXCEEDED`; this occurs before
ASGI, so no application request/correlation ID is available. Only Uvicorn's exact
known concurrency-warning message is mapped; other arbitrary text stays excluded.
The supported launcher configures logging before Uvicorn and preserves that setup.

Integrity queue rejection and shutdown are WARNING events with
`INTEGRITY_CAPACITY_EXCEEDED` and `INTEGRITY_EXECUTOR_CLOSED`. These operational codes
also appear in policy/orchestrator diagnostics instead of falsely identifying
capacity as an invalid signature or untrusted artifact. Signed fail-closed decision
reason codes remain unchanged. Integrity completion events retain the initiating
request's correlation metadata and report actual queue/worker timing. Successes
use DEBUG, and failures use ERROR. Normal readiness scan failures use DEBUG because
the readiness transition already reports the failure at ERROR. Failure after a
cancelled readiness waiter still emits ERROR so late failures remain visible.
For a shared readiness scan, `CALLER_CANCELLED` means at least one waiter cancelled;
completion belongs to the request that initiated the scan. Each cancellation has
its own correlation metadata. Full scans remain fresh and overlapping scans still
coalesce; logging does not cache approvals.

Readiness transitions identify policy, detector, release, audit or model failures
with fixed component/error codes. Repeating the same failure does not emit another
ERROR transition; DEBUG scan diagnostics can still be enabled when needed.

## Offline release activation

`python -m tools.activate_release` sends operational JSON logs to stderr while
preserving its existing stdout result. Events cover activation start, successful
activation with verified artifact digests, lock timeout/unavailability, validation
and publication failure, and rollback completion or failure. `RECOVERY_REQUIRED`
means automatic rollback failed and the operator must inspect retained artifacts.
No private keys, file contents, candidate paths or exception messages are logged.
These are diagnostic events, not additional signed audit evidence.


## Output DLP and dependency resilience

Output inspection emits ERROR events for invalid model content, invalid output
policy plans, detector service failures, and unsuccessful mask verification.
These events contain fixed error codes and stage names, never generated text,
matched values, redacted text, fingerprints, or exception messages. Ordinary
output policy denials do not produce ERROR events.

`output_decision_committed` is an INFO summary emitted only after the signed
OUTCOME write succeeds. It records the output effect, request ID, audit sequence,
`COMPLETED` or `OUTPUT_BLOCKED`, and whether an output mask was applied. A mask may
have been applied even when a later release check blocks disclosure; the effect
and execution status describe the final result. The operational error code keeps
capacity/shutdown distinct from untrusted artifacts, while existing API and signed
decision reason codes retain their fail-closed semantics. Failed OUTCOME writes
never emit this summary.

OPA diagnostics distinguish `input_policy` from `output_policy`. Output release
checks use `output_release`; `INTEGRITY_CAPACITY_EXCEEDED` and
`INTEGRITY_EXECUTOR_CLOSED` are limited WARNING diagnostics. Actual trust failures
remain ERROR events. `/v1/diagnostics/dlp` is retained as a known log route.

Circuit state changes emit `dependency_circuit_opened` (WARNING),
`dependency_circuit_half_open` (INFO), and `dependency_circuit_closed` (INFO), with
only the fixed `opa` or `model` stage. Stale request completions cannot log false
recovery. Calls refused locally by an open circuit use `OPA_CIRCUIT_OPEN` or
`MODEL_CIRCUIT_OPEN` as rate-limited WARNING diagnostics, including in orchestrator
logs. These codes distinguish local rejection from an attempted connection failure;
existing execution/audit outcomes remain unchanged. HTTP failures still produce
ERROR diagnostics. Safe health-probe retries emit DEBUG metadata with the next
attempt number. Logging does not introduce retries for generation or policy calls.
