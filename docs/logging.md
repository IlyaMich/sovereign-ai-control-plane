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
