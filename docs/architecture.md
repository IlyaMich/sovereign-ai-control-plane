# Architecture - signed releases and M7 operations

**Status:** API version `0.6.0`, including M6 signed releases and implemented M7 operational features. Performance acceptance remains subject to the [profiling criteria](concurrency-performance-profiling.md). The original M1 modular-monolith decision remains in [ADR-0001](adr/0001-modular-monolith.md); M4 policy snapshot decision in [ADR-0002](adr/0002-content-addressed-rego.md).

See the [response-side DLP design](response-side-dlp.md) for the proposed v4 output authorization and audited release boundary. The signed runtime must be upgraded before it becomes active.

## Intent and deployment

A local, fail-closed AI request security gateway intended to demonstrate policy-based routing, sensitive-data handling, response-side allow/block DLP and verifiable decisions. It is **not** a production multi-tenant control plane or proof of geographic sovereignty.

| Trust domain | Current components |
| --- | --- |
| Untrusted | API client and supplied prompt, purpose, requested destination ID |
| Local application | FastAPI ingress, `RequestOrchestrator`, Presidio/spaCy, deterministic redactor, plan validation |
| Local policy | OPA 1.8.0 serving the read-only `policy-active/` snapshot |
| Local execution | `sovereign-model` simulator |
| Optional simulated egress | `egress-gateway` and `external-simulator` on a second private Podman network |
| Durable evidence | SQLite `audit-data` volume, append chain and Ed25519 audit receipts |
| Offline operator | Separate Ed25519 release signer approves policy+detector digests and release generation |
| Offline reviewer | Network-disabled container, archived Rego, portable evidence ZIP, separately provisioned trust anchors |

~~~mermaid
flowchart TD
    Client[Untrusted client] --> API[FastAPI /v1/prompts]
    subgraph Local[Local trust boundary]
        API --> O[RequestOrchestrator]
        O --> D[Presidio / spaCy]
        D --> P[OPA Rego policy]
        P --> V[Validate ordered obligations]
        V --> R[REDACT + second scan when required]
        R --> A[Signed DECISION precommit]
        A --> E{Authorized route}
        E --> M[Local model simulator]
        E --> G[Optional egress gateway]
        M --> OD[Output Presidio + OPA DLP]
        G --> OD
        OD --> OUT[Signed OUTCOME: released or withheld]
        OUT --> DB[(SQLite audit chain)]
        OUT --> RETURN{Output authorized?}
        RETURN -->|yes| DELIVER[Return model output]
        RETURN -->|no| WITHHOLD[OUTPUT_BLOCKED without model text]
        A --> DB
    end
    G --> X[External simulator on test network]
    Signer[Offline release signer] --> Approval[Signed artifact approval]
    Approval -. validates .-> P
    Approval -. validates .-> D
    DB --> Export[Portable evidence export]
    Export --> Reviewer[Network-disabled reviewer]
~~~

The diagram is logical. The Docker/Podman simulation is not an internet egress implementation; the gateway and external simulator do not prove cloud residency or provider identity.

## Runtime responsibilities

- `app/domain/contracts.py`: frozen technology-neutral `PromptCommand`, `DetectionResult`, `PolicyDecision`, `ProcessedRequest` and port interfaces.
- `app/api/main.py`: request-body validation, API-key authentication, one fixed test `Principal("local-tester","local-tenant",...)`, sanitized errors, readiness, evidence/idempotency lookup and authenticated process-local diagnostics.
- `app/detection/*`: in-boundary Presidio/spaCy detection and validated, normalized finding spans. Unsupported non-ASCII text gives `UNKNOWN`; low coverage or invalid results fail closed.
- `app/policy/*`: strict OPA response parser, archive/active policy digest verification, offline policy replay.
- `app/enforcement/*`: validates approved destination IDs and `REDACT`/`ROUTE` order, performs deterministic replacement and second pass. Unregistered URLs cannot be selected from request data.
- `app/release/*`: independently signed release approval and activation; runtime receives trusted public keys, not private release-signing keys.
- `app/audit/*`: one local SQLite audit sequencer, HMAC input fingerprint, Ed25519 signed event chain, durable idempotency claims, bounded audit executor, exporter and disconnected verifier. The auxiliary claim registry is not independently signed.

Detection uses one worker thread, SQLite operations use one audit worker thread,
and request-time policy/release verification uses a bounded two-worker pool per
API process. Readiness performs full live-file verification in a separate
single-worker lane; overlapping probes share the in-progress scan. Worker slots
remain occupied until underlying work completes, even if the HTTP caller cancels.
HTTP ingress capacity is bounded before body buffering; prompt admission follows
authentication and validation. See [configuration](configuration.md).

## Request lifecycle and invariants

~~~mermaid
stateDiagram-v2
    [*] --> Authenticate
    Authenticate --> Detect: admitted request
    Detect --> Decide: supported classification
    Detect --> Deny: UNKNOWN / detector failure
    Decide --> Validate: verified OPA response and release
    Decide --> Deny: OPA unavailable / invalid approval
    Validate --> Transform: approved redaction obligation
    Validate --> Precommit: approved route without redaction
    Validate --> Deny: invalid plan
    Transform --> Precommit: second detection NO_PRIVATE_DETECTED
    Transform --> Deny: redaction failure / uncertain scan
    Deny --> Precommit
    Precommit --> Abort: audit commit fails
    Precommit --> Model: permitted decision durably signed
    Precommit --> Blocked: denial durably signed
    Model --> Outcome: success / ambiguous failure
    Blocked --> Outcome
    Outcome --> Complete: durable outcome commit
    Outcome --> Unresolved: commit failure / crash
~~~

The state diagram shows policy processing after ingress and optional idempotency
claiming. A supplied key is durably claimed before detection. Matching retries
and conflicting payloads return 409 before a second processing attempt. Claims
survive restart; unresolved claims are retained for operator inspection without
automatic execution recovery. See [request lifecycle](idempotency-and-request-lifecycle.md).

**Non-negotiable rules:**

1. Invalid credentials, unsupported input, missing detector coverage, unknown classifications, malformed OPA results, untrusted releases, invalid obligations and unapproved destinations do not invoke a model.
2. Every **admitted policy decision** commits a signed `DECISION` event before model execution. An audit precommit failure aborts forwarding.
3. A permitted external simulated route with detected PII must redact all detected categories and pass a second scan before forwarding.
4. `OUTCOME` is a separate event. A timeout or crash can leave an unknown/pending outcome; it must not be reported as definitively blocked.
5. Release identity, Rego source digest and detector artifact digest are checked against the active signed approval; version labels alone are insufficient.
6. No matched PII values, plaintext prompt or model response are stored in normal audit metadata. Metadata, offsets and principal IDs may still be sensitive.

## API and readiness

- `POST /v1/prompts`: `{"prompt":"...","destination_id":"sovereign-model","purpose":"GENERAL"}` with `X-API-Key` and optional `Idempotency-Key`. JSON fields are strictly validated; default prompt limit is 8,192 UTF-8 bytes and default request-body limit is 16,384 bytes, configurable per deployment.
- `GET /v1/requests/{request_id}`: query signed decision/outcome evidence using authenticated local-tenant scope.
- `GET /v1/idempotency/status`: authenticated lookup using `Idempotency-Key` in a header; reports `request_id`, `audit_state` and `execution_status`, without recovering model output.
- `GET /v1/diagnostics/concurrency`: authenticated process-local admission, worker, logging and event-loop diagnostics. Metrics use bounded rolling windows and reset on worker restart.
- `GET /health/live`: process status only.
- `GET /health/ready`: checks OPA digest/revision, detector integrity, active signed release, audit writability and local model health; failures return 503.

HTTP permit returns `COMPLETED` with output; policy denies return 403 `BLOCKED`; model failures return 502 `ERROR` with potentially unknown invocation status. An unavailable audit writer returns 503. Other ingress and lifecycle responses include:

| HTTP status | Trigger |
| --- | --- |
| 400 | Invalid idempotency key or malformed Content-Length |
| 401 | Invalid API key |
| 404 | Request or idempotency claim not found in the authenticated scope |
| 408 | Total body-read deadline exceeded before authentication or processing |
| 409 | Idempotency key already accepted, or reused with conflicting input |
| 413 | Request-body size exceeded |
| 422 | Invalid JSON/request fields or prompt size |
| 429 | Prompt admission full after authentication and validation (`Retry-After: 1`) |
| 503 | Outer HTTP ingress/server capacity, audit/idempotency unavailability, or failed readiness |

Ingress capacity also covers health, lookup and diagnostics requests. A Uvicorn
capacity rejection occurs before application middleware. These limits are per
process; they do not provide a deployment-wide rate limit. See [configuration](configuration.md).

**Not implemented:** arbitrary model providers, streaming, attachments/RAG, output DLP, tenant OIDC/JWT, admin policy API, independent egress attestation, multi-host audit consensus. See [threat model](threat-model.md) and [Milestone 6](signed-release-workflow.md).
