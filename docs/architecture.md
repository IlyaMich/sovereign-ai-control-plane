# Architecture — current Milestone 6 implementation

**Status:** Current as of API version `0.6.0`. The original M1 modular-monolith decision remains in [ADR-0001](adr/0001-modular-monolith.md); M4 policy snapshot decision in [ADR-0002](adr/0002-content-addressed-rego.md).

## Intent and deployment

A local, fail-closed AI request security gateway intended to demonstrate policy-based routing, sensitive-data handling, and verifiable decisions. It is **not** a production multi-tenant control plane or proof of geographic sovereignty.

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
        M --> OUT[Signed OUTCOME]
        G --> OUT
        OUT --> DB[(SQLite audit chain)]
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
- `app/api/main.py`: request-body validation, API-key authentication, one fixed test `Principal("local-tester","local-tenant",...)`, sanitized errors, readiness and evidence lookup.
- `app/detection/*`: in-boundary Presidio/spaCy detection and validated, normalized finding spans. Unsupported non-ASCII text gives `UNKNOWN`; low coverage or invalid results fail closed.
- `app/policy/*`: strict OPA response parser, archive/active policy digest verification, offline policy replay.
- `app/enforcement/*`: validates approved destination IDs and `REDACT`/`ROUTE` order, performs deterministic replacement and second pass. Unregistered URLs cannot be selected from request data.
- `app/release/*`: independently signed release approval and activation; runtime receives trusted public keys, not private release-signing keys.
- `app/audit/*`: one local SQLite audit sequencer, HMAC input fingerprint, Ed25519 signed event chain, exporter and disconnected verifier.

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

**Non-negotiable rules:**

1. Invalid credentials, unsupported input, missing detector coverage, unknown classifications, malformed OPA results, untrusted releases, invalid obligations and unapproved destinations do not invoke a model.
2. Every **admitted policy decision** commits a signed `DECISION` event before model execution. An audit precommit failure aborts forwarding.
3. A permitted external simulated route with detected PII must redact all detected categories and pass a second scan before forwarding.
4. `OUTCOME` is a separate event. A timeout or crash can leave an unknown/pending outcome; it must not be reported as definitively blocked.
5. Release identity, Rego source digest and detector artifact digest are checked against the active signed approval; version labels alone are insufficient.
6. No matched PII values, plaintext prompt or model response are stored in normal audit metadata. Metadata, offsets and principal IDs may still be sensitive.

## API and readiness

- `POST /v1/prompts`: `{"prompt":"...","destination_id":"sovereign-model","purpose":"GENERAL"}` with `X-API-Key`. JSON fields are strictly validated; prompt max 8,192 UTF-8 bytes, request body max 16,384 bytes.
- `GET /v1/requests/{request_id}`: query signed decision/outcome evidence using authenticated local-tenant scope.
- `GET /health/live`: process status only.
- `GET /health/ready`: checks OPA digest/revision, detector integrity, active signed release, audit writability and local model health; failures return 503.

HTTP permit returns `COMPLETED` with output; policy denies return 403 `BLOCKED`; model failures return 502 `ERROR` with potentially unknown invocation status. An unavailable audit writer returns 503.

**Not implemented:** arbitrary model providers, streaming, attachments/RAG, output DLP, tenant OIDC/JWT, admin policy API, independent egress attestation, multi-host audit consensus. See [threat model](threat-model.md) and [Milestone 6](milestone-6.md).
