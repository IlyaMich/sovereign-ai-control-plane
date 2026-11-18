# ADR-0001 — Modular monolith with external OPA and local simulator

**Status:** Accepted architectural decision (2026-11-18); historical M1 scope, still used in M6.

> **Current implementation:** Presidio/spaCy, an approved local simulator, optional *simulated* external egress, content-addressed policy, offline evidence replay, and separately signed releases were added in M2–M6. See [current architecture](../architecture.md). The original M1-only statements below are preserved as decision history.

## Context

The project must run locally with Podman and demonstrate deterministic
security decisions, sovereignty, verifiable auditing, and future extensibility.
A distributed platform with Kafka, Kubernetes, and PostgreSQL is a possible
future, not a requirement for the initial implementation.

## Decision

Implement FastAPI ingress, detection orchestration, enforcement, and audit in one
Python process. Define frozen domain models and `Protocol` interfaces. Run OPA
as a separate local process through its documented decision API. Run a local
simulator in another isolated container. Use transactional SQLite audit storage
with Ed25519-signed events. Only local routing is permitted.

## Alternatives considered

- One all-in-one process with hardcoded rules: smaller, but blurs policy and
  enforcement and makes distributed migration harder.
- Multiple microservices plus Kafka/PostgreSQL: demonstrates deployment patterns
  but adds substantial failure modes before security invariants are verified.
- Custom policy engine: unnecessary language/evaluation surface and would distract
  from enforcement and audit invariants. Rego remains replaceable behind a port.

## Consequences

- Local setup is small and tests can inject fake adapters.
- SQLite assumes one logical sequencer and will need redesign to scale out.
- In-process detection scales with the API; extraction is an expected migration.
- A future Presidio detector and policy bundle workflow can retain domain contracts.
- Stronger secrets, signed policy snapshots, and forensic replay remain later work.

## Subsequent evolution (through M6)

The modular monolith and technology-neutral domain ports remain. M2 added the real detector; M3 introduced verified redaction and an opt-in, simulated external route; M4–M5 added content-bound policy and detector provenance; M6 introduced an offline release signer. SQLite remains one local audit writer and the deployment is not distributed. These later features supersede the M1-only descriptions of future work above.
