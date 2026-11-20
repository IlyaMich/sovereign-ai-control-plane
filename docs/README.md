# Documentation guide

This index separates **current operational instructions** from historical milestone records and evaluation notes. Start with the root [README](../README.md) for scope and a local overview. Documentation describes a single-host reference implementation; do not treat simulated egress, synthetic evaluation, or signed evidence as proof of residency, production security, or compliance.

## Current system and operations

| Need | Source of truth |
| --- | --- |
| Architecture, components and request flow | [Architecture](architecture.md) |
| Threat boundaries and limitations | [Threat model](threat-model.md) |
| Environment options | [Configuration](configuration.md) and [`.env.example`](../.env.example) |
| Initial trusted state and migration | [Operator state migration](operator-state-migration.md) |
| Release keys, signing, activation, rollback | [Signed release workflow](signed-release-workflow.md) |
| Rego policy lifecycle | [Policy design](policy-design.md) |
| Detector provenance | [Detection design](detection-design.md) |
| Response inspection and masking controls | [Response-side DLP](response-side-dlp.md) |
| Audit, evidence trust and replay | [Audit design](audit-design.md) |
| Request retry and reconciliation | [Idempotency and lifecycle](idempotency-and-request-lifecycle.md) |
| Logs and metrics | [Logging](logging.md) |
| Verification | [Testing](testing.md) |
| Locally patched OPA build and supply chain | [Patched OPA](PATCHED_OPA.md) |

## Evaluation and performance

- [Detection evaluation](../evaluation/README.md), [enforcement replay](../evaluation/STAGE2.md), [stock Presidio comparison](../evaluation/adapters/STAGE3.md), and [response-side DLP evaluation](../evaluation/OUTPUT_DLP.md).
- [Performance framework](../performance/README.md), [concurrency profiling](concurrency-performance-profiling.md), and [overload/evidence lookup](overload-and-audit-lookup.md).
- [Detector and policy candidate notes](../evaluation/RECALL_CANDIDATE.md) are historical candidate rationale, **not** a substitute for a signed release and current evaluation results.

## Architectural history

- [ADR-0001 modular monolith](adr/0001-modular-monolith.md) and [ADR-0002 content-addressed Rego](adr/0002-content-addressed-rego.md).
- [M3 redaction and egress](history/redaction-and-egress.md), [M4 snapshots and replay](history/policy-snapshots-and-replay.md), [M5 detector provenance](history/detector-provenance-and-evidence.md).

Historical examples may predate signed-release protection. For deployment and state changes, always follow the current operator and signed-release guides rather than milestone-era commands.

## Submission preparation

See the [documentation audit](submission-documentation-audit.md) for proposed consolidations, known stale language, missing submission material and validation work. **This index is navigational, not an acceptance or release attestation.**
