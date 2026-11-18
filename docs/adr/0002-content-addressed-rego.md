# ADR-0002: Content-addressed Rego snapshots and offline decision replay

**Status:** Accepted for Milestone 4

## Context

Rego revisions in M3 were names, not cryptographic identities. A change to
`decision.rego` without a revision bump could change future decisions while
producing indistinguishable audit metadata. An independent reviewer could not
re-run old decisions after the live policy changed.

## Decision

Generate content-addressed snapshots from the exact source Rego/JSON files.
Archive every snapshot, give OPA a read-only copy, and include its digest in
every OPA decision. The API verifies the OPA digest and active/archived source
integrity before allowing execution. Preserve the original OPA answer in signed
audit evidence even when local enforcement denies a permitted plan. Provide a
separately deployable, disconnected reviewer with the pinned OPA CLI to
recompute the original decision from the recorded policy inputs.

## Alternatives considered

- **Revision string only:** simple, but no proof of exact Rego semantics.
- **Read OPA policy source on every request:** extra calls, TOCTOU window,
  multiple-file uncertainty, complex distributed upgrade semantics.
- **Signed OPA bundles with a release service:** strongest production path,
  but excessive infrastructure for a local MVP.

## Consequences

- Policy activation is an explicit build/archive/verify/recreate sequence.
- Old M1–M3 events remain integrity-verified but not replayable as Rego.
- Archives are required evidence: deleting them breaks replay.
- Local developer/host admin is trusted; the demo does not have independent
  signed release attestations or atomic multi-region rollout.
