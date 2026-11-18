# Milestone 4 — Content-bound policy evidence and offline OPA replay

## Guarantee

A policy evaluation's `policy_digest` binds its answer to an archived snapshot
of the exact policy **source bytes** and normalized relative filenames. The
control plane verifies that the active snapshot matches an archived copy, and
that the digest and revision returned by OPA are those of the same snapshot.
A mismatch results in a `POLICY_UNAVAILABLE` fail-closed decision. The signed
audit decision contains both the original OPA decision and any stricter local
enforcement override.

The audit verifier first verifies the full Ed25519-signed event chain, then
re-evaluates each M4 OPA decision offline against the content-addressed policy
snapshot. No plaintext prompt is needed because OPA receives only trusted
request attributes and normalized detection findings. Old M1–M3 events remain
verifiable for integrity, but **cannot** be claimed as policy-replayed.

## Snapshot format

`policies/decision.rego` is the editable source. The activation command
`python -m tools.build_policy_snapshot` produces:

- `policy-archive/<64hex>/decision.rego` — retained source bytes
- `policy-archive/<64hex>/snapshot.rego` — generated OPA rule identifying the digest
- `policy-archive/<64hex>/manifest.json` — digest, revision, file hashes and sizes
- `policy-active/` — an activated copy of the archive

SHA-256 is computed over a domain-separated, length-prefixed sequence of each
relative source file name and content. Generated metadata and the manifest are
excluded from the digest to avoid recursion; their exact contents are verified
separately. Additional `.rego` and `.json` source files can be added to
`policies/` and are included in the digest.

The source manifest is **not a signed release artifact**. The independent audit
signature binds the digest reported at decision time. Host administrators and
the policy build pipeline are within the trust boundary for this local demo.

## Deployment

OPA reads `policy-active` read-only, never editable source. The API sees both
active and archived source read-only. Updating source files alone is not a
policy activation. For a new policy release:

1. Edit `policies/decision.rego` and update the human revision if appropriate.
2. Run `python -m tools.build_policy_snapshot` from the repo root.
3. Run `python -m tools.verify_policy_snapshot` and the Rego test suite.
4. Recreate **OPA** (a simple restart is insufficient after the bind mount
   directory is replaced on certain systems):
   `podman compose -f deploy/compose.yaml --env-file .env up -d --force-recreate opa`.
5. Check `/health/ready` and send a synthetic prompt. If you changed the human
   revision, also set `EXPECTED_POLICY_REVISION` in `.env` and recreate the
   control-plane container.

During activation, a source/active/OPA mismatch will deny and log an audited
local policy-unavailable fallback. Complete activation when traffic is stopped
for predictable behavior. Unlike a production signed policy-bundle rollout,
this is **not an atomic distributed activation**.

**Do not delete old `policy-archive/<digest>/` directories** after recording
decisions. Preserve policy archives alongside evidence in protected backups.

## Audit record changes

The M4 `DECISION` event adds the following optional payload fields without
changing existing SQLite tables or the signed chain structure:

```json
{
  "policy_evidence_version": "2",
  "policy_snapshot": {"sha256": "<64-character digest>", "revision": "redaction-baseline-v3"},
  "policy_evaluation": {"effect": "PERMIT", "obligations": [], "reason_codes": ["..."], "policy_revision": "redaction-baseline-v3", "policy_digest": "<64-character digest>"},
  "decision": {"effect": "DENY", "obligations": [], "reason_codes": ["REDACTION_FAILED"], "policy_revision": "local-fail-closed-v1"}
}
```

This illustrates an OPA permit locally tightened into a redaction failure.
An ordinary permit will have the same `decision` and `policy_evaluation`.
If OPA was never contacted (unknown detection or policy outage),
`policy_evaluation` and `policy_snapshot` are `null`; the verifier reports the
local fail-closed decision as non-Rego-replayable, not as independently proven.

## Offline verification and replay

First take a **consistent SQLite snapshot**, rather than copying a live WAL
main database file. Retain a trusted verification public key and previously
witnessed chain-head checkpoint outside the writer's control. Then run the
`audit-reviewer` Compose service with `--profile audit-review`. It has no
network and has read-only mounts for the database and policy archive.

```powershell
podman compose -f deploy/compose.yaml --env-file .env --profile audit-review `
  run --build --rm audit-reviewer `
  --db /var/lib/sovereign/m4-review.sqlite `
  --public-key /var/lib/sovereign/audit-key.pub.pem `
  --archive /policy-archive
```

The reviewer internally runs `opa eval --data <archived-snapshot> --input
<recorded-policy-input> data.sovereign.authz.decision` without contacting live
OPA. An output of `REPLAY_VERIFIED` means the signed event chain checked out
and the recorded policy results were reproduced.

## Limits

- Historical M1–M3 signed events have no policy content digest; **integrity-only**.
- Policy replay proves decision equivalence, **not** correctness of the
  original private-data detection. Full detector replay needs authorized raw
  input and pinned NLP artifacts, which are intentionally not retained here.
- An OPA policy can depend on built-ins, external data, and environment state.
  The trusted policy authors must avoid runtime-dependent or nondeterministic
  operations. OPA replay executes in a disconnected reviewer container.
- A malicious host with the signing key and trusted checkpoints can rewrite
  the database and its supporting proof material. Independent witness storage
  remains required for meaningful tamper-evidence against a hostile host.
- The application validates policy source digests, not an independently
  signed attestation of the OPA binary or an uncompromised OPA process.
