# Audit event design, integrity, and replay (M1)

## Guarantee and event lifecycle

Every **admitted policy decision** must be durably committed as a `DECISION`
event before forwarding to any model. On successful completion or known denial,
an `OUTCOME` event follows. Model timeouts record `UNKNOWN` execution outcome:
a request may have reached a model even if no response was received.

A crash between forwarding and an outcome commit leaves a decision event without
an outcome. This is *pending/unknown*, not proof the request was blocked.

When audit storage is down before decision commit, requests fail closed; those
precommit rejections cannot be durably recorded in the unavailable store.

## Event representation

```json
{
  "schema_version": "1",
  "event_id": "random-uuid",
  "request_id": "random-uuid",
  "tenant_id": "local-tenant",
  "event_type": "DECISION",
  "timestamp": "2026-11-18T12:00:00+00:00",
  "payload": {
    "principal_id": "local-tester",
    "input_hmac_sha256": "(tenant-local keyed fingerprint)",
    "policy_input": {"principal": {}, "request": {}, "classification": {}},
    "decision": {"effect": "DENY", "obligations": [], "reason_codes": ["DEFAULT_DENY"], "policy_revision": "baseline-v1"}
  }
}
```

The event excludes plaintext prompt, exact matching values, and model output.
The HMAC derives a distinct key from local Ed25519 seed via HKDF for M1; a
production deployment should use separately managed, tenant-specific keys.

## Hash chain and signature

The writer uses deterministic Python JSON (sorted keys, UTF-8, compact separators,
no NaN) for **this bounded schema**. It is *not* yet RFC 8785/JCS and must not
be presented as such. RFC 8785 canonicalization will be a later compatibility
upgrade with a version change.

```text
hash_i = SHA256(
  b"sovereign-audit-event-v1\\0"
  || bytes(previous_hash)
  || uint64_be(sequence)
  || canonical_json(event)
)
signature_i = Ed25519_sign(private_key, bytes(hash_i))
```

A SQLite `BEGIN IMMEDIATE` write transaction serializes competing appends and
persists event, sequence, previous hash, current hash, and signature. SQLite uses
`PRAGMA synchronous=FULL` and WAL. The app is one local writer in M1.

The signature covers the hash which covers metadata, event type, sequence,
predecessor, and payload; a database editor cannot rewrite a verified event
without the signing key.

## Independent verification and truncation detection

`python -m tools.verify_audit --db ... --public-key ...` recomputes every hash,
checks event metadata consistency, sequence continuity, and Ed25519 signatures.
It does **not** load the private key and must use a public key already trusted
independently of the database.

An attacker could truncate the tail and retain a valid prefix. To detect it,
export a checkpoint of the known-good `{verified_events, latest_sequence,
latest_hash}` and retain it separately. `--checkpoint ...` requires exact match.
A checkpoint is a witness to a **specific** log state; new append events require
new checkpoints or a verifier strategy that checks earlier checkpoints as a
prefix of the later chain.

Example unit tests: `tests/test_audit_integrity.py` alters a record and removes
an event, showing both types of failure.

## Reconstruction scope

The metadata and `policy_input` retain the exact classification signals the
OPA evaluator saw, plus result and reason codes. This is sufficient to understand
**why the recorded policy decision was made**, but **not yet to independently
replay the exact historical policy bytecode**. M2/M3 will archive signed and
hash-pinned OPA bundles and add an offline policy replay command.

Re-running detection from the original prompt is impossible with M1 metadata
alone. Encrypted input evidence, key management, and authorized forensic replay
are intentionally deferred.

## Operational limitations

- Signer key and SQLite data are on the same local volume. An attacker controlling
  both can forge a new history unless the verifier has a trusted external public
  key and checkpoint.
- `GET /v1/requests/{id}` is a convenience evidence view, not a verified export.
- A process killed between a call and outcome commit produces an unresolved
  decision; reconciliation, idempotent model calls, and eventual completeness
  checks are later milestones.
- PostgreSQL/Kafka migration requires new sequencer/transaction semantics;
  Kafka publication alone is not an audit durability guarantee.


## Milestone 4 extension

New signed `DECISION` payloads preserve the original OPA response, its source
bundle digest and the resolved final enforcement decision. See
[milestone-4.md](milestone-4.md) for policy archive verification and replay.
The on-disk chain encoding and signature scheme are intentionally unchanged,
so older signed events remain verifiable. Legacy events lack policy digests
and are counted as integrity-only by the offline reviewer.
