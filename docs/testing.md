# Testing and milestone acceptance

## Automated tests

Run `python -m pytest -q` from repository root after installing `.[dev]`.

| Guarantee | Test coverage |
|---|---|
| Exact detection shapes and deterministic ordering | `test_domain_detection.py` |
| Missing/invalid OPA result denied | `test_policy_adapter.py` |
| Decision persisted before model invocation | `test_orchestrator.py` |
| Audit precommit failure prevents model call | `test_orchestrator.py` |
| Detector/OPA faults deny | `test_orchestrator.py` |
| Foreign destination rejected | `test_orchestrator.py` |
| Model timeout remains ambiguous | `test_orchestrator.py` |
| API key and validation safety | `test_api.py` |
| Oversized request body rejected | `test_api.py` |
| Tamper and truncation detection | `test_audit_integrity.py` |
| Concurrent sequence allocation integrity | `test_audit_integrity.py` |

## Manual Podman test matrix

1. Start Compose and check `/health/ready == READY`.
2. Submit ordinary prompt and assert HTTP 200 and two audit receipts.
3. Submit a private-key marker and assert HTTP 403.
4. Submit a public prompt targeting `external-model` and assert HTTP 403.
5. Stop OPA, repeat request, and assert HTTP 403 with `POLICY_UNAVAILABLE`.
6. Stop model, repeat local permitted request, and assert HTTP 502 with UNKNOWN outcome.
7. Make SQLite volume unwritable and assert HTTP 503 with no model invocation.
8. Take an offline audit snapshot, verify, alter an event, rerun verifier to fail.
9. Restore clean snapshot, preserve checkpoint, truncate a tail event, verify
   against the checkpoint and expect failure.
10. Verify `podman compose ... run --rm opa test /policies /policy-tests` passes.

The manual Podman scenario set has **not** been run in this authoring environment;
Podman is not installed here. The Python test suite has been run locally.

## Known gaps beyond milestone 1

- Presidio/spaCy recognition and false-positive/false-negative benchmark set.
- Redaction spans, overlap handling, reclassification, actual output DLP.
- Rego policy bundle immutability, exact digest, and replay against archived rules.
- Encrypted prompts for authorized forensic reconstruction.
- External egress service with network enforcement and allowlisted destinations.
- Real security/authn, rate limiting, production observability and key rotation.
