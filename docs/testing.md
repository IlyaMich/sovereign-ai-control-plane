# Milestone 2 test plan

## Automated Python tests

Run locally (requires development dependencies, not the NLP model):

```bash
python -m pip install -e '.[dev]'
python -m pytest -q
```

Run all tests **inside the built control-plane image**, where Presidio and the
pinned spaCy model are actually installed:

```powershell
podman compose -f deploy/compose.yaml --env-file .env exec control-plane python -m tools.smoke_detection
```

To run the full pytest suite against real NLP, set up a local Python environment
with Presidio, spaCy, the English model, and dev dependencies. The production
container deliberately does not include pytest or the test sources.

| Guarantee | Tests |
|---|---|
| Stable overlapping-entity aggregation, severity precedence | `test_detection_aggregation.py` |
| Unknown categories, missing coverage, invalid spans | `test_detection_aggregation.py` |
| Presidio adapter translation, no raw matched values | `test_presidio_adapter.py` |
| Real installed model pattern checks | `test_presidio_real_integration.py` (when model installed) |
| Fail-closed detector/OPA failures; durable decision before model | `test_orchestrator.py` |
| Strict OPA output schema and error handling | `test_policy_adapter.py` |
| Audit tampering, truncation, concurrent writes | `test_audit_integrity.py` |
| Authorization, input sanitization, request size limits | `test_api.py` |

## Podman smoke checks

```powershell
podman compose -f deploy/compose.yaml --env-file .env up --build -d
podman compose -f deploy/compose.yaml --env-file .env exec control-plane python -m tools.smoke_detection
podman compose -f deploy/compose.yaml --env-file .env run --rm opa test /policies /policy-tests
Invoke-RestMethod http://127.0.0.1:8000/health/ready
```

Use the PowerShell example in README to check a public prompt, an email and
a synthetic private-key marker. The old M1 tests for OPA outages, unauthorized
destinations, and independently verified audit corruption remain relevant.

**Not executable here:** this authoring environment has neither Podman/OPA
nor the installed Presidio package or spaCy English model, so I cannot claim
a real-container/NLP/OPA integration pass until those commands are run locally.

## Known limitations

- Best-effort detection, English/ASCII-only input scope, no guarantee of
  finding all PII, secrets, confidential business facts or regulated data.
- No redaction or external egress yet.
- M1 manually versioned Rego; no signed policy-bundle attestation.
- No cryptographically authenticated archive of full NLP model bytes.
- Full offline replay can verify OPA *inputs and reported output* from evidence,
  but reproducing old policy execution requires the correct archived Rego.
