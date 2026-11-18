# Sovereign AI Control Plane — Milestone 1

A locally runnable **security-first AI request gateway**. Its request path is:

```text
Client (X-API-Key)
  → FastAPI ingress (untrusted prompt)
  → demo deterministic recognizers (M2: Presidio + spaCy)
  → OPA Rego policy decision
  → local enforcement-plan validation
  → durable SHA-256-chain + Ed25519-signed DECISION event in SQLite
  → allowed local model simulator (no external network)
  → OUTCOME event (or unresolved/pending audit record on crash)
  → response with verifiable decision/outcome receipts
```

**This is an architectural baseline, not a complete production DLP/security product.**
The current recognizers handle a narrow subset of email / key formats only;
`NO_PRIVATE_DETECTED` never means globally safe. The only allowed route is to a
local simulator. External egress, redaction, real NLP, encrypted prompt evidence,
policy-bundle pinning, and multi-tenant authentication are deliberately deferred.

## What is already implemented

- Strict JSON API and fixed authenticated principal, request size limits, sanitized validation errors.
- Domain contracts independent of HTTP/OPA/SQLite, with ports for detection, policy, audit, and model execution.
- Fail-closed behavior for missing/invalid OPA output, unknown detection, invalid plan, and audit precommit failure.
- Actual OPA/Rego adapter and baseline Rego policy, with default deny and protected-credential blocking.
- Strict local destination registry; no caller-supplied URL accepted.
- Persistent SQLite append-by-application event chain, transactional sequence allocation, signatures per event.
- Independent offline verifier using a trusted public key and optionally a known-good checkpoint.
- Local deterministic HTTP model simulator with no raw-prompt logging.
- Test suite covering domain, API, policy adapter, audit integrity, concurrency, and fail-closed cases.

## Prerequisites

- Podman Desktop / Podman CLI and a **Compose provider** (`podman-compose` or Docker Compose).
  `podman compose` delegates to an installed Compose provider; Podman alone may not be enough.
- Available port `127.0.0.1:8000`.
- For running the Python tests without containers: Python 3.12+.

## Run on Podman

Run these commands **from the repository root**.

### Bash / Linux / macOS

```bash
python3 -c "import secrets; print('CONTROL_PLANE_API_KEY='+secrets.token_urlsafe(36))" > .env
podman compose -f deploy/compose.yaml up --build -d
podman compose -f deploy/compose.yaml ps
curl -fsS http://127.0.0.1:8000/health/ready
```

### PowerShell / Windows

```powershell
python -c "import secrets; print('CONTROL_PLANE_API_KEY='+secrets.token_urlsafe(36))" | Set-Content -Encoding ascii .env
podman compose -f deploy/compose.yaml up --build -d
podman compose -f deploy/compose.yaml ps
Invoke-RestMethod http://127.0.0.1:8000/health/ready
```

Most Compose providers read `.env` automatically; if yours does not, add `--env-file .env`
to the Compose command or export `CONTROL_PLANE_API_KEY` into your shell.

**Demo request (PowerShell):**

```powershell
$key = (Get-Content .env | Select-String '^CONTROL_PLANE_API_KEY=').ToString().Split('=',2)[1]
$body = @{prompt='Explain local policy evaluation'; destination_id='sovereign-model'; purpose='GENERAL'} | ConvertTo-Json
Invoke-RestMethod -Uri http://127.0.0.1:8000/v1/prompts -Method POST -Headers @{'X-API-Key'=$key} -ContentType 'application/json' -Body $body
```

**Demo request (Bash):**

```bash
set -a; source .env; set +a
curl -i -X POST http://127.0.0.1:8000/v1/prompts \
  -H "X-API-Key: $CONTROL_PLANE_API_KEY" -H 'Content-Type: application/json' \
  -d '{"prompt":"Explain local policy evaluation","destination_id":"sovereign-model","purpose":"GENERAL"}'
```

Expected HTTP statuses:

| Condition | HTTP | Result |
| --- | --- | --- |
| Allowed local prompt | `200` | `COMPLETED`, decision and outcome receipts, simulator response |
| Credential or disallowed destination | `403` | `BLOCKED`, auditable denial |
| Model timeout/error | `502` | `ERROR`, ambiguous model outcome recorded |
| Audit DB cannot commit | `503` | No model invocation if precommit fails |
| Invalid request | `422` / `413` | No admitted policy decision |
| Missing/wrong API key | `401` | Unauthorized |

## Verify behavior

```bash
# Credential blocked; never forwarded to the model:
curl -i -X POST http://127.0.0.1:8000/v1/prompts \
  -H "X-API-Key: $CONTROL_PLANE_API_KEY" -H 'Content-Type: application/json' \
  -d '{"prompt":"-----BEGIN PRIVATE KEY-----","destination_id":"sovereign-model"}'

# Explicit external routing is blocked:
curl -i -X POST http://127.0.0.1:8000/v1/prompts \
  -H "X-API-Key: $CONTROL_PLANE_API_KEY" -H 'Content-Type: application/json' \
  -d '{"prompt":"Hello","destination_id":"external-model"}'

# Stop OPA and repeat: the control plane must block, not forward.
podman compose -f deploy/compose.yaml stop opa
```

Restart OPA with `podman compose -f deploy/compose.yaml start opa`.

### Rego tests inside OPA container

```bash
podman compose -f deploy/compose.yaml run --rm opa test /policies /policy-tests
```

### Python tests

```bash
python -m pip install -e '.[dev]'
python -m pytest -q
```

### Audit verification

The audit data is persisted in the Compose volume `audit-data`. Inside the
control-plane container its paths are:

```text
/var/lib/sovereign/audit.sqlite
/var/lib/sovereign/audit-key.pem       # PRIVATE; never export or commit
/var/lib/sovereign/audit-key.pub.pem   # public verifier key
```

To verify from a trusted/offline environment, first safely snapshot the SQLite
DB and export the public key. **Keep a separately trusted copy of the public key**.
Use the CLI against the copied files:

```bash
python -m tools.verify_audit --db ./audit.sqlite --public-key ./trusted-audit-key.pub.pem
python -m tools.export_checkpoint --db ./audit.sqlite --public-key ./trusted-audit-key.pub.pem --out ./known-good-checkpoint.json
python -m tools.verify_audit --db ./audit.sqlite --public-key ./trusted-audit-key.pub.pem --checkpoint ./known-good-checkpoint.json
```

Preserve `known-good-checkpoint.json` **outside the writer's control**. If a later
snapshot has been truncated or rewritten, checking it against the checkpoint
reveals a mismatch. See [audit design](docs/audit-design.md) for assumptions and
an example tampering test.

## Docs

- [Architecture and contracts](docs/architecture.md)
- [Threat model and sovereignty boundary](docs/threat-model.md)
- [Policy semantics and versioning](docs/policy-design.md)
- [Evidence format, guarantees, verifier](docs/audit-design.md)
- [Test matrix and limitations](docs/testing.md)
- [Architecture decisions](docs/adr/0001-modular-monolith.md)

## Stop and clean up

```bash
podman compose -f deploy/compose.yaml down
```

To erase the persistent evidence volume as well (destructive):

```bash
podman compose -f deploy/compose.yaml down -v
```

**Security note:** The network is marked internal and the only published port is
bound to host loopback. Depending on the host, VM, and Podman backend, additional
host-to-container networking may exist; verify network policies on your system.
This project's threat model trusts the local host and administrator. It does
not guarantee no prompt disclosure on a compromised host.
