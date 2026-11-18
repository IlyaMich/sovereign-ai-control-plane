# Threat model and sovereignty (M1)

## Assets

- Confidential prompts and recognizer findings; the model is trusted only within
  the local boundary.
- Policy integrity, approved destinations, signed audit history, and signing key.
- Audit history and independently retained trust anchors/checkpoints.

## Trusted components

Local host/operator, Podman runtime, FastAPI image, OPA image and mounted Rego,
model simulator, SQLite named volume, and Ed25519 signing key. The API client and
its prompt are **not** trusted. The external internet is outside the boundary.

## Security controls implemented

- Authenticated ingress, strictly validated bodies, no user-supplied destination URLs.
- One private Compose network, no published OPA/model ports, API published on loopback.
- In-process plan validation, internal-only allowlist, zero external adapters.
- On any unexpected detector/OPA/plan failure, deny before invocation.
- Signed decision precommit before model invoke; no plaintext prompt in audit.
- Sanitized HTTP errors and disabled uvicorn access logging.

## Attacks considered

| Attack / failure | Current handling |
|---|---|
| Prompt injects instructions to bypass the guard | Prompt never interpreted as policy; OPA sees structured findings only |
| Caller supplies external URL or tenant claims | API rejects unknown fields; model gateway has fixed destination |
| OPA timeout or undefined result | Local fail-closed decision, audit, deny |
| Detector crashes | `UNKNOWN`, local fail-closed decision, audit, deny |
| Credentials present | Pattern detects selected formats, Rego blocks |
| Audit disk full | Request aborted before forwarding when precommit fails |
| Database event altered | Hash and signature verification fails |
| End of database deleted | Detectable only against external trusted checkpoint |
| Host administrator compromises signer and DB | Out of M1 threat model; independent trust anchor required |

## Known limitations / open threats

- Demo detector has serious false-negative risks: it is not a substitute for
  Presidio, model detection, or enterprise DLP. A `NO_PRIVATE_DETECTED` response
  only certifies that the **configured demo recognizers** completed.
- Only internal simulator model output is permitted. Output DLP and real model
  responses are not yet protected against leakage.
- API key authenticates one local identity. No per-user RBAC, rate limits, JWT,
  or tenant-specific policy management.
- Kubernetes egress controls, DNS pinning, host proxy bypass checks, SELinux
  labeling, rootless user mappings, and strict secret management remain future work.
- Host/VM networking differs among Windows Podman Machine, rootless Linux, and
  other backends; Compose `internal: true` is not a substitute for verification.
- Python dependencies and OPA image tags are version-ranged/tagged rather than
  reproducibly locked by hashes. A release should pin digests and build an SBOM.
- Key stored unencrypted in a local persistent volume for simplicity. Restrict
  volume permissions; do not use this as a production key-management design.
- Some pre-validation / unauthorized requests cannot produce decision records:
  the guarantee applies to **admitted policy decisions**, not all TCP/HTTP events.
