# Sovereign AI Control Plane — Milestone 6

**Milestone 6: independently signed policy/detector releases and portable approval verification.**

M5's content-addressed Rego and detector manifests establish *which bytes* were
used. M6 adds an offline Ed25519 release authority to approve those exact bytes
before deployment. The release signing key is **not** the runtime audit key and
must remain outside the repository and all containers. This improves provenance
without retaining raw prompts or model weights.

## Milestone 6 quick start (Windows PowerShell)

Preserve your existing `.env` and audit volume. Install `cryptography` on your
operator PC (`python -m pip install "cryptography>=43,<47"`). Then, from the
repository root:

```powershell
# Generates a local development release key OUTSIDE the checkout,
# builds the image, signs the exact detector/policy identities and activates.
.\Initialize-Milestone6.ps1

# Reuse the exact preapproved image; no rebuild on startup.
podman compose -f deploy/compose.yaml --env-file .env up --no-build --force-recreate -d
Invoke-RestMethod http://127.0.0.1:8000/health/ready
.\Verify-Milestone6.ps1
```

If you use the optional egress simulator, add `--profile egress-test` before `up`.
**Never run `podman compose down -v`.** New release approvals are mandatory by
default (`REQUIRE_SIGNED_RELEASE=true`); this is deliberately a gated migration.
For subsequent rollouts use `.\Initialize-Milestone6.ps1 -UseExistingKey` after
building an updated policy snapshot. Never regenerate existing private keys.

See [Milestone 6 release architecture and limits](docs/milestone-6.md) for
rollback, independent public-key pinning, evidence verification and threats.

---

# Sovereign AI Control Plane — Milestone 4

A locally runnable, **fail-closed AI security gateway**, with Presidio + local spaCy
classification, directly authored OPA/Rego rules, and cryptographically
verifiable audit evidence. Based on the working Milestone 1 repository.

```text
Client (X-API-Key)
   -> FastAPI ingress and trusted request context
   -> Presidio built-ins + custom deterministic patterns + local spaCy NLP
   -> our stable classification/coverage aggregator
   -> OPA policy decision (structured input; never the plaintext prompt)
   -> independent enforcement-plan validation
   -> durable SHA-256-chain + Ed25519-signed DECISION event
   -> permitted local model simulator (or optional separate simulated egress gateway)
   -> OUTCOME event and signed receipts
```

**Safety scope:** Detection is best effort, and the supported prompt language is
English ASCII. The default runtime has **no external route enabled**. An
optional test-only `external-simulator` route requires an explicit Compose
profile and environment flag, with verified redaction for supported PII.
This is not a production external-provider integration.


## Milestone 4 — Policy integrity and replay

A signed decision is now bound to the **exact archived Rego source bytes**, not
only to a human-assigned revision name. The policy author still edits
`policies/decision.rego`, but OPA serves only a generated, verified
`policy-active/` snapshot. The archive at `policy-archive/<digest>/` is retained
for forensic replay. The application fails closed if the active snapshot and
the digest returned by OPA do not match.

The existing SQLite schema, audit-signing key, request API, and redaction logic
are preserved. New decision events include a `policy_digest` and the original
OPA evaluation; offline verification re-runs the policy using a pinned OPA CLI.
Older signed audit events remain integrity-verifiable, but they cannot be
cryptographically tied to a historical Rego source file retroactively.

Read [Milestone 4 architecture and limitations](docs/milestone-4.md) for details.

### Upgrade from Milestone 3 (PowerShell)

Preserve `.env`, the existing audit volume, and signing keys. **Never use
`podman compose down -v`.** The ZIP includes the generated initial
`policy-active` snapshot and its matching content-addressed archive.

```powershell
python -m tools.verify_policy_snapshot
podman compose -f deploy/compose.yaml --env-file .env up --build --force-recreate -d
Invoke-RestMethod http://127.0.0.1:8000/health/ready
.\Verify-Milestone4.ps1
```

The reviewer is built only when running the verification script. It executes
OPA in a network-disabled container with read-only mounts. The test takes a
consistent SQLite backup in your existing audit volume; it does not modify
previous audit records. Use synthetic test prompts only.

### Editing policy in Milestone 4

```powershell
# Edit policies/decision.rego first. Generate and archive the new policy bytes:
python -m tools.build_policy_snapshot
python -m tools.verify_policy_snapshot

# Recreate OPA so the new active snapshot directory is mounted:
podman compose -f deploy/compose.yaml --env-file .env up -d --force-recreate opa

# If policy revision changes, update EXPECTED_POLICY_REVISION in .env,
# then recreate the control-plane service as well.
Invoke-RestMethod http://127.0.0.1:8000/health/ready
```

Rego tests now run against `/policies` (the generated active snapshot), not the
editable source directory. **Retain every archived policy snapshot** used by a
decision; deleting it prevents future historical replay.

---

## Milestone 3 changes

- Verified redaction using original detection offsets, with one second full
  classification pass on the transformed prompt before any model invocation.
- Rego decisions can contain ordered `REDACT` and `ROUTE` obligations.
- Fixed destination registry, default-deny external egress, optional separate
  simulated network and dedicated egress gateway.
- Durable signed audit evidence now includes transformation hashes and
  verification metadata, never plaintext prompt values.
- Readiness requires the active OPA revision `redaction-baseline-v3`.
- `tldextract` is configured for an offline packaged Public Suffix List snapshot.
- Existing API JSON format, SQLite records and Ed25519 keys remain compatible.

See [detection design](docs/detection-design.md), [OPA policy design](docs/policy-design.md),
[architecture](docs/architecture.md), [audit](docs/audit-design.md), and
[testing](docs/testing.md).

## Requirements

- Podman and an installed Compose provider (Docker Compose or podman-compose).
- An internet connection **during the first container build** to install
  Python dependencies and download the pinned spaCy model wheel from GitHub.
- Available `127.0.0.1:8000` port. Docker/Podman resources sufficient for the
  NLP model. No GPU required.
- For tests outside containers: Python 3.12+ and dev dependencies.

## Upgrade from Milestone 2 (Windows PowerShell)

1. Extract this ZIP as a separate directory, **or** back up your existing
   repository and copy/merge the source files into it.
2. Keep your existing `.env` file and `CONTROL_PLANE_API_KEY` secret; the ZIP
   deliberately contains no `.env` or private keys.
3. If upgrading your current deployment under the same Compose project name,
   retain the existing `audit-data` volume. **Do not run `down -v`.**
4. Use the new `--env-file .env` flag explicitly when running Compose.

From the project root:

```powershell
# Only for a fresh setup; if upgrading, keep your existing .env instead.
if (-not (Test-Path .env)) {
    python -c "import secrets; print('CONTROL_PLANE_API_KEY='+secrets.token_urlsafe(36))" |
      Set-Content -Encoding ascii .env
}

podman compose -f deploy/compose.yaml --env-file .env up --build --force-recreate -d
podman compose -f deploy/compose.yaml --env-file .env ps
Invoke-RestMethod http://127.0.0.1:8000/health/ready
```

> If you extracted to a **new directory**, Compose still uses the project name
> `sovereign-ai-control-plane`. Existing containers may need to be stopped with
> `podman compose -f deploy/compose.yaml --env-file .env down` from the original
> directory first. `down` without `-v` preserves the named audit volume.
> Keep a backup of audit evidence and keys before changing the environment.

### Test the real detector and Rego policies

```powershell
# Executes the actual installed Presidio + spaCy pipeline in the application image
podman compose -f deploy/compose.yaml --env-file .env exec control-plane `
  python -m tools.smoke_detection

# Execute Rego tests with the pinned OPA image
podman compose -f deploy/compose.yaml --env-file .env run --rm opa `
  test /policies /policy-tests
```

The real detector smoke test should report four PASS lines: ordinary text,
email, private-key marker, and unsupported script. The OPA tests should pass.

### Test through the API

```powershell
$key = (Get-Content .env | Select-String '^CONTROL_PLANE_API_KEY=').ToString().Split('=',2)[1]

function Invoke-SovereignPrompt([string]$Prompt, [string]$Destination = 'sovereign-model', [string]$Purpose = 'GENERAL') {
    $body = @{prompt=$Prompt; destination_id=$Destination; purpose=$Purpose} | ConvertTo-Json
    try {
        Invoke-RestMethod -Uri http://127.0.0.1:8000/v1/prompts `
          -Method POST -Headers @{'X-API-Key'=$key} `
          -ContentType 'application/json' -Body $body -ErrorAction Stop | ConvertTo-Json -Depth 10
    } catch {
        Write-Host "HTTP status: $([int]$_.Exception.Response.StatusCode)"
        if ($_.ErrorDetails.Message) { $_.ErrorDetails.Message }
    }
}

# Ordinary prompt: permitted to local model; response has signed receipts
Invoke-SovereignPrompt 'Explain local policy evaluation'

# Email: PRIVATE / MEDIUM, may be permitted for local routing
Invoke-SovereignPrompt 'Contact jane@example.com about the report'

# Secret: HIGH / CREDENTIAL_BLOCKED, HTTP 403
Invoke-SovereignPrompt '-----BEGIN PRIVATE KEY-----'

# Unapproved external destination: HTTP 403
Invoke-SovereignPrompt 'Hello world' 'external-model'

# Unsupported script: UNKNOWN / DETECTION_UNKNOWN, HTTP 403
Invoke-SovereignPrompt 'שלום'
```

The API is available at <http://127.0.0.1:8000/docs>. `/health/live` is a
process check; `/health/ready` checks OPA, model service and writable audit.

## Policy configuration (Milestone 3 background)

**For the current Milestone 4 activation workflow, follow the steps above:**
edit source, generate a policy snapshot, verify it, then recreate OPA.
A simple OPA restart is no longer sufficient after replacing the active mount
directory.

Rego is authored directly at `policies/decision.rego`, with the entry point:

`data.sovereign.authz.decision`

The baseline policy permits `sovereign-model` processing and offers a separate
`external-simulator` route for approved purposes and completed detection. The
external route is disabled by default at the enforcement registry, and private
PII may use it only after a verified `REDACT` obligation. All permissions
require the `presidio-spacy-v1` detector with required coverage and a
configuration digest. Approved purposes are `GENERAL`, `SUMMARIZATION` and
`INTERNAL_ANALYSIS`.
`API_CREDENTIAL` or `PRIVATE_KEY` findings are always blocked by baseline policy.

Modify Rego as an authorized developer, increment `revision` and the default
revision string, run Rego tests, then restart OPA:

```powershell
podman compose -f deploy/compose.yaml --env-file .env restart opa
```

We are intentionally **not** claiming cryptographic policy-bundle pinning in
M3. Evidence records the revision reported by OPA and the exact structured
policy inputs; attesting the actual policy bytes is later work.

## Regression tests

```bash
python -m pip install -e '.[dev]'
python -m pytest -q
```

Local Python tests without the English model run all lightweight tests and
**skip** the real NLP integration test. In a fully provisioned environment the
real NLP test runs. The container smoke command above validates the actual
installed dependencies without adding pytest to the production image.

## Audit evidence verification

Audit format and on-disk paths are unchanged from M1:

```text
/var/lib/sovereign/audit.sqlite
/var/lib/sovereign/audit-key.pem       # PRIVATE — do not export
/var/lib/sovereign/audit-key.pub.pem   # public verification key
```

To verify the signed audit chain, use a consistent SQLite snapshot and an
independently trusted verification key, then run:

```bash
python -m tools.verify_audit --db ./audit.sqlite --public-key ./trusted-audit-key.pub.pem
python -m tools.export_checkpoint --db ./audit.sqlite --public-key ./trusted-audit-key.pub.pem --out ./checkpoint.json
python -m tools.verify_audit --db ./audit.sqlite --public-key ./trusted-audit-key.pub.pem --checkpoint ./checkpoint.json
```

See [audit-design.md](docs/audit-design.md) for the threat model and limitations.
Never copy only an actively written SQLite main file while WAL is enabled;
use SQLite's online backup API for consistent snapshots.

## Stop and clean up

```powershell
podman compose -f deploy/compose.yaml --env-file .env down
```

**Never add `-v` unless you deliberately want to destroy your persistent audit
volume and signing keys.**


## Milestone 3 — Redaction, obligations, and simulated egress

This release adds a strict `REDACT` + `ROUTE` plan, a fixed destination registry,
post-redaction rescanning, and signed transformation evidence. It also sets
`tldextract` to use its packaged Public Suffix List, without runtime HTTP
requests, and verifies the active OPA policy revision in `/health/ready`.

### Upgrade safely from M2 (PowerShell, repo root)

Keep your existing `.env` file and your **audit volume**. Do not use `down -v`.

```powershell
# Make sure your existing key is still in .env.
podman compose -f deploy/compose.yaml --env-file .env up --build --force-recreate -d
Invoke-RestMethod http://127.0.0.1:8000/health/ready
podman compose -f deploy/compose.yaml --env-file .env run --rm opa test /policies /policy-tests
```

The expected live policy revision is `redaction-baseline-v3`.
A stale OPA policy causes readiness to return `503` rather than reporting false health.
The SQLite audit schema, signing key, and audit volume are unchanged.

### Default local-only mode

By default, `ENABLE_EXTERNAL_SIMULATOR=false`. Only `sovereign-model` can be
invoked. The new Rego policy may propose an external route, but the Python
planner rejects it with `INVALID_POLICY_PLAN` and records a denial.
No external-simulator or egress-gateway is started by default.

### Explicitly enable the simulated external boundary

Add `ENABLE_EXTERNAL_SIMULATOR=true` to `.env`, then recreate the containers
with the **test profile** (never use real sensitive data for this exercise):

```powershell
podman compose -f deploy/compose.yaml --env-file .env --profile egress-test up --build --force-recreate -d
Invoke-RestMethod http://127.0.0.1:8000/health/ready
$key = (Get-Content .env | Select-String '^CONTROL_PLANE_API_KEY=').ToString().Split('=',2)[1]
$body = @{ prompt='Please contact demo@example.com about the project'; destination_id='external-simulator'; purpose='GENERAL' } | ConvertTo-Json
Invoke-RestMethod -Uri http://127.0.0.1:8000/v1/prompts -Method POST -ContentType 'application/json' -Headers @{'X-API-Key'=$key} -Body ([Text.Encoding]::UTF8.GetBytes($body)) | ConvertTo-Json -Depth 10
```

Expected: `COMPLETED`, `PERMIT`, `REDACT` followed by `ROUTE`, model ID
`external-simulator`, and audited transformation metadata. Only the **redacted**
prompt is sent to the simulated external model. No raw prompt is written to
ordinary logs or audit records. The response returns only a SHA-256 prefix,
not the redacted text itself.

For stronger validation, use the in-repository unit test asserting exactly what
reaches the mock model. Failure, unknown classification, unsupported categories,
incomplete obligations, or failed post-redaction detection all block.

In this profile `egress-gateway` is the sole bridge between two private networks.
The external simulator is intentionally local; this is **not a real internet
provider integration or proof of production-grade network isolation**.

Disable after testing:

```powershell
# Edit .env back to ENABLE_EXTERNAL_SIMULATOR=false
podman compose -f deploy/compose.yaml --env-file .env --profile egress-test down
podman compose -f deploy/compose.yaml --env-file .env up -d --force-recreate
```

### Test matrix

```powershell
podman compose -f deploy/compose.yaml --env-file .env run --rm opa test /policies /policy-tests
# If running Python tests locally with dev dependencies:
python -m pytest -q
```

- Internal ordinary and PII prompts: allowed unless blocked by a specific rule.
- Credential and private key: always blocked.
- External simulator, ordinary prompt: allowed only when explicitly enabled.
- External simulator, recognized email/phone/person: redacted, rescanned, then routed when enabled.
- External simulator, credit card, SSN, credentials or unsupported input: blocked.
- Missing or duplicate obligations, wrong destination or post-redaction private findings: blocked.
- Audit decision is committed before any route. Model error results in an auditable unknown execution outcome.
- Signed evidence logs both the original classification and the outcome of transformation verification without storing plaintext.

**Scope:** Redaction is best-effort on correctly detected findings, not a
mathematical guarantee that every private entity has been found. The supported
language remains English ASCII. The experimental out-of-boundary simulator has
no direct network exposure to the host or control-plane service. There is no
real external model egress, streaming, or model-response classification yet.

**Policy versioning limitation:** `policy_revision` is an operator-supplied
identifier, not yet an archive of the complete signed Rego bundle. Exact
historical policy replay is an additional work item. Never describe the audit
integrity verifier as a full historical policy replay engine.

---

## Milestone 5 — Detector provenance and evidence packages

Milestone 5 adds an **image-build detector manifest** that inventories exact
spaCy model file hashes, classifier source hashes, and installed NLP dependency
versions. The control plane verifies this manifest at startup/readiness and
archives it in its persistent audit volume. Each new classification carries an
`artifact_digest`, bound to the signed decision event. M4 content-addressed
Rego policy replay remains unchanged.

**Run on Windows + Podman after upgrading files and preserving `.env` and audit volume:**

```powershell
podman compose -f deploy/compose.yaml --env-file .env up --build --force-recreate -d
Invoke-RestMethod http://127.0.0.1:8000/health/ready
.\Verify-Milestone5.ps1
```

The script verifies installed detector bytes, runs the full Rego tests, checks
the new signed detector evidence, exports a self-contained evidence ZIP to the
existing audit volume, and verifies it in the **network-disabled**
`audit-reviewer` service. An optional external simulator may still be started
with `--profile egress-test`; it is not needed for this test.

The ZIP includes audit metadata, policy sources and detector *manifests*, but
**no private signing key, model weights or raw prompt text**. It must still be
handled as sensitive. A ZIP carrying its own public key and checkpoint proves
only self-consistency; supply a separately pinned public key and witnessed
checkpoint to authenticate it against external trust anchors.

See [docs/milestone-5.md](docs/milestone-5.md) for data layout, trust boundaries,
CLI commands, and known limits. Do not run `podman compose down -v` while
upgrading: this would delete your audit history and keys.
