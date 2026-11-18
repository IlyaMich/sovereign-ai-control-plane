# Sovereign AI Control Plane — Milestone 2

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
   -> permitted local model simulator (no external network)
   -> OUTCOME event and signed receipts
```

**Safety scope:** M2 recognizes multiple classes of PII and some credential
formats, but detection is **best effort**, not a data-leak prevention guarantee.
The initial supported input is ASCII text evaluated with English recognizers.
Unsupported characters fail closed. A prompt with no findings is *not*
guaranteed free of confidential data. No external AI route or redaction is enabled.

## Milestone 2 changes

- Runtime `PresidioDetector` with the local `en_core_web_sm` 3.8.0 spaCy model
  and pinned `presidio-analyzer==2.2.366` dependency.
- Custom pattern recognizers for email addresses, API-key-style credentials and
  PEM private-key headers. Presidio supplies additional PII recognizers.
- Our technology-neutral `FindingAggregator`: deterministic overlap merging,
  sensitivity prioritization, minimum-score filtering, mandatory recognizer
  coverage and `UNKNOWN` for invalid/unsupported results.
- Additive `config_digest` field in the `DetectionResult` JSON/audit record.
- Direct OPA baseline policy `presidio-baseline-v2`: permitted local processing
  for approved purposes, explicit credential blocking, no external destination.
- Regression tests plus live-in-image Presidio smoke test and eight Rego tests.
- Existing M1 API shape, audit database, Ed25519 keys, and verifier retained.

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

## Upgrade from Milestone 1 (Windows PowerShell)

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

podman compose -f deploy/compose.yaml --env-file .env up --build -d
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

## Policy configuration

Rego is authored directly at `policies/decision.rego`, with the entry point:

`data.sovereign.authz.decision`

The policy only permits a `sovereign-model` route for successful
`presidio-spacy-v1` classifications with required coverage, a configuration
digest, and purpose `GENERAL`, `SUMMARIZATION` or `INTERNAL_ANALYSIS`.
`API_CREDENTIAL` or `PRIVATE_KEY` findings are always blocked by baseline policy.

Modify Rego as an authorized developer, increment `revision` and the default
revision string, run Rego tests, then restart OPA:

```powershell
podman compose -f deploy/compose.yaml --env-file .env restart opa
```

We are intentionally **not** claiming cryptographic policy-bundle pinning in
M2. Evidence records the revision reported by OPA and the exact structured
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
