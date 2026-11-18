# Sovereign AI Control Plane — Milestone 4 policy replay validation
# PowerShell 5.1+; run from repo root. No secret is printed.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-Check([bool]$condition, [string]$message) {
    if (-not $condition) { throw "FAIL: $message" }
    Write-Host "PASS: $message" -ForegroundColor Green
}

if (-not (Test-Path '.env') -or -not (Test-Path 'policy-active/manifest.json')) {
    throw 'Run from repo root; ensure .env and policy-active manifest exist.'
}
$manifest = Get-Content '.\policy-active\manifest.json' -Raw | ConvertFrom-Json
$keyLine = Get-Content .env | Where-Object { $_ -match '^CONTROL_PLANE_API_KEY=' } | Select-Object -First 1
if (-not $keyLine) { throw 'CONTROL_PLANE_API_KEY is missing' }
$key = $keyLine.Split('=',2)[1].Trim()

Write-Host "`n[1/4] Verify content-addressed active policy" -ForegroundColor Cyan
& python -m tools.verify_policy_snapshot
if ($LASTEXITCODE -ne 0) { throw 'Active snapshot validation failed' }

Write-Host "`n[2/4] Execute Rego tests against the active snapshot" -ForegroundColor Cyan
& podman compose -f deploy/compose.yaml --env-file .env run --rm opa test /policies /policy-tests
if ($LASTEXITCODE -ne 0) { throw 'OPA Rego policy tests failed' }

Write-Host "`n[3/4] Request authorization and signed evidence binding" -ForegroundColor Cyan
$body = @{prompt='Describe an idempotent request handler'; destination_id='sovereign-model'; purpose='GENERAL'} | ConvertTo-Json -Compress
$result = Invoke-RestMethod -Uri 'http://127.0.0.1:8000/v1/prompts' -Method POST `
  -Headers @{'X-API-Key'=$key} -ContentType 'application/json; charset=utf-8' `
  -Body ([System.Text.Encoding]::UTF8.GetBytes($body))
Assert-Check ($result.status -eq 'COMPLETED') 'Synthetic prompt completed'
Assert-Check ($result.decision.effect -eq 'PERMIT') 'OPA permitted approved local routing'
Assert-Check ($result.decision.policy_digest -eq $manifest.policy_digest) 'Decision is bound to active policy digest'

$history = Invoke-RestMethod -Uri "http://127.0.0.1:8000/v1/requests/$($result.request_id)" `
  -Headers @{'X-API-Key'=$key}
$event = $history.events | Where-Object { $_.event.event_type -eq 'DECISION' } | Select-Object -First 1
Assert-Check ($null -ne $event) 'Signed decision event exists'
Assert-Check ($event.event.payload.policy_evidence_version -eq '2') 'Evidence is M4 replay-capable'
Assert-Check ($event.event.payload.policy_snapshot.sha256 -eq $manifest.policy_digest) 'Evidence references archived source bytes'
Assert-Check ($event.event.payload.policy_evaluation.policy_digest -eq $manifest.policy_digest) 'Original OPA answer is preserved'

Write-Host "`n[4/4] Offline signed-audit verification and policy replay" -ForegroundColor Cyan
$container = (& podman ps --filter 'name=sovereign-ai-control-plane-control-plane-1' --format '{{.ID}}' |
  Where-Object { $_ -and $_.Trim() } | Select-Object -First 1)
if (-not $container) { throw 'Control-plane container not found in podman ps' }
$container = $container.Trim()
# A consistent SQLite online backup, visible read-only to the audit-reviewer.
$snapshot = "/var/lib/sovereign/m4-review-$([Guid]::NewGuid().ToString('N').Substring(0,8)).sqlite"
@'
import os
import sqlite3
from pathlib import Path

source_path = '/var/lib/sovereign/audit.sqlite'
target_path = Path(os.environ['AUDIT_SNAPSHOT_PATH'])
source = sqlite3.connect(source_path)
target = sqlite3.connect(str(target_path))
try:
    source.backup(target)
    # The live database is WAL-mode. SQLite's online backup inherits WAL mode,
    # but the reviewer has a read-only volume and cannot create WAL sidecars.
    # Change journal mode only on the disposable snapshot, never on the source.
    actual = target.execute('PRAGMA journal_mode=DELETE').fetchone()[0]
    if actual.lower() != 'delete':
        raise RuntimeError(f'Could not switch audit snapshot to DELETE journal mode: {actual}')
    target.commit()
finally:
    target.close()
    source.close()
print('Created standalone read-only-compatible audit snapshot')
'@ | & podman exec -i -e "AUDIT_SNAPSHOT_PATH=$snapshot" $container python -
if ($LASTEXITCODE -ne 0) { throw 'SQLite snapshot failed' }

& podman compose -f deploy/compose.yaml --env-file .env --profile audit-review `
  run --build --rm audit-reviewer `
  --db $snapshot --public-key /var/lib/sovereign/audit-key.pub.pem `
  --archive /policy-archive
if ($LASTEXITCODE -ne 0) { throw 'Offline audit/replay verification failed' }
Write-Host "`nMilestone 4 verification passed." -ForegroundColor Green
Write-Host "Snapshot left in the audit volume: $snapshot"
Write-Host 'Protect a public key and a witnessed checkpoint independently for a stronger trust model.'
