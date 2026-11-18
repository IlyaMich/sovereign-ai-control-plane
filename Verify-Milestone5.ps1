# Milestone 5: detector provenance + portable signed evidence (PowerShell 5.1+)
# Run in repo root after: podman compose -f deploy/compose.yaml --env-file .env up --build --force-recreate -d
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-M5([bool]$ok, [string]$message) {
    if (-not $ok) { throw "FAIL: $message" }
    Write-Host "PASS: $message" -ForegroundColor Green
}
if (-not (Test-Path '.env') -or -not (Test-Path '.\deploy\compose.yaml')) {
    throw 'Run from the repository root with .env and deploy/compose.yaml present.'
}
$line = Get-Content .env | Where-Object { $_ -match '^CONTROL_PLANE_API_KEY=' } | Select-Object -First 1
if (-not $line) { throw 'Missing CONTROL_PLANE_API_KEY' }
$key = $line.Split('=',2)[1].Trim()
$container = (& podman ps --filter 'name=sovereign-ai-control-plane-control-plane-1' --format '{{.ID}}' |
    Where-Object { $_ -and $_.Trim() } | Select-Object -First 1)
if (-not $container) { throw 'Control-plane container is not running.' }
$container = $container.Trim()

Write-Host "`n[1/5] Installed model and detector source provenance" -ForegroundColor Cyan
$inspection = & podman exec $container python -m tools.verify_detector_manifest
if ($LASTEXITCODE -ne 0) { throw 'Detector artifact manifest mismatch' }
$detector = $inspection | ConvertFrom-Json
Assert-M5 ($detector.status -eq 'VERIFIED') 'Build-time detector manifest matches installed artifacts'
$expectedDigest = $detector.detector_artifact_digest
Assert-M5 ($expectedDigest -match '^[0-9a-f]{64}$') 'Detector artifact digest is content-addressed'
Write-Host "Detector artifact digest: $expectedDigest"

Write-Host "`n[2/5] Rego regression and readiness" -ForegroundColor Cyan
& podman compose -f deploy/compose.yaml --env-file .env run --rm opa test /policies /policy-tests
if ($LASTEXITCODE -ne 0) { throw 'Rego test suite failed' }
$ready = Invoke-RestMethod 'http://127.0.0.1:8000/health/ready'
Assert-M5 ($ready.status -eq 'READY') 'Control plane policy, detector and audit readiness'

Write-Host "`n[3/5] Real Presidio classification and signed evidence" -ForegroundColor Cyan
$body = @{prompt='Explain why idempotent requests matter'; destination_id='sovereign-model'; purpose='GENERAL'} | ConvertTo-Json -Compress
$response = Invoke-RestMethod -Uri 'http://127.0.0.1:8000/v1/prompts' -Method POST `
    -Headers @{'X-API-Key'=$key} -ContentType 'application/json; charset=utf-8' `
    -Body ([System.Text.Encoding]::UTF8.GetBytes($body))
Assert-M5 ($response.status -eq 'COMPLETED' -and $response.decision.effect -eq 'PERMIT') 'Authorized local request completed'
Assert-M5 ($response.classification.artifact_digest -eq $expectedDigest) 'Classification identifies exact installed detector manifest'
Assert-M5 ($response.decision.policy_digest -match '^[0-9a-f]{64}$') 'OPA content-bound policy identity retained'
$history = Invoke-RestMethod -Uri "http://127.0.0.1:8000/v1/requests/$($response.request_id)" `
    -Headers @{'X-API-Key'=$key}
$event = $history.events | Where-Object { $_.event.event_type -eq 'DECISION' } | Select-Object -First 1
Assert-M5 ($null -ne $event -and $event.event.payload.detector_evidence_version -eq '1') 'Signed decision contains Milestone 5 detector evidence'
Assert-M5 ($event.event.payload.detector_snapshot.sha256 -eq $expectedDigest) 'Signed evidence binds detector artifact identity'

Write-Host "`n[4/5] Create consistent portable evidence ZIP" -ForegroundColor Cyan
$package = "/var/lib/sovereign/m5-evidence-$([guid]::NewGuid().ToString('N').Substring(0,8)).zip"
& podman exec $container python -m tools.export_evidence_package --out $package
if ($LASTEXITCODE -ne 0) { throw 'Portable evidence export failed' }
Write-Host "Evidence ZIP in audit volume: $package"

Write-Host "`n[5/5] Offline, network-disabled evidence replay" -ForegroundColor Cyan
& podman compose -f deploy/compose.yaml --env-file .env --profile audit-review `
    run --build --rm --entrypoint python audit-reviewer `
    -m tools.verify_evidence_package --bundle $package
if ($LASTEXITCODE -ne 0) { throw 'Offline evidence verification failed' }
Write-Host "`nMilestone 5 provenance and portable evidence checks passed." -ForegroundColor Green
Write-Host 'The verifier proves package SELF-CONSISTENCY until a separately trusted public key is supplied.'
Write-Host "Bundle retained at $package inside the audit volume. Protect any exported copy."
Write-Host 'Do not treat detection as replayed: no raw prompts or model weights are included.'
