# Sovereign AI Control Plane - Milestone 3 end-to-end security validation
# Run from the repository root (PowerShell 5.1+).
# Prerequisites: podman compose --profile egress-test up -d; ENABLE_EXTERNAL_SIMULATOR=true
# Only synthetic prompt data. Stops and restarts egress-gateway for one failure test.
[CmdletBinding()]
param(
    [switch]$SkipGatewayOutage,
    [switch]$InfrastructureOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "FAIL: $Message" }
    Write-Host "PASS: $Message" -ForegroundColor Green
}

function Invoke-TestPrompt {
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [Parameter(Mandatory)][string]$Destination,
        [string]$Purpose = 'GENERAL'
    )
    $body = @{ prompt = $Prompt; destination_id = $Destination; purpose = $Purpose } | ConvertTo-Json -Compress
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($body)
    try {
        $payload = Invoke-RestMethod -Uri 'http://127.0.0.1:8000/v1/prompts' -Method POST `
            -Headers @{ 'X-API-Key' = $script:apiKey } -ContentType 'application/json; charset=utf-8' `
            -Body $bytes -ErrorAction Stop
        return [pscustomobject]@{ Code = 200; Body = $payload }
    }
    catch {
        $resp = $_.Exception.Response
        if (-not $resp) { throw }
        $code = [int]$resp.StatusCode
        $raw = $_.ErrorDetails.Message
        if (-not $raw -and $resp -is [System.Net.HttpWebResponse]) {
            $reader = [System.IO.StreamReader]::new($resp.GetResponseStream())
            try { $raw = $reader.ReadToEnd() }
            finally { $reader.Dispose() }
        }
        if (-not $raw) { throw }
        return [pscustomobject]@{ Code = $code; Body = ($raw | ConvertFrom-Json) }
    }
}

function Get-AuditHistory([string]$RequestId) {
    return Invoke-RestMethod -Uri "http://127.0.0.1:8000/v1/requests/$RequestId" `
        -Headers @{ 'X-API-Key' = $script:apiKey }
}

function Get-ShaPrefix([string]$Text) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $digest = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text)) }
    finally { $sha.Dispose() }
    return [BitConverter]::ToString($digest).Replace('-', '').ToLowerInvariant().Substring(0, 16)
}

if (-not (Test-Path '.\deploy\compose.yaml') -or -not (Test-Path '.\.env')) {
    throw 'Run from the repository root, with deploy/compose.yaml and .env present.'
}
$apiKeyLine = Get-Content '.env' | Where-Object { $_ -match '^CONTROL_PLANE_API_KEY=' } | Select-Object -First 1
if (-not $apiKeyLine) { throw 'Missing CONTROL_PLANE_API_KEY in .env' }
$script:apiKey = $apiKeyLine.Split('=',2)[1].Trim()
$externalLine = Get-Content '.env' | Where-Object { $_ -match '^ENABLE_EXTERNAL_SIMULATOR=' } | Select-Object -First 1
if (-not $externalLine -or $externalLine.Split('=',2)[1].Trim().ToLowerInvariant() -ne 'true') {
    throw 'Set ENABLE_EXTERNAL_SIMULATOR=true in .env and start the egress-test profile first.'
}
$compose = @('compose', '-f', 'deploy/compose.yaml', '--env-file', '.env')
$composeWithProfile = @('compose', '-f', 'deploy/compose.yaml', '--env-file', '.env', '--profile', 'egress-test')

if (-not $InfrastructureOnly) {
Write-Host "`n[1/5] Redaction and expected forwarded payload digest" -ForegroundColor Cyan
$original = 'Please contact demo@example.com about the project'
$redacted = 'Please contact [REDACTED_EMAIL_ADDRESS] about the project'
$result = Invoke-TestPrompt -Prompt $original -Destination 'external-simulator'
Assert-True ($result.Code -eq 200 -and $result.Body.status -eq 'COMPLETED') 'Synthetic external redaction request completes'
Assert-True ($result.Body.classification.status -eq 'PRIVATE') 'Original prompt classified PRIVATE'
Assert-True ($result.Body.decision.effect -eq 'PERMIT') 'OPA permitted the authorized obligation plan'
Assert-True ($result.Body.decision.policy_revision -eq 'redaction-baseline-v3') 'M3 policy revision is active'
Assert-True ($result.Body.decision.obligations.Count -eq 2 -and
             $result.Body.decision.obligations[0].type -eq 'REDACT' -and
             $result.Body.decision.obligations[1].type -eq 'ROUTE') 'REDACT precedes ROUTE'
Assert-True ($result.Body.model_id -eq 'external-simulator') 'Destination is the external simulator'
$expectedPrefix = Get-ShaPrefix $redacted
$originalPrefix = Get-ShaPrefix $original
Assert-True ($expectedPrefix -ne $originalPrefix) 'Original and redacted prompts have distinct digests'
Assert-True ($result.Body.output -match [regex]::Escape($expectedPrefix)) 'External simulator output matches redacted prompt hash prefix'
Assert-True ($result.Body.output -notmatch [regex]::Escape($originalPrefix)) 'External simulator output does not match original prompt prefix'
Write-Host "  Redacted SHA-256 prefix: $expectedPrefix"

Write-Host "`n[2/5] Decision and transformation audit metadata" -ForegroundColor Cyan
$history = Get-AuditHistory $result.Body.request_id
$decision = $history.events | Where-Object { $_.event.event_type -eq 'DECISION' } | Select-Object -First 1
$outcome = $history.events | Where-Object { $_.event.event_type -eq 'OUTCOME' } | Select-Object -First 1
Assert-True ($null -ne $decision -and $null -ne $outcome) 'Both decision and outcome events exist'
$transform = $decision.event.payload.transformation
Assert-True ($transform.applied -eq $true) 'Transformation marked applied in durable evidence'
Assert-True ($transform.verification.status -eq 'NO_PRIVATE_DETECTED') 'Post-redaction verification reported no private data'
Assert-True ($transform.output_hmac_sha256 -and
             $transform.output_hmac_sha256 -ne $decision.event.payload.input_hmac_sha256) 'Original and transformed input fingerprints differ'
Assert-True ($outcome.event.payload.execution_status -eq 'COMPLETED' -and
             $outcome.event.payload.transformed -eq $true) 'Execution outcome records transformed delivery'
$serialized = $history | ConvertTo-Json -Depth 40 -Compress
Assert-True (-not $serialized.Contains('demo@example.com')) 'Raw synthetic email is absent from audit response'
Assert-True ($result.Body.decision_receipt.sequence -lt $result.Body.outcome_receipt.sequence) 'Decision event precedes outcome'

Write-Host "`n[3/5] Denial behavior" -ForegroundColor Cyan
$badDestination = Invoke-TestPrompt -Prompt 'Explain TLS' -Destination 'external-model'
Assert-True ($badDestination.Code -eq 403 -and $badDestination.Body.status -eq 'BLOCKED') 'Unregistered destination is blocked'
Assert-True ($null -eq $badDestination.Body.model_id) 'Unregistered destination was not invoked'
$credential = Invoke-TestPrompt -Prompt '-----BEGIN PRIVATE KEY-----' -Destination 'external-simulator'
Assert-True ($credential.Code -eq 403 -and $credential.Body.decision.effect -eq 'DENY') 'Credentials cannot use external route'
Assert-True ($credential.Body.decision.reason_codes -contains 'CREDENTIAL_BLOCKED') 'Credential-specific denial reason is retained'
$purpose = Invoke-TestPrompt -Prompt 'Explain TLS' -Destination 'external-simulator' -Purpose 'EXPORT'
Assert-True ($purpose.Code -eq 403 -and $purpose.Body.decision.effect -eq 'DENY') 'Unapproved purpose is denied'

} else {
    Write-Host 'Skipping groups 1-3; resuming at network isolation.' -ForegroundColor Yellow
}

Write-Host "`n[4/5] Network boundary: direct external-simulator connection" -ForegroundColor Cyan
# `podman compose ps -q` can produce no ID with certain external Compose
# providers even while the container is running. Query the Podman runtime.
$container = (& podman ps --filter 'name=sovereign-ai-control-plane-control-plane-1' --format '{{.ID}}' |
    Where-Object { $_ -and $_.Trim() } | Select-Object -First 1)
if (-not $container) {
    $container = (& podman ps --filter 'label=com.docker.compose.project=sovereign-ai-control-plane' `
        --filter 'label=com.docker.compose.service=control-plane' --format '{{.ID}}' |
        Where-Object { $_ -and $_.Trim() } | Select-Object -First 1)
}
if (-not $container) {
    throw 'Could not identify a running control-plane container with podman ps. Run: podman ps --format "table {{.Names}}\t{{.ID}}"'
}
$container = $container.Trim()
Write-Host "Using control-plane container ID: $container"
@'
import socket
try:
    s = socket.create_connection(('external-simulator', 9000), timeout=2.0)
    s.close()
except (OSError, TimeoutError):
    print('PASS: direct external-simulator TCP connection unavailable')
else:
    print('FAIL: direct external-simulator TCP connection succeeded')
    raise SystemExit(2)
'@ | & podman exec -i $container python -
if ($LASTEXITCODE -ne 0) { throw 'Network isolation test failed' }

if (-not $SkipGatewayOutage) {
    Write-Host "`n[5/5] Egress gateway outage (will restart gateway automatically)" -ForegroundColor Cyan
    $stopped = $false
    try {
        & podman @composeWithProfile stop egress-gateway
        if ($LASTEXITCODE -ne 0) { throw 'Could not stop egress-gateway' }
        $stopped = $true
        $unavailable = Invoke-TestPrompt -Prompt 'Explain local audit chaining' -Destination 'external-simulator'
        Assert-True ($unavailable.Code -eq 502 -and $unavailable.Body.status -eq 'ERROR') 'Gateway outage cannot produce COMPLETED'
        Assert-True ($null -eq $unavailable.Body.model_id) 'Gateway outage does not return an unauthorized fallback model'
        $outageHistory = Get-AuditHistory $unavailable.Body.request_id
        $outcomeEvent = $outageHistory.events | Where-Object { $_.event.event_type -eq 'OUTCOME' } | Select-Object -First 1
        Assert-True ($outcomeEvent.event.payload.execution_status -eq 'UNKNOWN') 'Ambiguous model execution recorded as UNKNOWN'
    }
    finally {
        if ($stopped) {
            & podman @composeWithProfile start egress-gateway
            if ($LASTEXITCODE -ne 0) { throw 'Failed to restart egress-gateway; start it manually.' }
            Write-Host 'Egress gateway restarted' -ForegroundColor Yellow
        }
    }
    $recovered = $false
    for ($attempt=0; $attempt -lt 10; $attempt++) {
        Start-Sleep -Seconds 1
        $healthy = Invoke-TestPrompt -Prompt 'Explain request signing' -Destination 'external-simulator'
        if ($healthy.Code -eq 200 -and $healthy.Body.status -eq 'COMPLETED') {
            $recovered = $true
            break
        }
    }
    Assert-True $recovered 'External simulator route recovers after restart'
} else {
    Write-Host "`n[5/5] Gateway outage skipped via -SkipGatewayOutage" -ForegroundColor Yellow
}

Write-Host "`n[Audit] Consistent snapshot and cryptographic chain verification" -ForegroundColor Cyan
$testDir = "/tmp/m3-security-$([guid]::NewGuid().ToString('N').Substring(0,8))"
@'
import os
import sqlite3
from pathlib import Path
folder = Path(os.environ['AUDIT_TEST_DIR'])
folder.mkdir(parents=True, exist_ok=True)
with sqlite3.connect('/var/lib/sovereign/audit.sqlite') as source:
    with sqlite3.connect(str(folder / 'snapshot.sqlite')) as target:
        source.backup(target)
print('Audit snapshot created')
'@ | & podman exec -i -e "AUDIT_TEST_DIR=$testDir" $container python -
if ($LASTEXITCODE -ne 0) { throw 'SQLite snapshot operation failed' }
& podman exec $container python -m tools.verify_audit `
    --db "$testDir/snapshot.sqlite" --public-key /var/lib/sovereign/audit-key.pub.pem
if ($LASTEXITCODE -ne 0) { throw 'Independent audit integrity verification failed' }
& podman exec $container python -m tools.export_checkpoint `
    --db "$testDir/snapshot.sqlite" --public-key /var/lib/sovereign/audit-key.pub.pem `
    --out "$testDir/checkpoint.json"
if ($LASTEXITCODE -ne 0) { throw 'Checkpoint export failed' }
& podman exec $container python -m tools.verify_audit `
    --db "$testDir/snapshot.sqlite" --public-key /var/lib/sovereign/audit-key.pub.pem `
    --checkpoint "$testDir/checkpoint.json"
if ($LASTEXITCODE -ne 0) { throw 'Checkpoint verification failed' }
Write-Host 'PASS: Audit snapshot, chain and checkpoint verified' -ForegroundColor Green

Write-Host "`nMilestone 3 checks passed (executed groups: $(if ($InfrastructureOnly) {'4, 5, audit'} else {'1, 2, 3, 4, 5, audit'}))." -ForegroundColor Green
Write-Host "Snapshot retained at $testDir/snapshot.sqlite (inside control-plane container)."
Write-Host "Checkpoint retained at $testDir/checkpoint.json (inside control-plane container)."
Write-Host 'For independent protection, copy checkpoint and public key to a location outside the audit container.' 
