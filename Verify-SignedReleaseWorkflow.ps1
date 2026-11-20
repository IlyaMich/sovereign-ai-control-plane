# M6: signed release trust + request evidence + portable offline approval authentication.
# Run in repo root after activating a signed release and recreating the deployment.
[CmdletBinding()]
param(
    # Historical audit SQLite snapshots can exceed the default 128 MiB cap.
    # Set explicitly for the exporter AND offline verifier; maximum 1024 MiB.
    [ValidateRange(1, 1024)]
    [int]$EvidenceMaxMiB = 128
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
function Assert-M6([bool]$ok, [string]$message) {
    if (-not $ok) { throw "FAIL: $message" }
    Write-Host "PASS: $message" -ForegroundColor Green
}
$apiLine = Get-Content .env | Where-Object { $_ -match '^CONTROL_PLANE_API_KEY=' } | Select-Object -First 1
if (-not $apiLine) { throw 'No API key in .env' }
$key = $apiLine.Split('=',2)[1].Trim()
$release = Get-Content .\release-active\release.json -Raw | ConvertFrom-Json
$container = (& podman ps --filter 'name=sovereign-ai-control-plane-control-plane-1' --format '{{.ID}}' |
    Where-Object { $_ -and $_.Trim() } | Select-Object -First 1)
if (-not $container) { throw 'No running control-plane container' }
$container = $container.Trim()

Write-Host '[1/5] Signed release matches policy source and approved detector' -ForegroundColor Cyan
python -m tools.verify_release
if ($LASTEXITCODE -ne 0) { throw 'Release validation failed' }
$manifest = (& podman exec $container python -m tools.verify_detector_manifest | ConvertFrom-Json)
if ($LASTEXITCODE -ne 0) { throw 'Detector integrity verification failed' }
Assert-M6 ($manifest.status -eq 'VERIFIED' -and
           $manifest.detector_artifact_digest -eq $release.payload.detector_digest) 'Installed detector is the approved detector'
Assert-M6 ($release.release_id -match '^[0-9a-f]{64}$') 'Release content address is present'

Write-Host '[2/5] Rego unit tests + signed-release readiness' -ForegroundColor Cyan
& podman compose -f deploy/compose.yaml --env-file .env run --rm opa test /policies /policy-tests
if ($LASTEXITCODE -ne 0) { throw 'OPA policy tests failed' }
$ready = Invoke-RestMethod http://127.0.0.1:8000/health/ready
Assert-M6 ($ready.status -eq 'READY') 'Runtime accepted signed policy/detector release'

Write-Host '[3/5] Real decision is bound to approved release' -ForegroundColor Cyan
$body = @{prompt='Explain key rotation in secure systems'; destination_id='sovereign-model'; purpose='GENERAL'} | ConvertTo-Json -Compress
$result = Invoke-RestMethod -Uri http://127.0.0.1:8000/v1/prompts -Method POST `
    -Headers @{'X-API-Key'=$key} -ContentType 'application/json; charset=utf-8' `
    -Body ([System.Text.Encoding]::UTF8.GetBytes($body))
Assert-M6 ($result.status -eq 'COMPLETED') 'Approved request completed'
$history = Invoke-RestMethod -Uri "http://127.0.0.1:8000/v1/requests/$($result.request_id)" `
    -Headers @{'X-API-Key'=$key}
$event = $history.events | Where-Object { $_.event.event_type -eq 'DECISION' } | Select-Object -First 1
Assert-M6 ($null -ne $event -and $event.event.payload.release_evidence_version -eq '1') 'Signed decision contains release approval evidence'
$ref = $event.event.payload.release_snapshot
Assert-M6 ($ref.release_id -eq $release.release_id -and
           $ref.policy_digest -eq $result.decision.policy_digest -and
           $ref.detector_digest -eq $manifest.detector_artifact_digest) 'Audit release identity matches evaluated artifacts'

Write-Host '[4/5] Export portable evidence with signed release archive' -ForegroundColor Cyan
$zip = "/var/lib/sovereign/m6-evidence-$([guid]::NewGuid().ToString('N').Substring(0,8)).zip"
& podman exec $container python -m tools.export_evidence_package --out $zip --max-uncompressed-mib $EvidenceMaxMiB
if ($LASTEXITCODE -ne 0) { throw 'Evidence export failed' }

Write-Host '[5/5] Network-disabled offline review using OUT-OF-BUNDLE release trust root' -ForegroundColor Cyan
& podman compose -f deploy/compose.yaml --env-file .env --profile audit-review `
    run --build --rm --entrypoint python audit-reviewer -m tools.verify_evidence_package `
    --bundle $zip --trusted-release-public-key /release-trust/release-signing.pub.pem `
    --max-uncompressed-mib $EvidenceMaxMiB
if ($LASTEXITCODE -ne 0) { throw 'Offline signed-release verification failed' }
Write-Host 'PASS: Milestone 6 workflow completed' -ForegroundColor Green
Write-Host "Evidence ZIP retained in audit volume: $zip"
Write-Host 'The release signer is independently pinned relative to ZIP; audit key/checkpoint still require separate anchors.'
