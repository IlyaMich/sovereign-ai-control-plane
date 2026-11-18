# M6 operator workflow (PowerShell 5.1+). Must be run from repository root.
# Creates a DEVELOPMENT release key outside Git, builds image, signs and activates.
# On future deployments, sign a new generation using --previous-release-id.
[CmdletBinding()]
param(
    [string]$KeyDirectory = "$env:USERPROFILE\.sovereign-ai-control-plane",
    [switch]$UseExistingKey
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not (Test-Path '.env') -or -not (Test-Path '.\deploy\compose.yaml')) {
    throw 'Run from the repository root, with .env and deploy/compose.yaml.'
}
if (-not (Test-Path '.\release-trust')) { New-Item -Type Directory release-trust | Out-Null }
if (-not (Test-Path '.\release-candidates')) { New-Item -Type Directory release-candidates | Out-Null }
if (-not (Test-Path $KeyDirectory)) { New-Item -Type Directory -Force $KeyDirectory | Out-Null }
$privateKey = Join-Path $KeyDirectory 'release-signing-private.pem'
$publicKey = (Join-Path (Resolve-Path .\release-trust).Path 'release-signing.pub.pem')
if (-not (Test-Path $privateKey)) {
    if ($UseExistingKey) { throw 'Existing release signing private key is missing.' }
    Write-Host '[Key] Generate local development-only release key' -ForegroundColor Cyan
    python -m tools.generate_release_key --private-key $privateKey --public-key $publicKey
    if ($LASTEXITCODE -ne 0) { throw 'Key generation failed' }
    Write-Host "Private key stored outside repo: $privateKey" -ForegroundColor Yellow
    Write-Host 'Protect this file using Windows ACLs; production requires HSM/KMS or managed signing.' -ForegroundColor Yellow
}
if (-not (Test-Path $publicKey)) {
    throw 'Trusted release PUBLIC key missing. Provision out-of-band; do not regenerate an existing key.'
}
# Keep an independent public-key copy for future forensic trust anchors.
$pin = Join-Path $KeyDirectory 'pinned-release-public.pem'
if (-not (Test-Path $pin)) { Copy-Item $publicKey $pin }
$pinHash = (Get-FileHash $pin -Algorithm SHA256).Hash
$trustHash = (Get-FileHash $publicKey -Algorithm SHA256).Hash
if ($pinHash -ne $trustHash) { throw 'Public-key pin mismatch; investigate before activating.' }

Write-Host '[1/5] Verify active archived policy' -ForegroundColor Cyan
python -m tools.verify_policy_snapshot
if ($LASTEXITCODE -ne 0) { throw 'Policy snapshot invalid' }

Write-Host '[2/5] Build the M6 control-plane image (do not start it before approval)' -ForegroundColor Cyan
podman compose -f deploy/compose.yaml --env-file .env build control-plane
if ($LASTEXITCODE -ne 0) { throw 'Podman image build failed' }

Write-Host '[3/5] Get artifact digest directly from freshly built image' -ForegroundColor Cyan
$lines = & podman compose -f deploy/compose.yaml --env-file .env `
    run --rm --no-deps --entrypoint python control-plane -m tools.verify_detector_manifest
if ($LASTEXITCODE -ne 0) { throw 'Detector artifact verification failed' }
# The detector tool prints a one-line JSON object. Filter out compose-provider status lines.
$found = @($lines | Where-Object { $_ -match '^\s*\{.*"detector_artifact_digest".*\}\s*$' })
if ($found.Count -ne 1) {
    $lines | ForEach-Object { Write-Host $_ }
    throw 'Cannot safely parse detector manifest. Run tool manually and inspect output.'
}
$manifest = $found[0] | ConvertFrom-Json
if ($manifest.status -ne 'VERIFIED' -or $manifest.detector_artifact_digest -notmatch '^[0-9a-f]{64}$') {
    throw 'Unexpected detector provenance output'
}
$digest = $manifest.detector_artifact_digest
Write-Host "Detector artifact digest: $digest"

Write-Host '[4/5] Sign release using key OUTSIDE runtime container' -ForegroundColor Cyan
$generation = 1
$previous = $null
if (Test-Path '.\release-active\release.json') {
    $current = Get-Content '.\release-active\release.json' -Raw | ConvertFrom-Json
    $generation = [long]$current.payload.generation + 1
    $previous = [string]$current.release_id
}
$candidate = "release-candidates\release-g$generation.json"
if (Test-Path $candidate) { throw "Refusing to overwrite $candidate" }
$arguments = @('-m', 'tools.sign_release', '--private-key', $privateKey,
               '--policy-snapshot', 'policy-active', '--detector-digest', $digest,
               '--generation', "$generation", '--out', $candidate)
if ($previous) { $arguments += @('--previous-release-id', $previous) }
& python @arguments
if ($LASTEXITCODE -ne 0) { throw 'Release signing failed' }

Write-Host '[5/5] Verify signature and activate immutable release' -ForegroundColor Cyan
python -m tools.activate_release --candidate $candidate --detector-digest $digest
if ($LASTEXITCODE -ne 0) { throw 'Release activation failed' }
python -m tools.verify_release
if ($LASTEXITCODE -ne 0) { throw 'Activated release does not verify' }
Write-Host 'Signed approval ready. Start containers WITHOUT rebuilding the image:' -ForegroundColor Green
Write-Host 'podman compose -f deploy/compose.yaml --env-file .env up --no-build --force-recreate -d'
Write-Host 'If using external simulator, add --profile egress-test before up.'
