# Fresh-install reviewer launcher. Requires Windows PowerShell and Python 3.12+.
# Never use this on an existing deployment: it refuses .env and .runtime.
[CmdletBinding()]
param(
    [string] $ReleaseTag,

    [string] $TrustedKeySha256,

    [string] $RegistrySha256,

    [string] $Project = 'sovereign-review',
    [ValidateRange(1, 65535)]
    [int] $ApiPort = 8000,
    [switch] $SovereignOnly,
    [ValidateSet('podman', 'docker')]
    [string] $Engine = 'podman'
)

$ErrorActionPreference = 'Stop'
$lockPath = Join-Path $PSScriptRoot 'deploy/submission-lock.json'
if (Test-Path -LiteralPath $lockPath -PathType Leaf) {
    $lock = Get-Content -LiteralPath $lockPath -Raw | ConvertFrom-Json
    if (-not $ReleaseTag) { $ReleaseTag = $lock.release_tag }
    if (-not $TrustedKeySha256) { $TrustedKeySha256 = $lock.trusted_key_sha256 }
    if (-not $RegistrySha256) { $RegistrySha256 = $lock.registry_sha256 }
}
if (-not $ReleaseTag -or -not $TrustedKeySha256 -or -not $RegistrySha256) {
    throw 'Supply -ReleaseTag, -TrustedKeySha256 and -RegistrySha256, or provide a reviewed deploy/submission-lock.json.'
}
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    throw 'Python 3.12+ is required. Install Python and reopen PowerShell.'
}

& $python.Source -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)'
if ($LASTEXITCODE -ne 0) {
    throw 'The python command must resolve to Python 3.12 or newer.'
}

Push-Location $PSScriptRoot
try {
    $modeArgs = @()
    if ($SovereignOnly) { $modeArgs += '--sovereign-only' }
    & $python.Source -m tools.submission_bootstrap `
        --release-tag $ReleaseTag `
        --trusted-key-sha256 $TrustedKeySha256 `
        --registry-sha256 $RegistrySha256 `
        --project $Project `
        --engine ($Engine.ToLowerInvariant()) `
        --api-port $ApiPort `
        --root $PSScriptRoot @modeArgs

    if ($LASTEXITCODE -ne 0) {
        throw "Reviewer bootstrap failed (exit code $LASTEXITCODE). Check the message above."
    }
}
finally {
    Pop-Location
}
