# Fresh-install reviewer launcher. Requires Windows PowerShell and Python 3.12+.
# Never use this on an existing deployment: it refuses .env and .runtime.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $ReleaseTag,

    [Parameter(Mandatory = $true)]
    [string] $TrustedKeySha256,

    [Parameter(Mandatory = $true)]
    [string] $RegistrySha256,

    [string] $Project = 'sovereign-review',
    [ValidateRange(1, 65535)]
    [int] $ApiPort = 8000
)

$ErrorActionPreference = 'Stop'
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
    & $python.Source -m tools.submission_bootstrap `
        --release-tag $ReleaseTag `
        --trusted-key-sha256 $TrustedKeySha256 `
        --registry-sha256 $RegistrySha256 `
        --project $Project `
        --api-port $ApiPort `
        --root $PSScriptRoot

    if ($LASTEXITCODE -ne 0) {
        throw "Reviewer bootstrap failed (exit code $LASTEXITCODE). Check the message above."
    }
}
finally {
    Pop-Location
}
