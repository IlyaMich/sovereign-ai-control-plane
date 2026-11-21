# Reviewer bootstrap from signed GHCR images (Windows + Podman or Docker)

This is the **fresh-host** path for the home-assignment submission, not a migration
or an upgrade to any existing installation. It installs a published signed release
without rebuilding the detector, OPA, or reviewer images.

## Prerequisites and trust handoff

The reviewer needs:

- Windows PowerShell, **Python 3.12+** (standard library only), Podman Desktop
  with a running Podman machine and Compose provider, or Docker Desktop with
  Linux containers and Docker Compose v2. Podman remains the validated default;
  Docker support requires a separate real-host acceptance run.
- A checkout of this repository. A **full source build is not required**.
- Access to the signed GitHub Release and all three GHCR images (ideally publicly
  readable, without GitHub authentication).
- A reviewed `deploy/submission-lock.json` supplied with the submission,
  containing the exact published `signed-gN` tag, the independently trusted
  SHA-256 fingerprint of `release-signing.pub.pem`, and the SHA-256 checksum of
  the release's `registry-images.json`.

The lock file is **not generated from untrusted downloaded content during
installation**. The assignment author must prepare it after publication and give
the reviewer a trustworthy reference (for example, a reviewed Git commit and
separately communicated signing-key fingerprint). The checked-in
[`submission-lock.example.json`](../deploy/submission-lock.example.json) is
only a template, and its placeholders are not usable. The SHA-256 of the image
manifest pins the exact three OCI image references, because the Ed25519
release approval itself signs the detector/policy identities, **not** the OCI digests.

### Author: prepare the final lock after a successful signed release

1. Finish and merge the intended source changes; run the
   [manual signed release process](ci-and-reproducibility.md) with the protected
   signer. Check that **all three images** and the `signed-gN` release exist.
2. Download `registry-images.json` from the exact release and calculate its
   SHA-256. Independently retrieve and validate the expected signing public-key
   fingerprint from the *trusted release authority*, not from the same unsigned
   download you intend to check. Verify the signed release and the image/detector
   identities using the operator tools before declaring the release ready.
3. Create `deploy/submission-lock.json` using the template, filling the tag and
   lowercase 64-character SHA-256 values. Commit it, record that commit for the
   submission, and communicate the trust fingerprint independently.
4. Test **anonymous** pullability on another machine or an uncredentialed Podman
   installation:
   ```powershell
   podman logout ghcr.io
   podman pull 'ghcr.io/ilyamich/sovereign-ai-control-plane@sha256:<approved-digest>'
   podman pull 'ghcr.io/ilyamich/sovereign-ai-control-plane-audit-reviewer@sha256:<approved-digest>'
   podman pull 'ghcr.io/ilyamich/sovereign-ai-control-plane-opa@sha256:<approved-digest>'
   ```
   Copy the exact `pull_by_digest` values from `registry-images.json`; the
   placeholders above are not working digests. Check the registry package
   visibility if anonymous pulls fail. The release workflow may not have
   completed successfully merely because a manifest digest was recorded.

The release publishing workflow requires a protected signer, configured
approval environment, independent trust material and N+1 predecessor history;
the bootstrap **does not** attempt to reproduce that privileged process.

## Reviewer: install in an empty checkout

Clone or extract the submitted repository, start the selected local engine,
and from the checkout root run (Podman is the default):

```powershell
.\bootstrap.ps1
```

For Docker Desktop in Linux-container mode, verify `docker info` and
`docker compose version`, then run:

```powershell
.\bootstrap.ps1 -Engine docker
```

Use a local Docker Desktop context with access to the checkout's host paths,
not a remote daemon. Do not reuse an existing installation's state or volumes.
Both engines use the same signed release and images.

By default this starts five containers: control plane, OPA, sovereign model,
egress gateway and external simulator. The last two are local, isolated
simulation services, not a real external provider. No external API key is needed.
The bootstrap enables the `egress-test` profile and sets
`ENABLE_EXTERNAL_SIMULATOR=true` only for the reviewer environment.

For the three-container sovereign-only deployment, use:

```powershell
.\bootstrap.ps1 -SovereignOnly
```

Combine both options with `.\bootstrap.ps1 -Engine docker -SovereignOnly`.

The standard development configuration remains opt-in for external simulation.

If the final lock was handed off separately and has not yet been checked in,
run with its three explicit values:

```powershell
.\bootstrap.ps1 -ReleaseTag signed-gN `
  -TrustedKeySha256 '<trusted-public-key-sha256>' `
  -RegistrySha256 '<registry-manifest-sha256>'
```

The script does the following, in order:

1. Refuses to proceed when `.env` or `.runtime` already exists; checks the selected engine
   and Compose rather than modifying an existing deployment.
2. Downloads only `release-state.tar.gz` and `registry-images.json` from the
   named GitHub Release (not the multi-GB image tarballs).
3. Bounds and safely extracts the release state in a temporary staging folder.
   Checks the independently pinned public-key fingerprint and the exact
   `registry-images.json` SHA-256; validates its three GHCR digest references
   and the signed release metadata's release ID and generation.
4. Pulls the three OCI images by immutable digest. Runs the offline release
   verifier in the prebuilt **reviewer container**, checks the application
   detector manifest against the signed approval, and checks image source
   revision labels against the image metadata.
5. Initializes a *fresh* Git-ignored `.runtime` from the signed public state.
   Creates a distinct `.env` with a randomly generated API key, signed policy
   revision, loopback-only API port and pinned image references. No release
   private key is created, copied or needed.
6. Starts both Compose files with `up --no-build` and, by default, the
   `egress-test` profile. Waits for authenticated API readiness. In full demo
   mode, sends one synthetic public request through the external simulator and
   requires a completed response from that destination. This creates audit events
   before the manual Postman demo.

Default Compose project is `sovereign-review`, host API is
`http://127.0.0.1:8000`. For another isolated name/port, use
`-Project review-example -ApiPort 8001`. The API key is stored in the
Git-ignored `.env`; do not send it to the assignment reviewer logs.

The reviewer can inspect the running services and test the API. Set `$engine`
to `podman` or `docker` to match the bootstrap selection:

```powershell
$engine = 'podman' # use 'docker' for Docker installations
& $engine compose -p sovereign-review -f deploy/compose.yaml `
  -f deploy/compose.ghcr.yaml --env-file .env --profile egress-test ps

$key = (Get-Content .env | Select-String '^CONTROL_PLANE_API_KEY=').ToString().Split('=',2)[1]
Invoke-RestMethod http://127.0.0.1:8000/health/ready `
  -Headers @{'X-API-Key'=$key}
```

For the full seven-case demo, import the [Postman collection](../deploy/postman/sovereign-demo.postman_collection.json) and [environment](../deploy/postman/sovereign-local.postman_environment.json). Select the environment and set its local `apiKey` from `.env`; never share it. Send each POST followed by its paired audit GET. In sovereign-only mode, run cases 01–03 only. Omit the profile from lifecycle commands for that mode.

For synthetic permit/deny demonstrations see
[submission reviewer walkthrough](submission-reviewer-guide.md). Never submit
real personal data, credentials or private keys to the simulator.

To stop without deleting the isolated audit volume:

```powershell
$engine = 'podman' # use 'docker' for Docker installations
& $engine compose -p sovereign-review -f deploy/compose.yaml `
  -f deploy/compose.ghcr.yaml --env-file .env --profile egress-test down
```

**Never** use `down -v`, delete `.runtime`, or rerun the fresh bootstrap over
an installed deployment. The audit database lives in a named container-engine volume.
The installation intentionally fails rather than reset or replace history.
Use the existing operator documentation for upgrades and migrations.

## Failure cases and limitations

- **404 / GHCR manifest unknown / unauthorized:** the exact image may not have
  been published, may have been removed, or may not be public. Verify release
  assets and package visibility; do not replace a digest with `:latest`.
- **Registry manifest checksum or public-key fingerprint differs:** stop and
  investigate the independent handoff, instead of trusting the downloaded key
  or disabling signatures.
- **Detector identity differs:** the signed release does not authorize the
  pulled image. Do not rebuild after approval or disable signed-release checks.
- **Readiness fails:** preserve `.runtime`, `.env`, the images and the audit
  volume. Inspect Compose logs and the expected revision before taking action.
- **Platform mismatch:** images published by the current workflow are built
  on Linux x86-64; arm64 reviewers may need x86-64 emulation or a separately
  reviewed multi-architecture release.
- **Trust boundary:** pinned GitHub release metadata plus verified Ed25519
  approval establish the selected artifact identity only under the trust
  assumptions of the reviewed checkout, pinned key and GHCR. This does not
  provide hardware attestation, independent audit-history witnessing, or
  real-world geographic residency assurances.

### Export and verify evidence with the selected engine

After the Postman cases, use the same engine, Compose project and port as
the installation. The examples below use the default project and full mode:

```powershell
$engine = 'docker' # or 'podman'
$composeArgs = @(
    '-p', 'sovereign-review',
    '-f', 'deploy/compose.yaml',
    '-f', 'deploy/compose.ghcr.yaml',
    '--env-file', '.env',
    '--profile', 'egress-test'
)
$zip = "/var/lib/sovereign/demo-evidence.zip"
& $engine compose @composeArgs exec -T control-plane `
    python -m tools.export_evidence_package --out $zip
& $engine compose @composeArgs --profile audit-review `
    run --rm --entrypoint python audit-reviewer `
    -m tools.verify_evidence_package --bundle $zip `
    --trusted-release-public-key /release-trust/release-signing.pub.pem
$container = (& $engine compose @composeArgs ps -q control-plane |
    Select-Object -First 1).Trim()
& $engine cp "${container}:${zip}" ./demo-evidence.zip
```

Omit the egress profile for sovereign-only installations. These commands use
prebuilt images and preserve the audit volume. Existing source-build and operator
PowerShell scripts remain Podman-oriented; do not use them as Docker migration tools.

### Source-build fallback

If the signed GHCR release is unavailable and the reviewer intentionally wants
a **different independently initialized local release**, follow the
[fresh-install reviewer guide](submission-reviewer-guide.md), using its own
signer directory and image-build path. Never use the repository's historical
generation-7 example as active release state.

### Validation status

The installer has offline unit tests for package path safety, digest-reference
validation and fresh environment generation. **Passing these tests is not
evidence of a successful real clean-host installation.** Before submission,
record a fresh Windows execution for each claimed engine, release tag, image digests,
detector/policy identity, readiness and synthetic smoke-test results in the
[submission evidence matrix](submission-evidence.md).
