# Reviewer bootstrap from signed GHCR images (Windows + Podman)

This is the **fresh-host** path for the home-assignment submission, not a migration
or an upgrade to any existing installation. It installs a published signed release
without rebuilding the detector, OPA, or reviewer images.

## Prerequisites and trust handoff

The reviewer needs:

- Windows PowerShell, **Python 3.12+** (standard library only), Podman Desktop
  with a running Podman machine, and a working Compose provider.
- A checkout of this repository. A **full source build is not required**.
- Access to the signed GitHub Release and all three GHCR images (ideally publicly
  readable, without GitHub authentication).
- A reviewed `deploy/submission-lock.json` supplied with the submission,
  containing the exact published `signed-gN` tag, signed release ID,
  independently trusted SHA-256 fingerprint of `release-signing.pub.pem`, and
  the three immutable `ghcr.io/...@sha256:...` image references.

The lock file is **not generated from untrusted downloaded content during
installation**. The assignment author must prepare it after publication and give
the reviewer a trustworthy reference (for example, a reviewed Git commit and
separately communicated signing-key fingerprint). The checked-in
[`submission-lock.example.json`](../deploy/submission-lock.example.json) is
only a template, and its placeholders are not usable. The reviewed lock directly
pins all three OCI images, since the Ed25519 approval signs the detector/policy
identities, **not** the OCI manifest digests. Downloaded `registry-images.json`
must agree with the trusted lock; it is not a trust anchor by itself.

### Author: prepare the final lock after a successful signed release

1. Finish and merge the intended source changes; run the
   [manual signed release process](ci-and-reproducibility.md) with the protected
   signer. Check that **all three images** and the `signed-gN` release exist.
2. Retrieve `registry-images.json` and the signed approval from the exact release.
   Independently validate the expected signing public-key fingerprint against
   the *trusted release authority*, not the downloaded file alone. Verify the
   signed release and installed detector identity before declaring the release ready.
3. Create `deploy/submission-lock.json` using the template. Record the tag,
   exact signed `release_id`, trusted public-key SHA-256 fingerprint, and all
   three immutable `pull_by_digest` values from the verified image metadata.
   Commit it, record that commit for the submission, and communicate trust
   independently. The reviewed checkout/lock must be trusted; do not derive a
   new lock from freshly downloaded untrusted assets during installation.
4. Test **anonymous** pullability on another machine or an uncredentialed Podman
   installation:
   ```powershell
   podman logout ghcr.io
   podman pull 'ghcr.io/ilyamich/sovereign-ai-control-plane@sha256:<approved-digest>'
   podman pull 'ghcr.io/ilyamich/sovereign-ai-control-plane-audit-reviewer@sha256:<approved-digest>'
   podman pull 'ghcr.io/ilyamich/sovereign-ai-control-plane-opa@sha256:<approved-digest>'
   ```
   Use the exact reviewed image references from `deploy/submission-lock.json`; the
   placeholders above are not working digests. Check the registry package
   visibility if anonymous pulls fail. The release workflow may not have
   completed successfully merely because a manifest digest was recorded.

The release publishing workflow requires a protected signer, configured
approval environment, independent trust material and N+1 predecessor history;
the bootstrap **does not** attempt to reproduce that privileged process.

## Reviewer: install in an empty checkout

Clone or extract the submitted repository, ensure that the Podman machine is
running, and from the checkout root run:

```powershell
.\bootstrap.ps1
```

If the final reviewed lock was handed off separately, point to that JSON file:

```powershell
.\bootstrap.ps1 -LockFile 'C:\trusted-handoff\submission-lock.json'
```

The script does the following, in order:

1. Refuses to proceed when `.env` or `.runtime` already exists; checks Podman
   and Compose rather than modifying an existing deployment.
2. Downloads only `release-state.tar.gz` and `registry-images.json` from the
   named GitHub Release (not the multi-GB image tarballs).
3. Bounds and safely extracts the release state in a temporary staging folder.
   Checks the independently pinned public-key fingerprint, signed release ID
   and generation. Compares every published image reference with the three
   immutable OCI digests in the trusted submission lock.
4. Pulls the three OCI images by immutable digest. Runs the offline release
   verifier in the prebuilt **reviewer container**, checks the application
   detector manifest against the signed approval, and checks image source
   revision labels against the image metadata.
5. Initializes a *fresh* Git-ignored `.runtime` from the signed public state.
   Creates a distinct `.env` with a randomly generated API key,
   loopback-only API port and pinned image references. No release
   private key is created, copied or needed.
6. Starts `deploy/compose.yaml` **with** `deploy/compose.ghcr.yaml` and
   `up --no-build`. Waits for authenticated API readiness.

Default Compose project is `sovereign-review`, host API is
`http://127.0.0.1:8000`. For another isolated name/port, use
`-Project review-example -ApiPort 8001`. The API key is stored in the
Git-ignored `.env`; do not send it to the assignment reviewer logs.

The reviewer can inspect the running services and test the API:

```powershell
podman compose -p sovereign-review -f deploy/compose.yaml `
  -f deploy/compose.ghcr.yaml --env-file .env ps

$key = (Get-Content .env | Select-String '^CONTROL_PLANE_API_KEY=').ToString().Split('=',2)[1]
Invoke-RestMethod http://127.0.0.1:8000/health/ready `
  -Headers @{'X-API-Key'=$key}
```

For synthetic permit/deny demonstrations see
[submission reviewer walkthrough](submission-reviewer-guide.md). Never submit
real personal data, credentials or private keys to the simulator.

To stop without deleting the isolated audit volume:

```powershell
podman compose -p sovereign-review -f deploy/compose.yaml `
  -f deploy/compose.ghcr.yaml --env-file .env down
```

**Never** use `down -v`, delete `.runtime`, or rerun the fresh bootstrap over
an installed deployment. The audit database lives in a named Podman volume.
The installation intentionally fails rather than reset or replace history.
Use the existing operator documentation for upgrades and migrations.

## Failure cases and limitations

- **404 / GHCR manifest unknown / unauthorized:** the exact image may not have
  been published, may have been removed, or may not be public. Verify release
  assets and package visibility; do not replace a digest with `:latest`.
- **Published image digest, release ID or public-key fingerprint differs from
  the trusted lock:** stop and investigate the independent handoff. Do not
  substitute a downloaded image or signing key or disable signature checks.
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
record one fresh Windows/Podman execution, release tag, image digests,
detector/policy identity, readiness and synthetic smoke-test results in the
[submission evidence matrix](submission-evidence.md).
