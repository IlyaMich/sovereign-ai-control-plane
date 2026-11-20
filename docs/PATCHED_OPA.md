# Patched OPA supply chain for the local sovereign control plane

## Reason
On 2026-11-20 Trivy reported CVE-2026-78661 (HIGH) in OPA v1.22.4
because the upstream binary bundled golang.org/x/net v0.60.0.
That package is patched in v0.62.0; no vulnerability suppression is used.

## Pinned sources
- OPA upstream version: **v1.22.4**
- Exact source commit: `ba39415db4b3c90cd68942a74b3cc2223ec2b23c`
- Patched Go module: `golang.org/x/net@v0.62.0`
- Build toolchain: `golang:1.27.4-alpine3.23`
- Build logic: `deploy/build_patched_opa.sh`

`deploy/OPAContainerfile` produces a non-root OPA server binary.
`deploy/ReviewerContainerfile` builds the same pinned, patched executable
for the audit reviewer. The release workflow compares the two actual binaries.

The source is fetched from GitHub and the checked-out commit is verified before
compilation. The module version is checked both in Go's module graph and the
built binary's embedded build info. High/Critical Trivy gates remain active.

## Build and test locally

```powershell
podman build -f deploy/OPAContainerfile -t sovereign-opa:local .
podman run --rm --entrypoint /opa sovereign-opa:local version
podman build -f deploy/ReviewerContainerfile -t sovereign-reviewer:local .
```

The default `deploy/compose.yaml` builds OPA locally. A successful **manual**
signed release also publishes the prebuilt OPA image to GHCR under the
`-opa` package alongside the application and reviewer images.

To use prebuilt images from the same signed release, set:
- `CONTROL_PLANE_IMAGE`
- `AUDIT_REVIEWER_IMAGE`
- `OPA_IMAGE`

using the digest-pinned values in `registry-images.json`, then use
`deploy/compose.ghcr.yaml` together with the base Compose file and `--no-build`.
Deployments must still supply their independently trusted signed release state.

## Upgrade policy
Update the OPA upstream SHA, Go toolchain and the patched module intentionally,
and allow the CI Rego tests, reviewer executable checks, and image security
scans to verify the new exact artifacts. Never silently replace the binary or
waive HIGH/CRITICAL findings.
