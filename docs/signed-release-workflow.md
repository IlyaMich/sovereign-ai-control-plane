# ADR / Milestone 6: Signed releases, controlled activation and verification

**Implementation status:** M6 is implemented and the Windows Podman operator verification passed (signature-backed policy and detector identities, 14/14 Rego tests, signed decision evidence, portable export, and disconnected replay with an out-of-bundle release public key). This validates the tested workflow; it does **not** establish independent audit-key/checkpoint trust, live host attestation or real-world residency. See [current architecture](architecture.md) and [threat model](threat-model.md).

## Why this milestone exists

M4 identified exactly which Rego source was evaluated, and M5 which Presidio/spaCy
artifacts produced classification and which portable evidence was retained. Hashes
are *identities*, not authorizations. A compromised operator could write a new
Rego source, construct its correct hash, and obtain internally consistent evidence.

M6 introduces an independently held **release signer**. It approves one deployment
as the tuple `(policy_digest, policy_revision, detector_digest, generation,
previous_release_id)`. A signing key is deliberately **not** the audit key, and
never enters the deployed containers. The API has only the public verifier key.

## Security contract

1. Offline authority generates an Ed25519 key. Private PEM stays outside the Git
   checkout, running containers, audit volume, and exported evidence ZIP.
2. A canonical schema-1 payload with purpose `ACTIVATE` names the exact Rego and
   detector digests and deployment generation. The signer signs the domain-separated
   canonical payload. The release ID is a separate domain-separated SHA-256 digest.
3. A release approval is activated *only if* the signature authenticates against
   provisioned public keys, the referenced policy exists and verifies, the
   detector digest matches the chosen image, and the generation is a strict
   successor of the previously active generation. Signed archival history is kept.
4. API startup, readiness, and authorization verify both the release signature
   and the exact active policy/detector identities. Invalid approvals fail closed,
   without model invocation. Local fail-closed decisions are audited.
5. Signed `DECISION` evidence binds `release_snapshot` (release ID, generation,
   policy digest, detector digest, signer key ID). The portable evidence exporter
   includes the referenced signed approvals (never private signing keys).
6. The offline reviewer verifies release signatures against a separately supplied
   public key **outside the evidence ZIP**. Without that key, it reports archive
   self-consistency only. Prior audit signatures and OPA replay remain unchanged.

## Existing deployment (Windows PowerShell + Podman)

Preserve `.env`, audit volume, and existing `policy-archive` and `policy-active`.
**Do not use `podman compose down -v`.** The signer key is independent of
`/var/lib/sovereign/audit-key.pem`.

1. Install Python >=3.12 and `cryptography>=43,<47` on the operator host.
2. Verify the active policy and release with `python -m tools.verify_policy_snapshot`
   and `python -m tools.verify_release`. Preserve the trusted private signing key
   outside the checkout and the corresponding public key in `release-trust/`.
   If an intended change needs approval, run
   `./Approve-And-ActivateRelease.ps1 -UseExistingKey` from the checkout root
   (`-KeyDirectory` selects the signer directory; the default is
   `%USERPROFILE%\.sovereign-ai-control-plane`). The helper builds the image,
   verifies its detector manifest, then signs and activates generation **N+1**
   referencing the currently active release. Stop OPA and control-plane before
   changing active policy/release artifacts; recreate them after approval.
3. Provision/protect the trusted public key separately on any reviewing host.
   Protect private key with OS ACLs and ideally encrypted storage/HSM.
4. Start containers with `podman compose -f deploy/compose.yaml --env-file .env up --no-build --force-recreate -d`.
5. Run `./Verify-SignedReleaseWorkflow.ps1` to check actual runtime approval, signed
   evidence, export and network-disabled offline release verification.

`make up` and `make restart` run a release preflight and use `--no-build`, preserving the approved image. If `make build` was already run, `.\Approve-And-ActivateRelease.ps1 -UseExistingKey -SkipBuild` approves the existing image as a new successor generation without rebuilding it.

### First installation with an independent release authority

Generation 1 applies only when the target deployment has no active release.
The committed release files represent an existing authority/history; generating
a new key does not authorize those approvals. `-UseExistingKey` also does not
recover a missing key or grant trust in another signer.

Prepare a separate deployment directory and a fresh audit volume under a unique
Compose project name (`COMPOSE_PROJECT_NAME`). Retain the supplied example
release history separately from its operational `release-active/`,
`release-archive/`, `release-candidates/` and `release-trust/` directories.
For this new history, those operational directories must start empty, with
`release-active/release.json` absent. Existing installations and their volumes,
keys and archives must be preserved.

Provision `.env`, build and verify the intended policy snapshot, then run
`./Approve-And-ActivateRelease.ps1` using a new external `-KeyDirectory`.
When the private key is absent, the helper creates a development keypair,
places its public key in `release-trust/`, builds/verifies the image and signs
its initial generation-1 approval. The helper does not create an isolated
project, clear example histories or reset volumes for you. Keep the chosen
Compose project name set for all later helper, startup and verification commands.
Provision the public key independently to reviewers, then start without rebuilding
and run `Verify-SignedReleaseWorkflow.ps1` as above.

### Subsequent policy rollouts / rollback

For a new policy, stop both OPA and control-plane before modifying active artifacts
(`podman compose -f deploy/compose.yaml --env-file .env stop opa control-plane`).
Edit `policies/decision.rego`, run
`python -m tools.build_policy_snapshot`, build the intended detector image,
then sign a new approval with **generation N+1** and previous release ID.
`Approve-And-ActivateRelease.ps1 -UseExistingKey` handles the normal next generation.
If the Rego revision string changes, also update `EXPECTED_POLICY_REVISION`
in `.env` and recreate the control-plane. Otherwise readiness fails closed.

Rollback is **not** activation of the old approval: sign a new generation
pointing to the *older archived policy digest*, and activate the new release.
For manual signing use `python -m tools.sign_release --policy-snapshot policy-archive/<OLD_DIGEST> ...`.
The activation utility copies that verified archived policy into `policy-active`.
Then recreate **both OPA and control-plane**; no hot reload of unsigned files.

### Independent public key & checkpoint validation

`Verify-SignedReleaseWorkflow.ps1` supplies `/release-trust/release-signing.pub.pem` from an
external mount relative to the evidence ZIP; the viewer can authenticate release
approval signatures. For independently authenticated audit history, **also** pin
`audit-key.pub.pem` and a witnessed checkpoint outside the audit volume, and
pass `--trusted-public-key` and `--trusted-checkpoint` to the offline verifier.
A checkpoint freshly generated from a possibly compromised archive is *not*
an independent witness of completeness.

## Limitations and security boundaries

- The developer key generator writes **unencrypted PKCS#8** PEM for local
  development; protect it with filesystem access controls. Never commit it.
- A pinned public key copied from an untrusted running system only establishes
  trust *after* a genuine independent validation/provisioning step.
- Monotonic generation is enforced by the **activation tool**, not a hardware
  monotonic counter. Host administrators able to alter both active release and
  local archives/trust material can still forcibly roll back the host. Production
  protection requires external witnesses/attested storage or an independent
  deployment authority and immutable signed release transparency log.
- Release signatures approve artifact **identities**, not correctness or safety
  of the source code, build system, OS, network, model inference, or host.
- This implementation is **single-host local control**, not a distributed
  quorum-based release controller. Race/crash between active policy copy and
  active release replacement results in *not ready* / fail closed, not an
  atomic cross-volume transaction.
- Verifying a signed release in the same compromised container is insufficient
  against a malicious administrator who can change the container binary.
- The historical archive retains M1-M5 records as integrity-replayable where
  supported; it does not manufacture release approvals for older events.
- A disabled `REQUIRE_SIGNED_RELEASE=false` switch is for **local migration/
  development only**; it bypasses the new authorization boundary.
- Detector provenance still does not replay classification without raw input
  and pinned NLP binaries. Privacy-first choice remains unchanged.

## M7.8 — Concurrent and crash-safe operator publication

Audit and development release signing keys are first written and fsynced under
private temporary filenames in their target directory, then published using
atomic, non-replacing hard links. A competing initializer loads and validates
the existing complete audit key; it never overwrites a key or reconstructs one
when signed audit events already exist. Existing public keys are checked against
their private key, with a missing verifier published the same way.

The development release keypair is **two files**, not an indivisible commit.
If a process dies after publishing the complete private PEM but before the
public PEM, do **not** generate another private key. An authorized operator can
recreate only the public PEM from the existing complete private PEM:

```powershell
python -m tools.generate_release_key --recover-public `
  --private-key C:\secure\signer.pem --public-key release-trust\signer.pub.pem
```

Release activation now holds `.release-activation.lock` beside
`release-active/release.json` across the predecessor/generation check, archive
publication, policy staging and final active release publication. The file is
intentionally retained; the OS releases the actual lock when a process exits.
All concurrent operators **must** use the same release-active directory and
this activation path. The new policy is copied into a sibling staging folder,
verified and synced before any active policy change; an in-process failure
attempts to restore the old policy. An abrupt crash between policy and release
publication still creates a temporary mismatch: the running control plane
must fail closed. Operators should stop OPA/control-plane before policy
activation, inspect any `.policy-backup-*` artifacts after a crash, and rerun
the original candidate if its predecessor remains active. Never delete an
archived release or sign over an ambiguous active generation.

Windows bind mounts and a portable filesystem cannot atomically publish a
nonempty policy directory and release.json as one transaction. M7.8 therefore
provides serialized activation, staged verified bytes and fail-closed recovery,
**not** cross-filesystem atomicity or a live zero-downtime policy rollout.
The older `tools.build_policy_snapshot` can update `policy-active` separately;
do not invoke it concurrently with activation. Stop services and coordinate
all operator commands during the release window.
