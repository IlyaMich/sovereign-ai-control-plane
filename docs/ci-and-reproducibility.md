# CI, protected signing, and reproducibility

This is a guide to the checked-in workflows, **not** a claim that an arbitrary commit passed. Inspect the checks on the exact PR SHA and preserve run links, scan output, release ID and build digests for the submission.

| Workflow | Trigger | Scope and boundary |
| --- | --- | --- |
| [CI](../.github/workflows/ci.yml) | PR to `main`, push to `main`, manual | Python 3.12; Ruff, mypy, full pytest with pinned spaCy `en_core_web_sm==3.8.0`; source policy snapshot built in temporary directories and tested with a locally built patched OPA; synthetic dataset manifest validation; Bandit and Trivy filesystem High/Critical gates |
| [Container CI](../.github/workflows/container-ci.yml) | PR/push to `main`, weekly schedule, manual | Builds application, patched OPA and reviewer images; verifies installed detector manifest and non-root users; Trivy High/Critical image gates; checks Compose syntax |
| [Manual Signed Release](../.github/workflows/manual-signed-release.yml) | **Manual dispatch only** on `main` | Checks exact `main_sha`, explicit `SIGN`, code/tests/scans and frozen image bytes; requires protected `signed-release` environment and isolated self-hosted `release-signer` runner for N+1 signing; publishes already scanned images and a GitHub Release; **does not deploy** |

## Operator prerequisites for the manual release

The signing environment must have configured approvers, a physically/logically isolated `self-hosted, linux, x64, release-signer` runner, externally maintained release history and private key, and an independently pinned `RELEASE_SIGNER_PUBLIC_KEY_SHA256` repository variable. Do **not** run unreviewed PR code or general CI jobs on that signer. The workflow validates that `main` still points at the requested SHA before signing and publication, and refuses existing GHCR tags.

The publication step creates application, reviewer and patched-OPA image references under GHCR, identifies each immutable OCI manifest by digest in `registry-images.json`, and publishes a `signed-gN` GitHub Release. **The Ed25519 approval binds policy and detector identities, not the OCI manifest digest.** Record both identities and verify the installed image independently. The workflow has an older isolated verifier dependency range (`cryptography>=43,<47`) while application dependencies specify `cryptography>=50.0.2,<51`; those are separate environments, not a reason to downgrade the application. Any change to CI dependency pinning should be a separate tested workflow change.

The base Compose file is a **build-capable developer** configuration. To use GHCR digests, use [`compose.ghcr.yaml`](../deploy/compose.ghcr.yaml) as an overlay, supply `CONTROL_PLANE_IMAGE`, `AUDIT_REVIEWER_IMAGE` and `OPA_IMAGE` from the release's `registry-images.json`, and use `up --no-build`. It does **not** automatically install or trust the signed operator state; see [signed release workflow](signed-release-workflow.md).

## Reproduction and evidence

From a clean developer environment at the exact commit, use `python -m pip install -e ".[dev]"`, install the pinned spaCy model, then run `python -m ruff check .`, `python -m ruff format --check .`, `python -m mypy`, `python -m pytest -q`, and `python -m evaluation.cli validate`. Verify the installed OPA binary using [the patched-OPA build](PATCHED_OPA.md). For local Rego without changing signed state, use `python -m tools.test_output_policy --opa-bin opa` with the correct OPA executable available.

CI does **not** establish a live signed-release installation, end-to-end Podman security, independent audit-key witnessing, real external inference, or production capacity. Full load profiling relies on a **separately supplied, Git-ignored** `benchmarks/` reviewer kit, so it cannot be claimed reproducible from this repository alone. Record its origin/checksum, environment, profile, result archive and audit-verifier output if submitted. See [testing](testing.md) and [evidence matrix](submission-evidence.md).
