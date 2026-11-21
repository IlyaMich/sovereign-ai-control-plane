# Submission reviewer walkthrough — local Windows/Podman simulation

**Purpose:** demonstrate candidate source, independently trusted release activation, input/output controls and evidence using **synthetic inputs only**. This is a human-operated checklist, **not a bootstrap script**, not a certification and not a reproducible remote-cloud deployment. The documented runtime path is Windows PowerShell, Python 3.12+ and Podman with a Compose provider. The build needs network access for pinned Python/NLP and OPA source dependencies; request processing is local after the image is built.

**Preferred fresh-reviewer path:** For a published, independently pinned GHCR
signed release, use [the build-free submission bootstrap](submission-bootstrap.md).
It provisions a separate local review installation from immutable images. The
manual source-build steps below remain the fallback for a newly signed local
development deployment. Neither path should overwrite an existing operator's state.

## 0. Choose the correct starting point

- **Existing approved deployment:** follow [operator-state migration](operator-state-migration.md) if needed, retain its `.env`, Git-ignored `.runtime/`, audit volume, image and **existing signer**. Never run first-install key generation, overwrite state or change policy just to demo.
- **Fresh isolated review deployment:** use a separate checkout/Compose project and port, an empty Git-ignored `.runtime/`, a new audit volume, a new external key directory and a strong local API key. Do not copy Git-tracked example `release-active/` or `policy-active/` into the live trust store. **Never** reuse a named volume or key from another deployment.

From the repo root in PowerShell, install development requirements; a clean host may need Podman, Git, Make (optional) and local permissions first:

```powershell
python -m pip install -e ".[dev]"
Copy-Item .env.example .env
```

Before continuing, **manually** replace `CONTROL_PLANE_API_KEY` with a strong unique key and set an isolated `COMPOSE_PROJECT_NAME` in the deployment environment. Keep `.env` out of Git. Review `API_PORT`, `ENABLE_EXTERNAL_SIMULATOR=false` and `OUTPUT_MASKING_ENABLED=false`; policy revision is checked against the signed release rather than duplicated in `.env`. `.env.example` describes **source v5**, not an existing operator's live release.

## 1. Only for a new independently isolated deployment

Choose a private signer directory **outside the repository**. The local helper creates a **development** release key when absent, signs a generation-1 approval and verifies the detector image it builds. It is not a substitute for a protected production signing service.

```powershell
python -m tools.build_policy_snapshot
python -m tools.verify_policy_snapshot
.\Approve-And-ActivateRelease.ps1 -KeyDirectory "C:\secure\review-only-signer"
python -m tools.verify_release
```

The helper builds the **control-plane** image. Ensure the local patched OPA and simulator service images are also built **before** the no-build startup, for example in this **fresh isolated** project:

```powershell
podman compose -f deploy/compose.yaml --env-file .env build opa sovereign-model
podman compose -f deploy/compose.yaml --env-file .env up --no-build --force-recreate -d
```

Do **not** run these build commands on an existing signed deployment as a shortcut: rebuilding `control-plane` changes its detector identity and requires new approval, and new image/OPA changes must be reviewed. To use signed GHCR images instead, follow [CI and reproducibility](ci-and-reproducibility.md) and verify independent trust before starting.

## 2. Verify live readiness and permitted/denied input

For either kind of **correctly activated** installation:

```powershell
python -m tools.verify_policy_snapshot
python -m tools.verify_release
$key = (Get-Content .env | Select-String '^CONTROL_PLANE_API_KEY=').ToString().Split('=',2)[1]
Invoke-RestMethod http://127.0.0.1:8000/health/ready -Headers @{'X-API-Key'=$key}
.\Verify-SignedReleaseWorkflow.ps1
```

The last script **generates synthetic requests and audit evidence**, performs Rego tests and exports/replays an evidence bundle. Its reviewer image may be built separately; it does not approve a new detector or reset the audit volume. Check its current content before running against important evidence.

A minimal local permit request (no secrets) can be reproduced as follows:

```powershell
$key = (Get-Content .env | Select-String '^CONTROL_PLANE_API_KEY=').ToString().Split('=',2)[1]
$headers = @{ 'X-API-Key' = $key }
$body = @{prompt='Summarize a fictional sunny day';destination_id='sovereign-model';purpose='GENERAL'} | ConvertTo-Json
Invoke-RestMethod -Uri http://127.0.0.1:8000/v1/prompts -Method Post -Headers $headers -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($body))
```

For a **denial** and signed evidence, use only an obviously fictitious private-key marker in the synthetic test harness (see `Verify-SignedReleaseWorkflow.ps1` and `tests/api/test_output_dlp_api.py`). The API may return HTTP 403 by design; capture the response without treating it as a failed deployment. **Do not paste actual credentials or regulated personal data into demonstration requests.** `GET /v1/requests/{request_id}` and the idempotency-status endpoint expose signed metadata, never cached model output.

## 3. Demonstrate output DLP and simulated external egress

Output DLP requires a **verified source policy with the output entrypoint and matching signed detector image**. The historical tracked generation-7 Rego example does **not** meet this condition. For source-level, network-free demonstrations run:

```powershell
python -m pytest -q tests/enforcement/test_output_dlp.py tests/api/test_output_dlp_api.py tests/integration/test_dlp_signed_runtime_integration.py
python -m evaluation.output.cli --mode controlled
python -m evaluation.output.cli --mode dataset --split development --limit 20
```

For full synthetic output metrics and safe signed-evidence interpretation see [output evaluation](../evaluation/OUTPUT_DLP.md). A test's temporary signed key does **not** prove deployment release approval.

The optional external route is a **second local simulator network**, not a real model provider. It must be explicitly enabled through `ENABLE_EXTERNAL_SIMULATOR=true` and the `egress-test` Compose profile, and the installed policy must approve its destination. Use only synthetic test data; consult [testing](testing.md) for controlled redaction and isolation checks.

## 4. Preserve evidence and shut down safely

Record the exact Git commit, image identifiers, release ID/generation/policy/detector digests, CI links, run IDs, synthetic dataset manifest checksum, environment versions, commands and independently pinned trust material. Keep `evaluation/runs/` and `performance/results/` artifacts in a separate private, checksummed evidence package; they are intentionally Git-ignored. See [submission evidence matrix](submission-evidence.md).

To stop a review installation while **preserving audit history**, use:

```powershell
podman compose -f deploy/compose.yaml --env-file .env down
```

**Never run `down -v`, `git clean -fdx` or delete `.runtime/`** on a deployment whose release identity or evidence is needed. Record a separately witnessed audit checkpoint if independent history completeness is an assurance goal. For key/approval failures, do **not** bypass signature verification; use [operator-state migration](operator-state-migration.md) and [release workflow](signed-release-workflow.md) to diagnose and recover.
