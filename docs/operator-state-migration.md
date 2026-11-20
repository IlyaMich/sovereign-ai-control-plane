# Operator-owned runtime state (Git-safe deployment)

## Why this exists

Git previously tracked example `policy-active/decision.rego`,
`policy-active/manifest.json`, and `release-active/release.json`. A Windows
Git checkout restored old sample approvals and converted Rego LF to CRLF,
breaking content-addressed policy integrity. Repositories are **source code**,
not the authoritative state store for signed live approvals.

Starting with this change, host-side operator commands and Compose only use
`.runtime/`, which is ignored by Git and excluded from Docker/Podman build
contexts. Old tracked directories remain **legacy examples** for now so that
the migration pull itself does not delete an existing installation.

Container-internal paths remain `/policy-active`, `/policy-archive`,
`/release-active`, `/release-archive` and `/release-trust`; only the
**host bind sources** move. The audit SQLite database and audit signing key
stay in the existing, Compose-project-specific named `audit-data` volume.
The external release private key remains outside this repository and `.runtime`.

Do not commit `.runtime`, copy the old generation-7 sample release into it,
run `git clean -fdx` on a deployed checkout, or use `podman compose down -v`.

## Migrate a running, valid legacy installation

These instructions preserve the existing generation, signer, audit history,
artifact hashes and approved image. They do **not** sign a new release.

1. In the **correct existing project checkout**, retain its `.env`,
   `COMPOSE_PROJECT_NAME`, and external signer directory. Confirm that
   `python -m tools.verify_policy_snapshot --active policy-active
   --archive policy-archive` and
   `python -m tools.verify_release --active release-active/release.json
   --archive release-archive --trust release-trust --policy-active policy-active
   --policy-archive policy-archive` pass **before updating code**.
   If they do not, investigate before migration; do not try to manufacture
   approvals. Stop the services:
   ```powershell
   podman compose -f deploy/compose.yaml --env-file .env stop control-plane opa
   ```
2. Make a copy of all six legacy folders to a **separate protected location
   outside this checkout** before Git changes. Include
   `policy-active`, `policy-archive`, `release-active`,
   `release-archive`, `release-candidates`, and `release-trust`.
   Never include private signing keys in the repository or in evidence ZIPs.
3. Pull the version containing this change. The PR deliberately **does not**
   delete or edit legacy sample files, but still make the backup first.
4. Run the dry-run and then the verified copy-only migration:
   ```powershell
   python -m tools.migrate_operator_state
   python -m tools.migrate_operator_state --apply
   ```
   The first reports `READY_TO_MIGRATE`; the second must report
   `MIGRATED_AND_VERIFIED` with the **same release ID, generation and policy
   digest** you saw before migration. The migration authenticates the
   original signed release and archives, copies exact bytes to a staging
   directory, authenticates them again, then publishes `.runtime`.
   It **refuses to overwrite** an existing `.runtime`. It does not edit or
   delete source files or touch the audit volume.
5. Verify the isolated state and start the **existing approved images**:
   ```powershell
   python -m tools.verify_policy_snapshot
   python -m tools.verify_release
   podman compose -f deploy/compose.yaml --env-file .env up --no-build --force-recreate -d
   ```
   Check the configured API port in `.env` (for example, the independent
   `sovereign-clean` project uses `API_PORT=8001`).
6. Run the operator verification on the correct Compose project:
   ```powershell
   .\Verify-SignedReleaseWorkflow.ps1 -EvidenceMaxMiB 512
   ```
   The script now discovers the container using Compose and uses `API_PORT`;
   it does not assume the default project name or port 8000.

**If validation fails**, keep the control plane and OPA stopped. Do not
overwrite `.runtime`, regenerate signing keys, delete an audit volume or
re-sign generation 1. Recover from the independently saved artifacts.

## New independent installation

Use a distinct Compose project name and API port in `.env` and a new
external release-signing key directory. Do **not** copy the committed legacy
release samples. Start a fresh ignored state:

```powershell
python -m tools.build_policy_snapshot
python -m tools.verify_policy_snapshot
.\Approve-And-ActivateRelease.ps1 -KeyDirectory "<path outside Git to new signer>"
```

The first approval is generation 1; start with `up --no-build` and verify.
There is no automatic migration of someone else's old deployment identity.

## Safe Compose configuration inspection

`podman compose -f deploy/compose.yaml --env-file .env config` prints the
resolved environment, including the API credential. For routine validation,
use `podman compose -f deploy/compose.yaml --env-file .env config --quiet`,
which validates without exposing environment values in logs or screenshots.
Rotate an API key if a verbose config dump was shared. Rotation of the API
credential is a configuration change and does not require re-signing detector
artifacts, but the control-plane container must be recreated to load it.

## Subsequent approved upgrades

Keep `.env`, `.runtime`, the external signer, and the named audit volume.
Git branch switches and pulls now touch source/example files, **not** the
active/archived approvals in `.runtime`. Always use the same signer that
matches `.runtime/release-trust`:

```powershell
podman compose -f deploy/compose.yaml --env-file .env stop opa control-plane
python -m tools.build_policy_snapshot  # Only when policy source intentionally changes
python -m tools.verify_policy_snapshot
.\Approve-And-ActivateRelease.ps1 -UseExistingKey -KeyDirectory "<existing signer path>"
podman compose -f deploy/compose.yaml --env-file .env up --no-build --force-recreate -d
python -m tools.verify_release
```

The helper rebuilds the intended image and signs generation N+1 against
`.runtime/release-active/release.json`. `--no-build` ensures the exact
approved image is started; never rebuild after approval.

Policy source and Rego test files are pinned to LF by `.gitattributes`.
Default operator verifiers and policy-build/sign/activate tools use `.runtime`;
explicit CLI overrides remain available for forensic or test use.

**Limitations:** `.runtime` is Git-ignored, not tamper-proof. Back it up with
appropriate ACLs/immutability and independently witness audit checkpoints.
A deliberate `git clean -fdx` or deletion of the checkout can destroy an
ignored folder. Production should use a protected external state directory or
dedicated volume with backup, rather than rely solely on `.gitignore`.
