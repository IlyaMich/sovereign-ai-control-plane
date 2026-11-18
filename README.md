# Sovereign AI Control Plane

A **local security reference implementation** for governing requests to AI models. The control plane detects sensitive input, evaluates versioned OPA/Rego policies, enforces approved routing and redaction, and records independently checkable evidence.

**Current implementation: Milestone 6 · API version 0.6.0.** M1–M6 functionality has been exercised on Windows with Podman Compose; the Milestone 6 operator verification reported `RELEASE_VERIFIED`, 14/14 Rego tests, signed request evidence, and successful disconnected policy replay. This is a **single-host prototype**, not a certified compliant or production multi-tenant platform.

## Capabilities at a glance

| Area | Implemented now | Important boundary |
| --- | --- | --- |
| Ingress | FastAPI `POST /v1/prompts`, API-key authentication, size limits, sanitized errors | One fixed local principal/tenant, not OIDC/RBAC |
| Detection | Local Presidio/spaCy, custom recognizers, deterministic normalized findings, coverage and `UNKNOWN` | Best-effort English ASCII scope; false negatives remain possible |
| Policy | Direct OPA/Rego with default deny; content-addressed archived policy snapshots | Rego inputs are structured detection metadata, not raw prompt text |
| Enforcement | `PERMIT`/`DENY`, ordered `REDACT` then `ROUTE`, post-redaction rescan, destination registry | External route is **test-only simulator**, disabled by default |
| Audit | SQLite WAL, signed SHA-256 event chain, decision committed before model invocation, separate outcome events | Keys live on the local host; a lost outcome can remain unresolved |
| Provenance | Detector model/source manifest, exact policy digest and archived replay | Artifact identity does not prove classifier correctness |
| Releases | Separate Ed25519 release approval for policy/detector identities, activation generation and predecessor | Local generation checks are not hardware-backed anti-rollback |
| Evidence | Portable ZIP; offline audit verification and OPA replay; optional independent public-key/checkpoint anchors | Without external audit key/checkpoint, history is self-consistent but not independently complete |

## System overview

~~~text
Untrusted caller -> FastAPI (X-API-Key) -> Presidio / spaCy
                                        -> OPA / Rego
                                        -> enforcement-plan validation
                                        -> optional REDACT + second detection
                                        -> SIGNED DECISION (durable precommit)
                                        -> approved model gateway
                                               |-> local sovereign simulator (default)
                                               \-> test-only egress gateway -> external simulator
                                        -> SIGNED OUTCOME

Offline release signer -> signed policy + detector approval -> runtime enforcement
Signed audit + policy snapshots + detector manifests + release approvals
                                        -> portable evidence ZIP
                                        -> network-disabled independent reviewer
~~~

The default Compose network is private. The API binds to `127.0.0.1:8000`; OPA and model ports are not published. The optional `egress-test` profile creates a separate simulated network. **Neither a Compose network nor a policy label establishes real-world data residency.**

## Start an existing Milestone 6 installation

Requirements: Windows PowerShell, Python 3.12+, Podman + Compose provider, and enough resources for local spaCy. Building the detector image requires network access to install dependencies and the pinned `en_core_web_sm` model; request processing does not download the model.

**Keep `.env`, the `audit-data` volume, policy archives, and the existing release signing key.** The example `release-active/` files in Git are not a substitute for possession of the corresponding trusted private key. For a brand-new independent installation, provision an appropriate release authority and initialize a clean deployment history instead of attempting to sign over another authority's previously active approval.

~~~powershell
# From the repository root, with .env and a trusted release key already provisioned:
python -m pip install "cryptography>=43,<47"
python -m tools.verify_policy_snapshot
python -m tools.verify_release

# If a new release is necessary, use the EXISTING signer and sign an N+1 approval.
# This rebuilds the intended image before signing:
.\Initialize-Milestone6.ps1 -UseExistingKey

# Run the EXACT approved image. Do not rebuild after signing:
podman compose -f deploy/compose.yaml --env-file .env up --no-build --force-recreate -d
Invoke-RestMethod http://127.0.0.1:8000/health/ready
.\Verify-Milestone6.ps1
~~~

For the optional simulated egress test, add `ENABLE_EXTERNAL_SIMULATOR=true` to `.env` and place `--profile egress-test` before `up`. Use **synthetic** inputs only.

**Never run `podman compose down -v`** on a deployment whose audit history or signing keys you need to keep. `down` without `-v` preserves the named volume.

### Developer workflows

~~~powershell
python -m pip install -e '.[dev]'
python -m pytest -q
podman compose -f deploy/compose.yaml --env-file .env exec control-plane python -m tools.smoke_detection
podman compose -f deploy/compose.yaml --env-file .env run --rm opa test /policies /policy-tests
~~~

A `Makefile` also provides `make test`, `make smoke`, `make test-policy` and other conveniences (requires Make). **Do not use `make up` as a signed production-style deployment command:** it invokes `up --build` and can rebuild detector artifacts after release approval. Use explicit `--no-build` Compose commands for M6 deployment.

### API smoke test (PowerShell)

~~~powershell
$key = (Get-Content .env | Select-String '^CONTROL_PLANE_API_KEY=').ToString().Split('=',2)[1]
$body = @{prompt='Explain local policy evaluation';destination_id='sovereign-model';purpose='GENERAL'} | ConvertTo-Json
Invoke-RestMethod -Uri http://127.0.0.1:8000/v1/prompts -Method POST -Headers @{'X-API-Key'=$key} -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($body)) | ConvertTo-Json -Depth 10
~~~

On an approved local request, expect `COMPLETED`, a `PERMIT` decision, and signed decision/outcome receipts. A private-key marker should be blocked; unsupported non-ASCII text is classified `UNKNOWN` and denied. `GET /v1/requests/{request_id}` returns tenant-scoped signed evidence metadata (not the raw prompt). API docs: `http://127.0.0.1:8000/docs`.

## Changing policy or detector code

Editing `policies/decision.rego` **does not activate** a new policy. The current M6 deployment requires a content-addressed policy snapshot and a **newly signed release** approving the exact policy and installed detector digests.

1. Review the proposed policy and run tests; build and verify the snapshot with `python -m tools.build_policy_snapshot` and `python -m tools.verify_policy_snapshot`.
2. Build the intended detector image and obtain the installed artifact digest.
3. Use the existing out-of-runtime private signing key to sign a new generation (predecessor must match the currently active release), then run `tools.activate_release` / `tools.verify_release`. The operator helper `Initialize-Milestone6.ps1 -UseExistingKey` covers the normal next-generation workflow.
4. If the Rego revision changed, update `EXPECTED_POLICY_REVISION` in `.env`.
5. Recreate **OPA and control-plane** with the approved image, without rebuilding; run `Verify-Milestone6.ps1`.

A rollback to older policy bytes is **a new signed generation**, not reactivation of an earlier approval. Retain every policy/release archive needed for replay. See [Milestone 6](docs/milestone-6.md).

## Evidence and trust

The exporter (`python -m tools.export_evidence_package --out /var/lib/sovereign/evidence.zip` inside the control plane) packages a consistent read-only SQLite snapshot, audit public key, relevant Rego snapshots, detector manifests and signed release approvals. `Verify-Milestone6.ps1` tests export and verification in a **network-disabled** reviewer.

A result of `EVIDENCE_PACKAGE_SELF_CONSISTENT` with `REPLAY_VERIFIED` confirms the package's internal signatures, chain, manifests and eligible policy replays. It does **not** by itself authenticate the audit signing key or establish complete history. A separately provisioned release verification key authenticates release approvals only. Use separately retained `--trusted-public-key` and `--trusted-checkpoint` for stronger audit authentication. A checkpoint generated inside the same ZIP is not an independent witness.

The verifier cannot replay original NLP classifications: raw prompts and original model binaries are intentionally absent. Historic M1–M3 events are integrity-only; later events are replayable to the extent supported by their recorded provenance.

## Documentation

- [Current architecture and request lifecycle](docs/architecture.md)
- [Current threat model and sovereignty limitations](docs/threat-model.md)
- [Detection and provenance](docs/detection-design.md)
- [Policy authoring, signing and activation](docs/policy-design.md)
- [Audit integrity, replay and evidence trust](docs/audit-design.md)
- [Testing and release verification](docs/testing.md)
- [Milestone 3: redaction and simulated egress](docs/milestone-3.md)
- [Milestone 4: content-bound Rego](docs/milestone-4.md)
- [Milestone 5: detector provenance](docs/milestone-5.md)
- [Milestone 6: release approvals](docs/milestone-6.md)
- [Architecture decisions (ADRs)](docs/adr/)

## Deliberate limitations / next work

This prototype does **not** provide a real external inference provider, evidence of geographic model residency, output DLP, OIDC or multi-tenant RBAC, full detector replay, production key protection, hardware anti-rollback, independent audit witnessing, or distributed audit sequencing. It uses synchronous processing and SQLite as one local writer.

The proposed next priorities are **independently witnessed audit checkpoints and externally pinned audit trust anchors**, then a real local inference runtime with stronger egress/workload identity, followed by enterprise governance and operations. These are roadmap items, **not implemented guarantees**. Security and compliance claims must be bounded by the threat model and actual deployment evidence.
