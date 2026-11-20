# Submission-readiness documentation audit — 2026-11-20

**Scope:** review of the default-branch Markdown documentation (root, `docs/`, `evaluation/`, `evaluation/adapters/`, `performance/`) and repository inventory, performed on `docs/submission-readiness-audit-20261120`. This is a documentation and submission-readiness assessment, **not** a new runtime test or independent security verification. No signed artifact, deployment, policy, dataset, or application code is changed by this review.

## Decisions and rationale

| Priority | Documents | Recommendation | Reason |
| --- | --- | --- | --- |
| P0 — resolved here | `evaluation/adapters/README.md` and `evaluation/README.md` | Retain the root evaluation guide as canonical; replace the nested near-duplicate with a pointer | The nested document duplicates Stage 1 instructions and links to nonexistent `evaluation/adapters/STAGE2.md`; Stage 2 actually lives at `evaluation/STAGE2.md` |
| P0 — resolved here | All documentation | Add `docs/README.md` as a functional index | Existing root README lists many documents but does not distinguish current procedures, historical ADRs, candidate evaluations and submission requirements |
| P1 | `README.md`, `docs/architecture.md`, `docs/response-side-dlp.md`, `docs/audit-design.md` | Refresh current versus candidate release status together **after checking the activated release** | These still refer to approved v4 and source v5 candidate; source changes and the approved runtime are not interchangeable |
| P1 | `evaluation/README.md`, `evaluation/STAGE2.md`, `evaluation/adapters/STAGE3.md`, `evaluation/OUTPUT_DLP.md` | Keep distinct stage-specific procedures; remove outdated future-tense stage claims during measured-result update | The Stage 1 guide says Stage 2 “will” test egress, though Stage 2 is already documented and implemented; the stage documents serve different reproducibility purposes |
| P1 | `docs/concurrency-performance-profiling.md`, `docs/overload-and-audit-lookup.md`, `performance/README.md` | Keep runnable guidance; consolidate status and evidence summary once verified artifacts are available | M7.9 collection and the newer performance runner are complementary, but the reader needs one clear current performance-results entry point |
| P2 | `evaluation/RECALL_CANDIDATE.md`, `evaluation/PHONE_RECALL_CANDIDATE.md`, `evaluation/REMEDIATION.md` | Keep as labelled historical candidate records or move under `evaluation/history/` after confirming the merged lineage | Preserve why detector changes were developed; do not imply candidates are already authorized releases |
| P2 | `docs/history/*`, `docs/adr/*` | Retain as history with warnings | Historical reasoning and evidence-design evolution are valuable; never copy old activation commands into current bootstrap instructions |
| P2 | `docs/signed-release-workflow.md`, `docs/policy-design.md`, `docs/operator-state-migration.md` | Retain separately; cross-link and assign one canonical procedure per action | Security-sensitive signer, policy, and state-migration instructions warrant dedicated documents |
| P2 | `docs/PATCHED_OPA.md` | Retain and review pin/patch procedure whenever OPA is upgraded | The pinned patched OPA build is important reproducibility and supply-chain material |

**Deletion policy:** Do not delete historical decisions, security explanations, or candidate evidence merely to reduce file count. Prefer an index, stable redirect, explicit archival status, or deduplication after validating references.

## Missing or insufficient submission-oriented material

1. **Reproducible clean-room setup/bootstrap guide:** prerequisites, supported host/OS, Podman/Compose version expectations, image-building order, independent signing authority, trust bootstrap, initialization without inherited live state, synthetic smoke checks, teardown that preserves evidence, and failure recovery.
2. **Reviewer walkthrough:** exact safe commands from a fresh checkout to a permitted prompt, denied sensitive prompt, optional simulated external egress, output-DLP block, signed audit verification, release verification and offline evidence replay. Distinguish steps that require a preexisting approved installation.
3. **Versioned acceptance/evidence matrix:** claims mapped to tests, commands, expected outputs, dataset digest, test environment and retained artifacts. The user's prior console-reported results (including a 1,200-case output run with zero unsafe sensitive releases) are useful candidates for this matrix but must be tied to committed or otherwise retained run artifacts before claiming reproducibility.
4. **CI and reproducibility reference:** explain `.github/workflows/ci.yml`, `container-ci.yml`, `manual-signed-release.yml`, required permissions and secrets, what a successful check proves, what is not covered, and treatment of the patched OPA dependency.
5. **Operator/tool command reference:** inventory `tools/` scripts and root PowerShell verification scripts, specifying prerequisites, side effects, read-only versus mutating behavior, and safe use with approved signed releases.
6. **Limitations and future-work statement in one place:** explicitly cover single-host SQLite concurrency, no multi-tenant authorization, no true residency proof, synthetic external egress, non-streaming/non-attachment scope, detector recall limits, local key custody, and independent audit trust.
7. **Release-ready metadata:** license, attribution/dependency notices, supported environment, maintenance/reproducibility policy, a pinned commit and any submission-specific rubric/checklist. Avoid inventing a license or compliance claim.

## Verification checklist before merging submission documentation

- Confirm which exact signed release and image are activated; ensure all v4/v5/current wording agrees with that evidence.
- Verify every relative Markdown link and every pasted command from repository root or the explicitly stated working directory.
- Run lint/format/typecheck/tests/OPA tests and CI; documentation edits alone do not prove these passed.
- Cross-check `.env.example`, Compose mounts, Makefile, `tools/` entry points, API endpoints and actual workflow permissions against written instructions.
- Validate clean-room bootstrap on a fresh empty state **without** destroying an existing audit volume or replacing any trusted signing key.
- Record measurable evaluation and performance claims with source artifacts, environment, dates, exact split and reviewer limitations.

## Deliberate boundaries of this branch

This branch only introduces navigation and an actionable audit, and deduplicates a demonstrably overlapping evaluation README. Broader status rewrites, historical document moves, destructive deletes and a bootstrap script are deferred until their assertions can be verified against signed release and evaluation evidence.
