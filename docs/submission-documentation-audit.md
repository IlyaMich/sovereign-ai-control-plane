# Submission-readiness documentation audit — 2026-11-20

**Scope:** review of the default-branch Markdown documentation (root, `docs/`, `evaluation/`, `evaluation/adapters/`, `performance/`) and repository inventory, performed on `docs/submission-readiness-audit-20261120`. This is a documentation and submission-readiness assessment, **not** a new runtime test or independent security verification. No signed artifact, deployment, policy, dataset, or application code is changed by this review.

## Decisions and rationale

| Priority | Documents | Recommendation | Reason |
| --- | --- | --- | --- |
| P0 — resolved here | `evaluation/adapters/README.md` and `evaluation/README.md` | Retain the root evaluation guide as canonical; replace the nested near-duplicate with a pointer | The nested document duplicates Stage 1 instructions and links to nonexistent `evaluation/adapters/STAGE2.md`; Stage 2 actually lives at `evaluation/STAGE2.md` |
| P0 — resolved here | All documentation | Add `docs/README.md` as a functional index | Existing root README lists many documents but does not distinguish current procedures, historical ADRs, candidate evaluations and submission requirements |
| P1 — resolved for repository claims | `README.md`, `docs/architecture.md`, `docs/response-side-dlp.md`, `docs/audit-design.md` | Clarified source vs historic sample vs separately verified runtime in [release status](release-status.md) | No live `.runtime` or host/image was available; actual running approval still requires on-host verification |
| P1 — resolved | `evaluation/README.md`, `evaluation/STAGE2.md`, `evaluation/adapters/STAGE3.md`, `evaluation/OUTPUT_DLP.md` | Corrected stage-status text, OPA version instructions and historical-run boundary | Stage guides remain distinct; Stage 2 defaults to tracked example policy, not live `.runtime` |
| P1 — partly resolved | `docs/concurrency-performance-profiling.md`, `docs/overload-and-audit-lookup.md`, `performance/README.md` | Kept separate runnable procedures and added submission status and evidence pointers to the performance README | No versioned result archive or independent `benchmarks/` reviewer kit is committed, so historical performance figures are not promoted to acceptance |
| P2 — resolved without move | `evaluation/RECALL_CANDIDATE.md`, `evaluation/PHONE_RECALL_CANDIDATE.md`, `evaluation/REMEDIATION.md` | Retained historical candidate rationale with explicit non-activation warning | Avoids breaking durable filenames and comparison instructions |
| P2 | `docs/history/*`, `docs/adr/*` | Retain as history with warnings | Historical reasoning and evidence-design evolution are valuable; never copy old activation commands into current bootstrap instructions |
| P2 | `docs/signed-release-workflow.md`, `docs/policy-design.md`, `docs/operator-state-migration.md` | Retain separately; cross-link and assign one canonical procedure per action | Security-sensitive signer, policy, and state-migration instructions warrant dedicated documents |
| P2 | `docs/PATCHED_OPA.md` | Retain and review pin/patch procedure whenever OPA is upgraded | The pinned patched OPA build is important reproducibility and supply-chain material |

**Deletion policy:** Do not delete historical decisions, security explanations, or candidate evidence merely to reduce file count. Prefer an index, stable redirect, explicit archival status, or deduplication after validating references.

## Submission deliverables and remaining external dependencies

The new [reviewer walkthrough](submission-reviewer-guide.md), [evidence matrix](submission-evidence.md), [CI guide](ci-and-reproducibility.md), [tools reference](tools-reference.md) and [release-status reconciliation](release-status.md) address the **documentation gaps** below. The following checklist distinguishes written instructions from independently reproduced evidence; documentation changes do not automatically satisfy the runtime parts.

## Missing or insufficient submission-oriented material

1. **Reviewer-ready clean-room walkthrough drafted:** [reviewer guide](submission-reviewer-guide.md) covers Windows/Podman, isolated state, signer, image-build order, synthetic smoke checks and safe teardown. A one-command bootstrap **script**, locked host tool versions and independent clean-room execution remain future submission tasks.
2. **Reviewer exercise documented:** [guide](submission-reviewer-guide.md) separates new and existing installations, points to tested synthetic denial/output scenarios, and includes signature verification and evidence replay. Actual clean-room test output remains to be retained.
3. **Evidence matrix drafted:** [submission evidence](submission-evidence.md) separates claims and trust boundaries. Preserve actual CI links, benchmark directories, dataset digests, environment and signed-release results before submitting numerical claims.
4. **CI and reproducibility documented:** [CI guide](ci-and-reproducibility.md) describes all three workflows, protected signer, digest-pinned publication and patched OPA. Check actual branch CI and key custody before calling the release safe.
5. **Tools reference drafted:** [tools reference](tools-reference.md) distinguishes read-only verifiers from state-mutating commands and synthetic traffic producers.
6. **Limitations documented:** [threat model](threat-model.md), [architecture](architecture.md), [release status](release-status.md), and [evidence matrix](submission-evidence.md) distinguish implementation from absent sovereignty/compliance/security claims.
7. **Release-ready metadata:** license, attribution/dependency notices, supported environment, maintenance/reproducibility policy, a pinned commit and any submission-specific rubric/checklist. Avoid inventing a license or compliance claim.

## Verification checklist before merging submission documentation

- Confirm which exact signed release and image are activated; ensure all v4/v5/current wording agrees with that evidence.
- Verify every relative Markdown link and every pasted command from repository root or the explicitly stated working directory.
- Run lint/format/typecheck/tests/OPA tests and CI; documentation edits alone do not prove these passed.
- Cross-check `.env.example`, Compose mounts, Makefile, `tools/` entry points, API endpoints and actual workflow permissions against written instructions.
- Validate clean-room bootstrap on a fresh empty state **without** destroying an existing audit volume or replacing any trusted signing key.
- Record measurable evaluation and performance claims with source artifacts, environment, dates, exact split and reviewer limitations.

## Deliberate boundaries of this branch

This branch changes **documentation only**: navigation, duplicate adapter guide, source/release status, OPA/evaluation accuracy, CI/reviewer/tool/evidence references and historical status wording. No live signing authority, signed approval, policy, image, dataset, runtime evidence or bootstrap script was changed. Actual host verification, licensing decision, submission rubric and independent fresh-install tests remain operator tasks.
