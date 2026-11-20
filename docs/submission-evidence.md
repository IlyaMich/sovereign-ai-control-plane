# Submission evidence and verification matrix

A submission claim must link to an exact commit, environment, command, and preserved output. **Do not treat a green unit test, synthetic benchmark or archive self-consistency as production approval.** This document is a reviewer checklist; it does not assert that the review branch was executed.

| Claim | Reproduction/evidence source | What it can establish | Remaining boundary |
| --- | --- | --- | --- |
| Python quality and behavior | `.github/workflows/ci.yml` jobs, `pytest` logs at exact SHA | Static checks and unit/integration suite for candidate source | Not a deployed signed image |
| Policy semantics | CI disposable policy build, `tests/rego/`, `tests/rego_output/`, patched OPA binary | Current candidate policy behavior for fixtures | Not live activation of the candidate |
| Detector integrity | `tools.verify_detector_manifest`, Container CI | Matching installed classifier/model bytes in tested image | No assertion of perfect recall |
| Signed activation | `tools.verify_release`, `tools.verify_runtime_release`, `Verify-SignedReleaseWorkflow.ps1` | Authenticated approval of exact policy/detector tuple when independently trusted public key provided | Local host/key compromise, real-world residency and remote attestation |
| Input detection | `evaluation.cli validate/detect/compare`, 1,200-case frozen v1 dataset and run artifacts | Synthetic exact/overlap scores and false negatives | Not production prevalence; safe external forwarding is separate |
| External routing and redaction | `evaluation.enforcement.cli`, Stage 2 guidance | In-memory simulated egress and fail-closed properties | No external cloud model or production secrets |
| Output DLP | `evaluation.output.cli`, output suite and run artifacts | Synthetic released/blocked/unsafe-release metrics, temporary signed chain and replay | Not proof of installed signed-release image or independent witness |
| Throughput and overload | `performance.cli`, M7.9 tools and **separately supplied** reviewer kit | Host-specific closed-loop throughput, p95, capacity rejection and audit delta | No production scale/SLO or portable independent reproduction without kit |
| Security scans and image dependencies | CI, Container CI, [patched OPA guide](PATCHED_OPA.md) | Scanner results for candidate files/images at tested date | Not future vulnerability immunity |
| Privacy and sovereignty | [threat model](threat-model.md) and [architecture](architecture.md) | Explicit scope and negative guarantees | No compliance certification or demonstrated geographic residency |

## Evidence bundle manifest (fill in for the final submission)

Record these together: Git SHA and PR/CI run URLs; Python/OS/Podman/Compose and OPA versions; policy digest/revision; detector digest, spaCy and Presidio versions; independently pinned signer key ID/public-key fingerprint; signed release ID/generation; source-dataset checksum and split; exact CLI commands; result files (`run.json`, comparison JSON, signed-evidence verification outputs); hardware and concurrency profile; and timestamps.

The development repository intentionally Git-ignores `evaluation/runs/`, `performance/results/` and other local benchmark outputs. Therefore a number reported in a console or Markdown is **not automatically reproducible evidence**. Retain and checksum the actual generated files in a separate submission evidence archive, redact credentials and host details, and document that synthetic evaluation keys are **not** operational trust anchors.

The [output evaluation guide](../evaluation/OUTPUT_DLP.md) records a dated synthetic v5-candidate run. The operator separately reported a 1,200-case output run with 1,200 passed, 0 failed, 450 released, 750 blocked, 0 unsafe sensitive releases, 0 false blocks, 2,400 verified signed events and 1,100 output-policy replays; these figures **must not be promoted to a verified submission claim** without preserving its complete run directory, environment and exact code/dataset identity. No current live release approval is inferred from that run.

For a reviewer-executable demonstration, follow [submission reviewer guide](submission-reviewer-guide.md) and [current release status](release-status.md).
