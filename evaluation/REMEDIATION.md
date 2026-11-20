# Known-violation external egress remediation (candidate)

> **Historical remediation rationale.** The reported unsafe-forward cases are synthetic and dated; this file does not attest a live signing-authority upgrade, prove production-safe egress, or replace the [current evidence requirements](../docs/submission-evidence.md).

The 2026-11-20 isolated Rego-backed 1,200-case replay reported 24 unsafe
external forwards: 14 SSN-shaped samples missed completely, six newline-split
names missed completely, and four newline-split names only partially redacted.
These inputs are synthetic. No real external API was contacted.

## Changes

- Add general syntactic US_SSN and multiline PERSON recognizers. They are
  heuristic, not proof that a number is issued or that two words form a name.
- Add `external_content_signals()` as a **second, independent, conservative**
  boundary check. `EnforcementPlanner` checks the original prompt before any
  external routing; `HTTPModelGateway` checks the actual outgoing payload before
  making an HTTP request. A hit denies the request locally. In the controlled
  orchestrator, `EXTERNAL_CONTENT_UNVERIFIED` is the expected reason code.
- Protect these new enforcement source bytes in the detector-artifact manifest's
  selected source hashes. The manifest is **not** an entire-image or policy
  attestation. This intentionally changes the approved artifact identity.

The guard deliberately rejects even a fully redacted multiline name if the
source contains a suspicious two-line pair. In addition, recognized PERSON
findings are denied externally until independently validated full-span
protection is available. This is a temporary conservative restriction on
external routing. Internal processing stays unaffected. The
filter can miss other PII, obfuscations, scripts, and name structures: zero
findings on this benchmark would **not** imply universal protection.

## Validation

From the repository root, in the detector-capable Python environment:

```powershell
python -m pytest -q tests/test_pre_egress_remediation.py tests/evaluation
python -m evaluation.cli validate
python -m evaluation.cli detect --split all
python -m evaluation.enforcement.cli --mode controlled --policy opa-cli --opa-bin opa
python -m evaluation.enforcement.cli --mode replay --split all --policy opa-cli --opa-bin opa
```

The Stage 2 runner uses an in-memory recording gateway, so its success depends
on the **planner** guard; the added HTTP sink test separately verifies the
last-mile barrier. The replay runs with local Rego snapshot verification but
*without* signed-release verification or live network egress. Do not treat
this as a deployed-release security claim.

Compare the new results to the frozen dataset v1 (`cases_sha256` unchanged),
including `unsafe_external_forward_count`, exact/overlap F1, `UNKNOWN`, group
accuracy and any newly blocked negatives. Preserve both run directories.

## Release precautions

Do not copy the updated source into the running approved container. The new
rules and `SOURCE_PATHS` change the detector manifest digest. If all tests are
accepted, build the intended image and approve a **new release generation**
using the existing signing authority and the repository's Milestone 6 release
workflow. Verify the new release, run startup readiness and end-to-end checks.
Do not rebuild after signing. Preserve audit volumes and private signing
material (`podman compose down -v` must not be used).
