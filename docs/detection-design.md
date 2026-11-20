# Sensitive-data detection, provenance and evaluation

**Current detector:** Local Microsoft Presidio Analyzer `2.2.366`, spaCy `en_core_web_sm` `3.8.0`, built-in recognizers and custom patterns. The control plane does **not** call an external detection API. Model installation occurs at container build time, not on prompt processing.

## Detection adapter

`PresidioDetector` implements the domain `Detector` port, with `FindingAggregator` normalizing each finding to `{category,start,end,recognizer,score}` (without the matched value). The adapter supports explicit credential/private-key patterns in addition to Presidio entities such as email, phone, person, card and US SSN.

The aggregator rejects malformed scores/spans/categories, missing required recognizer coverage and uncertain low-confidence findings, rather than silently declaring a clean prompt. It deterministically resolves overlapping spans using sensitivity, recognizer score and stable tie-breakers. `DetectionResult` includes:

- `status`: `PRIVATE`, `NO_PRIVATE_DETECTED` or `UNKNOWN`
- `sensitivity`, normalized `findings`, `coverage` and reason codes
- `detector_version = presidio-spacy-v1`
- `config_digest`: high-level detection settings
- `artifact_digest` (M5+): installed detector source/model artifact manifest identity

The current accepted input is **English ASCII**. Non-ASCII input is deliberately treated as `UNKNOWN` and blocked; this is a conservative scope limit, **not** language identification. Even for supported input, `NO_PRIVATE_DETECTED` means only that the configured recognizers found nothing at their thresholds. Business secrets, unknown credentials, adversarially formatted PII and false negatives remain risks.

## Required coverage and policy coupling

The baseline Rego requires coverage for `EMAIL_ADDRESS`, `PHONE_NUMBER`, `PERSON`, `CREDIT_CARD`, `US_SSN`, `API_CREDENTIAL` and `PRIVATE_KEY`; an untrusted caller cannot supply a trusted classification directly.

Credential detections are blocked even for the local route. The optional external **simulator** permits selected PII categories only with a `REDACT` obligation followed by a **second full scan** returning `NO_PRIVATE_DETECTED`. A second scan cannot prove that no undetected secrets remain.

## Manifest construction and release authorization

`deploy/Containerfile` installs the pinned English spaCy model, then executes:

~~~sh
python -m tools.build_detector_manifest
python -m tools.verify_detector_manifest
~~~

`/service/detector-active/manifest.json` hashes the installed `en_core_web_sm` files, selected detector/aggregator/domain source bytes, Python major/minor and versions of selected dependencies. It excludes `.pyc` files and is copied to the content-addressed `detector-archive/<digest>.json` in the audit volume.

Startup and readiness compare the actual installed artifacts with the build manifest. M6 also requires a **signed release approval** naming the exact `detector_digest` and the active `policy_digest`. A mismatched or untrusted release fails closed.

**Limitations:** The manifest does not hash the entire container image, OS libraries, all third-party packages or the OPA binary. Package version ranges and base-image tags are not fully reproducible supply-chain attestations. A manifest establishes identity for the enumerated bytes; it does not certify classifier quality or model residency.

## Audit and offline review

The signed decision records `policy_input.classification` with an artifact digest plus `detector_snapshot`; when redaction is performed, post-redaction verification must reference the approved detector as well. Portable evidence contains only the **manifest**, not model weights or plaintext prompts. An offline reviewer verifies the manifest, its content address, the signed audit reference, and the release approval where available.

`classification_replayed=0` is expected: no original prompt is included. This tradeoff prevents routine audit exports from duplicating sensitive content.

## Validation and future work

~~~powershell
podman compose -f deploy/compose.yaml --env-file .env exec control-plane python -m tools.smoke_detection
podman compose -f deploy/compose.yaml --env-file .env exec control-plane python -m tools.verify_detector_manifest
~~~

A developer-only [Stage 1 evaluation framework](../evaluation/README.md) includes
1,200 deterministic synthetic cases, dataset integrity validation, exact/overlap
entity scoring, abstention and unsafe-negative metrics, adversarial ASCII cases,
and HTML/CSV/JSON reports. It runs the standalone detector without modifying
operational policy, signed releases or audit data. Sequential call timings are
not a concurrency benchmark. The fixture and tooling do not establish production
accuracy, completed evaluation, or a release acceptance threshold.

Future improvements: non-English language coverage, reviewed detection baselines
and broader adversarial evaluation, model-image/SBOM signing, enforcement/egress
evaluation and consented encrypted forensic input retention where explicitly justified. See [testing](testing.md), [threat model](threat-model.md) and [Milestone 5](history/detector-provenance-and-evidence.md).
