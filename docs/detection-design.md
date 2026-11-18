# Milestone 2 — Local Presidio Detection

## Design

`PresidioDetector` is the runtime implementation of the technology-neutral `Detector` port.
The adapter uses `presidio-analyzer==2.2.366`, a locally installed `en_core_web_sm`
spaCy model version `3.8.0`, built-in recognizers, and explicit custom pattern recognizers.
Model files are installed **during the container build**, never downloaded on a
request path. There are no external detection API calls.

The custom patterns handle limited forms of email addresses, AWS access-key IDs,
OpenAI-style API tokens, GitHub-style tokens, and PEM private-key headers.
Presidio's built-in recognizers handle entities including phone numbers, cards,
SSNs, names, locations and IBANs. This **does not** constitute exhaustive
credential, medical-data, or trade-secret detection.

## Normalization and uncertainty

`FindingAggregator` converts provider results to the existing `Finding` contract:
category, start, end, recognizer and score. No matched text is serialized.

The aggregator:

1. Validates recognition coverage and every reported span/score/category.
2. Rejects unsupported/unknown entity types instead of silently dropping them.
3. Treats any finding below a configured score threshold (initially 0.50)
   as `UNKNOWN` instead of quietly discarding uncertain findings.
4. Resolves overlaps deterministically using **sensitivity**, then score, span
   length and stable tie-breakers. This prevents a low-risk entity from hiding
   a high-risk overlapping secret.
5. Maps categories to `MEDIUM` or `HIGH`, and emits stable `DETECTED_*` reason codes.
6. Adds a `config_digest` to the classification; the field is additive to M1.

The required coverage categories are `EMAIL_ADDRESS`, `PHONE_NUMBER`, `PERSON`,
`CREDIT_CARD`, `US_SSN`, `API_CREDENTIAL`, and `PRIVATE_KEY`. The adapter refuses to
start if Presidio does not report the required recognizers. Invalid result data
produces `UNKNOWN`. The orchestrator denies `UNKNOWN` without invoking OPA.

**Input scope:** M2 accepts only ASCII prompt text for classification. Non-ASCII
characters cause `UNKNOWN` and a local fail-closed denial. This conservative
restriction avoids treating unsupported scripts as clean. It is not genuine
language detection: ASCII-only non-English prose may evade English NLP models.
Future versions should add explicit, validated language support, coverage
tracking per language and benchmarks. Because Presidio is best-effort, even a
complete detector result means *no private data detected by configured methods*,
not that the request is definitely public.

## Versioning and evidence

`detector_version = presidio-spacy-v1` and `config_digest` are copied to OPA
input and audit evidence. A digest of the static configuration is useful for
tracking changes, but it does not prove the full installed spaCy model bytes.
Full model-artifact checksums and hermetic builds should precede regulated use.

Privacy boundaries: never log raw prompts, entity values, recognizer
explanations containing input text or model responses. Returned scores are
recognizer scores, not calibrated probabilities of correctness.

## Next step

Redaction is not enabled in M2. A future implementation must derive immutable
spans from this normalized structure, apply replacements, re-run detection as
necessary, and validate the result against the selected policy and destination.
