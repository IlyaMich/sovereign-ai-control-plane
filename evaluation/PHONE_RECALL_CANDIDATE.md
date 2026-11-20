# High-confidence phone recognition candidate

> **Historical candidate design note.** A source change or merged PR is not an activation. Current installed recognition depends on the independently verified detector digest in the host's signed release; see [release status](../docs/release-status.md).

This change is a separate follow-up to the merged full-span detector improvement
(PR #24). The frozen 1,200-case synthetic dataset and active signed release stay
unchanged.

## Motivation

In the earlier candidate evaluation, all 96 labeled `PHONE_NUMBER` spans
were classified as `UNKNOWN` in their prompts because a low-confidence
candidate triggered `LOW_CONFIDENCE_FINDING`. This is fail-closed, but it
prevents the detector from producing an explainable `PRIVATE` result for
well-formed phone numbers and can affect mixed-entity prompts.

## Change

1. Add a high-confidence `PHONE_NUMBER` regex for structured North American
   phone numbers: optional +1, optional parentheses, area/exchange with
   permitted starting digits, and standard spaces, dots, dashes or no
   separators. It does **not** target international formats generally.
2. In `FindingAggregator`, a low-confidence finding may be superseded **only**
   when a high-confidence finding of the same category completely covers it.
   Any uncovered low-confidence span or low-confidence finding from a
   different category still returns `UNKNOWN`.
3. Add regression tests for exact offsets, common hard negatives, duplicate
   weak/strong recognizers, incomplete spans, and mixed-category uncertainty.
4. Add a live Presidio integration check. This is essential because regex
   matching by itself is not end-to-end detector evaluation.

## Pre-validation observations (pattern only)

On the unchanged synthetic dataset, independent pattern inspection matched
96/96 labeled `PHONE_NUMBER` spans exactly and matched zero unlabeled
spans. This is **not** an end-to-end recall measurement, nor a proof of
real-world precision. No claim of improvement is made before the real
Presidio/spaCy and enforcement evaluations are rerun.

## Validation commands

Use the detector-capable environment and an existing **pre-phone** control-plane
run (the validated PR #24 candidate run, provided the dataset, model and
environment are equivalent).

```powershell
python -m pytest -q tests/test_phone_recall.py tests/test_detection_aggregation.py tests/test_presidio_real_integration.py
python -m pytest -q
python -m evaluation.cli validate
python -m evaluation.cli detect --split all --output-dir evaluation/runs/phone-candidate-v1
python -m evaluation.cli compare `
  --baseline evaluation/runs/recall-candidate-v1 `
  --candidate evaluation/runs/phone-candidate-v1
python -m evaluation.enforcement.cli --mode replay --split all --policy opa-cli --opa-bin opa
```

Inspect exact/overlap precision, recall, F1, status counts, per-category errors,
UNKNOWN changes, hard-negative false positives, new unsafe-negative cases,
and unsafe external forwards. New unsafe external forwards are an unacceptable
regression, even if exact recall improves.

## Signoff and release boundaries

The candidate changes detector rules and `aggregation.py`, which are part
of the approved detector manifest identity. Never update a currently running
signed image in place. After successful review, rebuild the intended runtime
image, generate/verify the detector manifest and approve a new signed successor
release using the current signing authority. Recreate from the approved image
without rebuilding it afterward.

This is scoped to English ASCII synthetic evaluation; it is not a complete
international phone detector or privacy certification.
