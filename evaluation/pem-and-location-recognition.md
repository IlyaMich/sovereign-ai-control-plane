# Detector recall candidate: complete PEM and US city/state spans

This candidate adds **two narrow, high-confidence custom Presidio patterns**.
It does not change policy, scoring thresholds, detection coverage requirements,
fail-closed handling, or runtime egress behavior.

## Changes

- `PRIVATE_KEY`: recognize a complete `BEGIN ... PRIVATE KEY` / matching `END`
  PEM block as one span. The pre-existing header-only recognizer remains, so
  incomplete or malformed key-like headers are still treated as sensitive.
  The new recognizer bounds its search to 8,192 characters (the default prompt
  size limit); larger configured prompts would require revisiting this bound.
  The matched begin/end label must agree.
- `LOCATION`: recognize `City, Full US State Name` as one span (including
  selected common multiword city names and `St.` / `Ft.` prefixes), without
  depending on spaCy to merge city and state entities. Deliberately avoid a
  generic multiword proper-noun regex that could consume preceding text.

**Reason for this scope:** Generic regex matching of arbitrary two-capitalized-word
names would also match ordinary titles and phrases in the wild. Candidate
patterns instead use strong structural evidence. Non-ASCII remains explicitly
unsupported; this candidate does not expand language coverage.

## What is and is not measured

On the unchanged synthetic dataset v1, independent regex inspection found:

| New pattern | Exact labeled spans matched | Additional unlabeled matches |
| --- | ---: | ---: |
| Complete PEM block | 58 | 0 |
| City, full US state | 86 | 0 |

These counts are **pattern-level matches**, not additional true positives or
measured improvements over the current Presidio/spaCy adapter. The existing
detector may already recognize some spans. Full detector precision, recall,
F1, and enforcement impact remain **unverified until evaluated**.

The matched corpus is synthetic, limited in variety, and must not be described
as representative production recall or as proof of no false positives.

## Tests and comparison

In a detector-capable local environment, with the pinned spaCy model installed:

```powershell
python -m pytest -q tests/detection/test_detector_recall_patterns.py tests/integration/test_presidio_real_integration.py
python -m evaluation.cli validate
python -m evaluation.cli detect --split all --output-dir evaluation/runs/recall-candidate-v1
```

To compare, use a preserved **control-plane** baseline generated from the
pre-change main branch with the *same dataset, Python environment, and model
versions*. Do not use the stock-Presidio adapter as the baseline.

```powershell
python -m evaluation.cli compare `
  --baseline evaluation/runs/<control-plane-baseline> `
  --candidate evaluation/runs/recall-candidate-v1
```

Inspect per-category false negatives, exact/overlap scores, false positives
on clean/hard negatives, UNKNOWN cases and new unsafe negatives. Afterwards,
run the enforcement replay with the actual local OPA executable:

```powershell
python -m evaluation.enforcement.cli --mode replay --split all --policy opa-cli --opa-bin opa
```

Keep dataset v1 unchanged and retain both runs. A candidate should only be
approved if meaningful recall improvements are confirmed without unacceptable
false positives, UNKNOWN regressions or unsafe external forwards.

## Deployment warning

`app/detection/rules.json` is part of the signed detector artifact identity.
Do **not** edit a running approved container or restart it against a stale
release. Following successful evaluation, rebuild the intended image,
regenerate/verify the detector manifest, approve a new signed successor release
using the existing authority, and start the approved image without rebuilding.

The sample tests alone do not establish production-detector correctness,
release integrity or provider/egress safety.
