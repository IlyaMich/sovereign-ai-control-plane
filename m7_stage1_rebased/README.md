# M7.1 refreshed candidate — pinned to `main` b0c328f

This is a **review-only, opt-in** patch for **bounded request admission and fail-fast backpressure**. It is rebased onto the repository's configuration overhaul (2026-11-19). It does **not** apply changes to GitHub, touch release keys, alter detector rules, or change policies.

## Changes

- `app/api/admission.py`: event-loop confined limiter, active/peak/rejected counters.
- `app/api/main.py`: per-FastAPI-instance limiter, authenticate first, return sanitized HTTP 429 with `Retry-After: 1` at capacity, release slot in `finally`.
- `app/infrastructure/config.py`: new immutable `AdmissionLimits` setting, `Settings.admission`, `MAX_INFLIGHT_REQUESTS` validated in `1..1024` using existing helpers.
- `deploy/compose.yaml`, `.env.example`, `docs/configuration.md`: add and document env propagation.
- `tests/test_m7_admission.py`: overload/audit/integrity/cancellation/independent-app/invalid-config regression cases.

This avoids the obsolete `Settings(max_inflight_requests=...)` field used in the previous patch. Current `RequestLimits`, `HTTPTimeouts`, and schema customization remain unchanged.

## Review and apply locally (PowerShell)

1. Obtain the matching `main` checkout and create a feature branch. Your checkout must have **HEAD exactly `b0c328f1d3ed180b8720bdf456791c67ebfce083`**, with no changes in the files the patch touches.
2. Extract this archive **into the repository root** (`m7_stage1_rebased/` should appear there).
3. From repository root:

```powershell
python m7_stage1_rebased/apply_stage1.py --root . --patch-out m7_1_rebased.patch
git apply --check m7_1_rebased.patch
# Inspect the patch before applying:
git apply --stat m7_1_rebased.patch
git apply m7_1_rebased.patch
```

Or `python m7_stage1_rebased/apply_stage1.py --root .` to print the diff without writing, then `--apply` to write directly. **Do not use both `--apply` and `git apply`.** Preflight deliberately fails on a changed HEAD or dirty target files, rather than silently patching incompatible changes.

## Validate

```powershell
python -m pytest -q tests/test_m7_admission.py tests/test_api.py tests/test_configuration.py tests/test_orchestrator.py
python -m ruff check app/api/admission.py app/api/main.py app/infrastructure/config.py tests/test_m7_admission.py
python -m ruff format --check app/api/admission.py app/api/main.py app/infrastructure/config.py tests/test_m7_admission.py
python -m mypy
python -m pytest -q
```

After the M6 benchmark baseline, use your **existing** signed-release build and activation procedure (with the pre-existing offline signer). Do not rebuild an image after approval. Verify runtime release and readiness before measuring. Avoid running `compose down -v` against meaningful audit history.

Config: add `MAX_INFLIGHT_REQUESTS=8` to `.env`, or set `4` to intentionally test 429 backpressure with eight synthetic load clients. Existing `benchmarks.suite` uses `--allow-overload` for intentional 429 tests. Match configuration and hardware for baseline/improved comparisons.

## Scope and security limits

Admission begins *after* ASGI body buffering/Pydantic validation. It prevents excess requests from entering the orchestrator but is not an edge connection limiter, an NLP executor, or a global limit across workers. The synchronous detector still blocks the event loop: that is **M7.2**. This release does not solve unresolved outcomes on cancellation, which will be addressed in **M7.4**. The test explicitly documents that a cancelled, already-committed decision can remain without an OUTCOME.

Tests in the patch can run after applying to the actual repository. The patch's standalone generator preflight is pinned to reviewed GitHub contents, but these integration tests have **not** been run against the user's private environment here.
