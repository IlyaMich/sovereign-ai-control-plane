# Response-side DLP (candidate, output-policy v4)

This change extends request-side enforcement without replacing the existing
signed policy, detector provenance, or audit sequence. **It is not active until
a new signed policy and detector release is approved and deployed.**

## Decision flow

1. Perform input detection, Rego authorization, transformation and verification.
2. Commit the signed `DECISION` **before** invoking the approved model.
3. Once the model returns, inspect the generated text locally through the same
   bounded Presidio detector. Generated text is never submitted to OPA.
4. Evaluate `data.sovereign.authz.output_decision` using normalized output
   findings, trusted principal, destination, purpose and `stage=OUTPUT`.
5. Independently enforce that only a complete `NO_PRIVATE_DETECTED`
   classification, with no findings, can authorize response release. Verify
   that the active signed release still matches the detector and policy.
6. Commit a signed `OUTCOME` with output classification, exact policy
   input/evaluation, final enforcement rationale, release flag, and a
   domain-separated keyed output fingerprint. **Only after this commit** is
   an authorized response returned.

The managed FastAPI application always injects the output policy evaluator.
Legacy direct test adapters can omit it; production must not do so. The
runtime has no separate `OUTPUT_DLP_ENABLED` toggle.

## Output decisions

| Output result | Action | External behavior |
| --- | --- | --- |
| Complete clean classification and Rego `PERMIT` | Release | HTTP 200, status `COMPLETED` |
| `PRIVATE`, including email/credentials | Withhold | HTTP 403, status `OUTPUT_BLOCKED` |
| `UNKNOWN`, unsupported script, detector failure | Withhold | HTTP 403, `OUTPUT_BLOCKED` |
| OPA failure or invalid output obligations | Withhold | HTTP 403, `OUTPUT_BLOCKED` |
| Missing/changed active release | Withhold | HTTP 403, `OUTPUT_BLOCKED` |
| Empty/oversized/invalid Unicode response | Withhold | HTTP 403, `OUTPUT_BLOCKED` |
| Outcome audit commit failure | Withhold | HTTP 503, no output returned |

Output text is capped by the configured `MAX_FORWARDED_PROMPT_BYTES` limit
(default 8192 bytes) before DLP inspection. This bounds inspection work but
does not itself limit bytes buffered by a future real HTTP inference provider.

**Important distinction:** `OUTPUT_BLOCKED` means the model **was invoked**,
but its generated response was **not released to the client**. The signed
outcome records `execution_status=COMPLETED`, `model_invoked=true`, and
`output_dlp.released=false`. Never claim a model was not called. The request
audit `decision.effect` remains unchanged and describes the earlier
authorization of the model invocation.

## Audit/evidence

Output evidence is nested in the signed `OUTCOME.output_dlp` object:

- `classification`: output findings, covered categories, detector identity
- `policy_input`: exact metadata evaluated, with `stage=OUTPUT`
- `policy_evaluation`: the actual OPA answer, if invoked
- `policy_snapshot`: digest and revision of archived output Rego
- `decision`: the final, locally enforced output result and rationale
- `output_hmac_sha256`: keyed correlation fingerprint of the generated text
- `released`: whether the application returned the model text

No raw model output, recognizer-matched substring, API key, or prompt is
persisted to signed evidence. A verifier can reproduce the **Rego output
decision** from signed metadata and archived policy, but **cannot rerun output
PII classification** without storing model text, which this design deliberately
avoids.

## Validate before activation

From the repository root in the detector-capable Python environment:

```powershell
python -m pytest -q tests/test_output_dlp.py tests/test_output_dlp_api.py tests/test_policy_replay.py
python -m pytest -q
python -m ruff check .
python -m ruff format --check .
python -m mypy
python -m tools.test_output_policy --opa-bin opa
```

`tools.test_output_policy` builds a **temporary** content-addressed snapshot
from `policies/` and runs both existing input and new output Rego tests,
without changing `policy-active/`, release metadata or signing keys.
The old active-policy Rego suite remains separately runnable until the
operator activates the new signed release.

Before runtime deployment:

1. Complete tests and inspect code diff.
2. Review `EXPECTED_POLICY_REVISION=redaction-response-dlp-v4` in the
   deployment environment (the old local `.env` may still pin v3).
3. Stop the old control-plane and OPA as required by the release process.
4. Build a **new** policy snapshot from `policies/`, build the intended
   detector image, and verify both artifact digests.
5. Sign/activate a new successor release using the **existing** release
   authority; do not reset audit data or regenerate signing keys.
6. Recreate using the approved image **without rebuilding**.
7. Verify readiness, clean-output delivery, synthetic private-output block,
   and exported-evidence replay.

Do not mutate signed `policy-active`, `release-active`, or live container
files before that approval. Do not use `podman compose down -v`.

## Limitations

This first version supports output **allow/block**, not output redaction.
False negatives remain possible with all best-effort classifiers. Output
classification is English/ASCII-only and reuses the same model and recognizers
as ingress. Output DLP applies at the API response boundary; it does **not**
retroactively prevent data already sent to a selected external model.
A production provider integration also needs streaming-response buffering,
strict response byte limits, request cancellation and workload identity.
