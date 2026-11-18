# Direct OPA/Rego policy model (M2)

The policy is `policies/decision.rego`. The app calls the OPA decision endpoint
`POST /v1/data/sovereign/authz/decision`, with structured `PolicyContext` input.
OPA receives **no raw prompt**; it receives categories and offsets, detection
status/coverage/version/configuration digest, trusted principal, purpose and
destination ID.

OPA returns the unchanged M1 `PolicyDecision` shape:

```json
{
  "effect": "PERMIT",
  "obligations": [{"type": "ROUTE", "destination_id": "sovereign-model"}],
  "reason_codes": ["APPROVED_INTERNAL_ROUTE", "PRESIDIO_DETECTION_COMPLETE"],
  "policy_revision": "presidio-baseline-v2"
}
```

## M2 baseline logic

- **Default deny.** Unknown/unsupported classification, invalid version,
  missing required coverage, unsupported purpose, external destination, etc.
- Only `presidio-spacy-v1` detections with a nonempty configuration digest and
  all required coverage categories can be considered for permission.
- `PRIVATE` and `NO_PRIVATE_DETECTED` can be routed **locally only**, for
  `GENERAL`, `SUMMARIZATION`, or `INTERNAL_ANALYSIS` purposes.
- Findings classified as `API_CREDENTIAL` or `PRIVATE_KEY` are denied even for
  the local model (`CREDENTIAL_BLOCKED`).
- Future high-risk or regulatory restrictions may be represented as additional
  Rego rules. M2 has no external route and no redaction obligation.
- Independently, the Python planner accepts only a single `ROUTE` obligation
  to `sovereign-model`. Malformed OPA output or unavailable OPA fails closed.

Only trusted local administrators can edit Rego. Update the `revision` string
when modifying policies, then restart OPA to load changed files:

```powershell
podman compose -f deploy/compose.yaml --env-file .env restart opa
```

Policy revisions are currently **manually maintained**; archived, signed
policy bundles and a verified active bundle digest are future work. The audit
record captures the declared revision but does not cryptographically prove
which Rego bytes were loaded. This limits strong historical policy replay.

Run tests using the real OPA image:

```powershell
podman compose -f deploy/compose.yaml --env-file .env run --rm opa test /policies /policy-tests
```

Regulation-oriented packs are feasible with new Rego modules and trusted
attribute definitions, but implementing controls is not equivalent to legal
compliance or regulatory certification.
