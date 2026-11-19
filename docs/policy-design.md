# Policy design and release activation — Milestone 6

**Current contract:** Direct Rego in `policies/decision.rego`, entry point `data.sovereign.authz.decision`. A policy source edit has no runtime effect until it becomes a verified snapshot within a **signed release approval**. For snapshot format see [ADR-0002](adr/0002-content-addressed-rego.md); for signer and rollout behavior see [Milestone 6](signed-release-workflow.md).

## Inputs, outcomes and obligations

OPA receives **structured** request and classification metadata, not plaintext prompts: trusted principal ID/tenant/roles, requested destination ID and purpose; detection status, findings, recognizer coverage, version, configuration digest and artifact digest.

Allowed effects are `DENY` or `PERMIT`. A deny must have no obligations. A permitted request has exactly one final `ROUTE` obligation and optionally an initial `REDACT` obligation specifying allowed categories. The Python `EnforcementPlanner` validates the returned obligations independently of OPA; malformed or unsupported plans are denied.

The current baseline:

| Scenario | Rego behavior | Enforcement boundary |
| --- | --- | --- |
| Unsupported/unknown detection, missing required coverage, invalid detector version | `DENY` | Fail closed |
| `API_CREDENTIAL` or `PRIVATE_KEY` detected | `DENY` with `CREDENTIAL_BLOCKED` | No model |
| Supported input, allowed purpose, `sovereign-model` | `PERMIT` + local `ROUTE` | Local model simulator |
| No detected private data, allowed purpose, `external-simulator` | `PERMIT` + external `ROUTE` | Only if optional simulator route is enabled |
| Supported detected EMAIL_ADDRESS/PHONE_NUMBER/PERSON, allowed purpose, `external-simulator` | `PERMIT` + `REDACT` then `ROUTE` | Post-redaction `NO_PRIVATE_DETECTED` required |
| High-risk regulated or unrecognized private category on external route | `DENY` | Fail closed |
| Unknown destination or purpose | `DENY` | Default deny |

Allowed purposes: `GENERAL`, `SUMMARIZATION` and `INTERNAL_ANALYSIS`. The policy requires the exact detector identifier `presidio-spacy-v1`, nonempty `config_digest` and coverage for `EMAIL_ADDRESS`, `PHONE_NUMBER`, `PERSON`, `CREDIT_CARD`, `US_SSN`, `API_CREDENTIAL` and `PRIVATE_KEY`.

**Important:** The `external-simulator` is **not** a real external LLM. Its route is disabled by default via `ENABLE_EXTERNAL_SIMULATOR=false`; even a Rego permit cannot cause an unregistered endpoint to be invoked.

## Policy identity and signed authorization

1. `tools.build_policy_snapshot` captures the exact Rego/JSON source bytes in `policy-archive/<sha256>/` and activates a verified copy under `policy-active/`.
2. OPA loads only `policy-active/`. Its answer includes the exact `policy_digest` as well as the human `policy_revision`.
3. The control plane validates OPA's digest against the archived snapshot and against the active signed release approval.
4. An Ed25519 release signer, **distinct from the audit signer**, approves a tuple of policy digest/revision, detector artifact digest, deployment generation and previous release ID.
5. The signed `DECISION` evidence contains both the original OPA evaluation and any stricter local denial; a replay reviewer re-evaluates the archived policy on the recorded structured inputs.

A Rego revision name is not itself an authorization, and a source hash alone is not a release signature.

## Safe change procedure

~~~powershell
# In the existing operator checkout, with policy reviewed:
python -m tools.build_policy_snapshot
python -m tools.verify_policy_snapshot
podman compose -f deploy/compose.yaml --env-file .env run --rm opa test /policies /policy-tests

# Build and SIGN the exact policy/detector artifacts using the existing key.
.\Approve-And-ActivateRelease.ps1 -UseExistingKey

# If the human Rego revision changed, update EXPECTED_POLICY_REVISION in .env.
# Recreate the active containers WITHOUT rebuilding approved artifacts.
podman compose -f deploy/compose.yaml --env-file .env up --no-build --force-recreate -d
.\Verify-SignedReleaseWorkflow.ps1
~~~

A rollback requires a **new signed successor generation** referencing archived older policy bytes. Do not reactivate an old signed approval or delete evidence archives. Activation is not atomic across hosts and does not include a quorum or hardware monotonic counter; treat release maintenance as an operator-controlled change window.

## Historical decisions and constraints

M1–M3 events can be signature-verified but not independently replayed against exact old Rego snapshots. M4+ records can replay eligible policy decisions. M5 ties classification to a detector manifest; M6 additionally binds approved release identity.

Rego evaluation equivalence does not prove the detector identified every secret. Rules that depend on nondeterministic external data or environment state weaken historical replay; policy authors must keep relevant inputs and semantics deterministic.

Regulatory policy packs, a policy-management API, independent approval workflows and tenant-specific governance are **planned extensions**, not implemented regulation-compliance claims.
