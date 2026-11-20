# Source, sample approvals, and running-release status

**Checked 2026-11-20 against the repository source; this is not an attestation of any live installation.**

The code in a checkout, the Git-tracked historical examples, the local operator's signed state and a running container are **four distinct things**. Claims that a policy or detector is "approved" must identify the corresponding **verified** signed release and installed image; a source merge or passing test does not activate it.

| Artifact | Repository observation | What it proves |
| --- | --- | --- |
| `pyproject.toml` and `app/api/main.py` | API/application version `0.6.0` | Source/API version only |
| `policies/decision.rego` | Source revision `redaction-response-dlp-v5`; includes `data.sovereign.authz.output_decision` and opt-in output masking rules | Candidate policy source, not live activation |
| `.env.example` | `EXPECTED_POLICY_REVISION=redaction-response-dlp-v5`, `OUTPUT_MASKING_ENABLED=false` | Example configuration for new-source activation; not a running operator's `.env` |
| Tracked `policy-active/manifest.json` | Historical example revision `redaction-baseline-v3`; digest `14dc07da86d2c1e658def210ffe70c80a34a2e76dcafb3251ae9edb830c5b7c2` | Example only, **not** current runtime state |
| Tracked `release-active/release.json` | Historical example generation **7**, release ID `996e77607d5f65f335d5deea8ebaa21c04f8ad164731382890638cf9422d25cd` | A checked-in example with its own signer; not evidence of operator approval |
| Operator-owned `.runtime/` | Git-ignored, not inspected by this review | Actual host policy, archives and approval depend on an independently provisioned trust root |
| Deployed image and running Podman stack | Not inspected by this review | Must be checked separately against the host's signed release and readiness |

Earlier local documentation reported an approved v4 output allow/block deployment. That remains a **historical operator report**; it cannot be inferred from the tracked generation-7 example, which predates the output entrypoint, nor from current source v5. The repository can demonstrate implemented output-side enforcement and synthetic tests without claiming that any particular host is running it.

## How to establish the actual installed state

On the **correct operator host**, from its checkout root, preserving `.env`, `.runtime`, the trusted signer, existing images and audit volume:

```powershell
python -m tools.verify_policy_snapshot
python -m tools.verify_release
podman compose -f deploy/compose.yaml --env-file .env ps
Invoke-RestMethod http://127.0.0.1:8000/health/ready
```

Verify the exact installed detector manifest against the release with the read-only runtime preflight used by `make release-check` (see [signed-release workflow](signed-release-workflow.md)). Inspect the reported **release ID, generation, policy revision/digest and detector digest**. If readiness or any signature/provenance check fails, do **not** label that image approved or bypass the check. Do not treat the example `release-active/` files as a bootstrap trust root.

Changing policy source, signed detector inputs, rules or built image identity requires a reviewed **new successor approval** with the existing authority for an existing deployment. A new, isolated deployment instead creates its **own generation-1 history and external signer**. Environment-only changes may require service recreation but not a new signature if approved artifact identity is unchanged. Details: [operator-state migration](operator-state-migration.md), [release workflow](signed-release-workflow.md), and [configuration](configuration.md).

## Assurance boundaries

- Synthetic output tests and temporary Ed25519 evaluation evidence are **not** production release approval or external audit witnessing.
- The local external-simulator route does **not** prove cloud egress safety, provider identity or geographic residency.
- A checked-in release signature cannot be authenticated without its independently trusted public key, and even an authenticated approval authorizes **artifact identity**, not correctness.
- The [submission evidence matrix](submission-evidence.md) records which tests can substantiate each claim and what remains to be validated.
