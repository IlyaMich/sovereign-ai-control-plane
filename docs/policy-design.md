# Direct OPA/Rego policy model

The initial policy is `policies/decision.rego` and the API entry point is
`data.sovereign.authz.decision` (`POST /v1/data/sovereign/authz/decision`).

Input contains only structured trusted context and detector findings; OPA never
receives the plaintext prompt. `decision` returns an object with exactly:

```json
{"effect":"PERMIT", "obligations":[{"type":"ROUTE", "destination_id":"sovereign-model"}], "reason_codes":["APPROVED_INTERNAL_ROUTE"], "policy_revision":"baseline-v1"}
```

M1 semantics:

- Default deny on undefined context, nonlocal destinations, and unsupported
  classification status/version.
- `API_CREDENTIAL` and `PRIVATE_KEY` findings produce an explicit deny even if
  the requested route is local.
- The only permitted route is the local simulator and only for successfully
  completed demo classifications. The API's independent planner rechecks this.
- Unknown output shape, missing OPA `result`, OPA timeout, and denied decision
  with route obligations are not interpreted as permits.
- Rules cannot authorize arbitrary external network operations via the public API.

Policy edits can change behavior, but the revision identifier is **manually
maintained** at this milestone; exact active bundle-digest attestation and
historical policy replay are not yet implemented. A future signed policy-bundle
workflow will pin revision+digest, archive the bundle, validate activation, and
audit policy changes. Without that, the recorded revision must not be treated
as a strong proof of which source bytes OPA evaluated.

Run Rego tests under the OPA container:

```bash
podman compose -f deploy/compose.yaml run --rm opa test /policies /policy-tests
```

Future regulation-oriented packs can be separate Rego modules and data bundles;
regulatory mapping will require domain/legal review. Supporting a rule does not
itself establish certification or legal compliance.
