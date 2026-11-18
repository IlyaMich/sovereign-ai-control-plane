# Configuration

Copy `.env.example` to `.env`. Compose interpolates these settings and passes application
settings into the relevant services. Direct Python deployments read process environment
variables; they do not automatically load `.env`.

| Setting | Default | Purpose |
| --- | --- | --- |
| `MAX_PROMPT_BYTES` | 8192 | Maximum ingress prompt size in UTF-8 bytes |
| `MAX_REQUEST_BODY_BYTES` | 16384 | Maximum complete ingress request, including JSON overhead |
| `MAX_FORWARDED_PROMPT_BYTES` | 8192 | Maximum prompt accepted by all model simulators and egress gateway |
| `OPA_TIMEOUT_SECONDS` | 2 | OPA evaluation HTTP timeout |
| `MODEL_TIMEOUT_SECONDS` | 10 | Model invocation HTTP timeout |
| `READINESS_TIMEOUT_SECONDS` | 1 | Timeout for each readiness HTTP probe |
| `SIMULATOR_EGRESS_TIMEOUT_SECONDS` | 5 | Gateway-to-external-simulator HTTP timeout |
| `API_HOST` | 127.0.0.1 | Published API host address |
| `API_PORT` | 8000 | Published API host port; container port stays 8000 |
| `SIMULATOR_UPSTREAM_URL` | http://external-simulator:9000 | Operator-controlled HTTP(S) origin; gateway appends `/generate` |

Limits must be positive integers. The body limit must exceed the ingress prompt limit.
Timeouts must be positive and finite; HTTPX applies them to individual network operations,
not to the entire request lifecycle. Invalid values fail startup. Character counts in
OpenAPI are a preliminary bound; UTF-8 byte validation also applies. Each API app instance
has its own limit and OpenAPI schema.

If increasing the ingress limit, also increase the body and forwarded limits as needed.
Redaction can expand text, so the forwarded allowance can be larger than the ingress
allowance. The simulator still validates UTF-8 bytes and rejects blank prompts.

`OPA_URL`, `MODEL_URL`, `EGRESS_GATEWAY_URL`, all existing policy/release/audit paths,
and the detector manifest/archive paths can be overridden through Compose. The simulator
upstream remains operator-controlled; API callers cannot supply a URL. Existing network
isolation and destination model-ID checks remain active.

`ACTIVE_POLICY_PATH`, `POLICY_ARCHIVE_PATH`, `RELEASE_ARCHIVE_PATH`, and
`RELEASE_TRUST_PATH` also move their corresponding container mount targets. Change
`RELEASE_ACTIVE_DIR` to move the release directory mount and default active release file.
An explicit `RELEASE_ACTIVE_PATH` must reference `release.json` within that mounted directory.
Change `AUDIT_DATA_DIR` to move the writable audit volume; default database, signing-key,
and detector-archive paths follow it. Explicit file/archive overrides must remain within
that writable volume. Host source directories are unchanged. Reviewer CLI arguments and
historical PowerShell verification scripts must use the chosen paths and API address.

`DETECTOR_MANIFEST_PATH` is also passed as an image build argument, so generated provenance
is written to the runtime path. The manifest build/verification CLI tools also respect
this environment variable; explicit CLI path arguments take precedence. Changing it
requires rebuilding and approving the image.
Recreate services to apply runtime environment changes. Never rebuild an image after
signing its detector digest; use the existing M6 initialization/signing/activation workflow.

## Detector rules

`app/detection/rules.json` is the single configuration source for:

- `threshold`: minimum accepted finding confidence, between 0 and 1. Lower-confidence
  findings produce `UNKNOWN`; they are never discarded as evidence of public text.
- `entity_categories`: unique entity identifiers requested from Presidio.
- `required_coverage`: nonempty required recognizers, all included in selected entities.
- `sensitivity_mapping`: exactly one `MEDIUM` or `HIGH` entry per selected entity.
- `patterns`: category-to-list mapping of `[name, regex, score]` custom recognizers.

The file is packaged with Python and copied into the image. It is validated at startup
and its actual installed bytes are hashed into the detector manifest. The same parsed
configuration drives aggregation and the classification configuration digest. Managed
requests reject rules changed after initialization. Existing archived manifests remain
verifiable; changed detector source/rules require a newly built, signed, activated release.
Do not edit generated manifests or historical approvals.

To change detection behavior, edit the JSON, run the checks, then run
`Initialize-Milestone6.ps1` (with the existing signing key) and recreate services using
`--no-build`. Coordinate coverage/category changes with `policies/decision.rego`, regenerate
the policy snapshot if needed, and obtain approval for both artifacts. The existing
English/ASCII restriction remains in effect.
