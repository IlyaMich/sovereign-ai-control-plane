package sovereign.authz

import rego.v1

# Baseline policy — milestone 1. All requests stay inside the local boundary.
# Local, approved principal and purpose attributes come from the API, not the caller.
# Future policy versions can add redact / external routing only after implementation.

revision := "baseline-v1"

default decision := {
    "effect": "DENY",
    "obligations": [],
    "reason_codes": ["DEFAULT_DENY"],
    "policy_revision": "baseline-v1",
}

has_protected_secret if {
    some finding in input.classification.findings
    finding.category in {"API_CREDENTIAL", "PRIVATE_KEY"}
}

is_local if {
    input.request.destination_id == "sovereign-model"
}

valid_classification if {
    input.classification.status in {"PRIVATE", "NO_PRIVATE_DETECTED"}
    input.classification.detector_version == "demo-patterns-v1"
}

decision := {
    "effect": "DENY",
    "obligations": [],
    "reason_codes": ["CREDENTIAL_BLOCKED"],
    "policy_revision": revision,
} if {
    has_protected_secret
}

decision := {
    "effect": "PERMIT",
    "obligations": [{"type": "ROUTE", "destination_id": "sovereign-model"}],
    "reason_codes": ["APPROVED_INTERNAL_ROUTE", "DEMO_DETECTION_LIMITED"],
    "policy_revision": revision,
} if {
    valid_classification
    is_local
    not has_protected_secret
}
