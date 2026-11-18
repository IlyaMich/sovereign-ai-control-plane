package sovereign.authz

import rego.v1

# Milestone 2 policy: local-only, default-deny, no redaction or external egress.
# Only trusted admins may edit policy files. Data classification comes from
# the in-boundary detector; neither the caller nor a downstream model may set it.
revision := "presidio-baseline-v2"

default decision := {
    "effect": "DENY",
    "obligations": [],
    "reason_codes": ["DEFAULT_DENY"],
    "policy_revision": "presidio-baseline-v2",
}

required_coverage := {
    "EMAIL_ADDRESS", "PHONE_NUMBER", "PERSON", "CREDIT_CARD",
    "US_SSN", "API_CREDENTIAL", "PRIVATE_KEY",
}

valid_classification if {
    input.classification.status in {"PRIVATE", "NO_PRIVATE_DETECTED"}
    input.classification.detector_version == "presidio-spacy-v1"
    input.classification.config_digest != ""
    every category in required_coverage {
        category in input.classification.coverage
    }
}

is_sovereign if {
    input.request.destination_id == "sovereign-model"
}

approved_purpose if {
    input.request.purpose in {"GENERAL", "SUMMARIZATION", "INTERNAL_ANALYSIS"}
}

has_credential if {
    some finding in input.classification.findings
    finding.category in {"API_CREDENTIAL", "PRIVATE_KEY"}
}

# In the current local baseline secrets are forbidden even for the local model.
decision := {
    "effect": "DENY",
    "obligations": [],
    "reason_codes": ["CREDENTIAL_BLOCKED"],
    "policy_revision": revision,
} if {
    valid_classification
    has_credential
}

# Every applicable rule uses mutually exclusive guards to avoid OPA complete
# rule conflicts or accidental shadowing by a more permissive rule.
decision := {
    "effect": "PERMIT",
    "obligations": [{"type": "ROUTE", "destination_id": "sovereign-model"}],
    "reason_codes": ["APPROVED_INTERNAL_ROUTE", "PRESIDIO_DETECTION_COMPLETE"],
    "policy_revision": revision,
} if {
    valid_classification
    is_sovereign
    approved_purpose
    not has_credential
}
