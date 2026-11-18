package sovereign.authz
import rego.v1

# M3: only simulated, statically allowlisted external routing with mandatory redaction.
revision := "redaction-baseline-v3"


required_coverage := {"EMAIL_ADDRESS", "PHONE_NUMBER", "PERSON", "CREDIT_CARD", "US_SSN", "API_CREDENTIAL", "PRIVATE_KEY"}

valid_classification if {
  input.classification.status in {"PRIVATE", "NO_PRIVATE_DETECTED"}
  input.classification.detector_version == "presidio-spacy-v1"
  input.classification.config_digest != ""
  every category in required_coverage { category in input.classification.coverage }
}

approved_purpose if {
  input.request.purpose in {"GENERAL", "SUMMARIZATION", "INTERNAL_ANALYSIS"}
}

has_credential if {
  some finding in input.classification.findings
  finding.category in {"API_CREDENTIAL", "PRIVATE_KEY"}
}

# Restricted to a narrow first-version transformation list; high-risk regulated
# categories, location and unknown categories cannot be sent externally.
redactable_categories := {"EMAIL_ADDRESS", "PHONE_NUMBER", "PERSON"}

all_redactable if {
  input.classification.status == "PRIVATE"
  count(input.classification.findings) > 0
  every finding in input.classification.findings {
    finding.category in redactable_categories
  }
}

# Named, mutually exclusive rule guards let the fallback emit the same
# content-bound digest as all other results. A Rego `default` cannot depend
# on data.sovereign.policy_meta.digest.
credential_denial if {
  valid_classification
  has_credential
}

internal_permit if {
  valid_classification
  input.request.destination_id == "sovereign-model"
  approved_purpose
  not has_credential
}

external_public_permit if {
  valid_classification
  input.request.destination_id == "external-simulator"
  approved_purpose
  input.classification.status == "NO_PRIVATE_DETECTED"
  not has_credential
}

external_redacted_permit if {
  valid_classification
  input.request.destination_id == "external-simulator"
  approved_purpose
  all_redactable
  not has_credential
}

decision := {
  "effect": "DENY", "obligations": [],
  "reason_codes": ["DEFAULT_DENY"],
  "policy_revision": revision,
  "policy_digest": data.sovereign.policy_meta.digest,
} if {
  not credential_denial
  not internal_permit
  not external_public_permit
  not external_redacted_permit
}

decision := {
  "effect": "DENY", "obligations": [],
  "reason_codes": ["CREDENTIAL_BLOCKED"], "policy_revision": revision,
  "policy_digest": data.sovereign.policy_meta.digest,
} if {
  credential_denial
}

decision := {
  "effect": "PERMIT",
  "obligations": [{"type": "ROUTE", "destination_id": "sovereign-model"}],
  "reason_codes": ["APPROVED_INTERNAL_ROUTE", "PRESIDIO_DETECTION_COMPLETE"],
  "policy_revision": revision,
  "policy_digest": data.sovereign.policy_meta.digest,
} if {
  internal_permit
}

decision := {
  "effect": "PERMIT",
  "obligations": [{"type": "ROUTE", "destination_id": "external-simulator"}],
  "reason_codes": ["APPROVED_SIMULATED_EXTERNAL_ROUTE", "NO_PRIVATE_DATA_DETECTED"],
  "policy_revision": revision,
  "policy_digest": data.sovereign.policy_meta.digest,
} if {
  external_public_permit
}

decision := {
  "effect": "PERMIT",
  "obligations": [
    {"type": "REDACT", "categories": ["EMAIL_ADDRESS", "PHONE_NUMBER", "PERSON"]},
    {"type": "ROUTE", "destination_id": "external-simulator"},
  ],
  "reason_codes": ["SIMULATED_EXTERNAL_REDACTION_REQUIRED"],
  "policy_revision": revision,
  "policy_digest": data.sovereign.policy_meta.digest,
} if {
  external_redacted_permit
}
