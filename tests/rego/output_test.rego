package sovereign.authz_test

import rego.v1
import data.sovereign.authz

output_clean := {
  "stage": "OUTPUT",
  "request": {"destination_id": "sovereign-model", "purpose": "GENERAL"},
  "classification": {
    "status": "NO_PRIVATE_DETECTED",
    "detector_version": "presidio-spacy-v1",
    "config_digest": "test-digest",
    "coverage": ["EMAIL_ADDRESS", "PHONE_NUMBER", "PERSON", "CREDIT_CARD", "US_SSN", "API_CREDENTIAL", "PRIVATE_KEY"],
    "findings": [],
  },
}

test_output_clear_is_permitted_without_obligations if {
  response := authz.output_decision with input as output_clean
  response.effect == "PERMIT"
  response.reason_codes == ["OUTPUT_CONTENT_CLEARED"]
  count(response.obligations) == 0
  response.policy_digest == data.sovereign.policy_meta.digest
}

test_output_private_is_denied if {
  response := authz.output_decision with input as object.union(output_clean, {
    "classification": object.union(output_clean.classification, {
      "status": "PRIVATE",
      "findings": [{"category": "EMAIL_ADDRESS", "start": 5, "end": 21}],
    })
  })
  response.effect == "DENY"
  response.reason_codes == ["OUTPUT_PRIVATE_DATA_BLOCKED"]
}

test_output_unknown_is_denied if {
  response := authz.output_decision with input as object.union(output_clean, {
    "classification": object.union(output_clean.classification, {"status": "UNKNOWN"})
  })
  response.effect == "DENY"
}

test_output_missing_coverage_is_denied if {
  response := authz.output_decision with input as object.union(output_clean, {
    "classification": object.union(output_clean.classification, {"coverage": ["EMAIL_ADDRESS"]})
  })
  response.effect == "DENY"
}

test_output_wrong_stage_is_denied if {
  response := authz.output_decision with input as object.union(output_clean, {"stage": "INPUT"})
  response.effect == "DENY"
}

test_output_unknown_destination_is_denied if {
  response := authz.output_decision with input as object.union(output_clean, {
    "request": {"destination_id": "unapproved", "purpose": "GENERAL"}
  })
  response.effect == "DENY"
}
