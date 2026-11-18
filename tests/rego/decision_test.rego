package sovereign.authz_test

import rego.v1
import data.sovereign.authz

base_classification := {
    "status": "NO_PRIVATE_DETECTED",
    "detector_version": "presidio-spacy-v1",
    "config_digest": "test-digest",
    "coverage": ["EMAIL_ADDRESS", "PHONE_NUMBER", "PERSON", "CREDIT_CARD", "US_SSN", "API_CREDENTIAL", "PRIVATE_KEY"],
    "findings": [],
}

test_allows_internal_prompt if {
    authz.decision.effect == "PERMIT" with input as {
        "request": {"destination_id": "sovereign-model", "purpose": "GENERAL"},
        "classification": base_classification,
    }
}

test_allows_private_pii_internal if {
    authz.decision.effect == "PERMIT" with input as {
        "request": {"destination_id": "sovereign-model", "purpose": "SUMMARIZATION"},
        "classification": object.union(base_classification, {"status": "PRIVATE", "findings": [{"category": "PERSON"}]}),
    }
}

test_denies_external_even_if_no_private_data if {
    authz.decision.effect == "DENY" with input as {
        "request": {"destination_id": "external-model", "purpose": "GENERAL"},
        "classification": base_classification,
    }
}

test_blocks_secret if {
    authz.decision.reason_codes == ["CREDENTIAL_BLOCKED"] with input as {
        "request": {"destination_id": "sovereign-model", "purpose": "GENERAL"},
        "classification": object.union(base_classification, {"status": "PRIVATE", "findings": [{"category": "PRIVATE_KEY"}]}),
    }
}

test_unknown_fails_closed if {
    authz.decision.effect == "DENY" with input as {
        "request": {"destination_id": "sovereign-model", "purpose": "GENERAL"},
        "classification": object.union(base_classification, {"status": "UNKNOWN"}),
    }
}

test_missing_recognizer_coverage_fails_closed if {
    authz.decision.effect == "DENY" with input as {
        "request": {"destination_id": "sovereign-model", "purpose": "GENERAL"},
        "classification": object.union(base_classification, {"coverage": ["EMAIL_ADDRESS"]}),
    }
}

test_unknown_policy_purpose_is_denied if {
    authz.decision.effect == "DENY" with input as {
        "request": {"destination_id": "sovereign-model", "purpose": "EXPORT"},
        "classification": base_classification,
    }
}

test_demo_detector_no_longer_authorized if {
    authz.decision.effect == "DENY" with input as {
        "request": {"destination_id": "sovereign-model", "purpose": "GENERAL"},
        "classification": object.union(base_classification, {"detector_version": "demo-patterns-v1"}),
    }
}
