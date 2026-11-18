package sovereign.authz_test

import rego.v1
import data.sovereign.authz

test_allows_internal_prompt if {
    authz.decision.effect == "PERMIT" with input as {
        "request": {"destination_id": "sovereign-model"},
        "classification": {"status": "NO_PRIVATE_DETECTED", "detector_version": "demo-patterns-v1", "findings": []},
    }
}

test_denies_external if {
    authz.decision.effect == "DENY" with input as {
        "request": {"destination_id": "external-model"},
        "classification": {"status": "NO_PRIVATE_DETECTED", "detector_version": "demo-patterns-v1", "findings": []},
    }
}

test_blocks_secret if {
    authz.decision.effect == "DENY" with input as {
        "request": {"destination_id": "sovereign-model"},
        "classification": {"status": "PRIVATE", "detector_version": "demo-patterns-v1", "findings": [{"category": "PRIVATE_KEY"}]},
    }
}
