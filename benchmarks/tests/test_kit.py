"""Quick local tests. Run: python -m pytest -q benchmarks/tests"""
import base64
import json
from pathlib import Path
import uuid

from benchmarks.compare import compare
from benchmarks.load import (
    check_event_evidence,
    check_receipt,
    quantile,
    synthetic_prompt,
    validate_result,
)
from benchmarks.suite import compare_chain_heads


def receipt(seq):
    return {"sequence": seq, "event_hash": "a" * 64,
            "signature": base64.b64encode(bytes(range(64))).decode("ascii")}


def test_synthetic_scenarios():
    assert "example.com" in synthetic_prompt("external_redaction", "test")
    assert "PRIVATE KEY" in synthetic_prompt("credential_deny", "test")
    assert not synthetic_prompt("unsupported_input", "test").isascii()
    assert synthetic_prompt("local_permit", "test").isascii()


def test_receipt_and_result_validation():
    obj = {
        "request_id": str(uuid.uuid4()), "status": "COMPLETED", "model_id": "sovereign-model",
        "decision": {"effect": "PERMIT", "obligations": [{"type": "ROUTE", "destination_id": "sovereign-model"}]},
        "decision_receipt": receipt(1), "outcome_receipt": receipt(2),
    }
    assert check_receipt(receipt(1))
    assert validate_result("local_permit", 200, obj) == []
    assert "unexpected_http_status" in validate_result("local_permit", 201, obj)
    assert validate_result("local_permit", 429, {"status": "REJECTED", "reason_codes": ["CAPACITY_EXCEEDED"]}, allow_overload=True) == []
    assert validate_result("local_permit", 429, {})


def test_matching_request_evidence():
    request_id = str(uuid.uuid4())
    row = {"request_id": request_id, "decision_receipt": receipt(1), "outcome_receipt": receipt(2)}
    events = [
        {"receipt": receipt(1), "event": {"request_id": request_id, "event_type": "DECISION",
                                          "tenant_id": "local-tenant", "payload": {"decision": {"effect": "DENY"}}}},
        {"receipt": receipt(2), "event": {"request_id": request_id, "event_type": "OUTCOME",
                                          "tenant_id": "local-tenant", "payload": {"execution_status": "BLOCKED", "model_invoked": False}}},
    ]
    assert check_event_evidence("credential_deny", row, events) == []
    assert check_event_evidence("credential_deny", row, events[:1]) == ["expected_exactly_two_events"]


def test_chain_head_delta():
    before = {"verified_events": 10, "latest_sequence": 10, "latest_hash": "a" * 64}
    after = {"verified_events": 16, "latest_sequence": 16, "latest_hash": "b" * 64}
    assert compare_chain_heads(before, after, {"audited_receipt_responses": 3})["passed"]
    assert not compare_chain_heads(before, after, {"audited_receipt_responses": 2})["passed"]


def test_quantiles_and_comparison(tmp_path: Path):
    assert quantile([10, 20, 30], 0.50) == 20
    base = tmp_path / "baseline" / "local_permit"
    new = tmp_path / "improved" / "local_permit"
    for path, rps in ((base, 1.0), (new, 2.0)):
        path.mkdir(parents=True)
        (path / "summary.json").write_text(json.dumps({
            "clients": 8, "duration_configured_s": 60, "scenario": "local_permit",
            "responses_per_test_second": rps, "goodput_per_test_second": rps,
            "expected_success_rate_pct": 100, "latency_ms": {"p50": 40, "p95": 50, "p99": 55},
            "transport_errors": 0, "evidence_validation_failures": 0,
            "functional_validation_failures": 0,
        }))
        (path / "assertions.json").write_text(json.dumps({"passed": True}))
    assert "Goodput in window/s" in compare(base.parent, new.parent)
