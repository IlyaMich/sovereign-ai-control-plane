"""Mixed synthetic traffic must preserve per-request checks and privacy."""

from __future__ import annotations

import asyncio
import base64
import json
import uuid

import httpx
import pytest

from benchmarks import load


def test_mixed_request_types_are_interleaved_and_bounded() -> None:
    assert set(load.SCENARIOS) >= {"mixed_traffic", *load.MIXED_SCENARIOS}
    assert [load.select_scenario("mixed_traffic", 0, n) for n in range(1, 7)] == [
        "local_permit",
        "credential_deny",
        "unsupported_input",
        "local_permit",
        "credential_deny",
        "unsupported_input",
    ]
    assert load.select_scenario("mixed_traffic", 1, 1) == "credential_deny"
    assert load.select_scenario("local_permit", 0, 1) == "local_permit"
    with pytest.raises(ValueError):
        load.select_scenario("mixed_traffic", 0, 0)
    with pytest.raises(ValueError):
        load.select_scenario("unrecognized", 0, 1)


def test_mixed_workload_keeps_individual_result_contracts(tmp_path, monkeypatch) -> None:
    responses = 0
    signature = base64.b64encode(bytes(64)).decode("ascii")

    async def handle(request: httpx.Request) -> httpx.Response:
        nonlocal responses
        assert request.headers.get("X-API-Key") == "synthetic-test-key"
        if request.url.path == "/health/ready":
            return httpx.Response(200, json={"status": "READY"})
        assert request.url.path == "/v1/prompts"
        prompt = json.loads(request.content)["prompt"]
        if "PRIVATE KEY" in prompt:
            scenario = "credential_deny"
        elif "café" in prompt:
            scenario = "unsupported_input"
        else:
            scenario = "local_permit"
        responses += 1
        await asyncio.sleep(0.003)
        reason = {
            "local_permit": [],
            "credential_deny": ["CREDENTIAL_BLOCKED"],
            "unsupported_input": ["DETECTION_UNKNOWN"],
        }[scenario]
        allowed = scenario == "local_permit"
        decision = {"effect": "PERMIT" if allowed else "DENY", "reason_codes": reason}
        body = {
            "request_id": str(uuid.uuid4()),
            "status": "COMPLETED" if allowed else "BLOCKED",
            "classification": {
                "status": "UNKNOWN" if scenario == "unsupported_input" else "COMPLETE",
            },
            "decision": decision,
            "model_id": "sovereign-model" if allowed else None,
            "decision_receipt": {
                "sequence": responses * 2 - 1,
                "event_hash": "a" * 64,
                "signature": signature,
            },
            "outcome_receipt": {
                "sequence": responses * 2,
                "event_hash": "b" * 64,
                "signature": signature,
            },
        }
        return httpx.Response(200 if allowed else 403, json=body)

    original = load.httpx.AsyncClient

    def factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handle)
        return original(*args, **kwargs)

    monkeypatch.setattr(load.httpx, "AsyncClient", factory)
    summary = asyncio.run(
        load.run(
            load.Config(
                api_url="http://127.0.0.1:8000",
                clients=3,
                duration=0.035,
                scenario="mixed_traffic",
                timeout=1.0,
                key="synthetic-test-key",
                label="test-only",
                output_dir=tmp_path,
                verify_evidence=False,
            )
        )
    )
    assert summary["request_count"] == responses
    assert summary["success_count"] == responses
    assert summary["functional_validation_failures"] == 0
    assert summary["transport_errors"] == 0
    assert set(summary["scenario_request_counts"]) == set(load.MIXED_SCENARIOS)
    assert summary["scenario_success_counts"] == summary["scenario_request_counts"]
    rows = [json.loads(line) for line in (tmp_path / "requests.jsonl").read_text().splitlines()]
    assert len(rows) == responses
    assert {row["scenario"] for row in rows} == set(load.MIXED_SCENARIOS)
    assert all(row["validation_errors"] == [] for row in rows)
    assert all("prompt" not in row and "output" not in row for row in rows)


def test_mixed_profile_has_correct_audit_review_configuration() -> None:
    from performance.config import load_profile

    profile = load_profile("mixed-traffic")
    assert profile.scenarios == ("mixed_traffic",)
    assert profile.runs == 3
    assert not profile.allow_overload
    assert profile.digest
