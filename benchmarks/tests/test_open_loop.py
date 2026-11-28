"""Deterministic open-loop load-generator tests; HTTP is mocked, never sent externally."""

from __future__ import annotations

import asyncio
import base64
import json
import math
import uuid

import httpx
import pytest

from benchmarks import load
from performance.config import load_profile

SIGNATURE = base64.b64encode(bytes(64)).decode("ascii")


def _receipt(sequence: int) -> dict:
    return {
        "sequence": sequence,
        "event_hash": "a" * 64,
        "signature": SIGNATURE,
    }


def _run_mock(
    tmp_path,
    monkeypatch,
    *,
    rate: float,
    clients: int = 4,
    duration: float = 0.26,
    response_delay: float = 0.003,
    reject_every: int | None = None,
):
    calls = 0

    async def handle(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        assert request.headers["X-API-Key"] == "test-only-key"
        if request.url.path == "/health/ready":
            return httpx.Response(200, json={"status": "READY"})
        assert request.url.path == "/v1/prompts"
        payload = json.loads(request.content)
        assert "PRIVATE KEY" in payload["prompt"]
        assert payload["destination_id"] == "sovereign-model"
        calls += 1
        this_call = calls
        await asyncio.sleep(response_delay)
        if reject_every is not None and this_call % reject_every == 0:
            return httpx.Response(
                429,
                json={"status": "REJECTED", "reason_codes": ["CAPACITY_EXCEEDED"]},
            )
        return httpx.Response(
            403,
            json={
                "request_id": str(uuid.uuid4()),
                "status": "BLOCKED",
                "decision": {"effect": "DENY", "reason_codes": ["CREDENTIAL_BLOCKED"]},
                "model_id": None,
                "decision_receipt": _receipt(2 * this_call - 1),
                "outcome_receipt": _receipt(2 * this_call),
            },
        )

    original = load.httpx.AsyncClient

    def factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handle)
        return original(*args, **kwargs)

    monkeypatch.setattr(load.httpx, "AsyncClient", factory)
    config = load.Config(
        api_url="http://127.0.0.1:8000",
        clients=clients,
        duration=duration,
        scenario="credential_deny",
        timeout=2,
        key="test-only-key",
        label="mock-open-loop",
        output_dir=tmp_path,
        verify_evidence=False,
        allow_overload=True,
        arrival_rate_rps=rate,
    )
    return asyncio.run(load.run(config))


def test_fixed_rate_is_offered_independently_of_response_completion(tmp_path, monkeypatch):
    summary = _run_mock(tmp_path, monkeypatch, rate=20.0, response_delay=0.035, reject_every=3)
    expected_arrivals = math.ceil(0.26 * 20)
    assert summary["arrival_rate_rps"] == 20.0
    assert summary["offered_requests"] == expected_arrivals
    assert summary["client_capacity_drops"] == 0
    assert summary["dispatched_requests"] == expected_arrivals
    assert summary["request_count"] == expected_arrivals
    assert summary["overload_rejections_429"] == 2
    assert summary["audited_receipt_responses"] == expected_arrivals - 2
    assert summary["functional_validation_failures"] == 0
    assert summary["transport_errors"] == 0
    assert summary["goodput_per_test_second"] <= summary["dispatched_rps"]

    rows = [json.loads(line) for line in (tmp_path / "requests.jsonl").read_text().splitlines()]
    assert len(rows) == expected_arrivals
    assert all(row["scenario"] == "credential_deny" for row in rows)
    assert all(row["schedule_lag_ms"] is not None for row in rows)
    assert all("prompt" not in row and "output" not in row for row in rows)


def test_client_capacity_drops_are_visible_and_not_counted_as_sent(tmp_path, monkeypatch):
    summary = _run_mock(
        tmp_path, monkeypatch, rate=40.0, clients=1, duration=0.23, response_delay=0.12
    )
    assert summary["offered_requests"] == math.ceil(0.23 * 40)
    assert summary["client_capacity_drops"] > 0
    assert summary["dispatched_requests"] < summary["offered_requests"]
    assert (
        summary["dispatched_requests"] + summary["client_capacity_drops"]
        == summary["offered_requests"]
    )
    assert summary["max_inflight_client_requests"] <= 1


@pytest.mark.parametrize("rate", [0.0, -1.0, 65.0, float("nan"), float("inf"), True])
def test_unsafe_rates_rejected_before_creating_results(tmp_path, rate):
    config = load.Config(
        "http://127.0.0.1:8000",
        1,
        1,
        "credential_deny",
        1,
        "test-only-key",
        "unsafe",
        tmp_path / "no-results",
        arrival_rate_rps=rate,
    )
    with pytest.raises(ValueError, match="open-loop rate"):
        asyncio.run(load.run(config))
    assert not config.output_dir.exists()


def test_profiles_are_versioned_and_closed_loop_is_unchanged():
    assert load_profile("baseline").arrival_rate_rps is None
    for rate in (4, 8, 16):
        profile = load_profile(f"open-loop-{rate}")
        assert profile.arrival_rate_rps == rate
        assert profile.levels == (32,)
        assert profile.scenarios == ("mixed_traffic",)
        assert profile.allow_overload
        assert profile.runs == 3


def test_unexpected_server_503_is_not_accepted_as_backpressure():
    errors = load.validate_result(
        "credential_deny",
        503,
        {"status": "ERROR", "reason_codes": ["AUDIT_UNAVAILABLE"]},
        allow_overload=True,
    )
    assert "unexpected_http_status" in errors
