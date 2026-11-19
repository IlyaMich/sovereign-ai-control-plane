"""Synthetic-only M7.9 overload and audit-lookup follow-up validation."""

from __future__ import annotations

import asyncio
import copy
import json
import uuid
from pathlib import Path

import httpx
import pytest

from tools.overload_and_audit_lookup import (
    accepted_rows,
    check_overload,
    lookup_rounds,
    verify_lookup,
)


def sample_row(index: int) -> dict:
    return {
        "request_id": str(uuid.UUID(int=index + 1)),
        "decision": {"sequence": index * 2 + 1, "event_hash": "a" * 64},
        "outcome": {"sequence": index * 2 + 2, "event_hash": "b" * 64},
    }


def sample_events(row: dict) -> dict:
    return {
        "request_id": row["request_id"],
        "events": [
            {
                "receipt": row["decision"],
                "event": {"event_type": "DECISION", "request_id": row["request_id"]},
            },
            {
                "receipt": row["outcome"],
                "event": {"event_type": "OUTCOME", "request_id": row["request_id"]},
            },
        ],
    }


def make_run(folder: Path, *, rejected: int = 8) -> None:
    s = folder / "local_permit"
    s.mkdir(parents=True, exist_ok=True)
    (folder / "suite.json").write_text(
        json.dumps({"errors": [], "clients": 16, "duration_s": 20}), encoding="utf-8"
    )
    (s / "assertions.json").write_text(json.dumps({"passed": True}), encoding="utf-8")
    (s / "summary.json").write_text(
        json.dumps(
            {
                "scenario": "local_permit",
                "http_statuses": {"200": 100, "429": rejected},
                "overload_rejections_429": rejected,
                "transport_errors": 0,
                "functional_validation_failures": 0,
                "evidence_validation_failures": 0,
                "duplicate_request_ids": 0,
                "unresolved_status_error": 0,
            }
        ),
        encoding="utf-8",
    )
    (folder / "m7_9_diagnostics.json").write_text(
        json.dumps(
            {
                "benchmark_exit_code": 0,
                "poll_errors": 0,
                "process_counter_reset": False,
                "benchmark_integrity_issues": [],
                "counter_changes": {"admission.rejected": rejected},
            }
        ),
        encoding="utf-8",
    )
    with (s / "requests.jsonl").open("w", encoding="utf-8") as out:
        for idx in range(12):
            row = sample_row(idx)
            out.write(
                json.dumps(
                    {
                        "request_id": row["request_id"],
                        "http_status": 200,
                        "request_status": "COMPLETED",
                        "decision_receipt": row["decision"],
                        "outcome_receipt": row["outcome"],
                    }
                )
                + "\n"
            )


def test_overload_requires_signed_integrity_and_actual_429(tmp_path):
    make_run(tmp_path)
    result = check_overload(tmp_path)
    assert result["passed"]
    assert result["admission_rejected_429"] == 8
    assert len(accepted_rows(tmp_path)) == 12
    make_run(tmp_path, rejected=0)
    assert "overload_not_triggered" in check_overload(tmp_path)["issues"]
    assertions = tmp_path / "local_permit" / "assertions.json"
    assertions.write_text('{"passed": false}', encoding="utf-8")
    assert not check_overload(tmp_path)["passed"]


def test_overload_rejects_unexpected_503(tmp_path):
    make_run(tmp_path)
    path = tmp_path / "local_permit" / "summary.json"
    data = json.loads(path.read_text("utf-8"))
    data["http_statuses"]["503"] = 1
    path.write_text(json.dumps(data), encoding="utf-8")
    assert "unexpected_http_response_codes" in check_overload(tmp_path)["issues"]


def test_evidence_must_match_original_receipts():
    row = sample_row(3)
    original = copy.deepcopy(sample_events(row))
    assert verify_lookup(original, row)
    original["events"][1]["receipt"]["sequence"] += 1
    assert not verify_lookup(original, row)


def diagnostics(rejections: int) -> dict:
    return {
        "scope": "process",
        "http_ingress": {"limit": 32, "active": 1, "rejected": 0},
        "admission": {"limit": 8, "active": 0, "rejected": 0},
        "detector": {"capacity": 8, "capacity_rejections": 0},
        "audit": {"capacity": 16, "capacity_rejections": rejections},
        "event_loop": {"p95_ms": 1.0},
        "audit_limits": {"maximum_auxiliary_jobs": 4},
    }


@pytest.mark.asyncio
async def test_four_way_no_rejections_eight_way_retries_and_verifies():
    refs = [sample_row(i) for i in range(8)]
    by_id = {r["request_id"]: r for r in refs}
    active = 0
    rejected = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal active, rejected
        if request.url.path == "/v1/diagnostics/concurrency":
            return httpx.Response(200, json=diagnostics(rejected))
        if request.url.path.startswith("/v1/requests/"):
            if active >= 4:
                rejected += 1
                return httpx.Response(
                    503, json={"status": "ERROR", "reason_codes": ["AUDIT_UNAVAILABLE"]}
                )
            active += 1
            try:
                await asyncio.sleep(0.01)
                ref = by_id[request.url.path.rsplit("/", 1)[1]]
                return httpx.Response(200, json=sample_events(ref))
            finally:
                active -= 1
        return httpx.Response(404)

    async with httpx.AsyncClient(
        base_url="http://127.0.0.1:8000", transport=httpx.MockTransport(handler)
    ) as client:
        four = await lookup_rounds(client, refs, concurrency=4, rounds=4)
        eight = await lookup_rounds(client, refs, concurrency=8, rounds=4)
    assert four["passed"] and four["transient_audit_503"] == 0
    assert eight["passed"] and eight["transient_audit_503"] > 0
    assert eight["eight_way_saturation_observed"]
    assert eight["successful_verified_queries"] == 32


@pytest.mark.asyncio
async def test_unknown_503_contract_fails_not_counted_as_backpressure():
    refs = [sample_row(i) for i in range(8)]

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/diagnostics/concurrency":
            return httpx.Response(200, json=diagnostics(0))
        return httpx.Response(503, text="unrelated server failure")

    async with httpx.AsyncClient(
        base_url="http://127.0.0.1:8000", transport=httpx.MockTransport(handler)
    ) as client:
        result = await lookup_rounds(client, refs, concurrency=4, rounds=1)
    assert not result["passed"]
    assert result["unexpected_errors"] == 4


@pytest.mark.asyncio
async def test_no_rejections_at_eight_is_not_false_successful_saturation_claim():
    refs = [sample_row(i) for i in range(8)]
    by_id = {r["request_id"]: r for r in refs}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/diagnostics/concurrency":
            return httpx.Response(200, json=diagnostics(0))
        ref = by_id[request.url.path.rsplit("/", 1)[1]]
        return httpx.Response(200, json=sample_events(ref))

    async with httpx.AsyncClient(
        base_url="http://127.0.0.1:8000", transport=httpx.MockTransport(handler)
    ) as client:
        result = await lookup_rounds(client, refs, concurrency=8, rounds=2)
    assert result["passed"]
    assert not result["eight_way_saturation_observed"]
