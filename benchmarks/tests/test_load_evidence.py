"""Offline verifier behavior checks: mock transport only; no secret or live network."""

from __future__ import annotations

import asyncio
import base64
from collections import deque

import httpx

from benchmarks import load as module

RID = "00000000-0000-4000-8000-000000000001"
SIGNATURE = base64.b64encode(bytes(64)).decode("ascii")
DEC = {"sequence": 1, "event_hash": "a" * 64, "signature": SIGNATURE}
OUT = {"sequence": 2, "event_hash": "b" * 64, "signature": SIGNATURE}
ROW = {"request_id": RID, "decision_receipt": DEC, "outcome_receipt": OUT}


def valid_evidence():
    return {
        "request_id": RID,
        "events": [
            {
                "receipt": DEC,
                "event": {
                    "event_type": "DECISION",
                    "request_id": RID,
                    "tenant_id": "local-tenant",
                    "payload": {"decision": {"effect": "DENY"}},
                },
            },
            {
                "receipt": OUT,
                "event": {
                    "event_type": "OUTCOME",
                    "request_id": RID,
                    "tenant_id": "local-tenant",
                    "payload": {"execution_status": "BLOCKED", "model_invoked": False},
                },
            },
        ],
    }


def mock_responses(*responses):
    remaining = deque(responses)

    async def handle(request: httpx.Request) -> httpx.Response:
        assert request.headers["X-API-Key"] == "secret"
        assert request.url.path == "/v1/requests/" + RID
        return remaining.popleft()

    return httpx.MockTransport(handle)


def verify(*responses):
    async def task():
        async with httpx.AsyncClient(
            base_url="http://127.0.0.1", transport=mock_responses(*responses)
        ) as client:
            return await module.verify_audited_response(
                client,
                key="secret",
                scenario="credential_deny",
                row=ROW,
                max_attempts=len(responses),
            )

    return asyncio.run(task())


def contract_503():
    return httpx.Response(503, json={"status": "ERROR", "reason_codes": ["AUDIT_UNAVAILABLE"]})


def test_retry_only_known_transient_503():
    assert verify(contract_503(), httpx.Response(200, json=valid_evidence())) == ([], 1)


def test_fail_closed_exhausted_retry():
    assert verify(contract_503(), contract_503()) == (
        ["evidence_audit_unavailable_retries_exhausted"],
        2,
    )


def test_does_not_retry_unknown_503():
    assert verify(httpx.Response(503, json={"reason_codes": ["OTHER"]})) == (
        ["evidence_unexpected_503"],
        0,
    )


def test_do_not_retry_500():
    assert verify(httpx.Response(500, json={"reason_codes": ["AUDIT_UNAVAILABLE"]})) == (
        ["evidence_unexpected_http_status"],
        0,
    )


def test_fail_closed_receipt_mismatch():
    doc = valid_evidence()
    doc["events"][0]["receipt"] = OUT
    assert verify(httpx.Response(200, json=doc)) == (["decision_receipt_mismatch"], 0)


def test_fail_closed_request_id_mismatch():
    doc = valid_evidence()
    doc["request_id"] = "other"
    assert verify(httpx.Response(200, json=doc)) == (["evidence_request_id_mismatch"], 0)


def test_fail_closed_bad_json():
    assert verify(httpx.Response(200, content=b"not-json")) == (["evidence_invalid_json"], 0)


def test_fail_closed_missing_receipts():
    async def task():
        async with httpx.AsyncClient(base_url="http://127.0.0.1") as client:
            return await module.verify_audited_response(
                client, key="secret", scenario="credential_deny", row={"request_id": RID}
            )

    assert asyncio.run(task()) == (["no_audited_response_receipt"], 0)


def test_safe_diagnostics_capacity_and_counts(tmp_path):
    """Short full run: load window excludes all evidence lookup work."""
    count = 0
    evidence_reads = 0
    evidence_active = 0
    peak_evidence_active = 0

    async def handle(request: httpx.Request) -> httpx.Response:
        nonlocal count, evidence_reads, evidence_active, peak_evidence_active
        if request.url.path == "/health/ready":
            return httpx.Response(200, json={"status": "READY"})
        if request.url.path == "/v1/prompts":
            count += 1
            await asyncio.sleep(0.015)
            return httpx.Response(
                403,
                json={
                    "status": "BLOCKED",
                    "decision": {"effect": "DENY", "reason_codes": ["CREDENTIAL_BLOCKED"]},
                    "model_id": None,
                    "request_id": str(__import__("uuid").UUID(int=count)),
                    "decision_receipt": DEC,
                    "outcome_receipt": OUT,
                },
            )
        if request.url.path == "/v1/diagnostics/concurrency":
            return httpx.Response(200, json={"audit_limits": {"maximum_auxiliary_jobs": 4}})
        if request.url.path.startswith("/v1/requests/"):
            evidence_reads += 1
            this_read = evidence_reads
            evidence_active += 1
            peak_evidence_active = max(peak_evidence_active, evidence_active)
            try:
                await asyncio.sleep(0.003)
            finally:
                evidence_active -= 1
            if this_read == 1:
                return contract_503()
            doc = valid_evidence()
            doc["request_id"] = request.url.path.rsplit("/", 1)[-1]
            for record in doc["events"]:
                record["event"]["request_id"] = doc["request_id"]
            return httpx.Response(200, json=doc)
        raise AssertionError(request.url.path)

    # Monkeypatch AsyncClient only for test; synthetic handler is never a network service.
    old_class = module.httpx.AsyncClient

    def client_factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handle)
        return old_class(*args, **kwargs)

    module.httpx.AsyncClient = client_factory
    try:
        config = module.Config(
            api_url="http://127.0.0.1:8000",
            clients=8,
            duration=0.018,
            scenario="credential_deny",
            timeout=1.0,
            key="secret",
            label="mock",
            output_dir=tmp_path,
        )
        result = asyncio.run(module.run(config))
    finally:
        module.httpx.AsyncClient = old_class
    assert result["evidence_validation_failures"] == 0
    assert result["evidence_transient_audit_503"] == 1
    assert result["transport_errors"] == 0
    assert result["functional_validation_failures"] == 0
    assert result["request_count"] >= 8
    assert peak_evidence_active <= 4
    assert len((tmp_path / "requests.jsonl").read_text().splitlines()) == result["request_count"]
