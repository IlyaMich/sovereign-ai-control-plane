"""M7.4 regression: durable optional idempotency, no duplicate inference."""

import asyncio
import json
import sqlite3
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing

import httpx
import pytest

from app.api.main import Components, create_app
from app.application.orchestrator import RequestOrchestrator
from app.audit.idempotency import (
    ClaimState,
    IdempotencyStore,
    IdempotencyUnavailable,
    audit_state,
    validate_key,
)
from app.audit.verify import verify_database
from app.detection.demo import DemoPatternDetector
from app.domain.contracts import ModelResult
from app.enforcement.gateway import EnforcementPlanner
from app.infrastructure.config import Settings
from tests.conftest import RecordingModel, StaticPolicy

API_KEY = "a-secret-for-tests-that-is-long-enough"
HEADERS = {"X-API-Key": API_KEY, "Idempotency-Key": "m7-lifecycle-unique-001"}
PAYLOAD = {
    "prompt": "Explain local policy evaluation",
    "destination_id": "sovereign-model",
    "purpose": "GENERAL",
}


def claim(store, key="m7-lifecycle-unique-001", **overrides):
    arguments = dict(
        tenant_id="local-tenant",
        principal_id="local-tester",
        key=key,
        prompt="Synthetic request A",
        destination_id="sovereign-model",
        purpose="GENERAL",
        request_id=str(uuid.uuid4()),
    )
    arguments.update(overrides)
    return store.claim(**arguments)


def make_app(audit, model=None):
    model = model or RecordingModel(audit)
    return create_app(
        Components(
            settings=Settings(api_key=API_KEY),
            orchestrator=RequestOrchestrator(
                DemoPatternDetector(), StaticPolicy(), audit, model, EnforcementPlanner()
            ),
            audit=audit,
            idempotency=IdempotencyStore(audit),
        )
    ), model


@pytest.mark.parametrize(
    "value", [None, "short", "x" * 129, "key with spaces", "key\ninvalid", "♥invalid♥"]
)
def test_invalid_keys_rejected(value):
    with pytest.raises(ValueError):
        validate_key(value)


def test_claim_and_payload_conflict_survive_store_recreation(audit):
    registry = IdempotencyStore(audit)
    first = claim(registry)
    assert first.state == ClaimState.CREATED
    assert claim(registry).state == ClaimState.EXISTING
    assert claim(registry, prompt="Synthetic request B").state == ClaimState.CONFLICT
    recreated = IdempotencyStore(audit)
    assert claim(recreated).request_id == first.request_id
    assert claim(recreated, principal_id="different-user").state == ClaimState.CREATED
    assert claim(recreated, tenant_id="different-tenant").state == ClaimState.CREATED
    assert (
        recreated.lookup(
            tenant_id="local-tenant", principal_id="local-tester", key="m7-lifecycle-unique-001"
        )
        == first.request_id
    )
    assert (
        recreated.lookup(
            tenant_id="local-tenant", principal_id="unknown-user", key="m7-lifecycle-unique-001"
        )
        is None
    )
    with closing(sqlite3.connect(audit.db_path)) as conn:
        rows = conn.execute("SELECT key_hmac, input_hmac FROM request_idempotency").fetchall()
    assert all(len(entry[0]) == len(entry[1]) == 64 for entry in rows)
    assert "Synthetic request A" not in json.dumps(rows)
    assert "m7-lifecycle-unique-001" not in json.dumps(rows)
    assert (
        verify_database(str(audit.db_path), str(audit.key_path.with_suffix(".pub.pem")))[
            "verified_events"
        ]
        == 0
    )


def test_simultaneous_same_key_one_winner_across_sqlite_connections(audit):
    registry = IdempotencyStore(audit)
    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lambda _: claim(registry), range(24)))
    assert sum(item.state == ClaimState.CREATED for item in results) == 1
    assert sum(item.state == ClaimState.EXISTING for item in results) == 23
    assert len({item.request_id for item in results}) == 1


def test_invalid_sqlite_store_failure_fails_closed(audit, monkeypatch):
    store = IdempotencyStore(audit)

    def fail():
        raise sqlite3.OperationalError("locked")

    monkeypatch.setattr(store, "_connect", fail)
    with pytest.raises(IdempotencyUnavailable):
        claim(store)
    with pytest.raises(IdempotencyUnavailable):
        store.lookup(
            tenant_id="local-tenant",
            principal_id="local-tester",
            key="m7-lifecycle-unique-001",
        )


def test_audit_state_never_assumes_replay_is_safe():
    decision = {"event": {"event_type": "DECISION", "payload": {}}}
    outcome = {"event": {"event_type": "OUTCOME", "payload": {"execution_status": "UNKNOWN"}}}
    assert audit_state([]) == ("UNRESOLVED", None)
    assert audit_state([decision]) == ("UNRESOLVED", None)
    assert audit_state([decision, outcome]) == ("OUTCOME_RECORDED", "UNKNOWN")
    assert audit_state([outcome]) == ("INVALID_AUDIT_LIFECYCLE", None)


@pytest.mark.asyncio
async def test_api_duplicate_returns_stable_request_id_with_no_extra_model_call(audit):
    app, model = make_app(audit)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        first = await client.post("/v1/prompts", headers=HEADERS, json=PAYLOAD)
        assert first.status_code == 200
        request_id = first.json()["request_id"]
        second = await client.post("/v1/prompts", headers=HEADERS, json=PAYLOAD)
        assert second.status_code == 409
        assert second.json()["status"] == "REPLAY_PREVENTED"
        assert second.json()["request_id"] == request_id
        assert len(model.calls) == 1
        status = await client.get("/v1/idempotency/status", headers=HEADERS)
        assert status.status_code == 200
        assert status.json() == {
            "request_id": request_id,
            "audit_state": "OUTCOME_RECORDED",
            "execution_status": "COMPLETED",
        }
        events = await client.get(f"/v1/requests/{request_id}", headers=HEADERS)
        assert [e["event"]["event_type"] for e in events.json()["events"]] == [
            "DECISION",
            "OUTCOME",
        ]
        changed = await client.post(
            "/v1/prompts", headers=HEADERS, json={**PAYLOAD, "prompt": "Different synthetic prompt"}
        )
        assert changed.status_code == 409
        assert changed.json()["reason_codes"] == ["IDEMPOTENCY_KEY_CONFLICT"]
        assert len(model.calls) == 1
        no_key_headers = {"X-API-Key": API_KEY}
        normal = await client.post("/v1/prompts", headers=no_key_headers, json=PAYLOAD)
        assert normal.status_code == 200
        assert len(model.calls) == 2
    assert (
        verify_database(str(audit.db_path), str(audit.key_path.with_suffix(".pub.pem")))[
            "verified_events"
        ]
        == 4
    )


class PausedModel:
    def __init__(self):
        self.entered = asyncio.Event()
        self.resume = asyncio.Event()
        self.calls = 0

    async def invoke(self, request_id, prompt, destination_id):
        self.calls += 1
        self.entered.set()
        await self.resume.wait()
        return ModelResult("sovereign-model", "synthetic")


@pytest.mark.asyncio
async def test_concurrent_retry_does_not_invoke_twice(audit):
    model = PausedModel()
    app, _ = make_app(audit, model)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        first = asyncio.create_task(client.post("/v1/prompts", headers=HEADERS, json=PAYLOAD))
        try:
            await asyncio.wait_for(model.entered.wait(), timeout=5)
            duplicate = await client.post("/v1/prompts", headers=HEADERS, json=PAYLOAD)
            assert duplicate.status_code == 409
            assert model.calls == 1
            observed = await client.get("/v1/idempotency/status", headers=HEADERS)
            assert observed.json()["audit_state"] == "UNRESOLVED"
        finally:
            model.resume.set()
            response = await asyncio.wait_for(first, timeout=5)
        assert response.status_code == 200
        assert duplicate.json()["request_id"] == response.json()["request_id"]


@pytest.mark.asyncio
async def test_client_cancellation_exposes_unresolved_audit_and_blocks_replay(audit):
    model = PausedModel()
    app, _ = make_app(audit, model)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        task = asyncio.create_task(client.post("/v1/prompts", headers=HEADERS, json=PAYLOAD))
        await asyncio.wait_for(model.entered.wait(), timeout=5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        status = await client.get("/v1/idempotency/status", headers=HEADERS)
        assert status.status_code == 200
        assert status.json()["audit_state"] == "UNRESOLVED"
        duplicate = await client.post("/v1/prompts", headers=HEADERS, json=PAYLOAD)
        assert duplicate.status_code == 409
        assert duplicate.json()["request_id"] == status.json()["request_id"]
        assert model.calls == 1
        model.resume.set()
    verified = verify_database(str(audit.db_path), str(audit.key_path.with_suffix(".pub.pem")))
    assert verified["verified_events"] == 1
