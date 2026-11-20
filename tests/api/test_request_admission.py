"""M7.1 per-app, fail-fast admission tests; no NLP image/containers required."""

import asyncio

import httpx
import pytest

from app.api.admission import InFlightAdmission
from app.api.main import Components, create_app
from app.application.orchestrator import RequestOrchestrator
from app.audit.verify import verify_database
from app.detection.demo import DemoPatternDetector
from app.domain.contracts import ModelResult
from app.enforcement.gateway import EnforcementPlanner
from app.infrastructure.config import AdmissionLimits, Settings
from tests.conftest import StaticPolicy

API_KEY = "a-secret-for-tests-that-is-long-enough"
HEADERS = {"X-API-Key": API_KEY}
PAYLOAD = {
    "prompt": "Synthetic concurrency test",
    "destination_id": "sovereign-model",
    "purpose": "GENERAL",
}


class BlockingModel:
    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.unblock = asyncio.Event()
        self.invocations = 0

    async def invoke(self, request_id, prompt, destination_id):
        self.invocations += 1
        self.started.set()
        await self.unblock.wait()
        return ModelResult("sovereign-model", "Synthetic fixture result")


def make_app(audit, *, maximum: int, model=None):
    model = model or BlockingModel()
    app = create_app(
        Components(
            settings=Settings(api_key=API_KEY, admission=AdmissionLimits(maximum)),
            orchestrator=RequestOrchestrator(
                DemoPatternDetector(), StaticPolicy(), audit, model, EnforcementPlanner()
            ),
            audit=audit,
        )
    )
    return app, model


def test_counter_bounds_and_detects_unbalanced_release():
    control = InFlightAdmission(2)
    assert control.try_enter()
    assert control.try_enter()
    assert not control.try_enter()
    assert (control.active, control.peak_active, control.rejected) == (2, 2, 1)
    control.leave()
    assert control.try_enter()
    control.leave()
    control.leave()
    assert control.active == 0
    with pytest.raises(RuntimeError):
        control.leave()


@pytest.mark.parametrize("value", [0, -1, 1025, True, 1.1])
def test_invalid_limits_fail_fast(value):
    with pytest.raises(ValueError):
        AdmissionLimits(value)
    with pytest.raises(ValueError):
        InFlightAdmission(value)


def test_configuration_reads_environment(monkeypatch):
    monkeypatch.setenv("CONTROL_PLANE_API_KEY", API_KEY)
    monkeypatch.setenv("MAX_INFLIGHT_REQUESTS", "4")
    assert Settings.from_env().admission.max_inflight_requests == 4
    monkeypatch.setenv("MAX_INFLIGHT_REQUESTS", "1025")
    with pytest.raises(ValueError):
        Settings.from_env()
    monkeypatch.setenv("MAX_INFLIGHT_REQUESTS", "abc")
    with pytest.raises(ValueError):
        Settings.from_env()


@pytest.mark.asyncio
async def test_overload_rejects_before_audit_and_recovers(audit):
    app, model = make_app(audit, maximum=1)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        first = asyncio.create_task(client.post("/v1/prompts", headers=HEADERS, json=PAYLOAD))
        try:
            await asyncio.wait_for(model.started.wait(), timeout=5)
            denied_auth = await client.post("/v1/prompts", json=PAYLOAD)
            assert denied_auth.status_code == 401
            overload = await client.post("/v1/prompts", headers=HEADERS, json=PAYLOAD)
            assert overload.status_code == 429
            assert overload.headers.get("retry-after") == "1"
            assert overload.json() == {
                "status": "REJECTED",
                "reason_codes": ["CAPACITY_EXCEEDED"],
                "detail": "Too Many Requests",
                "correlation_id": overload.headers["x-correlation-id"],
            }
            assert overload.headers["cache-control"] == "no-store"
            assert model.invocations == 1
            assert app.state.admission.active == 1
        finally:
            model.unblock.set()
            initial = await asyncio.wait_for(first, timeout=5)
        assert initial.status_code == 200
        again = await client.post("/v1/prompts", headers=HEADERS, json=PAYLOAD)
        assert again.status_code == 200
        assert model.invocations == 2
    assert app.state.admission.active == 0
    assert app.state.admission.peak_active == 1
    assert app.state.admission.rejected == 1
    for response in (initial, again):
        events = audit.get_events(response.json()["request_id"], "local-tenant")
        assert [e["event"]["event_type"] for e in events] == ["DECISION", "OUTCOME"]
    report = verify_database(str(audit.db_path), str(audit.key_path.with_suffix(".pub.pem")))
    assert report["verified_events"] == 4


@pytest.mark.asyncio
async def test_cancellation_releases_slot_without_fabricating_an_outcome(audit):
    app, model = make_app(audit, maximum=1)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        first = asyncio.create_task(client.post("/v1/prompts", headers=HEADERS, json=PAYLOAD))
        await asyncio.wait_for(model.started.wait(), timeout=5)
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first
        assert app.state.admission.active == 0
        model.unblock.set()
        following = await client.post("/v1/prompts", headers=HEADERS, json=PAYLOAD)
        assert following.status_code == 200
    # M7.1 only: cancelled model call remains unresolved in the audit. M7.4 will reconcile it.
    report = verify_database(str(audit.db_path), str(audit.key_path.with_suffix(".pub.pem")))
    assert report["verified_events"] == 3


@pytest.mark.asyncio
async def test_multiple_app_instances_have_independent_limits(audit):
    app1, model1 = make_app(audit, maximum=1)
    app2, model2 = make_app(audit, maximum=1)
    model1.unblock.set()
    model2.unblock.set()
    async with (
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app1), base_url="http://one") as first,
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app2), base_url="http://two") as second,
    ):
        one, two = await asyncio.gather(
            first.post("/v1/prompts", headers=HEADERS, json=PAYLOAD),
            second.post("/v1/prompts", headers=HEADERS, json=PAYLOAD),
        )
        assert one.status_code == two.status_code == 200
        assert app1.state.admission.active == app2.state.admission.active == 0
        assert app1.state.admission is not app2.state.admission
