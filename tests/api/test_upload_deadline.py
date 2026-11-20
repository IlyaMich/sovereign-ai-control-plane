"""Upload deadlines protect ingress capacity without timing out processing."""

import asyncio
from dataclasses import replace

import httpx
import pytest

from app.api.admission import InFlightAdmission
from app.api.body_limit import RequestBodyLimitMiddleware
from app.api.ingress_limit import HTTPIngressLimitMiddleware
from app.api.main import create_app
from app.infrastructure.config import IngressLimits, Settings
from tests.api.test_api import app_with_fakes
from tests.api.test_ingress_bounds import scope


@pytest.mark.asyncio
async def test_timed_out_uploads_release_all_slots_and_health_recovers():
    admission = InFlightAdmission(2)
    entered = 0
    ready = asyncio.Event()
    called = 0

    async def app(scope_, receive, send):
        nonlocal called
        called += 1
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    wrapped = HTTPIngressLimitMiddleware(
        RequestBodyLimitMiddleware(app, body_read_timeout_seconds=0.1), admission
    )

    async def stalled():
        nonlocal entered
        entered += 1
        if entered == 2:
            ready.set()
        await asyncio.Event().wait()

    messages = []

    async def send(message):
        messages.append(message)

    uploads = [asyncio.create_task(wrapped(scope(), stalled, send)) for _ in range(2)]
    try:
        await asyncio.wait_for(ready.wait(), 1)
        health = dict(scope("/health/live"), method="GET")
        await wrapped(health, stalled, send)
        assert admission.active == 2
        assert messages[0]["status"] == 503
        await asyncio.wait_for(asyncio.gather(*uploads), 1)
        assert admission.active == 0
        starts = [m for m in messages if m["type"] == "http.response.start"]
        assert [m["status"] for m in starts] == [503, 408, 408]
        assert all((b"connection", b"close") in m["headers"] for m in starts[1:])
        assert called == 0
        await wrapped(health, stalled, send)
        assert called == 1
        assert admission.active == 0
    finally:
        for task in uploads:
            task.cancel()
        await asyncio.gather(*uploads, return_exceptions=True)


@pytest.mark.asyncio
async def test_trickling_chunks_do_not_reset_total_deadline():
    reads = 0

    async def receive():
        nonlocal reads
        reads += 1
        await asyncio.sleep(0.01)
        return {"type": "http.request", "body": b"x", "more_body": True}

    async def forbidden(*args):
        pytest.fail("Incomplete upload reached application")

    messages = []

    async def send(message):
        messages.append(message)

    await asyncio.wait_for(
        RequestBodyLimitMiddleware(forbidden, body_read_timeout_seconds=0.08)(
            scope(), receive, send
        ),
        1,
    )
    assert reads > 1
    assert messages[0]["status"] == 408


@pytest.mark.asyncio
async def test_body_deadline_does_not_cancel_application_processing():
    async def receive():
        return {"type": "http.request", "body": b"{}", "more_body": False}

    async def app(scope_, receive_, send):
        assert (await receive_())["body"] == b"{}"
        await asyncio.sleep(0.05)
        await send({"type": "http.response.start", "status": 200, "headers": []})

    messages = []

    async def send(message):
        messages.append(message)

    await RequestBodyLimitMiddleware(app, body_read_timeout_seconds=0.01)(scope(), receive, send)
    assert messages[0]["status"] == 200


@pytest.mark.asyncio
@pytest.mark.parametrize("disconnect", [False, True])
async def test_disconnect_and_cancellation_release_ingress_slot(disconnect):
    admission = InFlightAdmission(1)
    started = asyncio.Event()

    async def receive():
        started.set()
        if disconnect:
            return {"type": "http.disconnect"}
        await asyncio.Event().wait()

    async def forbidden(*args):
        pytest.fail("Incomplete request reached application")

    middleware = HTTPIngressLimitMiddleware(RequestBodyLimitMiddleware(forbidden), admission)
    task = asyncio.create_task(middleware(scope(), receive, forbidden))
    await asyncio.wait_for(started.wait(), 1)
    if disconnect:
        await task
    else:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert admission.active == 0


@pytest.mark.parametrize("value", [0, -1, True, "10", None, float("nan"), float("inf")])
def test_invalid_body_deadlines_are_rejected(value):
    with pytest.raises(ValueError):
        IngressLimits(body_read_timeout_seconds=value)
    with pytest.raises(ValueError):
        RequestBodyLimitMiddleware(None, body_read_timeout_seconds=value)


@pytest.mark.parametrize("value", ["0", "-1", "nan", "inf", "invalid"])
def test_invalid_environment_deadline_fails_startup(monkeypatch, value):
    monkeypatch.setenv("CONTROL_PLANE_API_KEY", "a-valid-test-secret-long-enough")
    monkeypatch.setenv("BODY_READ_TIMEOUT_SECONDS", value)
    with pytest.raises(ValueError):
        Settings.from_env()


@pytest.mark.asyncio
async def test_configured_deadline_reaches_api_before_authentication(audit, monkeypatch):
    monkeypatch.setenv("CONTROL_PLANE_API_KEY", "a-valid-test-secret-long-enough")
    monkeypatch.setenv("BODY_READ_TIMEOUT_SECONDS", "0.02")
    settings = Settings.from_env()
    assert settings.ingress.body_read_timeout_seconds == 0.02
    components = app_with_fakes(audit).state.components
    components.settings = replace(components.settings, ingress=settings.ingress)
    app = create_app(components)

    async def chunks():
        yield b'{"prompt":"'
        await asyncio.sleep(1)
        yield b'synthetic"}'

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post("/v1/prompts", content=chunks())
        assert response.status_code == 408
        assert response.json() == {
            "status": "ERROR",
            "reason_codes": ["REQUEST_BODY_TIMEOUT"],
            "detail": "Request Timeout",
            "correlation_id": response.headers["x-correlation-id"],
        }
        assert response.headers["cache-control"] == "no-store"
        assert app.state.http_admission.active == 0
        assert app.state.admission.active == 0
        assert components.orchestrator.model.calls == []
