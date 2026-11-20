"""M7.6 ingress is checked before body consumption; all data is synthetic."""

import asyncio

import pytest

from app.api.admission import InFlightAdmission
from app.api.body_limit import RequestBodyLimitMiddleware
from app.api.ingress_limit import HTTPIngressLimitMiddleware
from app.infrastructure.config import IngressLimits, Settings
from tools.run_control_plane import server_limits


def scope(path="/v1/prompts"):
    return {
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "path": path,
        "headers": [],
        "query_string": b"",
        "scheme": "http",
        "server": ("test", 80),
    }


@pytest.mark.asyncio
async def test_slow_upload_consumes_outer_slot_and_excess_is_rejected_before_read():
    gate = asyncio.Event()
    entered = asyncio.Event()
    consumed = 0
    results = []

    async def app(scope_, receive, send):
        message = await receive()
        assert message["body"] == b"small"
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    wrapped = HTTPIngressLimitMiddleware(
        RequestBodyLimitMiddleware(app, max_bytes=16), InFlightAdmission(1)
    )

    async def slow_receive():
        nonlocal consumed
        consumed += 1
        entered.set()
        await gate.wait()
        return {"type": "http.request", "body": b"small", "more_body": False}

    async def unexpected_receive():
        nonlocal consumed
        consumed += 1
        raise AssertionError("Rejected request body must not be read")

    async def send(message):
        results.append(message)

    first = asyncio.create_task(wrapped(scope(), slow_receive, send))
    try:
        await asyncio.wait_for(entered.wait(), timeout=1)
        await wrapped(scope(), unexpected_receive, send)
        assert consumed == 1
        assert any(x.get("status") == 503 for x in results)
        assert not any(x.get("status") == 200 for x in results)
    finally:
        gate.set()
        await asyncio.wait_for(first, timeout=1)
    assert any(x.get("status") == 200 for x in results)
    assert wrapped.admission.active == 0
    assert wrapped.admission.rejected == 1


@pytest.mark.asyncio
async def test_ingress_slot_returns_on_app_error():
    admission = InFlightAdmission(1)

    async def broken_app(scope_, receive, send):
        raise RuntimeError("Synthetic failure")

    middleware = HTTPIngressLimitMiddleware(broken_app, admission)
    with pytest.raises(RuntimeError):
        await middleware(scope(), lambda: None, lambda m: None)
    assert admission.active == 0


@pytest.mark.parametrize("value", [0, -1, 1025, True, 1.5])
def test_ingress_setting_rejects_invalid_capacity(value):
    with pytest.raises(ValueError):
        IngressLimits(max_active_http_requests=value)


def test_configurable_ingress_and_server_limits(monkeypatch):
    monkeypatch.setenv("CONTROL_PLANE_API_KEY", "valid-test-secret-key-of-sufficient-length")
    monkeypatch.setenv("MAX_ACTIVE_HTTP_REQUESTS", "24")
    assert Settings.from_env().ingress.max_active_http_requests == 24
    monkeypatch.setenv("UVICORN_LIMIT_CONCURRENCY", "72")
    monkeypatch.setenv("UVICORN_KEEPALIVE_SECONDS", "4")
    assert server_limits() == (72, 4)
    monkeypatch.setenv("UVICORN_LIMIT_CONCURRENCY", "0")
    with pytest.raises(ValueError):
        server_limits()


def test_uvicorn_launcher_applies_outer_connection_limit(monkeypatch):
    from tools import run_control_plane

    seen = {}
    monkeypatch.setenv("UVICORN_LIMIT_CONCURRENCY", "70")
    monkeypatch.setenv("UVICORN_KEEPALIVE_SECONDS", "3")
    monkeypatch.setattr(run_control_plane.uvicorn, "run", lambda target, **kw: seen.update(kw))
    run_control_plane.main()
    assert seen["limit_concurrency"] == 70
    assert seen["timeout_keep_alive"] == 3
    assert seen["factory"] is True
    assert seen["proxy_headers"] is False
    assert seen["access_log"] is False
