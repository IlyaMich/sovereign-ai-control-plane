"""Operational logging privacy, concurrency, failure and audit-boundary regressions."""

import asyncio
import io
import json
import logging
import queue
import threading
import uuid

import httpx
import pytest
from fastapi.testclient import TestClient

from app.audit.async_executor import BoundedAuditExecutor
from app.audit.sqlite_store import AuditUnavailable
from app.domain.contracts import Principal, PromptCommand
from app.enforcement.gateway import HTTPModelGateway, ModelUnavailable
from app.infrastructure import logging as operational
from app.policy.opa import OPAPolicyEvaluator, PolicyEvaluationError
from tests.api.test_api import app_with_fakes
from tests.application.test_orchestrator import service
from tests.policy.test_policy_adapter import context as policy_context

SECRET = "SYNTHETIC-PRIVATE-CONTENT-987654321"
HEADERS = {"X-API-Key": "a-secret-for-tests-that-is-long-enough"}


@pytest.fixture
def events():
    operational.configure_logging()
    logger = logging.getLogger("sovereign")
    previous = logger.level
    logger.setLevel(logging.DEBUG)
    operational._limits.clear()
    captured = []

    class Capture(logging.Handler):
        def emit(self, record):
            captured.append(json.loads(operational.JSONFormatter().format(record)))

    handler = Capture()
    logger.addHandler(handler)
    try:
        yield captured
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous)


def test_formatter_excludes_messages_exceptions_and_unapproved_fields():
    try:
        raise ValueError(SECRET)
    except ValueError:
        import sys

        record = logging.LogRecord(
            "uvicorn.error", logging.ERROR, SECRET, 1, SECRET, (), sys.exc_info()
        )
    record.fields = {
        "prompt": SECRET,
        "output": SECRET,
        "headers": SECRET,
        "request_id": SECRET,
        "route": "/" + SECRET,
        "destination_id": SECRET,
        "error_code": "OPA_TIMEOUT",
    }
    rendered = operational.JSONFormatter().format(record)
    assert SECRET not in rendered
    data = json.loads(rendered)
    assert data["event"] == "runtime_message"
    assert data["route"] == "UNMATCHED"
    assert data["destination_id"] == "UNREGISTERED"
    assert data["error_code"] == "OPA_TIMEOUT"


def test_queue_sanitizes_before_enqueue_and_counts_overflow():
    records: queue.Queue[logging.LogRecord] = queue.Queue(maxsize=1)
    handler = operational.SafeQueueHandler(records)
    handler.setFormatter(operational.JSONFormatter())
    record = logging.LogRecord("test", logging.ERROR, SECRET, 1, SECRET, (), None)
    record.fields = {"prompt": SECRET}
    handler.emit(record)
    assert SECRET not in str(records.queue[0].__dict__)
    before = operational.logging_snapshot()["dropped_events"]
    handler.emit(record)
    assert records.qsize() == 1
    assert operational.logging_snapshot()["dropped_events"] == before + 1


def test_output_failure_is_counted_without_raw_error_output():
    class BrokenStream(io.StringIO):
        def write(self, text):
            raise OSError(SECRET)

    before = operational.logging_snapshot()["output_errors"]
    handler = operational.SafeStreamHandler(BrokenStream())
    handler.emit(logging.LogRecord("test", logging.INFO, "", 1, SECRET, (), None))
    assert operational.logging_snapshot()["output_errors"] == before + 1


def test_request_summary_and_early_failures_are_correlated_and_private(audit, events):
    with TestClient(app_with_fakes(audit)) as client:
        valid = client.post(
            "/v1/prompts?secret=" + SECRET,
            headers=HEADERS,
            json={"prompt": SECRET},
        )
        assert valid.status_code == 200
        correlation = valid.headers["x-correlation-id"]
        summary = next(
            e for e in events if e["event"] == "request_completed" and e.get("http_status") == 200
        )
        assert summary["correlation_id"] == correlation
        assert summary["request_id"] == valid.json()["request_id"]
        assert summary["route"] == "/v1/prompts"
        assert summary["duration_ms"] >= 0
        invalid = client.post("/v1/prompts", headers=HEADERS, json={"prompt": {"secret": SECRET}})
        large = client.post("/v1/prompts", headers=HEADERS, content=SECRET * 1000)
        denied = client.post("/v1/prompts", json={"prompt": SECRET})
        client.get("/" + SECRET)
        assert [invalid.status_code, large.status_code, denied.status_code] == [422, 413, 401]
        for response in (invalid, large, denied):
            uuid.UUID(response.headers["x-correlation-id"])
        assert any(e.get("http_status") == 413 for e in events)
    rendered = json.dumps(events)
    assert SECRET not in rendered
    assert HEADERS["X-API-Key"] not in rendered


@pytest.mark.asyncio
async def test_concurrent_requests_do_not_share_context(audit, events):
    app = app_with_fakes(audit)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        results = await asyncio.gather(
            *[
                client.post("/v1/prompts", headers=HEADERS, json={"prompt": "synthetic"})
                for _ in range(4)
            ]
        )
    for response in results:
        assert response.status_code == 200
        matching = [
            e for e in events if e.get("correlation_id") == response.headers["x-correlation-id"]
        ]
        summaries = [e for e in matching if e["event"] == "request_completed"]
        assert len(summaries) == 1
        assert summaries[0]["request_id"] == response.json()["request_id"]
    assert operational.context.get() is None


@pytest.mark.asyncio
@pytest.mark.parametrize("adapter,prefix", [("policy", "OPA"), ("model", "MODEL")])
@pytest.mark.parametrize(
    "failure,suffix",
    [
        ("timeout", "TIMEOUT"),
        ("connection", "CONNECTION_ERROR"),
        ("status", "HTTP_ERROR"),
        ("response", "INVALID_RESPONSE"),
    ],
)
async def test_adapters_classify_failures_without_exception_content(
    adapter, prefix, failure, suffix, events
):
    def upstream(request):
        if failure == "timeout":
            raise httpx.ReadTimeout(SECRET, request=request)
        if failure == "connection":
            raise httpx.ConnectError(SECRET, request=request)
        if failure == "status":
            return httpx.Response(503, text=SECRET)
        return httpx.Response(200, text=SECRET)

    async with httpx.AsyncClient(transport=httpx.MockTransport(upstream)) as client:
        if adapter == "policy":
            with pytest.raises(PolicyEvaluationError):
                await OPAPolicyEvaluator(client, "http://opa").evaluate(policy_context())
        else:
            with pytest.raises(ModelUnavailable):
                await HTTPModelGateway(client, "http://model").invoke(
                    str(uuid.uuid4()), SECRET, "sovereign-model"
                )
    assert any(e.get("error_code") == prefix + "_" + suffix for e in events)
    assert SECRET not in json.dumps(events)


@pytest.mark.asyncio
async def test_logging_failure_preserves_audit_before_model(audit, events, monkeypatch):
    def broken(*args, **kwargs):
        raise OSError(SECRET)

    orchestrator, model = service(audit)
    monkeypatch.setattr(logging.getLogger("sovereign.events"), "log", broken)
    command = PromptCommand(
        str(uuid.uuid4()),
        SECRET,
        "sovereign-model",
        "GENERAL",
        Principal("local-tester", "local-tenant", ("tester",)),
    )
    result = await orchestrator.process(command)
    assert result.status.value == "COMPLETED"
    assert len(model.calls) == 1
    assert [
        e["event"]["event_type"] for e in audit.get_events(command.request_id, "local-tenant")
    ] == ["DECISION", "OUTCOME"]


@pytest.mark.asyncio
async def test_failed_precommit_is_logged_and_prevents_model(audit, events):
    class BrokenAudit:
        def fingerprint(self, prompt):
            return "f" * 64

        def commit(self, *args):
            raise AuditUnavailable(SECRET)

    orchestrator, model = service(BrokenAudit())
    command = PromptCommand(
        str(uuid.uuid4()),
        SECRET,
        "sovereign-model",
        "GENERAL",
        Principal("local-tester", "local-tenant", ("tester",)),
    )
    with pytest.raises(AuditUnavailable):
        await orchestrator.process(command)
    assert model.calls == []
    assert any(e["event"] == "audit_commit_failed" for e in events)
    assert not any(e["event"] == "decision_committed" for e in events)
    assert SECRET not in json.dumps(events)


@pytest.mark.asyncio
async def test_cancelled_audit_records_actual_late_completion(audit, events):
    started, release = threading.Event(), threading.Event()
    executor = BoundedAuditExecutor(audit)
    correlation = str(uuid.uuid4())

    def held_write():
        started.set()
        assert release.wait(timeout=3)
        return audit.commit(correlation, "local-tenant", "DECISION", {})

    token = operational.context.set({"correlation_id": correlation, "request_id": correlation})
    task = asyncio.create_task(executor.run(held_write))
    try:
        assert await asyncio.to_thread(started.wait, 1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    finally:
        operational.context.reset(token)
        release.set()
        await executor.aclose()
        await asyncio.sleep(0)
    late = next(e for e in events if e["event"] == "audit_operation_finished")
    assert late["state"] == "CALLER_CANCELLED"
    assert late["correlation_id"] == correlation
    assert late["error_code"] == "NONE"
    assert len(audit.get_events(correlation, "local-tenant")) == 1


def test_repetitive_events_are_limited_with_suppression_count(events, monkeypatch):
    clock = [1.0]
    monkeypatch.setattr(operational.time, "monotonic", lambda: clock[0])
    operational.event("authentication_rejected", limited=True)
    operational.event("authentication_rejected", limited=True)
    clock[0] = 12.0
    operational.event("authentication_rejected", limited=True)
    matching = [e for e in events if e["event"] == "authentication_rejected"]
    assert len(matching) == 2
    assert matching[-1]["suppressed"] == 1


def test_readiness_logs_only_state_transitions(audit, events):
    app = app_with_fakes(audit)
    expected_revision = app.state.components.settings.expected_policy_revision
    healthy = [False]

    def upstream(request):
        if not healthy[0]:
            raise httpx.ReadTimeout(SECRET, request=request)
        if request.method == "POST":
            return httpx.Response(200, json={"result": {"policy_revision": expected_revision}})
        return httpx.Response(200, json={"status": "UP"})

    with TestClient(app) as client:
        upstream_client = httpx.AsyncClient(transport=httpx.MockTransport(upstream))
        app.state.components.client = upstream_client
        try:
            assert (
                client.get(
                    "/health/ready", headers={"X-API-Key": "a-secret-for-tests-that-is-long-enough"}
                ).status_code
                == 503
            )
            assert (
                client.get(
                    "/health/ready", headers={"X-API-Key": "a-secret-for-tests-that-is-long-enough"}
                ).status_code
                == 503
            )
            healthy[0] = True
            app.state.readiness_probe.completed_at = float("-inf")
            assert (
                client.get(
                    "/health/ready", headers={"X-API-Key": "a-secret-for-tests-that-is-long-enough"}
                ).status_code
                == 200
            )
            assert (
                client.get(
                    "/health/ready", headers={"X-API-Key": "a-secret-for-tests-that-is-long-enough"}
                ).status_code
                == 200
            )
            transitions = [e for e in events if e["event"] == "readiness_changed"]
            assert [(e["state"], e["stage"]) for e in transitions] == [
                ("NOT_READY", "policy"),
                ("READY", "runtime"),
            ]
            assert not any(e["event"] == "request_completed" for e in events)
        finally:
            # TestClient's lifespan closes the injected async client.
            pass
    assert SECRET not in json.dumps(events)


def test_idempotency_key_never_appears_in_logs(audit, events):
    from app.audit.idempotency import IdempotencyStore

    app = app_with_fakes(audit)
    app.state.components.idempotency = IdempotencyStore(audit)
    with TestClient(app) as client:
        headers = {**HEADERS, "Idempotency-Key": SECRET}
        first = client.post("/v1/prompts", headers=headers, json={"prompt": "synthetic"})
        second = client.post("/v1/prompts", headers=headers, json={"prompt": "synthetic"})
        assert first.status_code == 200
        assert second.status_code == 409
        summary = next(e for e in events if e.get("http_status") == 409)
        assert summary["request_id"] == first.json()["request_id"]
    assert SECRET not in json.dumps(events)


@pytest.mark.asyncio
async def test_unhandled_exception_is_safe_and_context_is_reset(audit, events):
    app = app_with_fakes(audit)

    async def broken(command):
        raise RuntimeError(SECRET)

    app.state.components.orchestrator.process = broken
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, raise_app_exceptions=False), base_url="http://test"
    ) as client:
        response = await client.post("/v1/prompts", headers=HEADERS, json={"prompt": SECRET})
        assert response.status_code == 500
    assert operational.context.get() is None
    assert any(e["event"] == "request_failed" for e in events)
    assert any(e.get("http_status") == 500 for e in events)
    assert SECRET not in json.dumps(events)


def test_invalid_log_level_rejected_without_echoing_value(monkeypatch):
    # Temporarily clear only the config sentinel; preserve the live test listener.
    monkeypatch.setattr(operational, "_listener", None)
    monkeypatch.setenv("LOG_LEVEL", SECRET)
    with pytest.raises(ValueError) as error:
        operational.configure_logging()
    assert SECRET not in str(error.value)


@pytest.mark.asyncio
async def test_late_audit_failure_is_logged_after_cancellation(audit, events):
    started, release = threading.Event(), threading.Event()
    executor = BoundedAuditExecutor(audit)

    def held_failure():
        started.set()
        assert release.wait(timeout=3)
        raise AuditUnavailable(SECRET)

    task = asyncio.create_task(executor.run(held_failure))
    try:
        assert await asyncio.to_thread(started.wait, 1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    finally:
        release.set()
        await executor.aclose()
        await asyncio.sleep(0)
    assert any(
        e.get("error_code") == "AUDIT_OPERATION_FAILED" and e["state"] == "CALLER_CANCELLED"
        for e in events
    )
    assert SECRET not in json.dumps(events)
