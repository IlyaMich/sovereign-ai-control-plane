"""Logging regressions for ingress, integrity offload and release publication."""

import asyncio
import json
import logging
import queue
import threading
import uuid
from contextlib import contextmanager
from types import SimpleNamespace
from typing import cast

import httpx
import pytest
from fastapi.testclient import TestClient

from app.api.admission import InFlightAdmission
from app.api.ingress_limit import HTTPIngressLimitMiddleware
from app.api.logging import RequestLoggingMiddleware
from app.domain.contracts import Principal, PromptCommand, ReleaseVerifier
from app.infrastructure import logging as operational
from app.infrastructure.integrity_executor import (
    BoundedIntegrityExecutor,
    IntegrityCapacityExceeded,
    IntegrityExecutorClosed,
)
from app.policy.opa import OPAPolicyEvaluator
from app.release.approvals import ReleaseIntegrityError, make_payload, sign_approval
from tests.api.test_api import app_with_fakes
from tests.application.test_orchestrator import service
from tests.infrastructure.test_logging import SECRET
from tests.infrastructure.test_logging import events as events
from tests.policy.test_policy_snapshots import SOURCE
from tests.release.test_release_approvals import D, approval_fixture


@pytest.mark.asyncio
async def test_ingress_overload_has_one_warning_even_for_health_requests(events):
    admission = InFlightAdmission(1)
    assert admission.try_enter()

    async def inner(*args):
        pytest.fail("Overload must not invoke application")

    async def receive():
        pytest.fail("Overload must not read prompt body")

    messages = []

    async def send(message):
        messages.append(message)

    app = RequestLoggingMiddleware(HTTPIngressLimitMiddleware(inner, admission))
    for path in ("/health/ready", "/v1/prompts", "/" + SECRET):
        await app({"type": "http", "path": path, "method": "POST"}, receive, send)
    overload = [e for e in events if e["event"] == "http_ingress_rejected"]
    assert len(overload) == 1
    assert overload[0]["level"] == "WARNING"
    assert overload[0]["error_code"] == "HTTP_INGRESS_CAPACITY_EXCEEDED"
    assert overload[0]["route"] == "/health/ready"
    headers = [m["headers"] for m in messages if m["type"] == "http.response.start"]
    assert len(headers) == 3
    assert dict(headers[0])[b"x-correlation-id"].decode() == overload[0]["correlation_id"]
    assert not any(e["event"] == "request_completed" for e in events)
    assert SECRET not in json.dumps(events)


def test_uvicorn_overload_is_identified_limited_and_private(events, monkeypatch):
    records: queue.Queue[logging.LogRecord] = queue.Queue(maxsize=8)
    handler = operational.SafeQueueHandler(records)
    handler.setFormatter(operational.JSONFormatter())
    clock = [1.0]
    monkeypatch.setattr(operational.time, "monotonic", lambda: clock[0])
    record = logging.LogRecord(
        "uvicorn.error", logging.WARNING, SECRET, 1, "Exceeded concurrency limit.", (), None
    )
    handler.handle(record)
    handler.handle(record)
    clock[0] = 12.0
    handler.handle(record)
    assert records.qsize() == 2
    first, second = [json.loads(records.get_nowait().getMessage()) for _ in range(2)]
    assert first["event"] == "server_capacity_exceeded"
    assert first["error_code"] == "UVICORN_CAPACITY_EXCEEDED"
    assert second["suppressed"] == 1
    assert "correlation_id" not in first
    assert SECRET not in json.dumps([first, second])
    # Similar arbitrary messages do not get promoted or echoed.
    record.msg = "Exceeded concurrency limit. " + SECRET
    handler.handle(record)
    other = json.loads(records.get_nowait().getMessage())
    assert other["event"] == "runtime_message"
    assert SECRET not in json.dumps(other)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error,code",
    [
        (IntegrityCapacityExceeded, "INTEGRITY_CAPACITY_EXCEEDED"),
        (IntegrityExecutorClosed, "INTEGRITY_EXECUTOR_CLOSED"),
        (ReleaseIntegrityError, "UNTRUSTED_RELEASE"),
    ],
)
@pytest.mark.parametrize("recheck", [False, True])
async def test_release_fail_closed_decision_has_accurate_operational_code(
    audit, events, error, code, recheck
):
    calls = 0

    class Release:
        def verify_active(self, **kwargs):
            nonlocal calls
            calls += 1
            if not recheck or calls == 2:
                raise error(SECRET)
            return {"release_id": "a" * 64, "payload": {"detector_digest": "b" * 64}}

    orchestrator, model = service(audit)
    orchestrator.release_store = cast(ReleaseVerifier, Release())
    result = await orchestrator.process(
        PromptCommand(
            str(uuid.uuid4()),
            "synthetic content",
            "sovereign-model",
            "GENERAL",
            Principal("tester", "local-tenant", ("tester",)),
        )
    )
    assert result.decision.reason_codes == ("UNTRUSTED_RELEASE",)
    assert model.calls == []
    safety = [e for e in events if e["event"] == "request_safety_failure"]
    assert safety[-1]["error_code"] == code
    assert safety[-1]["level"] == ("ERROR" if error is ReleaseIntegrityError else "WARNING")
    assert SECRET not in json.dumps(events)


@pytest.mark.asyncio
async def test_opa_closed_executor_is_logged_as_unavailable(audit, events):
    executor = BoundedIntegrityExecutor()
    await executor.aclose()
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: pytest.fail("No OPA call"))
    ) as client:
        evaluator = OPAPolicyEvaluator(client, "http://opa", integrity_executor=executor)
        orchestrator, model = service(audit, policy=evaluator)
        result = await orchestrator.process(
            PromptCommand(
                str(uuid.uuid4()),
                "synthetic content",
                "sovereign-model",
                "GENERAL",
                Principal("tester", "local-tenant", ("tester",)),
            )
        )
    assert result.decision.reason_codes == ("POLICY_INTEGRITY_FAILURE",)
    assert model.calls == []
    assert any(
        e["event"] == "policy_verification_unavailable"
        and e["error_code"] == "INTEGRITY_EXECUTOR_CLOSED"
        for e in events
    )
    assert not any(
        e.get("error_code") in {"POLICY_INTEGRITY_FAILED", "POLICY_INTEGRITY_FAILURE"}
        for e in events
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("fail", [False, True])
@pytest.mark.parametrize("readiness", [False, True])
async def test_integrity_late_completion_keeps_context_after_cancellation(events, fail, readiness):
    started, release = threading.Event(), threading.Event()
    executor = BoundedIntegrityExecutor(max_jobs=1, max_waiters=0, worker_threads=1)
    correlation = str(uuid.uuid4())

    def held():
        started.set()
        assert release.wait(3)
        if fail:
            raise RuntimeError(SECRET)
        return "synthetic approval"

    token = operational.context.set({"correlation_id": correlation, "request_id": correlation})
    task = asyncio.create_task(executor.check_readiness(held) if readiness else executor.run(held))
    try:
        assert await asyncio.to_thread(started.wait, 1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert not any(e["event"] == "integrity_operation_finished" for e in events)
        if not readiness:
            assert executor.snapshot()["active_jobs"] == 1
    finally:
        operational.context.reset(token)
        release.set()
        await executor.aclose()
        await asyncio.sleep(0)
    finished = [e for e in events if e["event"] == "integrity_operation_finished"]
    assert len(finished) == 1
    assert finished[0]["correlation_id"] == correlation
    assert finished[0]["state"] == "CALLER_CANCELLED"
    assert finished[0]["level"] == ("ERROR" if fail else "DEBUG")
    assert finished[0]["queue_wait_ms"] >= 0
    assert finished[0]["processing_ms"] >= 0
    assert SECRET not in json.dumps(events)


@pytest.mark.asyncio
@pytest.mark.parametrize("waiters,stage", [(0, "waiters"), (1, "timeout")])
async def test_integrity_capacity_reasons_are_logged(events, waiters, stage):
    started, release = threading.Event(), threading.Event()
    executor = BoundedIntegrityExecutor(
        max_jobs=1, max_waiters=waiters, worker_threads=1, queue_wait_seconds=0.02
    )

    def held():
        started.set()
        assert release.wait(3)

    task = asyncio.create_task(executor.run(held))
    try:
        assert await asyncio.to_thread(started.wait, 1)
        with pytest.raises(IntegrityCapacityExceeded):
            await executor.run(lambda: pytest.fail("Capacity must stay bounded"))
        event = next(e for e in events if e["event"] == "integrity_capacity_exceeded")
        assert event["stage"] == stage
    finally:
        release.set()
        await task
        await executor.aclose()


@pytest.mark.parametrize("component", ["policy", "detector", "release"])
def test_readiness_preserves_failing_component_and_limits_error_logs(audit, events, component):
    app = app_with_fakes(audit)
    deps = app.state.components

    def broken(*args, **kwargs):
        raise RuntimeError(SECRET)

    def upstream(request):
        return httpx.Response(200, json={"result": {"policy_revision": "redaction-baseline-v3"}})

    probe = httpx.AsyncClient(transport=httpx.MockTransport(upstream))
    deps.client = probe
    deps.integrity_executor = BoundedIntegrityExecutor()
    if component == "policy":
        evaluator = OPAPolicyEvaluator(probe, "http://opa")
        setattr(evaluator, "snapshots", SimpleNamespace(verify_active=broken))
        deps.orchestrator.policy = evaluator
    elif component == "detector":
        setattr(deps.orchestrator.detector, "check_integrity", broken)
    else:
        deps.orchestrator.release_store = cast(
            ReleaseVerifier, SimpleNamespace(verify_active=broken)
        )
    with TestClient(app) as client:
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
    transitions = [e for e in events if e["event"] == "readiness_changed"]
    assert len(transitions) == 1
    assert transitions[0]["stage"] == component
    assert transitions[0]["error_code"] == component.upper() + "_READINESS_FAILED"
    assert len([e for e in events if e["level"] == "ERROR"]) == 1
    assert SECRET not in json.dumps(events)


def test_release_lock_timeout_is_safe_and_does_not_activate(tmp_path, events, monkeypatch):
    _, _, store, candidate, _ = approval_fixture(tmp_path)

    @contextmanager
    def locked(*args, **kwargs):
        raise TimeoutError(SECRET)
        yield

    monkeypatch.setattr("app.release.approvals.interprocess_lock", locked)
    with pytest.raises(ReleaseIntegrityError):
        store.activate(candidate)
    assert not store.active.exists()
    assert any(e.get("error_code") == "RELEASE_ACTIVATION_LOCK_TIMEOUT" for e in events)
    assert SECRET not in json.dumps(events)


def test_release_success_logs_only_verified_identities(tmp_path, events):
    _, _, store, candidate, document = approval_fixture(tmp_path)
    store.activate(candidate)
    logged = next(e for e in events if e["event"] == "release_activated")
    assert logged["release_id"] == document["release_id"]
    assert logged["policy_digest"] == document["payload"]["policy_digest"]
    assert str(tmp_path) not in json.dumps(events)


@pytest.mark.parametrize("rollback_fails", [False, True])
def test_release_publication_reports_rollback_result(tmp_path, events, monkeypatch, rollback_fails):
    from app.detection.provenance import canonical
    from app.policy.snapshots import build_snapshot

    private, _, store, candidate, genesis = approval_fixture(tmp_path)
    store.activate(candidate)
    source = tmp_path / "changed-source"
    source.mkdir()
    (source / "decision.rego").write_text(SOURCE + "\n# changed bytes\n")
    snapshot = build_snapshot(source, store.policy_store.archive, tmp_path / "unused-active")
    changed = sign_approval(
        make_payload(snapshot.policy_digest, snapshot.policy_revision, D, 2, genesis["release_id"]),
        private,
    )
    candidate.write_bytes(canonical(changed) + b"\n")

    def failed(*args):
        raise OSError(SECRET)

    monkeypatch.setattr("app.release.approvals._atomic_replace", failed)
    if rollback_fails:
        import os

        original = os.replace

        def fail_restore(src, dst):
            if str(src).find(".policy-backup-") >= 0:
                raise OSError(SECRET)
            return original(src, dst)

        monkeypatch.setattr("app.release.approvals.os.replace", fail_restore)
    with pytest.raises(OSError):
        store.activate(candidate)
    expected = "release_rollback_failed" if rollback_fails else "release_rollback_completed"
    assert any(e["event"] == expected for e in events)
    assert any(e.get("error_code") == "RELEASE_PUBLICATION_FAILED" for e in events)
    if not rollback_fails:
        assert store.verify_active()["release_id"] == genesis["release_id"]
    assert SECRET not in json.dumps(events)
    assert str(tmp_path) not in json.dumps(events)


@pytest.mark.asyncio
async def test_opa_saturated_executor_logs_capacity_without_trust_failure(events):
    from app.policy.opa import PolicyIntegrityError
    from tests.policy.test_policy_adapter import context as policy_context

    started, release = threading.Event(), threading.Event()
    executor = BoundedIntegrityExecutor(max_jobs=1, max_waiters=0, worker_threads=1)

    def held():
        started.set()
        assert release.wait(3)

    task = asyncio.create_task(executor.run(held))
    try:
        assert await asyncio.to_thread(started.wait, 1)
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda _: pytest.fail("No OPA call"))
        ) as client:
            evaluator = OPAPolicyEvaluator(client, "http://opa", integrity_executor=executor)
            with pytest.raises(PolicyIntegrityError):
                await evaluator.evaluate(policy_context())
        assert any(
            e["event"] == "policy_verification_unavailable"
            and e["error_code"] == "INTEGRITY_CAPACITY_EXCEEDED"
            for e in events
        )
        assert not any(e.get("error_code") == "POLICY_INTEGRITY_FAILED" for e in events)
    finally:
        release.set()
        await task
        await executor.aclose()


@pytest.mark.asyncio
async def test_shared_readiness_logs_one_completion_and_preserves_each_cancellation(events):
    started, release = threading.Event(), threading.Event()
    executor = BoundedIntegrityExecutor()
    first_id, second_id = str(uuid.uuid4()), str(uuid.uuid4())

    def held():
        started.set()
        assert release.wait(3)
        return True

    token = operational.context.set({"correlation_id": first_id})
    first = asyncio.create_task(executor.check_readiness(held))
    operational.context.set({"correlation_id": second_id})
    second = None
    try:
        assert await asyncio.to_thread(started.wait, 1)
        second = asyncio.create_task(executor.check_readiness(held))
        await asyncio.sleep(0)
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first
        assert executor.snapshot()["readiness_coalesced"] == 1
    finally:
        operational.context.reset(token)
        release.set()
        if second is not None:
            assert await second is True
        await executor.aclose()
        await asyncio.sleep(0)
    finished = [e for e in events if e["event"] == "integrity_operation_finished"]
    assert len(finished) == 1
    assert finished[0]["correlation_id"] == first_id
    cancelled = [e for e in events if e["event"] == "integrity_wait_cancelled"]
    assert len(cancelled) == 1
    assert cancelled[0]["correlation_id"] == first_id
