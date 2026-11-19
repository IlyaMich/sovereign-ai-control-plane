"""M7.3 audit executor: synthetic-only, local SQLite with real Ed25519 signatures."""

import asyncio
import threading

import pytest

from app.application.orchestrator import RequestOrchestrator
from app.audit.async_executor import (
    AuditCapacityExceeded,
    AuditExecutorClosed,
    BoundedAuditExecutor,
)
from app.audit.sqlite_store import AuditUnavailable
from app.audit.verify import verify_database
from app.detection.demo import DemoPatternDetector
from app.domain.contracts import Principal, PromptCommand, RequestStatus
from app.enforcement.gateway import EnforcementPlanner
from app.infrastructure.config import AuditExecutionLimits, Settings
from tests.conftest import RecordingModel, StaticPolicy


class BlockingAudit:
    def __init__(self, original):
        self.original = original
        self.started = threading.Event()
        self.release = threading.Event()

    def fingerprint(self, prompt):
        return self.original.fingerprint(prompt)

    def commit(self, request_id, tenant_id, event_type, payload):
        self.started.set()
        if not self.release.wait(5):
            raise AuditUnavailable("Synthetic audit gate was not released")
        return self.original.commit(request_id, tenant_id, event_type, payload)

    def get_events(self, request_id, tenant_id):
        return self.original.get_events(request_id, tenant_id)

    def check_writable(self):
        return self.original.check_writable()


def make_command(index):
    return PromptCommand(
        f"m7-3-synthetic-{index}",
        "synthetic local prompt",
        "sovereign-model",
        "GENERAL",
        Principal("tester", "local-tenant", ("tester",)),
    )


@pytest.mark.asyncio
async def test_audit_commit_does_not_block_loop_and_no_model_before_precommit(audit):
    blocked = BlockingAudit(audit)
    executor = BoundedAuditExecutor(blocked, max_jobs=1, queue_wait_seconds=0.05)
    model = RecordingModel(audit)
    orchestrator = RequestOrchestrator(
        DemoPatternDetector(),
        StaticPolicy(),
        blocked,
        model,
        EnforcementPlanner(),
        audit_executor=executor,
    )
    task = asyncio.create_task(orchestrator.process(make_command(1)))
    try:
        assert await asyncio.to_thread(blocked.started.wait, 2)
        await asyncio.wait_for(asyncio.sleep(0.02), timeout=0.3)
        assert model.calls == []
        assert audit.get_events(make_command(1).request_id, "local-tenant") == []
    finally:
        blocked.release.set()
    result = await asyncio.wait_for(task, timeout=3)
    await executor.aclose()
    assert result.status == RequestStatus.COMPLETED
    assert [
        x["event"]["event_type"]
        for x in audit.get_events(make_command(1).request_id, "local-tenant")
    ] == ["DECISION", "OUTCOME"]


@pytest.mark.asyncio
async def test_capacity_failure_prevents_inference(audit):
    blocked = BlockingAudit(audit)
    executor = BoundedAuditExecutor(blocked, max_jobs=1, queue_wait_seconds=0.03)
    held = asyncio.create_task(executor.commit("hold", "local-tenant", "DECISION", {}))
    model = RecordingModel(audit)
    orchestrator = RequestOrchestrator(
        DemoPatternDetector(),
        StaticPolicy(),
        blocked,
        model,
        EnforcementPlanner(),
        audit_executor=executor,
    )
    try:
        assert await asyncio.to_thread(blocked.started.wait, 2)
        with pytest.raises(AuditCapacityExceeded):
            await orchestrator.process(make_command(2))
        assert model.calls == []
        assert audit.get_events(make_command(2).request_id, "local-tenant") == []
    finally:
        blocked.release.set()
        await held
        await executor.aclose()


@pytest.mark.asyncio
async def test_cancelled_precommit_keeps_worker_running_but_never_invokes_model(audit):
    blocked = BlockingAudit(audit)
    executor = BoundedAuditExecutor(blocked, max_jobs=1, queue_wait_seconds=0.04)
    model = RecordingModel(audit)
    orchestrator = RequestOrchestrator(
        DemoPatternDetector(),
        StaticPolicy(),
        blocked,
        model,
        EnforcementPlanner(),
        audit_executor=executor,
    )
    first = asyncio.create_task(orchestrator.process(make_command(3)))
    try:
        assert await asyncio.to_thread(blocked.started.wait, 2)
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first
        assert model.calls == []
        with pytest.raises(AuditCapacityExceeded):
            await executor.commit("new", "local-tenant", "DECISION", {})
    finally:
        blocked.release.set()
        await executor.aclose()
    # A cancelled caller can leave a committed, unresolved DECISION; M7.4 reconciles it.
    records = audit.get_events(make_command(3).request_id, "local-tenant")
    assert [record["event"]["event_type"] for record in records] == ["DECISION"]
    assert (
        verify_database(str(audit.db_path), str(audit.key_path.with_suffix(".pub.pem")))[
            "verified_events"
        ]
        == 1
    )


@pytest.mark.asyncio
async def test_concurrent_requests_create_valid_chain(audit):
    executor = BoundedAuditExecutor(audit, max_jobs=16, queue_wait_seconds=2)
    model = RecordingModel(audit)
    orchestrator = RequestOrchestrator(
        DemoPatternDetector(),
        StaticPolicy(),
        audit,
        model,
        EnforcementPlanner(),
        audit_executor=executor,
    )
    try:
        results = await asyncio.gather(
            *(orchestrator.process(make_command(i)) for i in range(10, 22))
        )
    finally:
        await executor.aclose()
    assert all(result.status == RequestStatus.COMPLETED for result in results)
    for result in results:
        assert result.decision_receipt.sequence < result.outcome_receipt.sequence
        events = audit.get_events(result.request_id, "local-tenant")
        assert [x["event"]["event_type"] for x in events] == ["DECISION", "OUTCOME"]
    verification = verify_database(str(audit.db_path), str(audit.key_path.with_suffix(".pub.pem")))
    assert verification["verified_events"] == 24


@pytest.mark.asyncio
async def test_failed_outcome_cannot_claim_success(audit):
    class FailingOutcome:
        def get_events(self, request_id, tenant_id):
            return audit.get_events(request_id, tenant_id)

        def check_writable(self):
            return audit.check_writable()

        def fingerprint(self, prompt):
            return audit.fingerprint(prompt)

        def commit(self, request_id, tenant_id, event_type, payload):
            if event_type == "OUTCOME":
                raise AuditUnavailable("Synthetic unavailable outcome")
            return audit.commit(request_id, tenant_id, event_type, payload)

    executor = BoundedAuditExecutor(FailingOutcome())
    model = RecordingModel(audit)
    orchestrator = RequestOrchestrator(
        DemoPatternDetector(),
        StaticPolicy(),
        audit,
        model,
        EnforcementPlanner(),
        audit_executor=executor,
    )
    try:
        with pytest.raises(AuditUnavailable):
            await orchestrator.process(make_command(30))
    finally:
        await executor.aclose()
    assert len(model.calls) == 1
    assert [
        x["event"]["event_type"]
        for x in audit.get_events(make_command(30).request_id, "local-tenant")
    ] == ["DECISION"]


@pytest.mark.asyncio
async def test_read_and_readiness_probe_use_executor(audit):
    executor = BoundedAuditExecutor(audit)
    try:
        await executor.check_writable()
        receipt = await executor.commit("read-probe", "tenant", "DECISION", {"safe": True})
        rows = await executor.get_events("read-probe", "tenant")
        assert len(rows) == 1
        assert rows[0]["sequence"] == receipt.sequence
    finally:
        await executor.aclose()
    with pytest.raises(AuditExecutorClosed):
        await executor.check_writable()


@pytest.mark.parametrize("max_jobs", [0, -1, 1025, True, 3.14])
def test_invalid_job_count(max_jobs):
    with pytest.raises(ValueError):
        AuditExecutionLimits(max_jobs=max_jobs)


@pytest.mark.parametrize("seconds", [0, -1, float("inf"), float("nan"), True])
def test_invalid_wait(seconds):
    with pytest.raises(ValueError):
        AuditExecutionLimits(queue_wait_seconds=seconds)


def test_environment_is_configurable(monkeypatch):
    monkeypatch.setenv("CONTROL_PLANE_API_KEY", "synthetic-test-api-key-very-long")
    monkeypatch.setenv("MAX_AUDIT_JOBS", "5")
    monkeypatch.setenv("AUDIT_QUEUE_WAIT_SECONDS", "0.2")
    assert Settings.from_env().audit_execution == AuditExecutionLimits(5, 0.2)
    monkeypatch.setenv("AUDIT_QUEUE_WAIT_SECONDS", "nan")
    with pytest.raises(ValueError):
        Settings.from_env()


@pytest.mark.asyncio
async def test_queued_audit_commit_survives_awaiting_caller_cancellation(audit):
    blocked = BlockingAudit(audit)
    executor = BoundedAuditExecutor(blocked, max_jobs=2, queue_wait_seconds=0.1)
    first = asyncio.create_task(executor.commit("queue-1", "local-tenant", "DECISION", {}))
    try:
        assert await asyncio.to_thread(blocked.started.wait, 2)
        second = asyncio.create_task(executor.commit("queue-2", "local-tenant", "DECISION", {}))
        await asyncio.sleep(0.02)
        assert not second.done()
        second.cancel()
        with pytest.raises(asyncio.CancelledError):
            await second
    finally:
        blocked.release.set()
        await first
        await executor.aclose()
    assert [x["event"]["event_type"] for x in audit.get_events("queue-2", "local-tenant")] == [
        "DECISION"
    ]
    result = verify_database(str(audit.db_path), str(audit.key_path.with_suffix(".pub.pem")))
    assert result["verified_events"] == 2
