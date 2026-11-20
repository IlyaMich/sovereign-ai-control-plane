"""M7.6 bounds audit waiters and auxiliary requests under real thread cancellation."""

import asyncio
import threading

import pytest

from app.audit.async_executor import AuditCapacityExceeded, BoundedAuditExecutor
from app.infrastructure.config import AuditExecutionLimits


class HeldStore:
    def __init__(self):
        self.started = threading.Event()
        self.release = threading.Event()
        self.calls = []

    def commit(self, request_id, tenant_id, event_type, payload):
        self.calls.append(event_type)
        self.started.set()
        if not self.release.wait(5):
            raise RuntimeError("HeldStore timeout")
        return event_type

    def get_events(self, request_id, tenant_id):
        return self.commit(request_id, tenant_id, "READ", {})

    def check_writable(self):
        self.commit("probe", "t", "PROBE", {})


@pytest.mark.asyncio
async def test_waiter_bound_fails_fast_and_waiter_cancellation_releases_capacity():
    store = HeldStore()
    lane = BoundedAuditExecutor(
        store, max_jobs=1, max_waiters=1, max_auxiliary_jobs=1, queue_wait_seconds=1
    )
    running = asyncio.create_task(lane.commit("1", "t", "DECISION", {}))
    waiter = None
    try:
        assert await asyncio.to_thread(store.started.wait, 1)
        waiter = asyncio.create_task(lane.commit("2", "t", "DECISION", {}))
        for _ in range(100):
            if lane.capacity_snapshot()["waiting_for_slot"] == 1:
                break
            await asyncio.sleep(0.01)
        assert lane.capacity_snapshot()["waiting_for_slot"] == 1
        with pytest.raises(AuditCapacityExceeded):
            await lane.commit("3", "t", "DECISION", {})
        waiter.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiter
        assert lane.capacity_snapshot()["waiting_for_slot"] == 0
        assert store.calls == ["DECISION"]
    finally:
        store.release.set()
        await running
        await lane.aclose()


@pytest.mark.asyncio
async def test_auxiliary_limit_stays_reserved_after_caller_cancellation():
    store = HeldStore()
    lane = BoundedAuditExecutor(
        store, max_jobs=2, max_waiters=1, max_auxiliary_jobs=1, queue_wait_seconds=1
    )
    lookup = asyncio.create_task(lane.get_events("1", "t"))
    decision = None
    try:
        assert await asyncio.to_thread(store.started.wait, 1)
        lookup.cancel()
        with pytest.raises(asyncio.CancelledError):
            await lookup
        assert lane.capacity_snapshot()["auxiliary_inflight"] == 1
        with pytest.raises(AuditCapacityExceeded):
            await lane.check_writable()
        # An audit DECISION can enter despite auxiliary saturation.
        decision = asyncio.create_task(lane.commit("2", "t", "DECISION", {}))
        await asyncio.sleep(0.02)
        assert lane.capacity_snapshot()["auxiliary_inflight"] == 1
    finally:
        store.release.set()
        if decision is not None:
            await decision
        await lane.aclose()
    for _ in range(100):
        if lane.capacity_snapshot()["auxiliary_inflight"] == 0:
            break
        await asyncio.sleep(0.01)
    assert lane.capacity_snapshot()["auxiliary_inflight"] == 0
    assert store.calls == ["READ", "DECISION"]


@pytest.mark.parametrize("value", [0, -1, 1025, True, 1.5])
def test_audit_waiter_limits_are_validated(value):
    with pytest.raises(ValueError):
        AuditExecutionLimits(max_waiters=value)
    with pytest.raises(ValueError):
        AuditExecutionLimits(max_auxiliary_jobs=value)
