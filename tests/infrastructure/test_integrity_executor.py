"""M7.7: synthetic-only concurrency and fail-closed verifier regression tests."""

import asyncio
import threading
from types import SimpleNamespace
from typing import cast

import httpx
import pytest

from app.domain.contracts import ReleaseVerifier
from app.infrastructure.integrity_executor import (
    BoundedIntegrityExecutor,
    IntegrityCapacityExceeded,
    IntegrityExecutorClosed,
)
from app.policy.opa import OPAPolicyEvaluator, PolicyIntegrityError
from app.policy.snapshots import PolicySnapshotStore
from tests.policy.test_policy_adapter import context


@pytest.mark.parametrize(
    "args",
    [
        {"max_jobs": 0},
        {"max_jobs": True},
        {"max_waiters": -1},
        {"max_waiters": 1025},
        {"queue_wait_seconds": 0},
        {"queue_wait_seconds": float("nan")},
        {"worker_threads": 0},
        {"worker_threads": 9},
    ],
)
def test_invalid_executor_configuration(args):
    with pytest.raises(ValueError):
        BoundedIntegrityExecutor(**args)


@pytest.mark.asyncio
async def test_slow_verification_does_not_block_event_loop_or_release_cancelled_capacity():
    started = threading.Event()
    release = threading.Event()

    def slow():
        started.set()
        if not release.wait(5):
            raise RuntimeError("Synthetic gate timed out")
        return "verified"

    executor = BoundedIntegrityExecutor(
        max_jobs=1, max_waiters=0, worker_threads=1, queue_wait_seconds=0.05
    )
    first = asyncio.create_task(executor.run(slow))
    try:
        assert await asyncio.to_thread(started.wait, 2)
        await asyncio.wait_for(asyncio.sleep(0.02), 0.5)
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first
        assert executor.snapshot()["active_jobs"] == 1
        with pytest.raises(IntegrityCapacityExceeded):
            await executor.run(lambda: "must not run")
    finally:
        release.set()
        await executor.aclose()
    await asyncio.sleep(0)
    assert executor.snapshot()["active_jobs"] == 0
    with pytest.raises(IntegrityExecutorClosed):
        await executor.run(lambda: 1)


@pytest.mark.asyncio
async def test_parallel_readiness_probes_share_only_inflight_scan():
    started = threading.Event()
    release = threading.Event()
    scans = []

    def scan():
        scans.append(1)
        started.set()
        if not release.wait(5):
            raise RuntimeError("Synthetic gate timed out")
        return "approved"

    executor = BoundedIntegrityExecutor(max_jobs=2)
    first = asyncio.create_task(executor.check_readiness(scan))
    try:
        assert await asyncio.to_thread(started.wait, 2)
        second = asyncio.create_task(executor.check_readiness(scan))
        await asyncio.sleep(0.01)
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first
        assert executor.snapshot()["readiness_scans"] == 1
        assert executor.snapshot()["readiness_coalesced"] == 1
    finally:
        release.set()
    assert await second == "approved"
    assert await executor.check_readiness(scan) == "approved"
    assert len(scans) == 2
    await executor.aclose()


@pytest.mark.asyncio
async def test_full_readiness_scan_cannot_starve_request_verification():
    started = threading.Event()
    release = threading.Event()

    def scan():
        started.set()
        if not release.wait(5):
            raise RuntimeError("Synthetic gate timed out")

    executor = BoundedIntegrityExecutor(max_jobs=2)
    task = asyncio.create_task(executor.check_readiness(scan))
    try:
        assert await asyncio.to_thread(started.wait, 2)
        assert await asyncio.wait_for(executor.run(lambda: 42), 0.5) == 42
    finally:
        release.set()
        await task
        await executor.aclose()


@pytest.mark.asyncio
async def test_opa_pre_and_post_signature_checks_use_the_executor():
    started = threading.Event()
    release = threading.Event()

    class SlowSnapshots:
        def verify_active(self):
            started.set()
            if not release.wait(5):
                raise RuntimeError("Synthetic gate timed out")
            return SimpleNamespace(policy_digest="a" * 64, policy_revision="baseline-v1")

    class Releases:
        def __init__(self):
            self.checks = 0

        def verify_active(self, **kwargs):
            self.checks += 1
            return {"release_id": "one"}

    def response(_):
        return httpx.Response(
            200,
            json={
                "result": {
                    "effect": "PERMIT",
                    "obligations": [{"type": "ROUTE", "destination_id": "sovereign-model"}],
                    "reason_codes": ["TEST_PERMIT"],
                    "policy_revision": "baseline-v1",
                    "policy_digest": "a" * 64,
                }
            },
        )

    executor = BoundedIntegrityExecutor(max_jobs=2)
    releases = Releases()
    async with httpx.AsyncClient(transport=httpx.MockTransport(response)) as client:
        evaluator = OPAPolicyEvaluator(
            client,
            "http://opa",
            cast(PolicySnapshotStore, SlowSnapshots()),
            cast(ReleaseVerifier, releases),
            integrity_executor=executor,
        )
        task = asyncio.create_task(evaluator.evaluate(context()))
        try:
            assert await asyncio.to_thread(started.wait, 2)
            await asyncio.wait_for(asyncio.sleep(0.02), 0.5)
            assert not task.done()
        finally:
            release.set()
        assert (await task).effect.value == "PERMIT"
        assert releases.checks == 2
    await executor.aclose()


@pytest.mark.asyncio
async def test_opa_executor_saturation_is_treated_as_integrity_failure():
    started = threading.Event()
    release = threading.Event()

    def hold():
        started.set()
        if not release.wait(5):
            raise RuntimeError("Synthetic gate timed out")

    executor = BoundedIntegrityExecutor(max_jobs=1, max_waiters=0, worker_threads=1)
    task = asyncio.create_task(executor.run(hold))
    try:
        assert await asyncio.to_thread(started.wait, 2)
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda _: pytest.fail("OPA must not be called"))
        ) as client:
            evaluator = OPAPolicyEvaluator(
                client,
                "http://opa",
                cast(PolicySnapshotStore, SimpleNamespace(verify_active=lambda: None)),
                integrity_executor=executor,
            )
            with pytest.raises(PolicyIntegrityError):
                await evaluator.evaluate(context())
    finally:
        release.set()
        await task
        await executor.aclose()
