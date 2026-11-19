"""M7.2 executor tests: no spaCy installation or running containers necessary."""

import asyncio
import threading

import pytest

from app.application.detector_executor import (
    BoundedDetectorExecutor,
    DetectorCapacityExceeded,
    DetectorExecutorClosed,
)
from app.domain.contracts import DetectionResult
from app.infrastructure.config import DetectorExecutionLimits, Settings


class BlockingDetector:
    def __init__(self):
        self.started = threading.Event()
        self.release = threading.Event()
        self.active = 0
        self.peak = 0
        self.calls = []
        self.lock = threading.Lock()

    def detect(self, prompt):
        with self.lock:
            self.active += 1
            self.peak = max(self.peak, self.active)
            self.calls.append(prompt)
        self.started.set()
        try:
            if not self.release.wait(timeout=5):
                raise RuntimeError("Test detector stalled")
            return DetectionResult.unknown("SYNTHETIC_TEST")
        finally:
            with self.lock:
                self.active -= 1


@pytest.mark.asyncio
async def test_detector_runs_off_event_loop_and_serializes_shared_analyzer():
    detector = BlockingDetector()
    worker = BoundedDetectorExecutor(detector, max_jobs=2, queue_wait_seconds=1)
    try:
        first = asyncio.create_task(worker.detect("synthetic one"))
        assert await asyncio.to_thread(detector.started.wait, 1)
        second = asyncio.create_task(worker.detect("synthetic two"))
        # Event loop must continue running even when detector is blocked.
        await asyncio.wait_for(asyncio.sleep(0.02), timeout=0.3)
        detector.release.set()
        assert (await first).reason_codes == ("SYNTHETIC_TEST",)
        assert (await second).reason_codes == ("SYNTHETIC_TEST",)
        assert detector.peak == 1
        assert detector.calls == ["synthetic one", "synthetic two"]
    finally:
        detector.release.set()
        await worker.aclose()


@pytest.mark.asyncio
async def test_cancelled_await_does_not_free_a_running_worker_slot():
    detector = BlockingDetector()
    worker = BoundedDetectorExecutor(detector, max_jobs=1, queue_wait_seconds=0.05)
    try:
        first = asyncio.create_task(worker.detect("synthetic cancel"))
        assert await asyncio.to_thread(detector.started.wait, 1)
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first
        with pytest.raises(DetectorCapacityExceeded):
            await worker.detect("must not enter while first job is running")
        assert detector.calls == ["synthetic cancel"]
        detector.release.set()
        # Thread completion schedules a permit release on the event loop.
        for _ in range(100):
            if detector.active == 0:
                await asyncio.sleep(0.01)
                break
            await asyncio.sleep(0.01)
        assert (await worker.detect("synthetic retry")).status.value == "UNKNOWN"
    finally:
        detector.release.set()
        await worker.aclose()


@pytest.mark.asyncio
async def test_closed_executor_rejects_new_submissions():
    detector = BlockingDetector()
    worker = BoundedDetectorExecutor(detector)
    await worker.aclose()
    with pytest.raises(DetectorExecutorClosed):
        await worker.detect("synthetic post-close")


@pytest.mark.parametrize("value", [0, -1, 1025, True, 1.5])
def test_invalid_job_limits_rejected(value):
    with pytest.raises(ValueError):
        DetectorExecutionLimits(max_jobs=value)


@pytest.mark.parametrize("value", [0, -1, float("nan"), float("inf"), True])
def test_invalid_wait_time_rejected(value):
    with pytest.raises(ValueError):
        DetectorExecutionLimits(queue_wait_seconds=value)


def test_detector_limits_environment(monkeypatch):
    monkeypatch.setenv("CONTROL_PLANE_API_KEY", "valid-key-for-local-synthetic-testing")
    monkeypatch.setenv("MAX_DETECTOR_JOBS", "3")
    monkeypatch.setenv("DETECTOR_QUEUE_WAIT_SECONDS", "0.25")
    limits = Settings.from_env().detector_execution
    assert limits == DetectorExecutionLimits(max_jobs=3, queue_wait_seconds=0.25)
    monkeypatch.setenv("DETECTOR_QUEUE_WAIT_SECONDS", "nan")
    with pytest.raises(ValueError):
        Settings.from_env()


@pytest.mark.asyncio
async def test_shutdown_drain_await_is_nonblocking_and_rejects_new_work():
    detector = BlockingDetector()
    worker = BoundedDetectorExecutor(detector, max_jobs=1)
    submitted = asyncio.create_task(worker.detect("synthetic shutdown"))
    try:
        assert await asyncio.to_thread(detector.started.wait, 1)
        closing = asyncio.create_task(worker.aclose())
        await asyncio.wait_for(asyncio.sleep(0.02), timeout=0.3)
        with pytest.raises(DetectorExecutorClosed):
            await worker.detect("must reject during shutdown")
    finally:
        detector.release.set()
    await submitted
    await asyncio.wait_for(closing, timeout=2)
