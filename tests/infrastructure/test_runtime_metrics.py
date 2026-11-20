"""M7.5 local diagnostics: synthetic-only, no model/OPA container required."""

import asyncio
import threading

import pytest
from fastapi.testclient import TestClient

from app.application.detector_executor import BoundedDetectorExecutor
from app.audit.async_executor import BoundedAuditExecutor
from app.domain.contracts import DetectionResult
from app.infrastructure.config import Settings, TelemetrySettings
from app.infrastructure.runtime_metrics import ExecutorMetrics, LoopLagMonitor
from tests.api.test_api import app_with_fakes


def test_bounded_rolling_metrics_and_percentiles():
    metrics = ExecutorMetrics(capacity=2, sample_window=2)
    metrics.begin_wait()
    assert metrics.snapshot()["waiting_for_capacity"] == 1
    metrics.end_wait()
    metrics.submit("decision")
    metrics.finish(wait_ms=2.0, processing_ms=3.0, failed=False)
    metrics.submit("outcome")
    metrics.finish(wait_ms=4.0, processing_ms=5.0, failed=True)
    metrics.submit("decision")
    metrics.finish(wait_ms=6.0, processing_ms=9.0, failed=False)
    metrics.refuse()
    snapshot = metrics.snapshot()
    assert snapshot["submitted"] == 3
    assert snapshot["completed"] == 3
    assert snapshot["failed"] == 1
    assert snapshot["capacity_rejections"] == 1
    assert snapshot["submitted_by_kind"] == {"decision": 2, "outcome": 1}
    assert snapshot["queue_wait"] == {
        "samples": 2,
        "p50_ms": 4.0,
        "p95_ms": 6.0,
        "max_ms": 6.0,
    }
    assert snapshot["processing"]["p95_ms"] == 9.0
    assert snapshot["active_jobs"] == 0


@pytest.mark.asyncio
async def test_loop_lag_monitor_bounded_and_shutdown():
    monitor = LoopLagMonitor(interval_seconds=0.01, sample_window=3)
    assert monitor.snapshot()["samples"] == 0
    monitor.start()
    await asyncio.sleep(0.06)
    current = monitor.snapshot()
    assert 1 <= current["samples"] <= 3
    assert current["p95_ms"] is not None
    await monitor.aclose()
    await monitor.aclose()


class FakeDetector:
    def __init__(self):
        self.prompts = []

    def detect(self, prompt):
        self.prompts.append(prompt)
        return DetectionResult.unknown("TEST_ONLY")


@pytest.mark.asyncio
async def test_detector_metrics_include_real_thread_work():
    fake = FakeDetector()
    executor = BoundedDetectorExecutor(fake, max_jobs=2, sample_window=8)
    try:
        result = await executor.detect("synthetic test")
        assert result.reason_codes == ("TEST_ONLY",)
        await asyncio.sleep(0.01)  # Completion callback is scheduled onto event loop
        snapshot = executor.metrics.snapshot()
        assert snapshot["submitted"] == snapshot["completed"] == 1
        assert snapshot["active_jobs"] == 0
        assert snapshot["queue_wait"]["samples"] == 1
        assert snapshot["processing"]["p95_ms"] is not None
    finally:
        await executor.aclose()


@pytest.mark.asyncio
async def test_audit_metrics_count_signed_commits_and_auxiliary_work(audit):
    executor = BoundedAuditExecutor(audit, max_jobs=2, sample_window=8)
    try:
        receipt = await executor.commit("m7-5-test", "local-tenant", "DECISION", {"ok": True})
        assert receipt.sequence >= 1
        assert await executor.run(lambda: 42) == 42
        await asyncio.sleep(0.01)
        snapshot = executor.metrics.snapshot()
        assert snapshot["submitted_by_kind"] == {"aux": 1, "commit_decision": 1}
        assert snapshot["completed"] == 2
        assert snapshot["failed"] == 0
        assert snapshot["active_jobs"] == 0
    finally:
        await executor.aclose()


@pytest.mark.asyncio
async def test_cancelled_detector_does_not_appear_finished_until_worker_stops():
    class HeldDetector:
        def __init__(self):
            self.started = threading.Event()
            self.release = threading.Event()

        def detect(self, prompt):
            self.started.set()
            assert self.release.wait(timeout=3)
            return DetectionResult.unknown("HELD")

    detector = HeldDetector()
    executor = BoundedDetectorExecutor(detector, max_jobs=1, sample_window=4)
    task = asyncio.create_task(executor.detect("synthetic held"))
    try:
        assert await asyncio.to_thread(detector.started.wait, 1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert executor.metrics.snapshot()["active_jobs"] == 1
    finally:
        detector.release.set()
        await executor.aclose()
    await asyncio.sleep(0.01)
    assert executor.metrics.snapshot()["active_jobs"] == 0


def test_diagnostics_require_auth_and_expose_no_request_data(audit):
    app = app_with_fakes(audit)
    with TestClient(app) as client:
        assert client.get("/v1/diagnostics/concurrency").status_code == 401
        response = client.get(
            "/v1/diagnostics/concurrency",
            headers={"X-API-Key": "a-secret-for-tests-that-is-long-enough"},
        )
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"
        assert response.json()["scope"] == "process"
        assert response.json()["detector"] is None  # Fake test app has no worker
        assert response.json()["admission"]["active"] == 0
        assert "a-secret-for-tests" not in response.text


@pytest.mark.parametrize(
    "interval,window",
    [(0, 10), (0.049, 10), (5.01, 10), (0.25, 0), (0.25, 4097)],
)
def test_invalid_telemetry_settings_are_rejected(interval, window):
    with pytest.raises(ValueError):
        TelemetrySettings(loop_lag_interval_seconds=interval, sample_window=window)


def test_configurable_telemetry(monkeypatch):
    monkeypatch.setenv("CONTROL_PLANE_API_KEY", "a-valid-synthetic-local-test-key")
    monkeypatch.setenv("LOOP_LAG_INTERVAL_SECONDS", "0.4")
    monkeypatch.setenv("METRICS_SAMPLE_WINDOW", "64")
    assert Settings.from_env().telemetry == TelemetrySettings(0.4, 64)
