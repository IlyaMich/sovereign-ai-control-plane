"""Bounded, content-free DLP telemetry and authenticated HTTP diagnostics."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.domain.contracts import DetectionStatus, RequestStatus
from app.infrastructure.dlp_metrics import DLPMetrics
from tests.test_api import app_with_fakes
from tests.test_output_dlp import command, make_service


def test_dlp_metrics_have_fixed_labels_and_bounded_latencies():
    metrics = DLPMetrics(sample_window=2)
    metrics.input_detection(DetectionStatus.NO_PRIVATE_DETECTED)
    metrics.output_detection(DetectionStatus.PRIVATE, 1.0)
    metrics.output_detection(DetectionStatus.UNKNOWN, 3.0)
    metrics.output_detection(DetectionStatus.NO_PRIVATE_DETECTED, 5.0)
    metrics.outcome(RequestStatus.OUTPUT_BLOCKED)
    metrics.outcome(RequestStatus.COMPLETED, masked=True)
    metrics.failure("OUTPUT_DETECTOR_UNAVAILABLE")
    report = metrics.snapshot()
    assert report["input_classifications"] == {"NO_PRIVATE_DETECTED": 1}
    assert report["response_outcomes"] == {"COMPLETED": 1, "OUTPUT_BLOCKED": 1}
    assert report["masked_responses"] == 1
    assert report["output_detection_latency"]["samples"] == 2
    assert report["output_detection_latency"]["p95_ms"] == 5.0
    with pytest.raises(ValueError):
        metrics.failure("secret=alice@example.com")


def test_dlp_diagnostics_requires_authentication_and_exposes_no_text(audit):
    app = app_with_fakes(audit)
    with TestClient(app) as client:
        assert client.get("/v1/diagnostics/dlp").status_code == 401
        headers = {"X-API-Key": "a-secret-for-tests-that-is-long-enough"}
        assert client.post(
            "/v1/prompts", headers=headers,
            json={"prompt": "Testing the DLP telemetry counts."},
        ).status_code == 200
        result = client.get("/v1/diagnostics/dlp", headers=headers)
        assert result.status_code == 200
        assert result.headers["Cache-Control"] == "no-store"
        assert result.json()["scope"] == "process"
        assert result.json()["input_classifications"]["NO_PRIVATE_DETECTED"] == 1
        for sensitive in ("Testing the DLP", "local-tester", "a-secret-for-tests"):
            assert sensitive not in result.text


@pytest.mark.asyncio
async def test_output_counts_are_updated_after_signed_audit(audit):
    service, _ = make_service(audit, "Reply jane@example.com")
    result = await service.process(command())
    assert result.status == RequestStatus.OUTPUT_BLOCKED
    snapshot = service.dlp_metrics.snapshot()
    assert snapshot["input_classifications"]["NO_PRIVATE_DETECTED"] == 1
    assert snapshot["output_classifications"]["PRIVATE"] == 1
    assert snapshot["response_outcomes"]["OUTPUT_BLOCKED"] == 1
    assert snapshot["masked_responses"] == 0
    assert snapshot["output_detection_latency"]["samples"] == 1
