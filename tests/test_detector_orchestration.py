"""M7.2 request-lifecycle integration: synthetic data and real signed SQLite audit."""

import asyncio
import threading

import pytest

from app.application.detector_executor import BoundedDetectorExecutor
from app.application.orchestrator import RequestOrchestrator
from app.audit.verify import verify_database
from app.domain.contracts import (
    DetectionResult,
    DetectionStatus,
    Effect,
    Finding,
    ModelResult,
    Obligation,
    PolicyDecision,
    Principal,
    PromptCommand,
    RequestStatus,
    Sensitivity,
)
from app.enforcement.gateway import Destination, DestinationRegistry, EnforcementPlanner
from tests.conftest import StaticPolicy


class SyntheticEmailDetector:
    def __init__(self):
        self.prompts = []

    def detect(self, prompt):
        self.prompts.append(prompt)
        entity = "a@example.test"
        if entity in prompt:
            start = prompt.index(entity)
            return DetectionResult(
                DetectionStatus.PRIVATE,
                Sensitivity.MEDIUM,
                (Finding("EMAIL_ADDRESS", start, start + len(entity), "synthetic", 1.0),),
                ("EMAIL_ADDRESS",),
                "synthetic-v1",
            )
        return DetectionResult(
            DetectionStatus.NO_PRIVATE_DETECTED,
            Sensitivity.NONE,
            (),
            ("EMAIL_ADDRESS",),
            "synthetic-v1",
        )


class RedactionPolicy:
    async def evaluate(self, context):
        return PolicyDecision(
            Effect.PERMIT,
            (
                Obligation("REDACT", categories=("EMAIL_ADDRESS",)),
                Obligation("ROUTE", "external-simulator"),
            ),
            ("SYNTHETIC_REDACTION",),
            "synthetic-policy-v1",
        )


class RecordingExternalModel:
    def __init__(self, audit):
        self.audit = audit
        self.calls = []

    async def invoke(self, request_id, prompt, destination_id):
        events = self.audit.get_events(request_id, "local-tenant")
        assert [e["event"]["event_type"] for e in events] == ["DECISION"]
        self.calls.append((request_id, prompt, destination_id))
        return ModelResult("external-simulator", "Synthetic output")


def external_command():
    return PromptCommand(
        "m7-2-verified-redaction",
        "contact a@example.test",
        "external-simulator",
        "GENERAL",
        Principal("tester", "local-tenant", ("tester",)),
    )


@pytest.mark.asyncio
async def test_redaction_and_second_scan_are_offloaded_before_invocation(audit):
    detector = SyntheticEmailDetector()
    executor = BoundedDetectorExecutor(detector, max_jobs=2)
    model = RecordingExternalModel(audit)
    registry = DestinationRegistry(
        (Destination("external-simulator", "http://egress-gateway:9010", "EXTERNAL_SIMULATED"),)
    )
    orchestrator = RequestOrchestrator(
        detector,
        RedactionPolicy(),
        audit,
        model,
        EnforcementPlanner(frozenset({"external-simulator"}), registry),
        detection_executor=executor,
    )
    try:
        result = await orchestrator.process(external_command())
    finally:
        await executor.aclose()
    assert result.status == RequestStatus.COMPLETED
    assert detector.prompts == ["contact a@example.test", "contact [REDACTED_EMAIL_ADDRESS]"]
    assert model.calls[0][1] == "contact [REDACTED_EMAIL_ADDRESS]"
    events = audit.get_events(result.request_id, "local-tenant")
    assert [e["event"]["event_type"] for e in events] == ["DECISION", "OUTCOME"]
    assert events[0]["event"]["payload"]["transformation"]["verification"]["status"] == (
        "NO_PRIVATE_DETECTED"
    )
    report = verify_database(str(audit.db_path), str(audit.key_path.with_suffix(".pub.pem")))
    assert report["verified_events"] == 2


class BusyDetector:
    def __init__(self):
        self.started = threading.Event()
        self.release = threading.Event()

    def detect(self, prompt):
        self.started.set()
        assert self.release.wait(timeout=5)
        return DetectionResult.unknown("SYNTHETIC_HOLD")


class NeverCalledModel:
    async def invoke(self, request_id, prompt, destination_id):
        raise AssertionError("No model call may occur on detector capacity exhaustion")


@pytest.mark.asyncio
async def test_detector_capacity_exhaustion_is_audited_and_fails_closed(audit):
    detector = BusyDetector()
    executor = BoundedDetectorExecutor(detector, max_jobs=1, queue_wait_seconds=0.05)
    held = asyncio.create_task(executor.detect("synthetic held job"))
    try:
        assert await asyncio.to_thread(detector.started.wait, 1)
        orchestrator = RequestOrchestrator(
            detector,
            StaticPolicy(),
            audit,
            NeverCalledModel(),
            EnforcementPlanner(),
            detection_executor=executor,
        )
        result = await orchestrator.process(
            PromptCommand(
                "m7-2-capacity",
                "synthetic request",
                "sovereign-model",
                "GENERAL",
                Principal("tester", "local-tenant", ("tester",)),
            )
        )
        assert result.status == RequestStatus.BLOCKED
        assert result.classification.reason_codes == ("DETECTION_CAPACITY_EXCEEDED",)
        assert result.decision.reason_codes == ("DETECTION_UNKNOWN",)
        events = audit.get_events(result.request_id, "local-tenant")
        assert [e["event"]["event_type"] for e in events] == ["DECISION", "OUTCOME"]
        assert events[1]["event"]["payload"]["model_invoked"] is False
    finally:
        detector.release.set()
        await held
        await executor.aclose()
