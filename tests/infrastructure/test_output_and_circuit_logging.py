"""Privacy and audit-order regressions for output DLP and dependency diagnostics."""

import json
import logging
import time
import uuid
from dataclasses import replace
from typing import cast

import httpx
import pytest
from fastapi.testclient import TestClient

from app.audit.sqlite_store import AuditUnavailable
from app.detection.demo import DemoPatternDetector
from app.domain.contracts import DetectionResult, ReleaseVerifier, RequestStatus
from app.enforcement.gateway import HTTPModelGateway, ModelUnavailable
from app.infrastructure.config import APIOperations
from app.infrastructure.integrity_executor import IntegrityCapacityExceeded, IntegrityExecutorClosed
from app.infrastructure.resilience import CircuitBreaker, ResilientHTTP
from app.policy.opa import OPAPolicyEvaluator, PolicyEvaluationError
from app.release.approvals import ReleaseIntegrityError
from tests.api.test_api import app_with_fakes
from tests.enforcement.test_output_dlp import OutputMaskPolicy, OutputPolicy, command, make_service
from tests.infrastructure.test_logging import HEADERS, SECRET
from tests.infrastructure.test_logging import events as events
from tests.policy.test_output_policy_adapter import context as output_context
from tests.policy.test_policy_adapter import context as input_context


def request():
    return replace(command(), request_id=str(uuid.uuid4()))


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["clean", "blocked", "masked"])
async def test_output_summary_follows_signed_outcome_without_content(audit, events, mode):
    output = "Reply jane@example.com" if mode != "clean" else SECRET
    kwargs = (
        {"output_policy": OutputMaskPolicy(), "output_masking_enabled": True}
        if mode == "masked"
        else {}
    )
    svc, _ = make_service(audit, output, **kwargs)
    cmd = request()
    result = await svc.process(cmd)
    summary = next(e for e in events if e["event"] == "output_decision_committed")
    assert summary["request_id"] == cmd.request_id
    assert summary["sequence"] == result.outcome_receipt.sequence
    assert audit.get_events(cmd.request_id, "tenant")[-1]["event"]["event_type"] == "OUTCOME"
    assert summary["effect"] == ("DENY" if mode == "blocked" else "PERMIT")
    assert summary["execution_status"] == ("OUTPUT_BLOCKED" if mode == "blocked" else "COMPLETED")
    assert summary["transformed"] is (mode == "masked")
    assert not any(e["level"] == "ERROR" for e in events)
    assert SECRET not in json.dumps(events)
    assert "jane@example.com" not in json.dumps(events)


@pytest.mark.asyncio
async def test_failed_output_audit_never_emits_committed_summary(audit, events):
    class BrokenOutcome:
        def fingerprint(self, value):
            return audit.fingerprint(value)

        def commit(self, request_id, tenant, event_type, payload):
            if event_type == "OUTCOME":
                raise AuditUnavailable(SECRET)
            return audit.commit(request_id, tenant, event_type, payload)

    svc, _ = make_service(audit, SECRET)
    svc.audit = BrokenOutcome()
    cmd = request()
    with pytest.raises(AuditUnavailable):
        await svc.process(cmd)
    assert not any(e["event"] == "output_decision_committed" for e in events)
    assert len(audit.get_events(cmd.request_id, "tenant")) == 1
    assert SECRET not in json.dumps(events)


@pytest.mark.asyncio
@pytest.mark.parametrize("output", ["", "X" * 100, "invalid surrogate \ud800"])
async def test_invalid_content_has_safe_failure_event(audit, events, output):
    svc, _ = make_service(audit, output, max_output_bytes=32)
    result = await svc.process(request())
    assert result.service_error == "OUTPUT_INVALID_CONTENT"
    failure = next(e for e in events if e["event"] == "output_content_invalid")
    assert failure["level"] == "ERROR"
    assert failure["error_code"] == "OUTPUT_INVALID_CONTENT"
    assert "invalid surrogate" not in json.dumps(events)
    assert "X" * 50 not in json.dumps(events)


@pytest.mark.asyncio
@pytest.mark.parametrize("mask", [False, True])
async def test_invalid_output_policy_plans_emit_errors(audit, events, mask):
    policy = OutputMaskPolicy() if mask else OutputPolicy(permit_private=True)
    svc, _ = make_service(audit, "Reply jane@example.com", output_policy=policy)
    result = await svc.process(request())
    assert result.service_error == "OUTPUT_INVALID_POLICY_PLAN"
    assert any(e["event"] == "output_policy_plan_invalid" and e["level"] == "ERROR" for e in events)
    assert "jane@example.com" not in json.dumps(events)


@pytest.mark.asyncio
@pytest.mark.parametrize("exception", [False, True])
async def test_mask_verification_failure_is_logged_without_exception_or_matches(
    audit, events, exception
):
    class Unverified(DemoPatternDetector):
        def detect(self, prompt):
            if "[REDACTED_EMAIL_ADDRESS]" in prompt:
                if exception:
                    raise RuntimeError(SECRET + prompt)
                return DetectionResult.unknown("UNKNOWN_AFTER_MASK")
            return super().detect(prompt)

    svc, _ = make_service(
        audit,
        "Reply jane@example.com",
        detector=Unverified(),
        output_policy=OutputMaskPolicy(),
        output_masking_enabled=True,
    )
    result = await svc.process(request())
    assert result.output is None
    assert result.service_error == "OUTPUT_MASK_VERIFICATION_FAILED"
    failure = next(e for e in events if e["event"] == "output_mask_verification_failed")
    assert failure["level"] == "ERROR"
    assert failure["stage"] == "output_mask"
    assert SECRET not in json.dumps(events)
    assert "jane@example.com" not in json.dumps(events)
    assert "[REDACTED_EMAIL_ADDRESS]" not in json.dumps(events)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error,code,level",
    [
        (IntegrityCapacityExceeded, "INTEGRITY_CAPACITY_EXCEEDED", "WARNING"),
        (IntegrityExecutorClosed, "INTEGRITY_EXECUTOR_CLOSED", "WARNING"),
        (ReleaseIntegrityError, "OUTPUT_UNTRUSTED_RELEASE", "ERROR"),
        (OSError, "OUTPUT_RELEASE_VERIFICATION_FAILED", "ERROR"),
    ],
)
async def test_output_release_failure_distinguishes_capacity_and_trust(
    audit, events, error, code, level
):
    class Detector(DemoPatternDetector):
        def detect(self, text):
            return replace(super().detect(text), artifact_digest="d" * 64)

    class Release:
        def __init__(self):
            self.calls = 0

        def verify_active(self, **kwargs):
            self.calls += 1
            if self.calls == 3:
                raise error(SECRET)
            return {
                "release_id": "b" * 64,
                "signer_key_id": "c" * 64,
                "payload": {
                    "generation": 1,
                    "policy_digest": "e" * 64,
                    "detector_digest": "d" * 64,
                },
            }

    svc, _ = make_service(audit, SECRET, detector=Detector())
    svc.release_store = cast(ReleaseVerifier, Release())
    result = await svc.process(request())
    assert result.output is None
    assert result.output_decision.reason_codes == ("OUTPUT_UNTRUSTED_RELEASE",)
    failure = next(e for e in events if e.get("stage") == "output_release")
    assert failure["error_code"] == code
    assert failure["level"] == level
    summary = next(e for e in events if e["event"] == "output_decision_committed")
    assert summary["error_code"] == code
    assert SECRET not in json.dumps(events)


@pytest.mark.asyncio
@pytest.mark.parametrize("dependency", ["opa", "model"])
async def test_circuit_rejections_are_limited_and_recovery_is_logged(events, dependency):
    healthy, calls = [False], []

    def upstream(request):
        calls.append(request)
        if not healthy[0]:
            return httpx.Response(503, text=SECRET)
        if dependency == "model":
            return httpx.Response(200, json={"model_id": "sovereign-model", "output": SECRET})
        return httpx.Response(
            200,
            json={
                "result": {
                    "effect": "DENY",
                    "obligations": [],
                    "reason_codes": ["TEST_DENY"],
                    "policy_revision": "v1",
                }
            },
        )

    transport = ResilientHTTP(APIOperations(circuit_failure_threshold=1, circuit_reset_seconds=1))
    async with httpx.AsyncClient(transport=httpx.MockTransport(upstream)) as client:
        evaluator = OPAPolicyEvaluator(client, "http://opa", resilient_http=transport)
        gateway = HTTPModelGateway(client, "http://model", resilient_http=transport)

        async def invoke():
            if dependency == "opa":
                return await evaluator.evaluate(input_context())
            return await gateway.invoke(str(uuid.uuid4()), SECRET, "sovereign-model")

        expected = PolicyEvaluationError if dependency == "opa" else ModelUnavailable
        with pytest.raises(expected):
            await invoke()
        before = len(events)
        for _ in range(3):
            with pytest.raises(expected):
                await invoke()
        assert len(calls) == 1
        rejected = events[before:]
        assert len(rejected) == 1
        assert rejected[0]["level"] == "WARNING"
        assert rejected[0]["error_code"] == dependency.upper() + "_CIRCUIT_OPEN"
        healthy[0] = True
        transport.circuits[dependency].opened_at = time.monotonic() - 2
        await invoke()
    transitions = [e for e in events if e["event"].startswith("dependency_circuit_")]
    assert [e["state"] for e in transitions] == ["OPEN", "HALF_OPEN", "CLOSED"]
    assert all(e["stage"] == dependency for e in transitions)
    assert SECRET not in json.dumps(events)


def test_old_generation_completion_does_not_log_false_recovery(events):
    breaker = CircuitBreaker(1, 1, dependency="model")
    previous = breaker.enter()
    breaker.finish(previous, True)
    breaker.finish(previous, False)
    assert not any(e["event"] == "dependency_circuit_closed" for e in events)
    breaker.opened_at = time.monotonic() - 2
    probe = breaker.enter()
    breaker.finish(probe, True)
    breaker.opened_at = time.monotonic() - 2
    recovered = breaker.enter()
    breaker.finish(recovered, False)
    assert [e["state"] for e in events] == ["OPEN", "HALF_OPEN", "OPEN", "HALF_OPEN", "CLOSED"]


@pytest.mark.asyncio
async def test_probe_retry_is_debug_metadata_only(events):
    calls = []

    def upstream(request):
        calls.append(request)
        if len(calls) == 1:
            raise httpx.ReadTimeout(SECRET, request=request)
        return httpx.Response(200, text=SECRET)

    transport = ResilientHTTP(APIOperations(probe_backoff_seconds=0.000001))
    async with httpx.AsyncClient(transport=httpx.MockTransport(upstream)) as client:
        await transport.request(client, "model", "GET", "http://model/" + SECRET, probe=True)
    retry = next(e for e in events if e["event"] == "dependency_probe_retry")
    assert retry["level"] == "DEBUG"
    assert retry["attempt"] == 2
    assert retry["error_code"] == "MODEL_TIMEOUT"
    assert SECRET not in json.dumps(events)


@pytest.mark.asyncio
@pytest.mark.parametrize("output", [False, True])
async def test_policy_failure_identifies_inspection_stage(events, output):
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(503, text=SECRET))
    ) as client:
        evaluator = OPAPolicyEvaluator(client, "http://opa")
        with pytest.raises(PolicyEvaluationError):
            if output:
                await evaluator.evaluate_output(output_context())
            else:
                await evaluator.evaluate(input_context())
    failure = next(e for e in events if e["event"] == "policy_evaluation_failed")
    assert failure["stage"] == ("output_policy" if output else "input_policy")
    assert failure["error_code"] == "OPA_HTTP_ERROR"
    assert SECRET not in json.dumps(events)


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", ["input_policy", "output_policy", "model"])
async def test_wrapped_circuit_rejection_stays_warning_in_orchestrator(audit, events, stage):
    transport = ResilientHTTP(APIOperations())
    dependency = "model" if stage == "model" else "opa"
    transport.circuits[dependency].opened_at = time.monotonic()

    def unreachable(request):
        pytest.fail("An open circuit must not attempt a connection")

    async with httpx.AsyncClient(transport=httpx.MockTransport(unreachable)) as client:
        svc, _ = make_service(audit, SECRET)
        evaluator = OPAPolicyEvaluator(client, "http://opa", resilient_http=transport)
        if stage == "input_policy":
            svc.policy = evaluator
        elif stage == "output_policy":
            svc.output_policy = evaluator
        else:
            svc.model = HTTPModelGateway(client, "http://model", resilient_http=transport)
        result = await svc.process(request())
    assert result.output is None
    assert any(
        e["error_code"] == dependency.upper() + "_CIRCUIT_OPEN" for e in events if "error_code" in e
    )
    assert not any(e["level"] == "ERROR" for e in events)
    assert SECRET not in json.dumps(events)


def test_dlp_diagnostics_route_is_preserved_in_request_log(audit, events):
    with TestClient(app_with_fakes(audit)) as client:
        response = client.get("/v1/diagnostics/dlp", headers=HEADERS)
    assert response.status_code == 200
    summary = next(e for e in events if e["event"] == "request_completed")
    assert summary["route"] == "/v1/diagnostics/dlp"
    assert summary["correlation_id"] == response.headers["x-correlation-id"]


@pytest.mark.asyncio
async def test_broken_log_output_does_not_bypass_masking_or_audit(audit, events, monkeypatch):
    def broken(*args, **kwargs):
        raise OSError(SECRET)

    svc, _ = make_service(
        audit,
        "Reply jane@example.com",
        output_policy=OutputMaskPolicy(),
        output_masking_enabled=True,
    )
    monkeypatch.setattr(logging.getLogger("sovereign.events"), "log", broken)
    cmd = request()
    result = await svc.process(cmd)
    assert result.status == RequestStatus.COMPLETED
    assert "jane@example.com" not in result.output
    assert len(audit.get_events(cmd.request_id, "tenant")) == 2
