"""Regression tests for untrusted detector negatives at the simulated external boundary.

These tests use ephemeral SQLite, a fixture policy and an in-memory model.
They never contact OPA or a real external model.
"""
from __future__ import annotations

import re

import httpx
import pytest

from app.application.orchestrator import RequestOrchestrator
from app.audit.sqlite_store import SQLiteAuditStore
from app.detection.config import DetectorConfig
from app.detection.provenance import SOURCE_PATHS
from app.domain.contracts import (
    DetectionResult, DetectionStatus, Effect, Finding, ModelResult, Obligation,
    PolicyDecision, Principal, PromptCommand, Sensitivity,
)
from app.enforcement.gateway import (
    Destination, DestinationRegistry, EnforcementPlanner, HTTPModelGateway,
    ModelUnavailable,
)
from app.enforcement.pre_egress import external_content_signals
from evaluation.dataset import load_dataset


REGISTRY = DestinationRegistry((
    Destination("sovereign-model", "http://sovereign-model:9000", "INTERNAL"),
    Destination("external-simulator", "http://external-simulator:9010", "EXTERNAL_SIMULATED"),
))


class FixtureDetector:
    def __init__(self, partial_name: bool = False):
        self.partial_name = partial_name

    def detect(self, prompt: str) -> DetectionResult:
        if self.partial_name and "Taylor" in prompt:
            offset = prompt.index("Taylor")
            return DetectionResult(
                DetectionStatus.PRIVATE, Sensitivity.MEDIUM,
                (Finding("PERSON", offset, offset + len("Taylor"), "fixture", 0.99),),
                ("EMAIL_ADDRESS", "PHONE_NUMBER", "PERSON", "CREDIT_CARD", "US_SSN",
                 "API_CREDENTIAL", "PRIVATE_KEY"),
                "presidio-spacy-v1", (), "test-config",
            )
        return DetectionResult(
            DetectionStatus.NO_PRIVATE_DETECTED, Sensitivity.NONE, (),
            ("EMAIL_ADDRESS", "PHONE_NUMBER", "PERSON", "CREDIT_CARD", "US_SSN",
             "API_CREDENTIAL", "PRIVATE_KEY"),
            "presidio-spacy-v1", (), "test-config",
        )


class PermissiveExternalFixture:
    async def evaluate(self, context):
        if context.classification.status == DetectionStatus.PRIVATE:
            obligations = (
                Obligation("REDACT", categories=("PERSON",)),
                Obligation("ROUTE", "external-simulator"),
            )
        else:
            obligations = (Obligation("ROUTE", "external-simulator"),)
        return PolicyDecision(Effect.PERMIT, obligations, ("FIXTURE_PERMIT",), "fixture-v1")


class RecordingModel:
    def __init__(self):
        self.calls: list[tuple[str, str]] = []

    async def invoke(self, request_id, prompt, destination_id):
        self.calls.append((prompt, destination_id))
        return ModelResult(destination_id, "synthetic-result")


async def _invoke(tmp_path, prompt: str, *, partial_name=False, destination="external-simulator"):
    audit = SQLiteAuditStore(str(tmp_path / "audit.sqlite"), str(tmp_path / "audit.pem"))
    model = RecordingModel()
    orch = RequestOrchestrator(
        FixtureDetector(partial_name), PermissiveExternalFixture(), audit, model,
        EnforcementPlanner(frozenset({"external-simulator", "sovereign-model"}), REGISTRY),
    )
    command = PromptCommand(
        "remediation-req", prompt, destination, "GENERAL",
        Principal("test", "test-tenant", ("tester",)),
    )
    result = await orch.process(command)
    events = audit.get_events("remediation-req", "test-tenant")
    return result, model.calls, events


@pytest.mark.asyncio
async def test_ssn_shaped_negative_is_denied_before_external_model(tmp_path):
    result, calls, events = await _invoke(tmp_path, "Account reference: 123-45-6789")
    assert result.status.value == "BLOCKED"
    assert result.decision.reason_codes == ("EXTERNAL_CONTENT_UNVERIFIED",)
    assert not calls
    assert [e["event"]["event_type"] for e in events] == ["DECISION", "OUTCOME"]


@pytest.mark.asyncio
async def test_partial_multiline_name_denied_despite_planned_redaction(tmp_path):
    result, calls, events = await _invoke(
        tmp_path, "Review <Taylor\nNguyen> before exporting", partial_name=True,
    )
    assert result.status.value == "BLOCKED"
    assert result.decision.reason_codes == ("EXTERNAL_CONTENT_UNVERIFIED",)
    assert not calls
    assert [e["event"]["event_type"] for e in events] == ["DECISION", "OUTCOME"]


@pytest.mark.asyncio
async def test_single_line_person_partial_detection_cannot_be_redacted_externally(tmp_path):
    result, calls, _events = await _invoke(
        tmp_path, "Review Taylor Nguyen before exporting", partial_name=True,
    )
    assert result.status.value == "BLOCKED"
    assert result.decision.reason_codes == ("EXTERNAL_CONTENT_UNVERIFIED",)
    assert not calls


@pytest.mark.asyncio
async def test_clean_external_request_can_still_be_forwarded(tmp_path):
    result, calls, events = await _invoke(tmp_path, "Explain deterministic policy evaluation")
    assert result.status.value == "COMPLETED"
    assert len(calls) == 1
    assert calls[0][1] == "external-simulator"
    assert [e["event"]["event_type"] for e in events] == ["DECISION", "OUTCOME"]


@pytest.mark.asyncio
async def test_http_sink_blocks_suspicious_external_payload_even_without_planner():
    actual_requests = []

    def handler(request):
        actual_requests.append(request)
        return httpx.Response(200, json={"model_id": "external-simulator", "output": "ok"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        gateway = HTTPModelGateway(client, "http://sovereign-model:9000", REGISTRY)
        with pytest.raises(ModelUnavailable):
            await gateway.invoke("sink-negative-control", "123-45-6789", "external-simulator")
    assert not actual_requests


def test_all_known_24_violations_are_flagged_without_detector():
    cases = {c.id: c for c in load_dataset().cases}
    ids = [*(f"STANDARD_SENSITIVE-{i:04d}" for i in range(216, 256, 3))]
    ids.extend(f"ADVERSARIAL-{i:04d}" for i in (3, 12, 21, 30, 75, 84, 93, 102, 111, 120))
    assert len(ids) == 24 and len(set(ids)) == 24
    for cid in ids:
        assert external_content_signals(cases[cid].text, cases[cid].text), cid


def test_clean_and_hard_negatives_are_not_preemptively_blocked():
    negatives = [c for c in load_dataset().cases if c.group in ("clean", "hard_negative")]
    assert len(negatives) == 450
    assert not [c.id for c in negatives if external_content_signals(c.text, c.text)]


def test_generalized_recognizer_rules_match_shapes_not_sample_ids():
    cfg = DetectorConfig.load()
    patterns = dict(cfg.patterns)
    for category, sample in (
        ("US_SSN", "431-27-8492"),
        ("PERSON", "Morgan\nPatel"),
    ):
        assert any(re.search(regex, sample) and score >= cfg.threshold
                   for _name, regex, score in patterns[category])
    assert not any(re.search(regex, "000-00-0000") for _name, regex, _score in
                   patterns["US_SSN"])
    # Presidio may enable global IGNORECASE flags; the custom name shape must
    # remain case-sensitive and avoid turning arbitrary multiline prose into PII.
    assert not any(re.search(regex, "ordinary\nprose", flags=re.IGNORECASE)
                   for _name, regex, _score in patterns["PERSON"])


def test_release_manifest_covers_egress_gate_and_planner_source():
    assert "app/enforcement/pre_egress.py" in SOURCE_PATHS
    assert "app/enforcement/gateway.py" in SOURCE_PATHS
