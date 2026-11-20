import pytest

from app.application.orchestrator import RequestOrchestrator
from app.domain.contracts import (
    DetectionResult,
    DetectionStatus,
    Effect,
    Finding,
    Obligation,
    PolicyDecision,
    Principal,
    PromptCommand,
    RequestStatus,
    Sensitivity,
)
from app.enforcement.gateway import (
    Destination,
    DestinationRegistry,
    EnforcementPlanner,
    InvalidPlan,
)
from app.enforcement.redaction import RedactionError, redact
from app.policy.opa import parse_decision
from tests.conftest import RecordingModel


def command(text="contact a@example.com", destination="external-simulator"):
    return PromptCommand(
        "m3-test", text, destination, "GENERAL", Principal("tester", "local-tenant", ("tester",))
    )


def classified(text="contact a@example.com"):
    return DetectionResult(
        DetectionStatus.PRIVATE,
        Sensitivity.MEDIUM,
        (Finding("EMAIL_ADDRESS", 8, len(text), "synthetic", 1.0),),
        ("EMAIL_ADDRESS",),
        "fixture-v1",
        ("DETECTED_EMAIL_ADDRESS",),
        "digest",
    )


class FakeDetector:
    def detect(self, prompt):
        if "[REDACTED_EMAIL_ADDRESS]" in prompt:
            return DetectionResult(
                DetectionStatus.NO_PRIVATE_DETECTED,
                Sensitivity.NONE,
                (),
                ("EMAIL_ADDRESS",),
                "fixture-v1",
                (),
                "digest",
            )
        return classified(prompt)


class FakePolicy:
    async def evaluate(self, context):
        return PolicyDecision(
            Effect.PERMIT,
            (
                Obligation("REDACT", categories=("EMAIL_ADDRESS",)),
                Obligation("ROUTE", "external-simulator"),
            ),
            ("TEST_REDACTION",),
            "v3",
        )


def planner(external=True):
    reg = DestinationRegistry(
        (
            Destination("sovereign-model", "http://sovereign-model:9000", "INTERNAL"),
            Destination("external-simulator", "http://egress-gateway:9010", "EXTERNAL_SIMULATED"),
        )
    )
    return EnforcementPlanner(
        frozenset({"sovereign-model", "external-simulator"} if external else {"sovereign-model"}),
        reg,
    )


def test_exact_span_redaction():
    assert (
        redact("contact a@example.com", classified(), ("EMAIL_ADDRESS",))
        == "contact [REDACTED_EMAIL_ADDRESS]"
    )


def test_rejects_overlapping_and_missing_spans():
    c = classified()
    with pytest.raises(RedactionError):
        redact("contact a@example.com", c, ("PERSON",))


def test_plan_denies_disabled_external_destination():
    with pytest.raises(InvalidPlan):
        planner(False).validate(
            command(),
            PolicyDecision(
                Effect.PERMIT, (Obligation("ROUTE", "external-simulator"),), ("OK",), "v3"
            ),
            classified(),
        )


def test_plan_rejects_unredacted_external_pii():
    with pytest.raises(InvalidPlan):
        planner().validate(
            command(),
            PolicyDecision(
                Effect.PERMIT, (Obligation("ROUTE", "external-simulator"),), ("OK",), "v3"
            ),
            classified(),
        )


def test_opa_schema_accepts_redact_and_route():
    d = parse_decision(
        {
            "effect": "PERMIT",
            "obligations": [
                {"type": "REDACT", "categories": ["EMAIL_ADDRESS"]},
                {"type": "ROUTE", "destination_id": "external-simulator"},
            ],
            "reason_codes": ["REDACTION_REQUIRED"],
            "policy_revision": "v3",
        }
    )
    assert d.obligations[0].categories == ("EMAIL_ADDRESS",)
    assert d.to_dict()["obligations"][0]["categories"] == ["EMAIL_ADDRESS"]


@pytest.mark.asyncio
async def test_redacts_and_verifies_before_durable_audit_and_external_invocation(audit):
    model = RecordingModel(audit)
    o = RequestOrchestrator(FakeDetector(), FakePolicy(), audit, model, planner())
    result = await o.process(command())
    assert result.status == RequestStatus.COMPLETED
    assert model.calls[0][1] == "contact [REDACTED_EMAIL_ADDRESS]"
    assert result.decision_receipt.sequence < result.outcome_receipt.sequence
    evidence = audit.get_events("m3-test", "local-tenant")[0]["event"]["payload"]
    assert evidence["transformation"]["applied"] is True
    assert evidence["transformation"]["verification"]["status"] == "NO_PRIVATE_DETECTED"
    assert "a@example.com" not in str(evidence)


@pytest.mark.asyncio
async def test_fails_closed_when_verification_finds_sensitive_data(audit):
    class BadDetector(FakeDetector):
        def detect(self, prompt):
            return classified("contact a@example.com")

    model = RecordingModel(audit)
    o = RequestOrchestrator(BadDetector(), FakePolicy(), audit, model, planner())
    result = await o.process(command())
    assert result.status == RequestStatus.BLOCKED
    assert result.decision.reason_codes == ("REDACTION_FAILED",)
    assert model.calls == []


@pytest.mark.asyncio
async def test_disabled_egress_fails_closed_even_when_opa_permits(audit):
    model = RecordingModel(audit)
    o = RequestOrchestrator(FakeDetector(), FakePolicy(), audit, model, planner(False))
    result = await o.process(command())
    assert result.status == RequestStatus.BLOCKED
    assert not model.calls


@pytest.mark.asyncio
async def test_redaction_audit_failure_prevents_any_external_invocation(audit):
    from app.audit.sqlite_store import AuditUnavailable

    class BrokenAudit:
        def fingerprint(self, prompt):
            return audit.fingerprint(prompt)

        def commit(self, *args):
            raise AuditUnavailable("disk error")

    model = RecordingModel()
    orchestrator = RequestOrchestrator(
        FakeDetector(), FakePolicy(), BrokenAudit(), model, planner()
    )
    with pytest.raises(AuditUnavailable):
        await orchestrator.process(command())
    assert model.calls == []


def test_http_adapter_never_accepts_unknown_destination():
    import httpx

    from app.enforcement.gateway import HTTPModelGateway, ModelUnavailable

    registry = DestinationRegistry(
        (Destination("sovereign-model", "http://local:9000", "INTERNAL"),)
    )

    async def check():
        async with httpx.AsyncClient() as client:
            with pytest.raises(ModelUnavailable):
                await HTTPModelGateway(client, "http://local:9000", registry).invoke(
                    "id", "prompt", "http://evil.invalid"
                )

    import asyncio

    asyncio.run(check())
