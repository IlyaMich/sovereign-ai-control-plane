import pytest

from app.application.orchestrator import RequestOrchestrator
from app.audit.sqlite_store import AuditUnavailable
from app.detection.demo import DemoPatternDetector
from app.domain.contracts import Principal, PromptCommand, RequestStatus
from app.enforcement.gateway import EnforcementPlanner
from tests.conftest import RecordingModel, StaticPolicy


def command(prompt="hello", destination="sovereign-model"):
    return PromptCommand("req-abc", prompt, destination, "GENERAL", Principal("local-tester", "local-tenant", ("tester",)))


def service(audit, policy=None, model=None, detector=None):
    model = model or RecordingModel(audit)
    return RequestOrchestrator(
        detector or DemoPatternDetector(), policy or StaticPolicy(),
        audit, model, EnforcementPlanner(),
    ), model


@pytest.mark.asyncio
async def test_durable_decision_precedes_model_invocation(audit):
    orchestrator, model = service(audit)
    result = await orchestrator.process(command("hello"))
    assert result.status == RequestStatus.COMPLETED
    assert len(model.calls) == 1
    assert result.decision_receipt.sequence == 1
    assert result.outcome_receipt.sequence == 2
    assert [x["event"]["event_type"] for x in audit.get_events("req-abc", "local-tenant")] == ["DECISION", "OUTCOME"]


@pytest.mark.asyncio
async def test_external_destination_never_invoked(audit):
    orchestrator, model = service(audit, policy=StaticPolicy(destination_id="external-demo"))
    result = await orchestrator.process(command(destination="external-demo"))
    assert result.status == RequestStatus.BLOCKED
    assert result.decision.reason_codes == ("INVALID_POLICY_PLAN",)
    assert model.calls == []


@pytest.mark.asyncio
async def test_opa_failure_is_audited_and_fails_closed(audit):
    orchestrator, model = service(audit, policy=StaticPolicy(raise_error=True))
    result = await orchestrator.process(command())
    assert result.status == RequestStatus.BLOCKED
    assert result.decision.reason_codes == ("POLICY_UNAVAILABLE",)
    assert model.calls == []


@pytest.mark.asyncio
async def test_detector_error_is_unknown_and_never_forwarded(audit):
    class BrokenDetector:
        def detect(self, prompt):
            raise RuntimeError("Contains very sensitive input: " + prompt)
    orchestrator, model = service(audit, detector=BrokenDetector())
    result = await orchestrator.process(command("secret"))
    assert result.status == RequestStatus.BLOCKED
    assert result.classification.status.value == "UNKNOWN"
    assert "secret" not in str(audit.get_events("req-abc", "local-tenant"))
    assert not model.calls


@pytest.mark.asyncio
async def test_audit_precommit_failure_prevents_model_invocation(audit):
    class FailAudit:
        def fingerprint(self, prompt):
            return "f" * 64
        def commit(self, *args):
            raise AuditUnavailable("disk unavailable")
    model = RecordingModel()
    orchestrator = RequestOrchestrator(DemoPatternDetector(), StaticPolicy(), FailAudit(), model, EnforcementPlanner())
    with pytest.raises(AuditUnavailable):
        await orchestrator.process(command())
    assert model.calls == []


@pytest.mark.asyncio
async def test_ambiguous_model_failure_audited_as_unknown(audit):
    model = RecordingModel(audit, fail=True)
    orchestrator, _ = service(audit, model=model)
    result = await orchestrator.process(command())
    assert result.status == RequestStatus.ERROR
    assert audit.get_events("req-abc", "local-tenant")[1]["event"]["payload"]["execution_status"] == "UNKNOWN"


@pytest.mark.asyncio
async def test_failed_outcome_audit_never_claims_success(audit):
    class FailSecondWrite:
        def fingerprint(self, prompt):
            return audit.fingerprint(prompt)

        def commit(self, *args):
            if args[2] == "OUTCOME":
                raise AuditUnavailable("outcome commit failed")
            return audit.commit(*args)

    model = RecordingModel(audit)
    orchestrator = RequestOrchestrator(
        DemoPatternDetector(), StaticPolicy(), FailSecondWrite(), model, EnforcementPlanner()
    )
    with pytest.raises(AuditUnavailable):
        await orchestrator.process(command())
    assert len(model.calls) == 1  # model may already have processed it
    assert len(audit.get_events("req-abc", "local-tenant")) == 1  # unresolved
