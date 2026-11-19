import pytest

from app.application.orchestrator import RequestOrchestrator
from app.detection.demo import DemoPatternDetector
from app.domain.contracts import Principal, PromptCommand, RequestStatus
from app.enforcement.gateway import EnforcementPlanner
from app.policy.opa import PolicyIntegrityError
from tests.conftest import RecordingModel


class IntegrityFailPolicy:
    async def evaluate(self, context):
        raise PolicyIntegrityError("snapshot does not match active policy")


@pytest.mark.asyncio
async def test_snapshot_integrity_failure_is_audited_and_never_forwarded(audit):
    model = RecordingModel(audit)
    orchestrator = RequestOrchestrator(
        DemoPatternDetector(), IntegrityFailPolicy(), audit, model, EnforcementPlanner()
    )
    request = PromptCommand(
        "m4-integrity",
        "hello",
        "sovereign-model",
        "GENERAL",
        Principal("tester", "local-tenant", ("tester",)),
    )
    result = await orchestrator.process(request)
    assert result.status == RequestStatus.BLOCKED
    assert result.decision.reason_codes == ("POLICY_INTEGRITY_FAILURE",)
    assert model.calls == []
    events = audit.get_events("m4-integrity", "local-tenant")
    assert len(events) == 2
    assert events[0]["event"]["payload"]["policy_evaluation"] is None
    assert events[1]["event"]["payload"]["model_invoked"] is False
