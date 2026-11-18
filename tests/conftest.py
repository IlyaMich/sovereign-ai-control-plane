import pytest

from app.audit.sqlite_store import SQLiteAuditStore
from app.domain.contracts import Effect, ModelResult, Obligation, PolicyDecision


class StaticPolicy:
    def __init__(self, effect=Effect.PERMIT, raise_error=False, destination_id="sovereign-model"):
        self.effect = effect
        self.raise_error = raise_error
        self.destination_id = destination_id

    async def evaluate(self, context):
        if self.raise_error:
            raise RuntimeError("OPA unreachable")
        if self.effect == Effect.DENY:
            return PolicyDecision.deny("TEST_DENY", "test-v1")
        return PolicyDecision(
            Effect.PERMIT, (Obligation("ROUTE", self.destination_id),),
            ("TEST_PERMIT",), "test-v1",
        )


class RecordingModel:
    def __init__(self, audit=None, fail=False):
        self.calls = []
        self.audit = audit
        self.fail = fail

    async def invoke(self, request_id, prompt, destination_id):
        if self.audit is not None:
            assert self.audit.get_events(request_id, "local-tenant")[0]["event"]["event_type"] == "DECISION"
        self.calls.append((request_id, prompt, destination_id))
        if self.fail:
            raise TimeoutError("Model timeout")
        return ModelResult("sovereign-model", "Fixture response")


@pytest.fixture
def audit(tmp_path):
    return SQLiteAuditStore(str(tmp_path / "audit.sqlite"), str(tmp_path / "audit-key.pem"))
