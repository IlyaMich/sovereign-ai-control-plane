"""Security-critical request lifecycle; deny on uncertainty, commit before invoke."""
from __future__ import annotations

from app.audit.sqlite_store import AuditUnavailable
from app.domain.contracts import (
    AuditWriter, DetectionResult, DetectionStatus, Detector, Effect, ModelGateway,
    PolicyContext, PolicyDecision, PolicyEvaluator, ProcessedRequest, PromptCommand,
    RequestStatus,
)
from app.enforcement.gateway import EnforcementPlanner, InvalidPlan, ModelUnavailable


class RequestOrchestrator:
    def __init__(
        self, detector: Detector, policy: PolicyEvaluator, audit: AuditWriter,
        model: ModelGateway, planner: EnforcementPlanner,
    ):
        self.detector = detector
        self.policy = policy
        self.audit = audit
        self.model = model
        self.planner = planner

    async def process(self, command: PromptCommand) -> ProcessedRequest:
        try:
            classification = self.detector.detect(command.prompt)
        except Exception:
            # Never expose raw exception messages (may contain the input prompt).
            classification = DetectionResult.unknown()

        policy_input = PolicyContext(command, classification)
        if classification.status == DetectionStatus.UNKNOWN:
            decision = PolicyDecision.deny("DETECTION_UNKNOWN")
        else:
            try:
                decision = await self.policy.evaluate(policy_input)
            except Exception:
                decision = PolicyDecision.deny("POLICY_UNAVAILABLE")

        try:
            self.planner.validate(command, decision)
        except InvalidPlan:
            decision = PolicyDecision.deny("INVALID_POLICY_PLAN")

        # No raw prompt, finding value, model response, or credential is written to the audit log.
        evidence = {
            "principal_id": command.principal.principal_id,
            "input_hmac_sha256": self.audit.fingerprint(command.prompt),
            "policy_input": policy_input.to_dict(),
            "decision": decision.to_dict(),
        }
        # This is a synchronous durable commit, which MUST succeed before any model call.
        decision_receipt = self.audit.commit(
            command.request_id, command.principal.tenant_id, "DECISION", evidence
        )

        if decision.effect == Effect.DENY:
            outcome = {"execution_status": "BLOCKED", "model_invoked": False}
            outcome_receipt = self.audit.commit(
                command.request_id, command.principal.tenant_id, "OUTCOME", outcome
            )
            return ProcessedRequest(
                command.request_id, RequestStatus.BLOCKED, classification, decision,
                decision_receipt, outcome_receipt,
            )

        try:
            # The planner guarantees precisely one approved ROUTE obligation.
            model_result = await self.model.invoke(
                command.request_id, command.prompt, command.destination_id
            )
        except Exception:
            # The remote call might have reached the model; distinguish it from a block.
            outcome_receipt = self.audit.commit(
                command.request_id, command.principal.tenant_id, "OUTCOME",
                {"execution_status": "UNKNOWN", "model_invoked": "UNKNOWN", "destination_id": command.destination_id},
            )
            return ProcessedRequest(
                command.request_id, RequestStatus.ERROR, classification, decision,
                decision_receipt, outcome_receipt,
            )

        # An audit write failure here yields an unresolved decision record, not a false success.
        outcome_receipt = self.audit.commit(
            command.request_id, command.principal.tenant_id, "OUTCOME",
            {"execution_status": "COMPLETED", "model_invoked": True,
             "destination_id": command.destination_id, "model_id": model_result.model_id},
        )
        return ProcessedRequest(
            command.request_id, RequestStatus.COMPLETED, classification, decision,
            decision_receipt, outcome_receipt,
            output=model_result.output, model_id=model_result.model_id,
        )
