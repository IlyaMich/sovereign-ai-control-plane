"""Security-critical lifecycle; prepare and verify transformations before audit and egress."""
from __future__ import annotations

from app.domain.contracts import (
    AuditWriter, DetectionResult, DetectionStatus, Detector, Effect, ModelGateway,
    PolicyContext, PolicyDecision, PolicyEvaluator, ProcessedRequest, PromptCommand,
    RequestStatus,
)
from app.enforcement.gateway import EnforcementPlanner, InvalidPlan
from app.enforcement.redaction import RedactionError, redact
from app.policy.opa import PolicyIntegrityError


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
            classification = DetectionResult.unknown()

        policy_input = PolicyContext(command, classification)
        if classification.status == DetectionStatus.UNKNOWN:
            decision = PolicyDecision.deny("DETECTION_UNKNOWN")
        else:
            try:
                decision = await self.policy.evaluate(policy_input)
            except PolicyIntegrityError:
                decision = PolicyDecision.deny("POLICY_INTEGRITY_FAILURE")
            except Exception:
                decision = PolicyDecision.deny("POLICY_UNAVAILABLE")

        opa_decision = decision if decision.policy_digest else None
        forwarded_prompt = command.prompt
        transformed = False
        verification = None
        try:
            self.planner.validate(command, decision, classification)
            if decision.effect == Effect.PERMIT:
                redactions = [o for o in decision.obligations if o.type == "REDACT"]
                if redactions:
                    forwarded_prompt = redact(command.prompt, classification, redactions[0].categories)
                    transformed = True
                    # Fail closed for incomplete or broken verification; no prompt forwarded.
                    verification = self.detector.detect(forwarded_prompt)
                    if verification.status != DetectionStatus.NO_PRIVATE_DETECTED:
                        raise RedactionError("Transformed prompt did not pass classification")
        except InvalidPlan:
            decision = PolicyDecision.deny("INVALID_POLICY_PLAN")
            transformed = False
            forwarded_prompt = command.prompt
        except RedactionError:
            decision = PolicyDecision.deny("REDACTION_FAILED")
            transformed = False
            forwarded_prompt = command.prompt
        except Exception:
            decision = PolicyDecision.deny("TRANSFORMATION_VERIFICATION_UNAVAILABLE")
            transformed = False
            forwarded_prompt = command.prompt

        evidence = {
            "policy_evidence_version": "2",
            "principal_id": command.principal.principal_id,
            "input_hmac_sha256": self.audit.fingerprint(command.prompt),
            "policy_input": policy_input.to_dict(),
            "decision": decision.to_dict(),
            # Preserve OPA's original answer even when local safety checks override it.
            "policy_evaluation": opa_decision.to_dict() if opa_decision else None,
            "policy_snapshot": ({"sha256": opa_decision.policy_digest,
                                 "revision": opa_decision.policy_revision}
                                if opa_decision else None),
            "transformation": {
                "applied": transformed,
                "output_hmac_sha256": self.audit.fingerprint(forwarded_prompt) if transformed else None,
                "verification": verification.to_dict() if transformed and verification else None,
            },
        }
        # MUST commit before any model call (including a simulated external call).
        decision_receipt = self.audit.commit(
            command.request_id, command.principal.tenant_id, "DECISION", evidence
        )

        if decision.effect == Effect.DENY:
            outcome_receipt = self.audit.commit(
                command.request_id, command.principal.tenant_id, "OUTCOME",
                {"execution_status": "BLOCKED", "model_invoked": False}
            )
            return ProcessedRequest(
                command.request_id, RequestStatus.BLOCKED, classification, decision,
                decision_receipt, outcome_receipt,
            )

        try:
            model_result = await self.model.invoke(command.request_id, forwarded_prompt, command.destination_id)
        except Exception:
            outcome_receipt = self.audit.commit(
                command.request_id, command.principal.tenant_id, "OUTCOME",
                {"execution_status": "UNKNOWN", "model_invoked": "UNKNOWN", "destination_id": command.destination_id,
                 "transformed": transformed},
            )
            return ProcessedRequest(
                command.request_id, RequestStatus.ERROR, classification, decision,
                decision_receipt, outcome_receipt,
            )

        outcome_receipt = self.audit.commit(
            command.request_id, command.principal.tenant_id, "OUTCOME",
            {"execution_status": "COMPLETED", "model_invoked": True,
             "destination_id": command.destination_id, "model_id": model_result.model_id,
             "transformed": transformed},
        )
        return ProcessedRequest(
            command.request_id, RequestStatus.COMPLETED, classification, decision,
            decision_receipt, outcome_receipt, output=model_result.output, model_id=model_result.model_id,
        )
