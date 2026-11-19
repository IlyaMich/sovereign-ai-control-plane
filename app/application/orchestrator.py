"""Security-critical lifecycle; prepare and verify transformations before audit and egress."""

from __future__ import annotations

from typing import Any

from app.application.detector_executor import (
    BoundedDetectorExecutor,
    DetectorCapacityExceeded,
)
from app.audit.async_executor import BoundedAuditExecutor
from app.domain.contracts import (
    AuditReceipt,
    AuditWriter,
    DetectionResult,
    DetectionStatus,
    Detector,
    Effect,
    ModelGateway,
    PolicyContext,
    PolicyDecision,
    PolicyEvaluator,
    ProcessedRequest,
    PromptCommand,
    ReleaseVerifier,
    RequestStatus,
)
from app.enforcement.gateway import EnforcementPlanner, InvalidPlan
from app.enforcement.redaction import RedactionError, redact
from app.policy.opa import PolicyIntegrityError
from app.release.approvals import ReleaseIntegrityError, summary


class RequestOrchestrator:
    def __init__(
        self,
        detector: Detector,
        policy: PolicyEvaluator,
        audit: AuditWriter,
        model: ModelGateway,
        planner: EnforcementPlanner,
        release_store: ReleaseVerifier | None = None,
        detection_executor: BoundedDetectorExecutor | None = None,
        audit_executor: BoundedAuditExecutor | None = None,
    ):
        self.detector = detector
        self.policy = policy
        self.audit = audit
        self.model = model
        self.planner = planner
        self.release_store = release_store
        self.detection_executor = detection_executor
        self.audit_executor = audit_executor

    async def _detect(self, prompt: str) -> DetectionResult:
        if self.detection_executor is None:
            # Legacy/test adapters remain injectable without a thread pool.
            return self.detector.detect(prompt)
        return await self.detection_executor.detect(prompt)

    async def _commit(
        self, request_id: str, tenant_id: str, event_type: str, payload: dict[str, Any]
    ) -> AuditReceipt:
        if self.audit_executor is None:
            # Legacy/test adapters remain supported. The production path
            # uses the nonblocking bounded audit executor.
            return self.audit.commit(request_id, tenant_id, event_type, payload)
        return await self.audit_executor.commit(request_id, tenant_id, event_type, payload)

    async def process(self, command: PromptCommand) -> ProcessedRequest:
        try:
            classification = await self._detect(command.prompt)
        except DetectorCapacityExceeded:
            classification = DetectionResult.unknown("DETECTION_CAPACITY_EXCEEDED")
        except Exception:
            classification = DetectionResult.unknown()

        policy_input = PolicyContext(command, classification)
        approved_release = None
        release_untrusted = False
        if self.release_store is not None:
            try:
                approved_release = self.release_store.verify_active(
                    detector_digest=classification.artifact_digest
                    if classification.artifact_digest
                    else None
                )
            except ReleaseIntegrityError:
                release_untrusted = True
        if release_untrusted:
            decision = PolicyDecision.deny("UNTRUSTED_RELEASE")
        elif classification.status == DetectionStatus.UNKNOWN:
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
                    forwarded_prompt = redact(
                        command.prompt, classification, redactions[0].categories
                    )
                    transformed = True
                    # Fail closed for incomplete or broken verification; no prompt forwarded.
                    verification = await self._detect(forwarded_prompt)
                    if verification.status != DetectionStatus.NO_PRIVATE_DETECTED or (
                        approved_release is not None
                        and verification.artifact_digest
                        != approved_release["payload"]["detector_digest"]
                    ):
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

        if approved_release is not None and self.release_store is not None:
            try:
                rechecked = self.release_store.verify_active(
                    detector_digest=classification.artifact_digest
                    if classification.artifact_digest
                    else None,
                    policy_digest=opa_decision.policy_digest if opa_decision else None,
                )
                if rechecked["release_id"] != approved_release["release_id"]:
                    raise ReleaseIntegrityError("Active release changed during request")
            except ReleaseIntegrityError:
                decision = PolicyDecision.deny("UNTRUSTED_RELEASE")
                opa_decision = None  # An untrusted evaluation must not be used for replay.
                forwarded_prompt = command.prompt
                transformed = False
                verification = None
                approved_release = None
        detector_digest = classification.artifact_digest
        evidence = {
            **(
                {"release_evidence_version": "1", "release_snapshot": summary(approved_release)}
                if approved_release
                else {}
            ),
            "policy_evidence_version": "2",
            **(
                {
                    "detector_evidence_version": "1",
                    "detector_snapshot": {"sha256": detector_digest, "schema_version": 1},
                }
                if detector_digest
                else {}
            ),
            "principal_id": command.principal.principal_id,
            "input_hmac_sha256": self.audit.fingerprint(command.prompt),
            "policy_input": policy_input.to_dict(),
            "decision": decision.to_dict(),
            # Preserve OPA's original answer even when local safety checks override it.
            "policy_evaluation": opa_decision.to_dict() if opa_decision else None,
            "policy_snapshot": (
                {"sha256": opa_decision.policy_digest, "revision": opa_decision.policy_revision}
                if opa_decision
                else None
            ),
            "transformation": {
                "applied": transformed,
                "output_hmac_sha256": self.audit.fingerprint(forwarded_prompt)
                if transformed
                else None,
                "verification": verification.to_dict() if transformed and verification else None,
            },
        }
        # MUST commit before any model call (including a simulated external call).
        decision_receipt = await self._commit(
            command.request_id, command.principal.tenant_id, "DECISION", evidence
        )

        if decision.effect == Effect.DENY:
            outcome_receipt = await self._commit(
                command.request_id,
                command.principal.tenant_id,
                "OUTCOME",
                {"execution_status": "BLOCKED", "model_invoked": False},
            )
            return ProcessedRequest(
                command.request_id,
                RequestStatus.BLOCKED,
                classification,
                decision,
                decision_receipt,
                outcome_receipt,
            )

        try:
            model_result = await self.model.invoke(
                command.request_id, forwarded_prompt, command.destination_id
            )
        except Exception:
            outcome_receipt = await self._commit(
                command.request_id,
                command.principal.tenant_id,
                "OUTCOME",
                {
                    "execution_status": "UNKNOWN",
                    "model_invoked": "UNKNOWN",
                    "destination_id": command.destination_id,
                    "transformed": transformed,
                },
            )
            return ProcessedRequest(
                command.request_id,
                RequestStatus.ERROR,
                classification,
                decision,
                decision_receipt,
                outcome_receipt,
            )

        outcome_receipt = await self._commit(
            command.request_id,
            command.principal.tenant_id,
            "OUTCOME",
            {
                "execution_status": "COMPLETED",
                "model_invoked": True,
                "destination_id": command.destination_id,
                "model_id": model_result.model_id,
                "transformed": transformed,
            },
        )
        return ProcessedRequest(
            command.request_id,
            RequestStatus.COMPLETED,
            classification,
            decision,
            decision_receipt,
            outcome_receipt,
            output=model_result.output,
            model_id=model_result.model_id,
        )
