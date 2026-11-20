"""Security-critical lifecycle; prepare and verify transformations before audit and egress."""

from __future__ import annotations

import logging
import time
from functools import partial
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
    OutputPolicyContext,
    OutputPolicyEvaluator,
    PolicyContext,
    PolicyDecision,
    PolicyEvaluator,
    ProcessedRequest,
    PromptCommand,
    ReleaseVerifier,
    RequestStatus,
)
from app.enforcement.gateway import EnforcementPlanner, ExternalContentUnverified, InvalidPlan
from app.enforcement.redaction import RedactionError, redact
from app.infrastructure.dlp_metrics import DLPMetrics
from app.infrastructure.integrity_executor import (
    BoundedIntegrityExecutor,
    integrity_unavailable_code,
)
from app.infrastructure.logging import event
from app.infrastructure.resilience import circuit_unavailable_code
from app.policy.opa import PolicyIntegrityError
from app.release.approvals import ReleaseIntegrityError, summary


def detection_service_error(result: DetectionResult) -> str | None:
    """Unsupported input/low confidence are policy denials; broken detection is a service error."""
    failures = {
        "DETECTION_UNAVAILABLE",
        "DETECTION_CAPACITY_EXCEEDED",
        "RECOGNIZER_COVERAGE_INCOMPLETE",
        "DETECTION_RESULT_INVALID",
    }
    return next((code for code in result.reason_codes if code in failures), None)


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
        integrity_executor: BoundedIntegrityExecutor | None = None,
        output_policy: OutputPolicyEvaluator | None = None,
        max_model_output_bytes: int = 8192,
        output_masking_enabled: bool = False,
        dlp_metrics: DLPMetrics | None = None,
    ):
        self.detector = detector
        self.policy = policy
        self.audit = audit
        self.model = model
        self.planner = planner
        self.release_store = release_store
        self.detection_executor = detection_executor
        self.audit_executor = audit_executor
        self.integrity_executor = integrity_executor
        self.output_policy = output_policy
        if type(output_masking_enabled) is not bool:
            raise ValueError("Invalid output masking flag")
        self.output_masking_enabled = output_masking_enabled
        self.dlp_metrics = dlp_metrics or DLPMetrics()
        if type(max_model_output_bytes) is not int or max_model_output_bytes <= 0:
            raise ValueError("Invalid model output size bound")
        self.max_model_output_bytes = max_model_output_bytes

    async def _detect(self, prompt: str) -> DetectionResult:
        if self.detection_executor is None:
            # Legacy/test adapters remain injectable without a thread pool.
            return self.detector.detect(prompt)
        return await self.detection_executor.detect(prompt)

    async def _commit(
        self, request_id: str, tenant_id: str, event_type: str, payload: dict[str, Any]
    ) -> AuditReceipt:
        started = time.perf_counter()
        try:
            if self.audit_executor is None:
                receipt = self.audit.commit(request_id, tenant_id, event_type, payload)
            else:
                receipt = await self.audit_executor.commit(
                    request_id, tenant_id, event_type, payload
                )
        except Exception:
            if event_type == "OUTCOME":
                self.dlp_metrics.failure("OUTCOME_AUDIT_UNAVAILABLE")
            event(
                "audit_commit_failed",
                level=logging.ERROR,
                request_id=request_id,
                event_type=event_type,
                error_code="AUDIT_COMMIT_FAILED",
            )
            raise
        event(
            "audit_committed",
            level=logging.DEBUG,
            request_id=request_id,
            event_type=event_type,
            sequence=receipt.sequence,
            duration_ms=round((time.perf_counter() - started) * 1000, 3),
        )
        return receipt

    async def _verify_release(self, **checks: Any) -> dict[str, Any]:
        verifier = self.release_store
        if verifier is None:
            raise ReleaseIntegrityError("Release verifier unavailable")
        verify = partial(verifier.verify_active, **checks)
        if self.integrity_executor is not None:
            return await self.integrity_executor.run(verify)
        # Keep existing injected test adapters usable without an executor.
        return verify()

    async def process(self, command: PromptCommand) -> ProcessedRequest:
        service_error = None
        try:
            classification = await self._detect(command.prompt)
        except DetectorCapacityExceeded:
            service_error = "DETECTION_CAPACITY_EXCEEDED"
            event(
                "detector_capacity_exceeded",
                level=logging.WARNING,
                limited=True,
                request_id=command.request_id,
                error_code="DETECTION_CAPACITY_EXCEEDED",
            )
            classification = DetectionResult.unknown("DETECTION_CAPACITY_EXCEEDED")
        except Exception:
            event(
                "detection_failed",
                level=logging.ERROR,
                request_id=command.request_id,
                error_code="DETECTION_FAILED",
                stage="detection",
            )
            classification = DetectionResult.unknown()
            service_error = "DETECTION_UNAVAILABLE"

        self.dlp_metrics.input_detection(classification.status)
        service_error = service_error or detection_service_error(classification)
        policy_input = PolicyContext(command, classification)
        approved_release = None
        release_untrusted = False
        release_error_code = "UNTRUSTED_RELEASE"
        if self.release_store is not None:
            try:
                approved_release = await self._verify_release(
                    detector_digest=classification.artifact_digest
                    if classification.artifact_digest
                    else None
                )
            except Exception as exc:
                release_untrusted = True
                release_error_code = integrity_unavailable_code(exc) or (
                    "UNTRUSTED_RELEASE"
                    if isinstance(exc, ReleaseIntegrityError)
                    else "RELEASE_VERIFICATION_FAILED"
                )
        if release_untrusted:
            service_error = release_error_code
            event(
                "request_safety_failure",
                level=logging.WARNING
                if release_error_code.startswith("INTEGRITY_")
                else logging.ERROR,
                limited=release_error_code.startswith("INTEGRITY_"),
                request_id=command.request_id,
                error_code=release_error_code,
            )
            decision = PolicyDecision.deny("UNTRUSTED_RELEASE")
        elif classification.status == DetectionStatus.UNKNOWN:
            decision = PolicyDecision.deny("DETECTION_UNKNOWN")
        else:
            try:
                decision = await self.policy.evaluate(policy_input)
            except PolicyIntegrityError as exc:
                unavailable = integrity_unavailable_code(exc)
                service_error = unavailable or "POLICY_INTEGRITY_FAILURE"
                event(
                    "request_safety_failure",
                    level=logging.WARNING if unavailable else logging.ERROR,
                    limited=unavailable is not None,
                    request_id=command.request_id,
                    error_code=unavailable or "POLICY_INTEGRITY_FAILURE",
                )
                decision = PolicyDecision.deny("POLICY_INTEGRITY_FAILURE")
            except Exception as exc:
                circuit_code = circuit_unavailable_code(exc, "OPA")
                event(
                    "request_safety_failure",
                    level=logging.WARNING if circuit_code else logging.ERROR,
                    limited=circuit_code is not None,
                    stage="input_policy",
                    request_id=command.request_id,
                    error_code=circuit_code or "POLICY_UNAVAILABLE",
                )
                decision = PolicyDecision.deny("POLICY_UNAVAILABLE")
                service_error = "POLICY_UNAVAILABLE"

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
        except ExternalContentUnverified:
            event(
                "request_safety_failure",
                level=logging.WARNING,
                request_id=command.request_id,
                error_code="EXTERNAL_CONTENT_UNVERIFIED",
            )
            decision = PolicyDecision.deny("EXTERNAL_CONTENT_UNVERIFIED")
            transformed = False
            forwarded_prompt = command.prompt
            verification = None
        except InvalidPlan:
            event(
                "request_safety_failure",
                level=logging.ERROR,
                request_id=command.request_id,
                error_code="INVALID_POLICY_PLAN",
            )
            decision = PolicyDecision.deny("INVALID_POLICY_PLAN")
            service_error = "INVALID_POLICY_PLAN"
            transformed = False
            forwarded_prompt = command.prompt
        except RedactionError:
            event(
                "request_safety_failure",
                level=logging.ERROR,
                request_id=command.request_id,
                error_code="REDACTION_FAILED",
            )
            decision = PolicyDecision.deny("REDACTION_FAILED")
            service_error = "REDACTION_FAILED"
            transformed = False
            forwarded_prompt = command.prompt
        except Exception:
            event(
                "request_safety_failure",
                level=logging.ERROR,
                request_id=command.request_id,
                error_code="TRANSFORMATION_VERIFICATION_UNAVAILABLE",
            )
            decision = PolicyDecision.deny("TRANSFORMATION_VERIFICATION_UNAVAILABLE")
            service_error = "TRANSFORMATION_VERIFICATION_UNAVAILABLE"
            transformed = False
            forwarded_prompt = command.prompt

        if approved_release is not None and self.release_store is not None:
            try:
                rechecked = await self._verify_release(
                    detector_digest=classification.artifact_digest
                    if classification.artifact_digest
                    else None,
                    policy_digest=opa_decision.policy_digest if opa_decision else None,
                )
                if rechecked["release_id"] != approved_release["release_id"]:
                    raise ReleaseIntegrityError("Active release changed during request")
            except Exception as exc:
                unavailable = integrity_unavailable_code(exc)
                event(
                    "request_safety_failure",
                    level=logging.WARNING if unavailable else logging.ERROR,
                    limited=unavailable is not None,
                    request_id=command.request_id,
                    error_code=unavailable
                    or (
                        "UNTRUSTED_RELEASE"
                        if isinstance(exc, ReleaseIntegrityError)
                        else "RELEASE_VERIFICATION_FAILED"
                    ),
                )
                decision = PolicyDecision.deny("UNTRUSTED_RELEASE")
                service_error = unavailable or "UNTRUSTED_RELEASE"
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

        event(
            "decision_committed",
            request_id=command.request_id,
            effect=decision.effect.value,
            transformed=transformed,
            sequence=decision_receipt.sequence,
        )

        if decision.effect == Effect.DENY:
            outcome_receipt = await self._commit(
                command.request_id,
                command.principal.tenant_id,
                "OUTCOME",
                {"execution_status": "BLOCKED", "model_invoked": False},
            )
            self.dlp_metrics.outcome(RequestStatus.BLOCKED)
            return ProcessedRequest(
                command.request_id,
                RequestStatus.BLOCKED,
                classification,
                decision,
                decision_receipt,
                outcome_receipt,
                service_error=service_error,
            )

        try:
            model_result = await self.model.invoke(
                command.request_id, forwarded_prompt, command.destination_id
            )
        except Exception as exc:
            circuit_code = circuit_unavailable_code(exc, "MODEL")
            event(
                "model_execution_unknown",
                level=logging.WARNING if circuit_code else logging.ERROR,
                limited=circuit_code is not None,
                request_id=command.request_id,
                execution_status="UNKNOWN",
                error_code=circuit_code or "MODEL_EXECUTION_UNKNOWN",
            )
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
            self.dlp_metrics.outcome(RequestStatus.ERROR)
            return ProcessedRequest(
                command.request_id,
                RequestStatus.ERROR,
                classification,
                decision,
                decision_receipt,
                outcome_receipt,
                service_error="MODEL_UNAVAILABLE",
            )

        # Legacy fixture adapters may omit output_policy. The managed application
        # ALWAYS injects the content-bound OPA output evaluator.
        output_classification = None
        output_decision = None
        output_evaluation = None
        output_context = None
        if self.output_policy is not None:
            content = model_result.output
            released_content = content
            mask_applied = False
            mask_verification = None
            output_detection_ms = 0.0
            output_error_code = None
            try:
                valid_content = (
                    isinstance(content, str)
                    and bool(content)
                    and len(content.encode("utf-8")) <= self.max_model_output_bytes
                )
            except UnicodeError:
                valid_content = False
            if not valid_content:
                event(
                    "output_content_invalid",
                    level=logging.ERROR,
                    stage="output_content",
                    request_id=command.request_id,
                    error_code="OUTPUT_INVALID_CONTENT",
                )
                output_classification = DetectionResult.unknown("OUTPUT_INVALID_CONTENT")
                output_decision = PolicyDecision.deny("OUTPUT_INVALID_CONTENT")
                service_error = "OUTPUT_INVALID_CONTENT"
            else:
                detection_started = time.perf_counter()
                try:
                    output_classification = await self._detect(content)
                except Exception:
                    event(
                        "output_detection_failed",
                        level=logging.ERROR,
                        request_id=command.request_id,
                        error_code="OUTPUT_DETECTION_UNAVAILABLE",
                    )
                    self.dlp_metrics.failure("OUTPUT_DETECTOR_UNAVAILABLE")
                    output_classification = DetectionResult.unknown("OUTPUT_DETECTION_UNAVAILABLE")
                    service_error = "OUTPUT_DETECTION_UNAVAILABLE"
                finally:
                    output_detection_ms = 1000.0 * (time.perf_counter() - detection_started)

                if output_classification.status == DetectionStatus.UNKNOWN:
                    if detection_service_error(output_classification):
                        event(
                            "output_detection_failed",
                            level=logging.ERROR,
                            stage="output_detection",
                            request_id=command.request_id,
                            error_code="OUTPUT_DETECTION_UNAVAILABLE",
                        )
                        service_error = "OUTPUT_DETECTION_UNAVAILABLE"
                    output_decision = PolicyDecision.deny("OUTPUT_DETECTION_UNKNOWN")
                else:
                    output_context = OutputPolicyContext(
                        command, output_classification, self.output_masking_enabled
                    )
                    try:
                        output_decision = await self.output_policy.evaluate_output(output_context)
                        output_evaluation = output_decision
                    except Exception as exc:
                        unavailable = integrity_unavailable_code(exc) or circuit_unavailable_code(
                            exc, "OPA"
                        )
                        output_error_code = unavailable or "OUTPUT_POLICY_UNAVAILABLE"
                        event(
                            "output_policy_failed",
                            level=logging.WARNING if unavailable else logging.ERROR,
                            limited=unavailable is not None,
                            stage="output_policy",
                            request_id=command.request_id,
                            error_code=output_error_code,
                        )
                        self.dlp_metrics.failure("OUTPUT_POLICY_UNAVAILABLE")
                        output_decision = PolicyDecision.deny("OUTPUT_POLICY_UNAVAILABLE")
                        service_error = "OUTPUT_POLICY_UNAVAILABLE"

            if output_classification is None or output_decision is None:
                raise RuntimeError(
                    "Output inspection did not produce a classification and decision"
                )
            self.dlp_metrics.output_detection(
                output_classification.status,
                output_detection_ms,
            )
            output_obligations = output_decision.obligations
            mask_requested = output_decision.effect == Effect.PERMIT and bool(output_obligations)
            if output_decision.effect == Effect.PERMIT:
                if mask_requested:
                    # Only a trusted, explicitly enabled Rego REDACT obligation
                    # permits transforming a response. High-risk categories and
                    # arbitrary obligations are never silently accepted.
                    allowed = {"EMAIL_ADDRESS", "PHONE_NUMBER"}
                    findings = output_classification.findings
                    valid_mask = (
                        self.output_masking_enabled
                        and len(output_obligations) == 1
                        and output_obligations[0].type == "REDACT"
                        and set(output_obligations[0].categories) == allowed
                        and output_classification.status == DetectionStatus.PRIVATE
                        and bool(findings)
                        and all(f.category in allowed for f in findings)
                        and output_context is not None
                    )
                    if not valid_mask:
                        output_decision = PolicyDecision.deny("OUTPUT_INVALID_POLICY_PLAN")
                        service_error = "OUTPUT_INVALID_POLICY_PLAN"
                    else:
                        try:
                            released_content = redact(
                                content, output_classification, output_obligations[0].categories
                            )
                            if len(released_content.encode("utf-8")) > self.max_model_output_bytes:
                                raise RedactionError("Masked response exceeds size bound")
                            if any(content[f.start : f.end] in released_content for f in findings):
                                raise RedactionError("Original matched value remains")
                            mask_verification = await self._detect(released_content)
                            if (
                                mask_verification.status != DetectionStatus.NO_PRIVATE_DETECTED
                                or mask_verification.findings
                                or mask_verification.artifact_digest
                                != output_classification.artifact_digest
                            ):
                                raise RedactionError("Output masking verification was not clean")
                            mask_applied = True
                        except Exception:
                            event(
                                "output_mask_verification_failed",
                                level=logging.ERROR,
                                stage="output_mask",
                                request_id=command.request_id,
                                error_code="OUTPUT_MASK_VERIFICATION_FAILED",
                            )
                            self.dlp_metrics.failure("OUTPUT_MASK_VERIFY_FAILED")
                            output_decision = PolicyDecision.deny("OUTPUT_MASK_VERIFICATION_FAILED")
                            service_error = "OUTPUT_MASK_VERIFICATION_FAILED"
                elif (
                    output_classification.status != DetectionStatus.NO_PRIVATE_DETECTED
                    or output_classification.findings
                    or output_context is None
                ):
                    output_decision = PolicyDecision.deny("OUTPUT_INVALID_POLICY_PLAN")
                    service_error = "OUTPUT_INVALID_POLICY_PLAN"

            if service_error == "OUTPUT_INVALID_POLICY_PLAN":
                event(
                    "output_policy_plan_invalid",
                    level=logging.ERROR,
                    stage="output_policy",
                    request_id=command.request_id,
                    error_code="OUTPUT_INVALID_POLICY_PLAN",
                )

            # A signed release must remain trusted *after* model execution.
            # No output is released against a changed or unavailable authority.
            if self.release_store is not None and output_decision.effect == Effect.PERMIT:
                try:
                    if approved_release is None:
                        raise ReleaseIntegrityError("No approved release")
                    output_digest = output_classification.artifact_digest
                    if not output_digest or output_digest != detector_digest:
                        raise ReleaseIntegrityError("Output detector identity differs")
                    checked = await self._verify_release(
                        detector_digest=output_digest,
                        policy_digest=(
                            output_evaluation.policy_digest if output_evaluation else None
                        ),
                    )
                    if checked["release_id"] != approved_release["release_id"]:
                        raise ReleaseIntegrityError("Release changed during output inspection")
                except Exception as exc:
                    unavailable = integrity_unavailable_code(exc)
                    output_error_code = unavailable or (
                        "OUTPUT_UNTRUSTED_RELEASE"
                        if isinstance(exc, ReleaseIntegrityError)
                        else "OUTPUT_RELEASE_VERIFICATION_FAILED"
                    )
                    event(
                        "output_release_unavailable"
                        if unavailable
                        else "output_release_untrusted"
                        if isinstance(exc, ReleaseIntegrityError)
                        else "output_release_verification_failed",
                        level=logging.WARNING if unavailable else logging.ERROR,
                        limited=unavailable is not None,
                        stage="output_release",
                        request_id=command.request_id,
                        error_code=output_error_code,
                    )
                    output_decision = PolicyDecision.deny("OUTPUT_UNTRUSTED_RELEASE")
                    service_error = "OUTPUT_UNTRUSTED_RELEASE"

            released = output_decision.effect == Effect.PERMIT
            # Output evidence contains *only* structure, identities, and a keyed
            # fingerprint. No generated text or extracted sensitive values.
            output_evidence = {
                "schema_version": 2 if mask_requested else 1,
                "classification": output_classification.to_dict(),
                "policy_input": (
                    output_context.to_dict()
                    if output_context is not None
                    else OutputPolicyContext(
                        command, output_classification, self.output_masking_enabled
                    ).to_dict()
                ),
                "policy_evaluation": (
                    output_evaluation.to_dict() if output_evaluation is not None else None
                ),
                "policy_snapshot": (
                    {
                        "sha256": output_evaluation.policy_digest,
                        "revision": output_evaluation.policy_revision,
                    }
                    if output_evaluation is not None and output_evaluation.policy_digest
                    else None
                ),
                "decision": output_decision.to_dict(),
                "output_hmac_sha256": (
                    self.audit.fingerprint("model-output-v1\x00" + content)
                    if valid_content
                    else None
                ),
                "released": released,
                **(
                    {
                        "transformation": {
                            "applied": mask_applied,
                            "verification": (
                                mask_verification.to_dict()
                                if mask_verification is not None
                                else None
                            ),
                            "masked_hmac_sha256": (
                                self.audit.fingerprint(
                                    "model-output-masked-v1\x00" + released_content
                                )
                                if mask_applied
                                else None
                            ),
                        }
                    }
                    if mask_requested
                    else {}
                ),
            }
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
                    "output_dlp": output_evidence,
                },
            )
            event(
                "output_decision_committed",
                request_id=command.request_id,
                stage="output_policy",
                effect=output_decision.effect.value,
                sequence=outcome_receipt.sequence,
                execution_status="COMPLETED" if released else "OUTPUT_BLOCKED",
                transformed=mask_applied,
                error_code=output_error_code
                or service_error
                or ("OUTPUT_ALLOWED" if released else "OUTPUT_POLICY_DENIED"),
            )
            self.dlp_metrics.outcome(
                RequestStatus.COMPLETED if released else RequestStatus.OUTPUT_BLOCKED,
                masked=mask_applied and released,
            )
            return ProcessedRequest(
                command.request_id,
                RequestStatus.COMPLETED if released else RequestStatus.OUTPUT_BLOCKED,
                classification,
                decision,
                decision_receipt,
                outcome_receipt,
                output=released_content if released else None,
                model_id=model_result.model_id,
                output_classification=output_classification,
                output_decision=output_decision,
                service_error=service_error,
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
        self.dlp_metrics.outcome(RequestStatus.COMPLETED)
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
