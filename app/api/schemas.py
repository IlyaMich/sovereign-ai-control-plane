"""HTTP contracts with per-application UTF-8 prompt limits."""

from typing import Any, ClassVar, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.domain.contracts import DetectionStatus, Effect, RequestStatus, Sensitivity
from app.infrastructure.config import RequestLimits


def validate_prompt_bytes(value: str, maximum: int) -> str:
    if len(value.encode("utf-8")) > maximum or not value.strip():
        raise ValueError("Invalid prompt size")
    return value


class PromptInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    max_prompt_bytes: ClassVar[int] = RequestLimits.max_prompt_bytes

    prompt: str = Field(min_length=1, max_length=RequestLimits.max_prompt_bytes)
    destination_id: str = Field(default="sovereign-model", pattern=r"^[a-z][a-z0-9-]{0,63}$")
    purpose: str = Field(default="GENERAL", pattern=r"^[A-Z][A-Z0-9_]{0,39}$")

    @field_validator("prompt")
    @classmethod
    def check_prompt_bytes(cls, value: str) -> str:
        return validate_prompt_bytes(value, cls.max_prompt_bytes)


def prompt_input_model(maximum: int) -> type[PromptInput]:
    class ConfiguredPromptInput(PromptInput):
        max_prompt_bytes: ClassVar[int] = maximum
        prompt: str = Field(min_length=1, max_length=maximum)

    return ConfiguredPromptInput


# Explicit wire models keep documentation independent of internal dataclasses.


class ErrorResponse(BaseModel):
    status: str
    reason_codes: list[str]
    detail: str
    correlation_id: str | None
    request_id: str | None = None


class FindingResponse(BaseModel):
    category: str
    start: int
    end: int
    recognizer: str
    score: float


class ClassificationResponse(BaseModel):
    status: DetectionStatus
    sensitivity: Sensitivity
    findings: list[FindingResponse]
    coverage: list[str]
    detector_version: str
    reason_codes: list[str]
    config_digest: str
    artifact_digest: str | None = None


class ObligationResponse(BaseModel):
    type: str
    destination_id: str | None = None
    categories: list[str] | None = None


class DecisionResponse(BaseModel):
    effect: Effect
    obligations: list[ObligationResponse]
    reason_codes: list[str]
    policy_revision: str
    policy_digest: str | None = None


class ReceiptResponse(BaseModel):
    sequence: int
    event_hash: str
    signature: str


class PromptResponse(BaseModel):
    request_id: str
    status: RequestStatus
    classification: ClassificationResponse
    decision: DecisionResponse
    decision_receipt: ReceiptResponse
    outcome_receipt: ReceiptResponse
    model_id: str | None
    output: str | None
    output_classification: ClassificationResponse | None = None
    output_decision: DecisionResponse | None = None


class PromptFailureResponse(PromptResponse):
    reason_codes: list[str]
    detail: str
    correlation_id: str | None


class AuditEventResponse(BaseModel):
    schema_version: str
    event_id: str
    request_id: str
    tenant_id: str
    event_type: Literal["DECISION", "OUTCOME"]
    timestamp: str
    # Signed payloads evolve independently; preserve every historical field.
    payload: dict[str, Any]


class EvidenceResponse(BaseModel):
    sequence: int
    event: AuditEventResponse
    receipt: ReceiptResponse


class RequestHistoryResponse(BaseModel):
    request_id: str
    events: list[EvidenceResponse]


class IdempotencyStatusResponse(BaseModel):
    request_id: str
    audit_state: Literal["UNRESOLVED", "OUTCOME_RECORDED", "INVALID_AUDIT_LIFECYCLE"]
    execution_status: str | None


class HealthResponse(BaseModel):
    status: Literal["UP", "READY", "TEST_MODE"]


class AdmissionResponse(BaseModel):
    limit: int
    active: int
    peak_active: int
    rejected: int


class DistributionResponse(BaseModel):
    samples: int
    p50_ms: float | None
    p95_ms: float | None
    max_ms: float | None


class ExecutorResponse(BaseModel):
    capacity: int
    active_jobs: int
    waiting_for_capacity: int
    peak_active_jobs: int
    submitted: int
    completed: int
    failed: int
    capacity_rejections: int
    submitted_by_kind: dict[str, int]
    queue_wait: DistributionResponse
    processing: DistributionResponse


class AuditLimitsResponse(BaseModel):
    maximum_waiters: int
    waiting_for_slot: int
    maximum_auxiliary_jobs: int
    auxiliary_inflight: int


class IntegrityResponse(BaseModel):
    capacity: int
    max_waiters: int
    active_jobs: int
    waiting_for_capacity: int
    rejected: int
    completed: int
    failed: int
    readiness_running: bool
    readiness_scans: int
    readiness_coalesced: int


class LoopLagResponse(DistributionResponse):
    sample_interval_seconds: float


class DiagnosticsResponse(BaseModel):
    scope: Literal["process"]
    logging: dict[str, int | str]
    http_ingress: AdmissionResponse
    admission: AdmissionResponse
    operations: AdmissionResponse
    detector: ExecutorResponse | None
    audit: ExecutorResponse | None
    audit_limits: AuditLimitsResponse | None
    event_loop: LoopLagResponse
    integrity: IntegrityResponse | None


def error_responses(*codes: int) -> dict:
    """Shared documented transport contract, including pre-routing rejections."""
    from http import HTTPStatus

    return {
        code: {"model": ErrorResponse, "description": HTTPStatus(code).phrase} for code in codes
    }


class DLPDiagnosticsResponse(BaseModel):
    scope: Literal["process"]
    input_classifications: dict[str, int]
    output_classifications: dict[str, int]
    response_outcomes: dict[str, int]
    masked_responses: int
    failures: dict[str, int]
    output_detection_latency: DistributionResponse
    persistence: Literal["in_memory_reset_on_restart"]
