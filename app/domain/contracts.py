"""Technology-neutral domain contracts. Only primitive data and Python stdlib types."""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol


class DetectionStatus(StrEnum):
    PRIVATE = "PRIVATE"
    NO_PRIVATE_DETECTED = "NO_PRIVATE_DETECTED"
    UNKNOWN = "UNKNOWN"


class Sensitivity(StrEnum):
    NONE = "NONE"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    UNKNOWN = "UNKNOWN"


class Effect(StrEnum):
    PERMIT = "PERMIT"
    DENY = "DENY"


class RequestStatus(StrEnum):
    BLOCKED = "BLOCKED"
    COMPLETED = "COMPLETED"
    ERROR = "ERROR"


@dataclass(frozen=True)
class Principal:
    principal_id: str
    tenant_id: str
    roles: tuple[str, ...]


@dataclass(frozen=True)
class PromptCommand:
    request_id: str
    prompt: str
    destination_id: str
    purpose: str
    principal: Principal


@dataclass(frozen=True)
class Finding:
    category: str
    start: int
    end: int
    recognizer: str
    score: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "start": self.start,
            "end": self.end,
            "recognizer": self.recognizer,
            "score": self.score,
        }


@dataclass(frozen=True)
class DetectionResult:
    status: DetectionStatus
    sensitivity: Sensitivity
    findings: tuple[Finding, ...]
    coverage: tuple[str, ...]
    detector_version: str
    reason_codes: tuple[str, ...] = ()
    config_digest: str = ""
    artifact_digest: str = ""

    @classmethod
    def unknown(cls, reason_code: str = "DETECTION_UNAVAILABLE") -> DetectionResult:
        return cls(
            DetectionStatus.UNKNOWN,
            Sensitivity.UNKNOWN,
            (),
            (),
            "unknown",
            (reason_code,),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "sensitivity": self.sensitivity.value,
            "findings": [f.to_dict() for f in self.findings],
            "coverage": list(self.coverage),
            "detector_version": self.detector_version,
            "reason_codes": list(self.reason_codes),
            "config_digest": self.config_digest,
            **({"artifact_digest": self.artifact_digest} if self.artifact_digest else {}),
        }


@dataclass(frozen=True)
class PolicyContext:
    command: PromptCommand
    classification: DetectionResult

    def to_dict(self) -> dict[str, Any]:
        return {
            "principal": {
                "id": self.command.principal.principal_id,
                "tenant_id": self.command.principal.tenant_id,
                "roles": list(self.command.principal.roles),
            },
            "request": {
                "destination_id": self.command.destination_id,
                "purpose": self.command.purpose,
            },
            "classification": self.classification.to_dict(),
        }


@dataclass(frozen=True)
class Obligation:
    type: str
    destination_id: str | None = None
    categories: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"type": self.type}
        if self.destination_id is not None:
            result["destination_id"] = self.destination_id
        if self.categories:
            result["categories"] = list(self.categories)
        return result


@dataclass(frozen=True)
class PolicyDecision:
    effect: Effect
    obligations: tuple[Obligation, ...]
    reason_codes: tuple[str, ...]
    policy_revision: str
    policy_digest: str = ""

    @classmethod
    def deny(cls, reason: str, revision: str = "local-fail-closed-v1") -> PolicyDecision:
        return cls(Effect.DENY, (), (reason,), revision)

    def to_dict(self) -> dict[str, Any]:
        return {
            "effect": self.effect.value,
            "obligations": [o.to_dict() for o in self.obligations],
            "reason_codes": list(self.reason_codes),
            "policy_revision": self.policy_revision,
            **({"policy_digest": self.policy_digest} if self.policy_digest else {}),
        }


@dataclass(frozen=True)
class ModelResult:
    model_id: str
    output: str


@dataclass(frozen=True)
class AuditReceipt:
    sequence: int
    event_hash: str
    signature: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "event_hash": self.event_hash,
            "signature": self.signature,
        }


@dataclass(frozen=True)
class ProcessedRequest:
    request_id: str
    status: RequestStatus
    classification: DetectionResult
    decision: PolicyDecision
    decision_receipt: AuditReceipt
    outcome_receipt: AuditReceipt
    output: str | None = None
    model_id: str | None = None


class Detector(Protocol):
    def detect(self, prompt: str) -> DetectionResult: ...


class PolicyEvaluator(Protocol):
    async def evaluate(self, context: PolicyContext) -> PolicyDecision: ...


class AuditWriter(Protocol):
    def fingerprint(self, prompt: str) -> str: ...

    def commit(self, request_id: str, tenant_id: str, event_type: str, payload: dict[str, Any]) -> AuditReceipt: ...


class ModelGateway(Protocol):
    async def invoke(self, request_id: str, prompt: str, destination_id: str) -> ModelResult: ...
