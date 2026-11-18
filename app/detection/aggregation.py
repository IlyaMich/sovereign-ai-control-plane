"""Stable, PII-free mapping of recognizer findings to domain classifications.

This module deliberately does not depend on Presidio: different detection backends
can produce the same domain contract. All offsets refer to the original Python string.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
import hashlib
import json

from app.domain.contracts import DetectionResult, DetectionStatus, Finding, Sensitivity

# Unknown categories must never silently become safe-to-route data.
SENSITIVITY_BY_CATEGORY: dict[str, Sensitivity] = {
    "EMAIL_ADDRESS": Sensitivity.MEDIUM,
    "PHONE_NUMBER": Sensitivity.MEDIUM,
    "PERSON": Sensitivity.MEDIUM,
    "LOCATION": Sensitivity.MEDIUM,
    "CREDIT_CARD": Sensitivity.HIGH,
    "US_SSN": Sensitivity.HIGH,
    "IBAN_CODE": Sensitivity.HIGH,
    "API_CREDENTIAL": Sensitivity.HIGH,
    "PRIVATE_KEY": Sensitivity.HIGH,
}
REQUIRED_COVERAGE: frozenset[str] = frozenset({
    "EMAIL_ADDRESS", "PHONE_NUMBER", "PERSON", "CREDIT_CARD",
    "US_SSN", "API_CREDENTIAL", "PRIVATE_KEY",
})
SEVERITY = {Sensitivity.NONE: 0, Sensitivity.MEDIUM: 1, Sensitivity.HIGH: 2}


@dataclass(frozen=True)
class RawFinding:
    category: str
    start: int
    end: int
    recognizer: str
    score: float


def configuration_digest(config: dict) -> str:
    """Stable identifier for the static detection policy, without request data."""
    data = json.dumps(config, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


class FindingAggregator:
    def __init__(
        self,
        *,
        version: str,
        config_digest: str,
        required: frozenset[str] = REQUIRED_COVERAGE,
        threshold: float = 0.50,
    ) -> None:
        self.version = version
        self.config_digest = config_digest
        self.required = required
        self.threshold = threshold

    def aggregate(
        self, *, prompt: str, raw: Iterable[RawFinding], coverage: Iterable[str],
    ) -> DetectionResult:
        supported = frozenset(coverage)
        if not self.required.issubset(supported):
            return DetectionResult.unknown("RECOGNIZER_COVERAGE_INCOMPLETE")

        observations = list(raw)
        # A backend emitting invalid spans, NaN scores, or unknown entity categories is
        # not a trustworthy negative detection result. Fail closed instead of dropping it.
        for item in observations:
            if (item.category not in SENSITIVITY_BY_CATEGORY or
                not isinstance(item.start, int) or not isinstance(item.end, int) or
                not (0 <= item.start < item.end <= len(prompt)) or
                not (0.0 <= item.score <= 1.0) or
                not item.recognizer or not isinstance(item.recognizer, str)):
                return DetectionResult.unknown("DETECTION_RESULT_INVALID")

        # Low-scoring candidates are uncertainty, not proof that the text is
        # public. Mark the whole classification UNKNOWN for fail-closed routing.
        if any(item.score < self.threshold for item in observations):
            return DetectionResult.unknown("LOW_CONFIDENCE_FINDING")
        # Severity first ensures an email or person recognizer cannot mask a
        # higher-risk credential over the same span. Then confidence, length and
        # stable lexical tie-breakers remove order dependence from recognizer calls.
        observations.sort(key=lambda x: (
            -SEVERITY[SENSITIVITY_BY_CATEGORY[x.category]], -x.score,
            -(x.end - x.start), x.start, x.end, x.category, x.recognizer,
        ))
        kept: list[RawFinding] = []
        for item in observations:
            if not any(item.start < old.end and old.start < item.end for old in kept):
                kept.append(item)
        kept.sort(key=lambda x: (x.start, x.end, x.category, x.recognizer))
        findings = tuple(Finding(x.category, x.start, x.end, x.recognizer, x.score) for x in kept)
        sensitivity = (Sensitivity.HIGH if any(SENSITIVITY_BY_CATEGORY[f.category] == Sensitivity.HIGH for f in findings)
                       else Sensitivity.MEDIUM if findings else Sensitivity.NONE)
        reason_codes = tuple(sorted({"DETECTION_COMPLETE"} | {"DETECTED_" + f.category for f in findings}))
        return DetectionResult(
            DetectionStatus.PRIVATE if findings else DetectionStatus.NO_PRIVATE_DETECTED,
            sensitivity, findings, tuple(sorted(supported)), self.version, reason_codes,
            self.config_digest,
        )
