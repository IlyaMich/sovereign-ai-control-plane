"""Stable, PII-free mapping of recognizer findings to domain classifications.

This module deliberately does not depend on Presidio: different detection backends
can produce the same domain contract. All offsets refer to the original Python string.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass

from app.detection.config import DEFAULT_CONFIG
from app.domain.contracts import DetectionResult, DetectionStatus, Finding, Sensitivity

SENSITIVITY_BY_CATEGORY = dict(DEFAULT_CONFIG.sensitivity_mapping)
REQUIRED_COVERAGE = DEFAULT_CONFIG.required_coverage
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
        threshold: float = DEFAULT_CONFIG.threshold,
        sensitivity_mapping: dict[str, Sensitivity] | None = None,
    ) -> None:
        self.version = version
        self.config_digest = config_digest
        self.required = required
        self.threshold = threshold
        self.sensitivity_mapping = dict(
            SENSITIVITY_BY_CATEGORY if sensitivity_mapping is None else sensitivity_mapping
        )

    def aggregate(
        self,
        *,
        prompt: str,
        raw: Iterable[RawFinding],
        coverage: Iterable[str],
    ) -> DetectionResult:
        supported = frozenset(coverage)
        if not self.required.issubset(supported):
            return DetectionResult.unknown("RECOGNIZER_COVERAGE_INCOMPLETE")

        observations = list(raw)
        # A backend emitting invalid spans, NaN scores, or unknown entity categories is
        # not a trustworthy negative detection result. Fail closed instead of dropping it.
        for item in observations:
            if (
                item.category not in self.sensitivity_mapping
                or not isinstance(item.start, int)
                or not isinstance(item.end, int)
                or not (0 <= item.start < item.end <= len(prompt))
                or not (0.0 <= item.score <= 1.0)
                or not item.recognizer
                or not isinstance(item.recognizer, str)
            ):
                return DetectionResult.unknown("DETECTION_RESULT_INVALID")

        # Ignore a weak candidate only if a strong detection of the SAME
        # category fully covers it. This prevents an inferior recognizer from
        # turning a confidently detected phone number into UNKNOWN, without
        # ignoring unrelated or partially covered low-confidence signals.
        strong = [item for item in observations if item.score >= self.threshold]
        for weak in (item for item in observations if item.score < self.threshold):
            if not any(
                candidate.category == weak.category
                and candidate.start <= weak.start
                and weak.end <= candidate.end
                for candidate in strong
            ):
                return DetectionResult.unknown("LOW_CONFIDENCE_FINDING")
        observations = strong
        # Severity first ensures an email or person recognizer cannot mask a
        # higher-risk credential over the same span. Then confidence, length and
        # stable lexical tie-breakers remove order dependence from recognizer calls.
        observations.sort(
            key=lambda x: (
                -SEVERITY[self.sensitivity_mapping[x.category]],
                -x.score,
                -(x.end - x.start),
                x.start,
                x.end,
                x.category,
                x.recognizer,
            )
        )
        kept: list[RawFinding] = []
        for item in observations:
            if not any(item.start < old.end and old.start < item.end for old in kept):
                kept.append(item)
        kept.sort(key=lambda x: (x.start, x.end, x.category, x.recognizer))
        findings = tuple(Finding(x.category, x.start, x.end, x.recognizer, x.score) for x in kept)
        sensitivity = (
            Sensitivity.HIGH
            if any(self.sensitivity_mapping[f.category] == Sensitivity.HIGH for f in findings)
            else Sensitivity.MEDIUM
            if findings
            else Sensitivity.NONE
        )
        reason_codes = tuple(
            sorted({"DETECTION_COMPLETE"} | {"DETECTED_" + f.category for f in findings})
        )
        return DetectionResult(
            DetectionStatus.PRIVATE if findings else DetectionStatus.NO_PRIVATE_DETECTED,
            sensitivity,
            findings,
            tuple(sorted(supported)),
            self.version,
            reason_codes,
            self.config_digest,
        )
