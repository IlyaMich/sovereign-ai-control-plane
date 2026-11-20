"""Privacy-preserving, process-local DLP counters; never accept arbitrary labels.

Counters reset on process restart. Signed audit evidence remains the durable
source of truth; this view is operational telemetry, not historical reporting.
"""

from __future__ import annotations

from collections import Counter, deque

from app.domain.contracts import DetectionStatus, RequestStatus
from app.infrastructure.runtime_metrics import _distribution


class DLPMetrics:
    """Updated on the owning FastAPI event loop after detection/audit steps."""

    def __init__(self, sample_window: int = 512) -> None:
        if type(sample_window) is not int or not 1 <= sample_window <= 4096:
            raise ValueError("Invalid DLP metrics window")
        self.input_status: Counter[str] = Counter()
        self.output_status: Counter[str] = Counter()
        self.outcomes: Counter[str] = Counter()
        self.failures: Counter[str] = Counter()
        self.masked = 0
        self._inspection_ms: deque[float] = deque(maxlen=sample_window)

    def input_detection(self, status: DetectionStatus) -> None:
        self.input_status[status.value] += 1

    def output_detection(self, status: DetectionStatus, elapsed_ms: float) -> None:
        self.output_status[status.value] += 1
        self._inspection_ms.append(max(0.0, elapsed_ms))

    def outcome(self, status: RequestStatus, *, masked: bool = False) -> None:
        self.outcomes[status.value] += 1
        self.masked += int(masked)

    def failure(self, kind: str) -> None:
        # An allowlist prevents diagnostic cardinality or sensitive text leakage.
        if kind not in {
            "OUTCOME_AUDIT_UNAVAILABLE",
            "OUTPUT_DETECTOR_UNAVAILABLE",
            "OUTPUT_POLICY_UNAVAILABLE",
            "OUTPUT_MASK_VERIFY_FAILED",
        }:
            raise ValueError("Unknown DLP failure kind")
        self.failures[kind] += 1

    def snapshot(self) -> dict:
        return {
            "scope": "process",
            "input_classifications": dict(sorted(self.input_status.items())),
            "output_classifications": dict(sorted(self.output_status.items())),
            "response_outcomes": dict(sorted(self.outcomes.items())),
            "masked_responses": self.masked,
            "failures": dict(sorted(self.failures.items())),
            "output_detection_latency": _distribution(self._inspection_ms),
            "persistence": "in_memory_reset_on_restart",
        }
