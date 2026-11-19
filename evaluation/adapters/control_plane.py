"""Stage 1 adapter to the existing, unmodified PresidioDetector API."""
from __future__ import annotations

from typing import Any


class ControlPlaneAdapter:
    name = "control-plane"

    def __init__(self, detector: Any) -> None:
        self._detector = detector

    @classmethod
    def create(cls) -> "ControlPlaneAdapter":
        # Lazy load: schema, scoring, and tests work without the spaCy NLP model.
        from app.detection.presidio_detector import PresidioDetector

        return cls(PresidioDetector.create())

    def detect(self, text: str) -> dict[str, Any]:
        # Preserve UNKNOWN and reason codes verbatim; do not normalize to negative.
        return self._detector.detect(text).to_dict()
