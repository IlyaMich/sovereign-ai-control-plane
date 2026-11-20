"""Narrow, explainable corrections for NLP-only technical label false positives.

Never filter structural credentials, emails, or non-spaCy findings. Removing a
recognizer result is inherently a precision/recall trade-off and must be
evaluated against frozen positives before approving a new signed detector.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from app.detection.aggregation import RawFinding

# The technical phrase BEGIN KEY in a prose discussion of PEM syntax is not
# a person's name. Both surrounding cues are required, not just uppercase text.
_TECHNICAL_MARKER = re.compile(
    r"\b(?:instruction|literal|marker|delimiter|token)\b[^.\n]{0,64}"
    r"\bBEGIN KEY\b[^.\n]{0,64}\b(?:PEM|private key|header)\b",
    re.IGNORECASE,
)


def refine_person_technical_markers(
    text: str, observations: Iterable[RawFinding]
) -> tuple[RawFinding, ...]:
    """Drop only spaCy PERSON on the bounded, context-confirmed marker."""
    matched = _TECHNICAL_MARKER.search(text)
    return tuple(
        finding
        for finding in observations
        if not (
            matched is not None
            and finding.category == "PERSON"
            and finding.recognizer == "SpacyRecognizer"
            and 0 <= finding.start < finding.end <= len(text)
            and text[finding.start : finding.end] == "BEGIN KEY"
            and matched.start() <= finding.start
            and finding.end <= matched.end()
        )
    )
