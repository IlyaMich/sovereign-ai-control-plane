"""Targeted precision/recall checks for high-confidence detector recognizers.

Pattern-level checks run without Presidio or spaCy. End-to-end recognition
is exercised separately by tests/test_presidio_real_integration.py.
"""

from __future__ import annotations

import re

import pytest

from app.detection.config import DetectorConfig
from evaluation.dataset import load_dataset

# Presidio's default PatternRecognizer regex flags.
FLAGS = re.IGNORECASE | re.MULTILINE | re.DOTALL


def _pattern(category: str, name: str) -> re.Pattern[str]:
    config = DetectorConfig.load()
    patterns = dict(config.patterns)[category]
    matches = [(regex, score) for title, regex, score in patterns if title == name]
    assert len(matches) == 1
    regex, score = matches[0]
    assert score >= config.threshold
    return re.compile(regex, FLAGS)


@pytest.mark.parametrize(
    "label",
    (
        "PRIVATE KEY",
        "RSA PRIVATE KEY",
        "EC PRIVATE KEY",
        "OPENSSH PRIVATE KEY",
        "ENCRYPTED PRIVATE KEY",
    ),
)
def test_full_pem_block_recognized_as_one_span(label: str) -> None:
    value = (
        f"-----BEGIN {label}-----\n"
        "SYNTHETIC-INVALID-KEY-MATERIAL\n"
        f"-----END {label}-----"
    )
    text = "Never export this value: " + value + " End of request."
    pattern = _pattern("PRIVATE_KEY", "complete-pem-private-key-block")
    matches = list(pattern.finditer(text))
    assert len(matches) == 1
    assert matches[0].span() == (text.index(value), text.index(value) + len(value))


def test_full_pem_recognizer_does_not_join_mismatched_boundaries() -> None:
    pattern = _pattern("PRIVATE_KEY", "complete-pem-private-key-block")
    assert pattern.search("-----BEGIN PRIVATE KEY-----\nDATA\n-----END RSA PRIVATE KEY-----") is None
    assert pattern.search("-----BEGIN PRIVATE KEY----- FAKE ONLY") is None


@pytest.mark.parametrize(
    "value",
    (
        "Madison, Wisconsin",
        "New York, New York",
        "St. Louis, Missouri",
        "Ft. Worth, Texas",
        "Seattle, Washington",
    ),
)
def test_city_and_full_state_are_one_location_span(value: str) -> None:
    text = f"The meeting was arranged in {value} yesterday."
    pattern = _pattern("LOCATION", "us-city-full-state")
    matches = list(pattern.finditer(text))
    assert len(matches) == 1
    assert matches[0].span() == (text.index(value), text.index(value) + len(value))


@pytest.mark.parametrize(
    "text",
    (
        "The location field is empty.",
        "Use the string PLACE_NAME, STATE_NAME in the template.",
        "Review Taylor Nguyen before exporting.",
        "Use Seattle and Washington as separate search terms.",
    ),
)
def test_city_state_pattern_avoids_unstructured_mentions(text: str) -> None:
    assert _pattern("LOCATION", "us-city-full-state").search(text) is None


def test_new_patterns_match_only_annotated_spans_in_frozen_dataset() -> None:
    """Focused fixture assurance, not a claim about full Presidio precision."""
    cases = load_dataset().cases
    new_patterns = {
        "LOCATION": _pattern("LOCATION", "us-city-full-state"),
        "PRIVATE_KEY": _pattern("PRIVATE_KEY", "complete-pem-private-key-block"),
    }
    exact_hits = {"LOCATION": 0, "PRIVATE_KEY": 0}
    for case in cases:
        for category, pattern in new_patterns.items():
            for match in pattern.finditer(case.text):
                assert any(
                    entity.category == category
                    and (entity.start, entity.end) == match.span()
                    for entity in case.entities
                ), (case.id, category, match.span())
                exact_hits[category] += 1

    # These are counts of spans matched by the new patterns, not measured
    # improvements over the existing spaCy/Presidio baseline.
    assert exact_hits == {"LOCATION": 86, "PRIVATE_KEY": 58}
