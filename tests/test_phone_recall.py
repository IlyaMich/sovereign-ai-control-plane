"""Safety-focused checks for high-confidence phone recognition and aggregation.

These tests use synthetic numbers only and do not require a live model.
"""

from __future__ import annotations

import re

import pytest

from app.detection.aggregation import REQUIRED_COVERAGE, FindingAggregator, RawFinding
from app.detection.config import DetectorConfig
from app.domain.contracts import DetectionStatus
from evaluation.dataset import load_dataset


def _phone_regex() -> re.Pattern[str]:
    config = DetectorConfig.load()
    patterns = dict(config.patterns)["PHONE_NUMBER"]
    candidates = [
        (regex, score) for name, regex, score in patterns if name == "north-american-number"
    ]
    assert len(candidates) == 1
    expression, confidence = candidates[0]
    assert confidence >= config.threshold
    # Match the flags used by Presidio's PatternRecognizer.
    return re.compile(expression, re.IGNORECASE | re.MULTILINE | re.DOTALL)


@pytest.mark.parametrize(
    "value",
    (
        "202-555-0102",
        "202 555 0102",
        "202.555.0102",
        "(202) 555-0102",
        "+1 202-555-0102",
        "2025550102",
    ),
)
def test_common_north_american_phone_formats(value: str) -> None:
    text = f"Please call {value} for the synthetic test."
    match = _phone_regex().search(text)
    assert match is not None
    assert match.group() == value


@pytest.mark.parametrize(
    "text",
    (
        "Synthetic reference 123-45-6789.",
        "Credit card 4111 1111 1111 1111.",
        "Build version 2026.11.20.",
        "order-20255501021",
        "x2025550102",
        "Client phone: user at example dot com.",
        "000-000-0000",
    ),
)
def test_phone_recognizer_does_not_match_common_negatives(text: str) -> None:
    assert _phone_regex().search(text) is None


def test_phone_pattern_exact_matches_on_frozen_synthetic_corpus() -> None:
    dataset = load_dataset()
    pattern = _phone_regex()
    total = 0
    for case in dataset.cases:
        matches = tuple(pattern.finditer(case.text))
        for match in matches:
            assert any(
                expected.category == "PHONE_NUMBER"
                and (expected.start, expected.end) == match.span()
                for expected in case.entities
            ), (case.id, match.span())
            total += 1

    # A pattern-level result, not evidence of end-to-end Presidio recall.
    assert total == 96


def _aggregate(prompt: str, findings: list[RawFinding]):
    return FindingAggregator(version="presidio-spacy-v1", config_digest="test-config").aggregate(
        prompt=prompt, raw=findings, coverage=REQUIRED_COVERAGE
    )


def test_strong_full_span_supersedes_weak_same_category() -> None:
    prompt = "Call 202-555-0102 for assistance."
    start = prompt.index("202-555-0102")
    end = start + len("202-555-0102")
    high = RawFinding("PHONE_NUMBER", start, end, "custom-high", 0.96)
    weak = RawFinding("PHONE_NUMBER", start, end, "stock-low", 0.4)
    first = _aggregate(prompt, [high, weak])
    second = _aggregate(prompt, [weak, high])
    assert first == second
    assert first.status == DetectionStatus.PRIVATE
    assert len(first.findings) == 1
    assert first.findings[0].recognizer == "custom-high"
    assert first.findings[0].score == 0.96


def test_uncovered_low_confidence_still_fails_closed() -> None:
    prompt = "Call 202-555-0102 and review John."
    start = prompt.index("202-555-0102")
    end = start + len("202-555-0102")
    high = RawFinding("PHONE_NUMBER", start, end, "custom-high", 0.96)
    weak_phone = RawFinding("PHONE_NUMBER", start, end, "stock-low", 0.4)
    name = prompt.index("John")
    weak_person = RawFinding("PERSON", name, name + 4, "stock-low-person", 0.3)
    result = _aggregate(prompt, [weak_phone, high, weak_person])
    assert result.status == DetectionStatus.UNKNOWN
    assert "LOW_CONFIDENCE_FINDING" in result.reason_codes


def test_partial_or_other_category_evidence_cannot_hide_uncertainty() -> None:
    prompt = "Call 202-555-0102 for assistance."
    start = prompt.index("202-555-0102")
    end = start + len("202-555-0102")
    high = RawFinding("PHONE_NUMBER", start + 4, end, "short-strong", 0.96)
    weak = RawFinding("PHONE_NUMBER", start, end, "full-weak", 0.4)
    assert _aggregate(prompt, [high, weak]).status == DetectionStatus.UNKNOWN

    other = RawFinding("PERSON", start, end, "other-strong", 0.96)
    assert _aggregate(prompt, [other, weak]).status == DetectionStatus.UNKNOWN
