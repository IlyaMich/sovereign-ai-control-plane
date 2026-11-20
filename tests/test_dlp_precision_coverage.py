"""Narrow precision guard and expanded structural credential regression tests."""

from __future__ import annotations

import re

import pytest

from app.detection.aggregation import RawFinding
from app.detection.config import DEFAULT_CONFIG
from app.detection.precision import refine_person_technical_markers
from app.detection.presidio_detector import PresidioDetector
from app.domain.contracts import DetectionStatus
from evaluation.dataset import load_dataset


def _spacy_person(text: str, term: str) -> RawFinding:
    start = text.index(term)
    return RawFinding("PERSON", start, start + len(term), "SpacyRecognizer", 0.85)


def test_technical_begin_key_person_false_positive_removed():
    prompt = "Synthetic negative 0009: The instruction says BEGIN KEY, not a PEM private key."
    finding = _spacy_person(prompt, "BEGIN KEY")
    assert refine_person_technical_markers(prompt, (finding,)) == ()


@pytest.mark.parametrize(
    "content",
    [
        "Meeting with BEGIN KEY at the office.",
        "The instruction says BEGIN KEY and nothing more.",
        "A private key holder called BEGIN KEY attended.",
    ],
)
def test_marker_precision_guard_requires_all_context_clues(content):
    finding = _spacy_person(content, "BEGIN KEY")
    assert refine_person_technical_markers(content, (finding,)) == (finding,)


def test_precision_filter_never_suppresses_structural_email_or_other_recognizer():
    text = "The instruction says BEGIN KEY, not a PEM private key. Contact jane@example.com"
    person = _spacy_person(text, "BEGIN KEY")
    email_start = text.index("jane@example.com")
    email = RawFinding(
        "EMAIL_ADDRESS", email_start, email_start + 16, "SovereignEmailRecognizer", 0.99
    )
    assert refine_person_technical_markers(text, (person, email)) == (email,)
    other_person = RawFinding("PERSON", person.start, person.end, "TrustedOther", 0.95)
    assert refine_person_technical_markers(text, (other_person,)) == (other_person,)


def test_new_credential_patterns_require_full_token_shape():
    patterns = dict(DEFAULT_CONFIG.patterns)["API_CREDENTIAL"]
    compiled = {name: re.compile(regex) for name, regex, _ in patterns}
    gitlab = "glpat-" + "A1b2C3d4E5f6G7h8I9j0"
    slack = "xoxb-" + "1234567890-" + "1234567890-" + "aBcD1eFgH2iJkL3mN4oP"
    assert compiled["gitlab-personal-access-token"].search("token=" + gitlab)
    assert compiled["slack-bot-and-user-token"].search("token=" + slack)
    for text in ("glpat-", "glpat-short", "xoxb-", "xoxb-123-456-abc", "glpat-example"):
        assert not compiled["gitlab-personal-access-token"].search(text)
        assert not compiled["slack-bot-and-user-token"].search(text)


@pytest.fixture(scope="module")
def real_presidio():
    pytest.importorskip("en_core_web_sm")
    return PresidioDetector.create()


def test_full_presidio_no_longer_marks_literal_begin_key_as_person(real_presidio):
    target = next(case for case in load_dataset().cases if case.id == "HARD_NEGATIVE-0009")
    prediction = real_presidio.detect(target.text)
    assert prediction.status == DetectionStatus.NO_PRIVATE_DETECTED
    assert not prediction.findings


@pytest.mark.parametrize(
    "token",
    [
        "glpat-" + "A1b2C3d4E5f6G7h8I9j0",
        "xoxb-" + "1234567890-" + "1234567890-" + "aBcD1eFgH2iJkL3mN4oP",
    ],
)
def test_full_presidio_detects_new_high_confidence_credentials(real_presidio, token):
    result = real_presidio.detect("Synthetic token: " + token)
    assert result.status == DetectionStatus.PRIVATE
    assert "API_CREDENTIAL" in {finding.category for finding in result.findings}
