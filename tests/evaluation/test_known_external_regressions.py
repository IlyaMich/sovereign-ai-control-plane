"""Safety regressions for known 2026-11-20 real-detector replay findings.

A passing pre-egress guard test does NOT establish universal PII detection.
Full Rego-backed replay must still run against the new signed release candidate.
"""
from __future__ import annotations

import pytest

from app.enforcement.pre_egress import external_content_signals
from evaluation.dataset import load_dataset

# Frozen v1 benchmark case IDs verified against the archived 1200-case replay.
KNOWN_UNSAFE = (
    *(f"STANDARD_SENSITIVE-{i:04d}" for i in range(216, 256, 3)),
    "ADVERSARIAL-0003", "ADVERSARIAL-0012", "ADVERSARIAL-0021",
    "ADVERSARIAL-0030", "ADVERSARIAL-0075", "ADVERSARIAL-0084",
    "ADVERSARIAL-0093", "ADVERSARIAL-0102", "ADVERSARIAL-0111",
    "ADVERSARIAL-0120",
)


def test_all_24_previously_unsafe_cases_are_screened():
    dataset = load_dataset()
    by_id = {case.id: case for case in dataset.cases}
    assert len(KNOWN_UNSAFE) == 24
    assert len(set(KNOWN_UNSAFE)) == 24
    for cid in KNOWN_UNSAFE:
        case = by_id[cid]
        assert case.expected_status == "PRIVATE"
        assert external_content_signals(case.text, case.text), cid


def test_partial_redaction_cannot_erase_source_signal():
    source = "Transfer note: <Taylor\nNguyen>."
    partially_redacted = source.replace("Taylor", "[REDACTED_PERSON]")
    # The remaining surname may be undetectable to a second Presidio scan.
    assert "MULTILINE_PROPER_NAME" in external_content_signals(source, partially_redacted)
    assert "MULTILINE_PROPER_NAME" not in external_content_signals(
        partially_redacted, partially_redacted
    )


@pytest.mark.parametrize("source", [
    "The account lists 123-45-6789",
    "The account lists 219 09 9999",
    "The account lists 111.22.3333",
    "Please review: <Avery\nChen>",
    "Please review: <AVERY\nCHEN>",
])
def test_generalized_suspicious_external_forms_are_blocked(source):
    assert external_content_signals(source, source)


@pytest.mark.parametrize("source", [
    "Documentation references 000-00-0000 as an invalid placeholder",
    "Internal work: Explain latency and throughput",
    "Contact [REDACTED_EMAIL_ADDRESS] for details",
    "First\nsecond is not a proper name pair",
])
def test_expected_clean_payloads_are_not_screened(source):
    assert external_content_signals(source, source) == ()


def test_known_clean_dataset_remains_eligible_for_external_route():
    dataset = load_dataset()
    negatives = [c for c in dataset.cases if c.group in {"clean", "hard_negative"}]
    assert len(negatives) == 450
    for case in negatives:
        assert not external_content_signals(case.text, case.text), case.id


@pytest.mark.asyncio
async def test_all_24_fail_closed_with_a_deliberately_blind_detector():
    """If Stage 2 is installed, exercise real orchestrator and temporary audit."""
    pytest.importorskip("app.application.orchestrator")
    from app.domain.contracts import DetectionResult, DetectionStatus, Sensitivity
    from evaluation.enforcement.core import replay_cases

    class BlindDetector:
        def detect(self, prompt: str) -> DetectionResult:
            return DetectionResult(
                DetectionStatus.NO_PRIVATE_DETECTED, Sensitivity.NONE, (),
                ("EMAIL_ADDRESS", "PHONE_NUMBER", "PERSON", "CREDIT_CARD",
                 "US_SSN", "API_CREDENTIAL", "PRIVATE_KEY"),
                "presidio-spacy-v1", (), "blind-detector-fixture",
            )

    selected = tuple(c for c in load_dataset().cases if c.id in KNOWN_UNSAFE)
    report = await replay_cases(selected, detector=BlindDetector())
    assert report["cases"] == 24
    assert report["unsafe_external_forward_count"] == 0, report["issues"]
    assert report["incomplete_or_unknown_cases"] == 0
    assert all(not r["forwarded"] for r in report["rows"])
