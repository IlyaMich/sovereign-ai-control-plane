import math

from app.detection.aggregation import REQUIRED_COVERAGE, FindingAggregator, RawFinding
from app.domain.contracts import DetectionStatus, Sensitivity


def aggregator():
    return FindingAggregator(version="presidio-spacy-v1", config_digest="digest-test")


def test_determinism_and_deduplication_independent_of_recognizer_order():
    prompt = "email alice@example.com"
    values = [
        RawFinding("EMAIL_ADDRESS", 6, len(prompt), "regex", 0.97),
        RawFinding("EMAIL_ADDRESS", 6, len(prompt), "builtin", 0.85),
        RawFinding("PERSON", 6, 11, "spacy", 0.83),
    ]
    a = aggregator().aggregate(prompt=prompt, raw=values, coverage=REQUIRED_COVERAGE)
    b = aggregator().aggregate(prompt=prompt, raw=reversed(values), coverage=REQUIRED_COVERAGE)
    assert a == b
    assert len(a.findings) == 1
    assert a.findings[0].recognizer == "regex"
    assert a.status == DetectionStatus.PRIVATE
    assert a.sensitivity == Sensitivity.MEDIUM
    assert "alice@example.com" not in str(a.to_dict())
    assert a.config_digest == "digest-test"


def test_credentials_have_priority_over_lower_risk_overlaps():
    text = "-----BEGIN PRIVATE KEY-----"
    raw = [
        RawFinding("PERSON", 0, 11, "nlp", 0.99),
        RawFinding("PRIVATE_KEY", 0, len(text), "pattern", 0.98),
    ]
    result = aggregator().aggregate(prompt=text, raw=raw, coverage=REQUIRED_COVERAGE)
    assert result.findings[0].category == "PRIVATE_KEY"
    assert result.sensitivity == Sensitivity.HIGH


def test_unsupported_category_fails_closed():
    result = aggregator().aggregate(
        prompt="abc",
        raw=[RawFinding("UNMAPPED_SECRET", 0, 3, "test", 0.9)],
        coverage=REQUIRED_COVERAGE,
    )
    assert result.status == DetectionStatus.UNKNOWN
    assert "DETECTION_RESULT_INVALID" in result.reason_codes


def test_missing_mandatory_recognizers_fails_closed():
    result = aggregator().aggregate(prompt="hello", raw=[], coverage=["EMAIL_ADDRESS"])
    assert result.status == DetectionStatus.UNKNOWN
    assert "RECOGNIZER_COVERAGE_INCOMPLETE" in result.reason_codes


def test_invalid_offsets_and_scores_fail_closed():
    for bad in (
        RawFinding("PERSON", -1, 3, "nlp", 0.9),
        RawFinding("PERSON", 0, 100, "nlp", 0.9),
        RawFinding("PERSON", 0, 2, "nlp", math.nan),
    ):
        result = aggregator().aggregate(prompt="hello", raw=[bad], coverage=REQUIRED_COVERAGE)
        assert result.status == DetectionStatus.UNKNOWN


def test_public_classification_requires_complete_coverage():
    result = aggregator().aggregate(prompt="hello", raw=[], coverage=REQUIRED_COVERAGE)
    assert result.status == DetectionStatus.NO_PRIVATE_DETECTED
    assert result.sensitivity == Sensitivity.NONE
    assert result.reason_codes == ("DETECTION_COMPLETE",)


def test_low_confidence_is_unknown_not_public():
    result = aggregator().aggregate(
        prompt="John", raw=[RawFinding("PERSON", 0, 4, "nlp", 0.2)], coverage=REQUIRED_COVERAGE
    )
    assert result.status == DetectionStatus.UNKNOWN
    assert "LOW_CONFIDENCE_FINDING" in result.reason_codes
