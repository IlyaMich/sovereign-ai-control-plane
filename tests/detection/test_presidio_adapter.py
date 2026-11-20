"""Adapter-level contract tests without heavyweight NLP dependencies.

The container smoke checks additionally use the real installed spaCy model.
"""

from types import SimpleNamespace

import pytest

from app.detection.aggregation import REQUIRED_COVERAGE
from app.detection.presidio_detector import PresidioDetector
from app.domain.contracts import DetectionStatus


class StubAnalyzer:
    def __init__(self, results=(), coverage=REQUIRED_COVERAGE):
        self.results = results
        self.coverage = coverage
        self.calls = []

    def get_supported_entities(self, *, language):
        assert language == "en"
        return list(self.coverage)

    def analyze(self, **kwargs):
        self.calls.append(kwargs)
        return self.results


def test_presidio_adapter_maps_explanations_and_hides_values():
    prompt = "Email bob@example.com please"
    stub = StubAnalyzer(
        [
            SimpleNamespace(
                entity_type="EMAIL_ADDRESS",
                start=6,
                end=21,
                score=0.97,
                recognition_metadata={"recognizer_name": "EmailPattern"},
                analysis_explanation=None,
            )
        ]
    )
    result = PresidioDetector(stub).detect(prompt)
    assert result.status == DetectionStatus.PRIVATE
    assert result.findings[0].recognizer == "EmailPattern"
    assert stub.calls[0]["return_decision_process"] is True
    assert "bob@example.com" not in str(result.to_dict())


def test_presidio_adapter_refuses_missing_recognizers_at_startup():
    with pytest.raises(RuntimeError, match="recognizers missing"):
        PresidioDetector(StubAnalyzer(coverage={"EMAIL_ADDRESS"}))


def test_presidio_analyzer_failure_propagates_to_orchestrator():
    class BadAnalyzer(StubAnalyzer):
        def analyze(self, **kwargs):
            raise RuntimeError("sensitive value! should never log this")

    with pytest.raises(RuntimeError):
        PresidioDetector(BadAnalyzer()).detect("sensitive value")


def test_unsupported_characters_fail_closed_without_invoking_nlp():
    stub = StubAnalyzer()
    result = PresidioDetector(stub).detect("שלום")
    assert result.status == DetectionStatus.UNKNOWN
    assert "UNSUPPORTED_CHARACTER_SET" in result.reason_codes
    assert stub.calls == []
