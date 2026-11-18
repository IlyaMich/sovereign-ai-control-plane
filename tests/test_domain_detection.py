from app.detection.demo import DemoPatternDetector
from app.domain.contracts import DetectionStatus, Sensitivity


def test_pattern_detection_is_stable_and_does_not_store_values():
    detector = DemoPatternDetector()
    prompt = "Email jane@example.com then jane@example.com"
    first = detector.detect(prompt)
    assert first == detector.detect(prompt)
    assert first.status == DetectionStatus.PRIVATE
    assert len(first.findings) == 2
    assert first.findings[0].category == "EMAIL_ADDRESS"
    assert "jane@example.com" not in str(first.to_dict())


def test_secret_is_high_sensitivity():
    result = DemoPatternDetector().detect("-----BEGIN PRIVATE KEY-----")
    assert result.sensitivity == Sensitivity.HIGH
    assert result.findings[0].category == "PRIVATE_KEY"


def test_non_matching_prompt_has_limited_coverage():
    result = DemoPatternDetector().detect("Hello from the local test")
    assert result.status == DetectionStatus.NO_PRIVATE_DETECTED
    assert "DEMO_RECOGNIZERS_ONLY" in result.reason_codes
