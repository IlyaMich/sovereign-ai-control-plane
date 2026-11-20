"""Runs against installed Presidio/spaCy in the Podman image, skipped otherwise."""

import importlib.util

import pytest


@pytest.mark.skipif(
    importlib.util.find_spec("presidio_analyzer") is None
    or importlib.util.find_spec("en_core_web_sm") is None,
    reason="Presidio and pinned spaCy model are only installed in the M2 container",
)
def test_real_presidio_detects_patterns_and_completes_coverage():
    from app.detection.presidio_detector import PresidioDetector

    detector = PresidioDetector.create()

    email = detector.detect("Contact jane@example.com")
    assert email.status.value == "PRIVATE"
    assert "EMAIL_ADDRESS" in {f.category for f in email.findings}
    assert email.config_digest

    secret = detector.detect("-----BEGIN PRIVATE KEY-----")
    assert secret.status.value == "PRIVATE"
    assert "PRIVATE_KEY" in {f.category for f in secret.findings}
    assert secret.sensitivity.value == "HIGH"

    clean = detector.detect("Explain local policy evaluation in simple terms")
    assert clean.status.value != "UNKNOWN"


@pytest.mark.skipif(
    importlib.util.find_spec("presidio_analyzer") is None
    or importlib.util.find_spec("en_core_web_sm") is None,
    reason="Requires pinned Presidio and spaCy model",
)
def test_real_presidio_preserves_new_full_spans():
    """End-to-end check that configured recognizers survive Presidio aggregation."""
    from app.detection.presidio_detector import PresidioDetector

    detector = PresidioDetector.create()
    labels = (
        (
            "PRIVATE_KEY",
            "-----BEGIN PRIVATE KEY-----\n"
            "SYNTHETIC-INVALID-KEY-MATERIAL\n"
            "-----END PRIVATE KEY-----",
        ),
        ("LOCATION", "Madison, Wisconsin"),
    )
    for category, value in labels:
        prompt = "Handle carefully: " + value + " before exporting."
        result = detector.detect(prompt)
        expected = (prompt.index(value), prompt.index(value) + len(value))
        assert result.status.value == "PRIVATE", (category, result.reason_codes)
        assert any(
            finding.category == category
            and (finding.start, finding.end) == expected
            for finding in result.findings
        ), (category, result.to_dict())
