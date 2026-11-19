"""Stage 1 adapter to the existing, unmodified PresidioDetector API."""

from __future__ import annotations

from importlib import metadata
from typing import Any

MODEL_INSTALL_COMMAND = (
    "python -m pip install "
    '"https://github.com/explosion/spacy-models/releases/download/'
    'en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl"'
)


class DetectorSetupError(RuntimeError):
    """Safe-to-display setup failure detected before processing benchmark cases."""


def _validate_dependencies() -> None:
    """Provide actionable, content-free diagnostics for common local install errors."""
    for distribution in ("presidio-analyzer", "spacy"):
        try:
            metadata.version(distribution)
        except metadata.PackageNotFoundError as exc:
            raise DetectorSetupError(
                f"Required package '{distribution}' is missing from this Python environment. "
                'Run: python -m pip install -e ".[dev]"'
            ) from exc
    try:
        version = metadata.version("en-core-web-sm")
    except metadata.PackageNotFoundError as exc:
        raise DetectorSetupError(
            "Required spaCy model 'en_core_web_sm' (3.8.0) is not installed. "
            f"Run: {MODEL_INSTALL_COMMAND}"
        ) from exc
    if version != "3.8.0":
        raise DetectorSetupError(
            f"Installed spaCy model version {version!r} is incompatible; expected 3.8.0. "
            f"Run: {MODEL_INSTALL_COMMAND}"
        )


class ControlPlaneAdapter:
    name = "control-plane"

    def __init__(self, detector: Any) -> None:
        self._detector = detector

    @classmethod
    def create(cls) -> "ControlPlaneAdapter":
        # Lazy load: schema, scoring, and tests work without the spaCy NLP model.
        _validate_dependencies()
        from app.detection.presidio_detector import PresidioDetector

        try:
            detector = PresidioDetector.create()
        except RuntimeError as exc:
            # Recognize only source-controlled setup failures. Never print
            # arbitrary exception strings that might contain request data.
            message = str(exc)
            if message.startswith("spaCy English model not installed;"):
                raise DetectorSetupError(
                    "spaCy cannot load 'en_core_web_sm' (3.8.0). "
                    f"Reinstall the pinned model: {MODEL_INSTALL_COMMAND}"
                ) from exc
            if message.startswith("Unexpected spaCy model version;"):
                raise DetectorSetupError(
                    "Loaded spaCy model does not match the required version 3.8.0. "
                    f"Reinstall the pinned model: {MODEL_INSTALL_COMMAND}"
                ) from exc
            if message.startswith("Required Presidio recognizers missing:"):
                raise DetectorSetupError(
                    "Presidio does not provide all recognizers required by "
                    "app/detection/rules.json. Verify installed dependency versions "
                    "and run the detector initialization check in evaluation/README.md."
                ) from exc
            raise
        return cls(detector)

    def detect(self, text: str) -> dict[str, Any]:
        # Preserve UNKNOWN and reason codes verbatim; do not normalize to negative.
        return self._detector.detect(text).to_dict()
