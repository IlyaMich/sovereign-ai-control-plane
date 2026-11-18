"""Local-only Presidio adapter with pinned spaCy model and custom pattern recognizers.

No cloud service, network model download, or remote NLP is invoked at request time.
Model artifacts must be installed into the image ahead of time.
"""
from __future__ import annotations

from typing import Any
from dataclasses import replace

from app.detection.provenance import archive_manifest, load_verified, DetectorIntegrityError

from app.detection.aggregation import (
    FindingAggregator, RawFinding, REQUIRED_COVERAGE, SENSITIVITY_BY_CATEGORY, configuration_digest,
)
from app.domain.contracts import DetectionResult

VERSION = "presidio-spacy-v1"
MODEL_NAME = "en_core_web_sm"
MODEL_VERSION = "3.8.0"

# Restrict the Presidio output to our explicit taxonomy. Other categories may be
# added deliberately, including their sensitivity mapping and policy tests.
ENTITY_CATEGORIES = (
    "EMAIL_ADDRESS", "PHONE_NUMBER", "PERSON", "LOCATION", "CREDIT_CARD",
    "US_SSN", "IBAN_CODE", "API_CREDENTIAL", "PRIVATE_KEY",
)

# These patterns deliberately detect *markers* and key formats rather than claim
# exhaustive secrets scanning. They use synthetic-safe patterns in tests.
CUSTOM_PATTERNS = {
    "API_CREDENTIAL": (
        ("aws-access-key", r"\bAKIA[0-9A-Z]{16}\b", 0.99),
        ("openai-style-key", r"\bsk-[A-Za-z0-9_-]{16,}\b", 0.98),
        ("github-pat", r"\bgh[pousr]_[A-Za-z0-9]{20,}\b", 0.98),
    ),
    "PRIVATE_KEY": (
        ("pem-private-key-header", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", 0.99),
    ),
    "EMAIL_ADDRESS": (
        ("standard-email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", 0.97),
    ),
}


class PresidioDetector:
    """Adapter implements app.domain.contracts.Detector (synchronous)."""

    def __init__(self, analyzer: Any, *, model_name: str = MODEL_NAME,
                 artifact_digest: str = "", provenance_path: str = "") -> None:
        self._analyzer = analyzer
        self._artifact_digest = artifact_digest
        self._provenance_path = provenance_path
        self._aggregator = FindingAggregator(
            version=VERSION,
            config_digest=configuration_digest({
                "version": VERSION, "nlp_model": model_name,
                "model_version": MODEL_VERSION,
                "entity_categories": ENTITY_CATEGORIES,
                "patterns": CUSTOM_PATTERNS,
                "required_coverage": sorted(REQUIRED_COVERAGE),
                "sensitivity_mapping": {k: v.value for k, v in SENSITIVITY_BY_CATEGORY.items()},
                "min_score": 0.50,
            }),
        )
        # Validate coverage at initialization (rather than treating missing
        # recognizers as evidence that a prompt is public).
        self._coverage = frozenset(analyzer.get_supported_entities(language="en"))
        missing = REQUIRED_COVERAGE - self._coverage
        if missing:
            raise RuntimeError("Required Presidio recognizers missing: " + ", ".join(sorted(missing)))

    @classmethod
    def create(cls, *, manifest_path: str | None = None,
               archive_root: str | None = None) -> "PresidioDetector":
        # Lazy imports keep domain tests and alternate adapters independent of
        # an installed heavyweight NLP runtime.
        import spacy
        # Presidio's email recognizer calls tldextract. Disable its first-use
        # network lookup and filesystem cache; use the packaged suffix snapshot.
        import tldextract
        tldextract.extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
        from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer
        from presidio_analyzer.nlp_engine import NlpEngineProvider

        try:
            model = spacy.load(MODEL_NAME)
        except (OSError, ImportError) as exc:
            raise RuntimeError("spaCy English model not installed; container image is incomplete") from exc
        model_version = str(model.meta.get("version", ""))
        if model_version != MODEL_VERSION:
            raise RuntimeError("Unexpected spaCy model version; refusing to run unpinned detection")

        provider = NlpEngineProvider(nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": MODEL_NAME}],
        })
        nlp_engine = provider.create_engine()
        analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])
        for category, patterns in CUSTOM_PATTERNS.items():
            recognizer = PatternRecognizer(
                supported_entity=category,
                name="Sovereign" + category.replace("_", "").title() + "Recognizer",
                patterns=[Pattern(name=name, regex=regex, score=score) for name, regex, score in patterns],
                supported_language="en",
            )
            analyzer.registry.add_recognizer(recognizer)
        if manifest_path is not None:
            # Start-up fails closed if code, model, or dependency bytes differ.
            manifest = load_verified(manifest_path, verify_live=True)
            if archive_root is None:
                raise DetectorIntegrityError("Detector archive is required in managed mode")
            archive_manifest(manifest, archive_root)
            return cls(analyzer, artifact_digest=manifest["digest"],
                       provenance_path=manifest_path)
        # Standalone developer/test mode; not authoritative for audit provenance.
        return cls(analyzer)

    def check_integrity(self) -> None:
        if self._provenance_path:
            actual = load_verified(self._provenance_path, verify_live=True)
            if actual["digest"] != self._artifact_digest:
                raise DetectorIntegrityError("Detector artifact identity has changed")

    def detect(self, prompt: str) -> DetectionResult:
        # Cheap per-request manifest check, plus full installed-byte integrity
        # checking at startup and readiness. Never continue with a changed ID.
        if self._provenance_path:
            if load_verified(self._provenance_path)["digest"] != self._artifact_digest:
                raise DetectorIntegrityError("Detector identity changed after initialization")
        # The initial scope is English/ASCII text. Unsupported scripts must not
        # be silently classified as nonprivate by an English-only NER model.
        if not prompt.isascii():
            return replace(DetectionResult.unknown("UNSUPPORTED_CHARACTER_SET"),
                           artifact_digest=self._artifact_digest)
        # Analyzer defaults to requesting all supported entities; limit the
        # result to the audited taxonomy and request decision metadata.
        raw = self._analyzer.analyze(
            text=prompt, language="en", entities=list(ENTITY_CATEGORIES),
            return_decision_process=True,
        )
        observations: list[RawFinding] = []
        for r in raw:
            metadata = getattr(r, "recognition_metadata", None) or {}
            explanation = getattr(r, "analysis_explanation", None)
            recognizer = (
                metadata.get("recognizer_name") or
                getattr(explanation, "recognizer", None) or
                "presidio-unknown-recognizer"
            )
            observations.append(RawFinding(
                category=r.entity_type, start=r.start, end=r.end,
                recognizer=str(recognizer), score=float(r.score),
            ))
        result = self._aggregator.aggregate(prompt=prompt, raw=observations, coverage=self._coverage)
        return replace(result, artifact_digest=self._artifact_digest)
