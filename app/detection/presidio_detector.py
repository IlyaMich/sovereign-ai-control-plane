"""Local-only Presidio adapter with pinned spaCy model and custom pattern recognizers.

No cloud service, network model download, or remote NLP is invoked at request time.
Model artifacts must be installed into the image ahead of time.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from app.detection.aggregation import (
    FindingAggregator,
    RawFinding,
    configuration_digest,
)
from app.detection.config import DEFAULT_CONFIG, DetectorConfig
from app.detection.precision import refine_person_technical_markers
from app.detection.provenance import DetectorIntegrityError, archive_manifest, load_verified
from app.domain.contracts import DetectionResult

VERSION = "presidio-spacy-v1"
MODEL_NAME = "en_core_web_sm"
MODEL_VERSION = "3.8.0"

ENTITY_CATEGORIES = DEFAULT_CONFIG.entity_categories
CUSTOM_PATTERNS = dict(DEFAULT_CONFIG.patterns)


class PresidioDetector:
    """Adapter implements app.domain.contracts.Detector (synchronous)."""

    def __init__(
        self,
        analyzer: Any,
        *,
        model_name: str = MODEL_NAME,
        artifact_digest: str = "",
        provenance_path: str = "",
        config: DetectorConfig | None = None,
    ) -> None:
        self._config = config or DetectorConfig.load()
        self._analyzer = analyzer
        self._artifact_digest = artifact_digest
        self._provenance_path = provenance_path
        self._aggregator = FindingAggregator(
            version=VERSION,
            required=self._config.required_coverage,
            threshold=self._config.threshold,
            sensitivity_mapping=dict(self._config.sensitivity_mapping),
            config_digest=configuration_digest(
                {
                    "version": VERSION,
                    "nlp_model": model_name,
                    "model_version": MODEL_VERSION,
                    **self._config.to_dict(),
                }
            ),
        )
        # Validate coverage at initialization (rather than treating missing
        # recognizers as evidence that a prompt is public).
        self._coverage = frozenset(analyzer.get_supported_entities(language="en")) & frozenset(
            self._config.entity_categories
        )
        missing = self._config.required_coverage - self._coverage
        if missing:
            raise RuntimeError(
                "Required Presidio recognizers missing: " + ", ".join(sorted(missing))
            )

    @classmethod
    def create(
        cls, *, manifest_path: str | None = None, archive_root: str | None = None
    ) -> "PresidioDetector":
        # Lazy imports keep domain tests and alternate adapters independent of
        # an installed heavyweight NLP runtime.
        config = DetectorConfig.load()
        import spacy

        # Presidio's email recognizer calls tldextract. Disable its first-use
        # network lookup and filesystem cache; use the packaged suffix snapshot.
        import tldextract

        # Replace the wrapped default with an offline callable of the same interface.
        tldextract.extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)  # type: ignore[assignment]
        from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer
        from presidio_analyzer.nlp_engine import NlpEngineProvider

        try:
            model = spacy.load(MODEL_NAME)
        except (OSError, ImportError) as exc:
            raise RuntimeError(
                "spaCy English model not installed; container image is incomplete"
            ) from exc
        model_version = str(model.meta.get("version", ""))
        if model_version != MODEL_VERSION:
            raise RuntimeError("Unexpected spaCy model version; refusing to run unpinned detection")

        provider = NlpEngineProvider(
            nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": MODEL_NAME}],
            }
        )
        nlp_engine = provider.create_engine()
        analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])
        for category, patterns in dict(config.patterns).items():
            recognizer = PatternRecognizer(
                supported_entity=category,
                name="Sovereign" + category.replace("_", "").title() + "Recognizer",
                patterns=[
                    Pattern(name=name, regex=regex, score=score) for name, regex, score in patterns
                ],
                supported_language="en",
            )
            analyzer.registry.add_recognizer(recognizer)
        if manifest_path is not None:
            # Start-up fails closed if code, model, or dependency bytes differ.
            manifest = load_verified(manifest_path, verify_live=True)
            if archive_root is None:
                raise DetectorIntegrityError("Detector archive is required in managed mode")
            archive_manifest(manifest, archive_root)
            return cls(
                analyzer,
                artifact_digest=manifest["digest"],
                provenance_path=manifest_path,
                config=config,
            )
        # Standalone developer/test mode; not authoritative for audit provenance.
        return cls(analyzer, config=config)

    def check_integrity(self) -> None:
        if self._provenance_path:
            if DetectorConfig.load() != self._config:
                raise DetectorIntegrityError("Detector rules changed after initialization")
            actual = load_verified(self._provenance_path, verify_live=True)
            if actual["digest"] != self._artifact_digest:
                raise DetectorIntegrityError("Detector artifact identity has changed")

    def detect(self, prompt: str) -> DetectionResult:
        # Cheap per-request manifest check, plus full installed-byte integrity
        # checking at startup and readiness. Never continue with a changed ID.
        if self._provenance_path:
            if DetectorConfig.load() != self._config:
                raise DetectorIntegrityError("Detector rules changed after initialization")
            if load_verified(self._provenance_path)["digest"] != self._artifact_digest:
                raise DetectorIntegrityError("Detector identity changed after initialization")
        # The initial scope is English/ASCII text. Unsupported scripts must not
        # be silently classified as nonprivate by an English-only NER model.
        if not prompt.isascii():
            return replace(
                DetectionResult.unknown("UNSUPPORTED_CHARACTER_SET"),
                artifact_digest=self._artifact_digest,
            )
        # Analyzer defaults to requesting all supported entities; limit the
        # result to the audited taxonomy and request decision metadata.
        raw = self._analyzer.analyze(
            text=prompt,
            language="en",
            entities=list(self._config.entity_categories),
            score_threshold=0.0,  # Preserve low-confidence findings for fail-closed aggregation.
            return_decision_process=True,
        )
        observations: list[RawFinding] = []
        for r in raw:
            metadata = getattr(r, "recognition_metadata", None) or {}
            explanation = getattr(r, "analysis_explanation", None)
            recognizer = (
                metadata.get("recognizer_name")
                or getattr(explanation, "recognizer", None)
                or "presidio-unknown-recognizer"
            )
            observations.append(
                RawFinding(
                    category=r.entity_type,
                    start=r.start,
                    end=r.end,
                    recognizer=str(recognizer),
                    score=float(r.score),
                )
            )
        result = self._aggregator.aggregate(
            prompt=prompt,
            raw=refine_person_technical_markers(prompt, observations),
            coverage=self._coverage
        )
        return replace(result, artifact_digest=self._artifact_digest)
