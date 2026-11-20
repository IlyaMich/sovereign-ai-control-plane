"""Developer-only stock Presidio baseline with no Sovereign custom recognizers.

Use the same pinned English spaCy model and threshold as the candidate for a
controlled baseline. This adapter is NOT a production Detector, does not load
any Sovereign patterns, and does not claim production coverage or policy safety.
"""

from __future__ import annotations

import hashlib
import json
from importlib import metadata
from typing import Any

from evaluation.adapters.control_plane import DetectorSetupError, _validate_dependencies

# Frozen benchmark taxonomy; do not import app/detection/rules.json, which
# includes the candidate's custom recognizers and may evolve independently.
TAXONOMY = (
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "PERSON",
    "LOCATION",
    "CREDIT_CARD",
    "US_SSN",
    "IBAN_CODE",
    "API_CREDENTIAL",
    "PRIVATE_KEY",
)
MODEL = "en_core_web_sm"
MODEL_VERSION = "3.8.0"
THRESHOLD = 0.5


def _config_digest(details: dict[str, Any]) -> str:
    data = json.dumps(details, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(data.encode("ascii")).hexdigest()


class StockPresidioAdapter:
    name = "presidio-stock"

    def __init__(
        self,
        analyzer: Any,
        supported_categories: tuple[str, ...],
        *,
        presidio_version: str = "test-only-unverified",
    ) -> None:
        self._analyzer = analyzer
        self.supported_categories = tuple(sorted(set(supported_categories) & set(TAXONOMY)))
        self._details: dict[str, Any] = {
            "kind": "stock-presidio-built-in-recognizers-only",
            "model": MODEL,
            "model_version": MODEL_VERSION,
            "presidio_version": presidio_version,
            "threshold": THRESHOLD,
            "evaluation_scope": "ASCII English; unsupported input returns UNKNOWN",
            "taxonomy": list(TAXONOMY),
            "supported_categories": list(self.supported_categories),
            "unsupported_categories": sorted(set(TAXONOMY) - set(self.supported_categories)),
            "aggregation": "Presidio native output; no Sovereign aggregation or patterns",
        }
        self._digest = _config_digest(self._details)

    @classmethod
    def create(cls) -> "StockPresidioAdapter":
        _validate_dependencies()
        # Like the production adapter, prohibit Presidio's tldextract
        # recognizer from downloading a public-suffix snapshot at runtime.
        import spacy
        import tldextract
        from presidio_analyzer import AnalyzerEngine
        from presidio_analyzer.nlp_engine import NlpEngineProvider

        tldextract.extract = tldextract.TLDExtract(  # type: ignore[assignment]
            suffix_list_urls=(), cache_dir=None
        )
        try:
            model = spacy.load(MODEL)
        except (OSError, ImportError) as exc:
            raise DetectorSetupError("Pinned spaCy model could not be loaded") from exc
        if str(model.meta.get("version", "")) != MODEL_VERSION:
            raise DetectorSetupError("Loaded spaCy model is not version 3.8.0")
        provider = NlpEngineProvider(
            nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": MODEL}],
            }
        )
        analyzer = AnalyzerEngine(nlp_engine=provider.create_engine(), supported_languages=["en"])
        supported = tuple(analyzer.get_supported_entities(language="en"))
        if not set(TAXONOMY).intersection(supported):
            raise DetectorSetupError("Stock Presidio has no supported benchmark categories")
        version = metadata.version("presidio-analyzer")
        if version != "2.2.366":
            raise DetectorSetupError("Stock Presidio baseline requires presidio-analyzer==2.2.366")
        return cls(analyzer, supported, presidio_version=version)

    def describe(self) -> dict[str, Any]:
        """Reproducible baseline identity and explicit missing-recognizer coverage."""
        return {**self._details, "config_digest": self._digest}

    def detect(self, text: str) -> dict[str, Any]:
        if not text.isascii():
            return {
                "status": "UNKNOWN",
                "findings": [],
                "reason_codes": ["UNSUPPORTED_CHARACTER_SET"],
                "detector_version": "presidio-stock-v1",
                "config_digest": self._digest,
            }
        raw = self._analyzer.analyze(
            text=text,
            language="en",
            entities=list(self.supported_categories),
            score_threshold=THRESHOLD,
        )
        findings = [
            {"category": item.entity_type, "start": item.start, "end": item.end} for item in raw
        ]
        findings.sort(key=lambda f: (f["start"], f["end"], f["category"]))
        return {
            "status": "PRIVATE" if findings else "NO_PRIVATE_DETECTED",
            "findings": findings,
            "reason_codes": [],
            "detector_version": "presidio-stock-v1",
            "config_digest": self._digest,
        }
