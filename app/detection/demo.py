"""M1-only recognizers; NOT a complete PII or secrets detector.

M2 replaces this adapter with Presidio and pinned local NLP models. Any result
from this adapter is eligible for the sovereign simulator ONLY, never egress.
"""

import re

from app.domain.contracts import DetectionResult, DetectionStatus, Finding, Sensitivity


class DemoPatternDetector:
    VERSION = "demo-patterns-v1"
    _PATTERNS = (
        ("PRIVATE_KEY", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), 100),
        ("API_CREDENTIAL", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), 100),
        ("API_CREDENTIAL", re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"), 100),
        ("EMAIL_ADDRESS", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), 10),
    )

    def detect(self, prompt: str) -> DetectionResult:
        matches: list[tuple[int, Finding]] = []
        for category, pattern, priority in self._PATTERNS:
            for m in pattern.finditer(prompt):
                matches.append(
                    (priority, Finding(category, m.start(), m.end(), "demo-patterns", 1.0))
                )
        # Resolve overlaps in a predictable priority/start/category order.
        matches.sort(key=lambda pair: (-pair[0], pair[1].start, pair[1].category))
        kept: list[Finding] = []
        for _, finding in matches:
            if not any(finding.start < old.end and old.start < finding.end for old in kept):
                kept.append(finding)
        kept.sort(key=lambda f: (f.start, f.end, f.category))
        sensitive = any(f.category in ("API_CREDENTIAL", "PRIVATE_KEY") for f in kept)
        return DetectionResult(
            status=DetectionStatus.PRIVATE if kept else DetectionStatus.NO_PRIVATE_DETECTED,
            sensitivity=Sensitivity.HIGH
            if sensitive
            else (Sensitivity.MEDIUM if kept else Sensitivity.NONE),
            findings=tuple(kept),
            coverage=("EMAIL_ADDRESS", "API_CREDENTIAL", "PRIVATE_KEY"),
            detector_version=self.VERSION,
            reason_codes=("DEMO_RECOGNIZERS_ONLY",),
        )
