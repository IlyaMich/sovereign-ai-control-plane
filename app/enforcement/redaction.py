"""Deterministic single-pass redaction using original offsets; never expose values."""

from app.domain.contracts import DetectionResult


class RedactionError(Exception):
    pass


def redact(prompt: str, classification: DetectionResult, categories: tuple[str, ...]) -> str:
    allowed = set(categories)
    findings = sorted(classification.findings, key=lambda f: (f.start, f.end, f.category))
    if not findings or not allowed or any(f.category not in allowed for f in findings):
        raise RedactionError("Missing required span or category")
    cursor = 0
    parts: list[str] = []
    for finding in findings:
        if not (cursor <= finding.start < finding.end <= len(prompt)):
            raise RedactionError("Invalid or overlapping span")
        parts.extend((prompt[cursor : finding.start], f"[REDACTED_{finding.category}]"))
        cursor = finding.end
    parts.append(prompt[cursor:])
    result = "".join(parts)
    if result == prompt:
        raise RedactionError("No transformation performed")
    return result
