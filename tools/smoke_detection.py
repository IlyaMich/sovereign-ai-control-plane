"""Smoke tests with the real installed Presidio+spaCy adapter (no cloud traffic)."""
from app.detection.presidio_detector import PresidioDetector


def main() -> None:
    detector = PresidioDetector.create()
    fixtures = [
        ("ordinary", "Compute a sum of two integers", "NO_PRIVATE_DETECTED", None),
        ("email", "Contact jane@example.com for details", "PRIVATE", "EMAIL_ADDRESS"),
        ("private-key", "-----BEGIN PRIVATE KEY-----", "PRIVATE", "PRIVATE_KEY"),
        ("unsupported-script", "שלום", "UNKNOWN", None),
    ]
    for title, prompt, status, category in fixtures:
        result = detector.detect(prompt)
        categories = {f.category for f in result.findings}
        if result.status.value != status or (category and category not in categories):
            raise RuntimeError(f"Detection smoke failed: {title} ({result.status.value}; {sorted(categories)})")
        print(f"PASS: {title} -> {result.status.value}")
    print("Real Presidio/spaCy smoke tests passed")


if __name__ == "__main__":
    main()
