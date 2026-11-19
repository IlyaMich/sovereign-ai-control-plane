"""Create the frozen, synthetic v1 ground truth. No production imports or network use.

Do not modify v1 to improve a benchmark score. Publish a new dataset version instead.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).parent / "datasets" / "v1"
VERSION = "1.0.0"
COUNTS = {
    "standard_sensitive": 350,
    "clean": 250,
    "hard_negative": 200,
    "mixed_entities": 150,
    "adversarial": 150,
    "unsupported": 100,
}
CATEGORIES = (
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
NAMES = (
    "Avery Chen",
    "Morgan Patel",
    "Riley Brooks",
    "Taylor Nguyen",
    "Jamie Rivera",
    "Casey Morgan",
    "Jordan Ellis",
    "Sydney Parker",
    "Alex Kim",
    "Robin Shah",
)
LOCATIONS = (
    "Seattle, Washington",
    "Austin, Texas",
    "Denver, Colorado",
    "Portland, Oregon",
    "Boston, Massachusetts",
    "Chicago, Illinois",
    "Miami, Florida",
    "Phoenix, Arizona",
)
CARDS = (
    "4111 1111 1111 1111",
    "5555 5555 5555 4444",
    "3782 822463 10005",
    "4000 0000 0000 0002",
)  # Public payment-network test number patterns; no accounts.
IBANS = (
    "GB82 WEST 1234 5698 7654 32",
    "DE89 3704 0044 0532 0130 00",
    "FR14 2004 1010 0505 0001 3M02 606",
)  # Publicly documented examples.
SSNS = ("123-45-6789", "219-09-9999", "111-22-3333")  # Synthetic example strings only.
PREFIXES = (
    "Review the submitted note: ",
    "Extract sensitive values from: ",
    "The customer wrote: ",
    "Prepare a response about ",
    "Security review of: ",
    "Summarize this text: ",
    "The support ticket contains ",
    "Check the privacy of ",
    "Assess forwarding eligibility for ",
    "The analyst recorded ",
)
SUFFIXES = (
    " for the support team.",
    " in the case notes.",
    " before exporting.",
    " for tomorrow's report.",
    " in the attached message.",
)


def value_for(category: str, i: int) -> str:
    if category == "EMAIL_ADDRESS":
        return f"test.contact{i:04d}@example.com"
    if category == "PHONE_NUMBER":
        return f"202-555-01{i % 100:02d}"
    if category == "PERSON":
        return NAMES[i % len(NAMES)]
    if category == "LOCATION":
        return LOCATIONS[i % len(LOCATIONS)]
    if category == "CREDIT_CARD":
        return CARDS[i % len(CARDS)]
    if category == "US_SSN":
        return SSNS[i % len(SSNS)]
    if category == "IBAN_CODE":
        return IBANS[i % len(IBANS)]
    if category == "API_CREDENTIAL":
        return f"sk-testsynthetic{i:04d}AbC987654321"
    if category == "PRIVATE_KEY":
        return (
            "-----BEGIN PRIVATE KEY-----\n"
            f"INVALID-EXAMPLE-KEY-CONTENT-{i:04d}\n"
            "-----END PRIVATE KEY-----"
        )
    raise ValueError(category)


def build_text(parts: list[str | tuple[str, str]]) -> tuple[str, list[dict[str, object]]]:
    text = ""
    spans: list[dict[str, object]] = []
    for part in parts:
        if isinstance(part, str):
            text += part
        else:
            cat, value = part
            start = len(text)
            text += value
            spans.append({"category": cat, "start": start, "end": len(text)})
    return text, spans


def record(
    group: str,
    i: int,
    parts: list[str | tuple[str, str]],
    tags: list[str],
    *,
    in_scope: bool = True,
) -> dict:
    text, spans = build_text(parts)
    status = "UNKNOWN" if not in_scope else "PRIVATE" if spans else "NO_PRIVATE_DETECTED"
    return {
        "id": f"{group.upper()}-{i + 1:04d}",
        "text": text,
        "expected_entities": spans,
        "expected_status": status,
        "in_scope": in_scope,
        "group": group,
        "tags": sorted(set(tags)),
        "split": ("development" if i % 5 == 0 else "validation" if i % 5 == 1 else "evaluation"),
    }


def generate() -> list[dict]:
    cases: list[dict] = []
    distribution = (
        ("EMAIL_ADDRESS", 50),
        ("PHONE_NUMBER", 45),
        ("PERSON", 45),
        ("LOCATION", 35),
        ("CREDIT_CARD", 40),
        ("US_SSN", 40),
        ("IBAN_CODE", 35),
        ("API_CREDENTIAL", 35),
        ("PRIVATE_KEY", 25),
    )
    index = 0
    for category, count in distribution:
        for k in range(count):
            n = index + 1
            parts: list[str | tuple[str, str]] = [
                f"Task {n:04d}: " + PREFIXES[n % len(PREFIXES)],
                (category, value_for(category, n)),
                SUFFIXES[(n // 7) % len(SUFFIXES)],
            ]
            cases.append(record("standard_sensitive", index, parts, ["standard", category.lower()]))
            index += 1

    CLEAN = (
        "Describe a local policy engine with deterministic results.",
        "Explain the difference between latency and throughput.",
        "Propose a database index for frequently queried fields.",
        "What is a signed content-addressed release manifest?",
        "Summarize an example request lifecycle without identifiers.",
        "Write a unit test for a pure sorting function.",
        "Explain the purpose of an audit event sequence.",
        "Document a bounded thread pool for a Python application.",
        "Describe how retries interact with idempotency.",
        "Draft an internal status update about testing progress.",
        "How does a SHA-256 digest help detect changes?",
        "Compare local inference with a simulated remote gateway.",
        "Outline a deployment validation checklist.",
        "Summarize requirements for strict JSON validation.",
        "Explain why checks should run before forwarding data.",
        "Describe a software license review workflow.",
        "Build a sample decision table without personal details.",
        "Write instructions for a reproducible software build.",
        "Explain what a confidence threshold does in a classifier.",
        "Describe common causes of false positive alerts.",
        "Compare synchronous and asynchronous execution.",
        "Prepare a neutral architecture review agenda.",
        "Propose a deterministic reporting format.",
        "List the phases of a security testing program.",
        "Explain the role of an isolated test environment.",
    )
    for i in range(COUNTS["clean"]):
        text = f"Internal exercise {i + 1:04d}. {CLEAN[i % len(CLEAN)]}"
        cases.append(record("clean", i, [text], ["negative", "clean"]))

    HARD = (
        "The email field is blank: user at example dot com.",
        "The literal token EMAIL_ADDRESS is a schema field.",
        "Example template: name@example (not an email address).",
        "This text contains a placeholder: 000-00-0000.",
        "The sample card field contains XXXX-XXXX-XXXX-XXXX.",
        "A database column is named credit_card_number.",
        "Only the text API_CREDENTIAL is present, not a credential.",
        "The string 'sk-' is a prefix, not a full token.",
        "The instruction says BEGIN KEY, not a PEM private key.",
        "A regex example uses [0-9]{16}, not an account number.",
        "IBAN_CODE is a symbolic field name in the schema.",
        "US_SSN is an enum value in this unit test.",
        "The phrase 'person entity' refers to a detector category.",
        "The term 'location' is the name of a data column.",
        "Contact details were removed from this note.",
        "A test contains 4111-XXXX-XXXX-XXXX as masked digits.",
        "The dummy key reads AKIA followed by sixteen placeholders.",
        "No telephone digits are present in the contact field.",
        "The workflow calls a method named redact_person().",
        "The policy revision is redaction-baseline-v3.",
    )
    for i in range(COUNTS["hard_negative"]):
        cases.append(
            record(
                "hard_negative",
                i,
                [f"Synthetic negative {i + 1:04d}: {HARD[i % len(HARD)]}"],
                ["negative", "hard_negative"],
            )
        )

    for i in range(COUNTS["mixed_entities"]):
        a = CATEGORIES[i % len(CATEGORIES)]
        b = CATEGORIES[(i * 5 + 3) % len(CATEGORIES)]
        if a == b:
            b = CATEGORIES[(CATEGORIES.index(a) + 1) % len(CATEGORIES)]
        n = i + 701
        parts = [
            f"Combined request {i + 1:04d}: first is ",
            (a, value_for(a, n)),
            "; second is ",
            (b, value_for(b, n + 11)),
            ". Treat both as sample inputs.",
        ]
        cases.append(record("mixed_entities", i, parts, ["mixed", a.lower(), b.lower()]))

    # Hard cases are intentionally within ASCII; ordinary recognizers may miss them.
    # Exact spans designate the entire sensitive token, even when broken by separators.
    for i in range(COUNTS["adversarial"]):
        category = CATEGORIES[i % len(CATEGORIES)]
        n = i + 2001
        if category == "EMAIL_ADDRESS":
            variant = (f"case{n}@example.com", f"case{n} @ example . com", f"CASE{n}@EXAMPLE.COM")[
                i % 3
            ]
        elif category == "PHONE_NUMBER":
            variant = (
                f"202.555.01{n % 100:02d}",
                f"202 555 01{n % 100:02d}",
                f"(202) 555-01{n % 100:02d}",
            )[i % 3]
        elif category == "PERSON":
            variant = (
                NAMES[n % len(NAMES)],
                NAMES[n % len(NAMES)].upper(),
                NAMES[n % len(NAMES)].replace(" ", "\n"),
            )[i % 3]
        elif category == "LOCATION":
            variant = (
                LOCATIONS[n % len(LOCATIONS)],
                LOCATIONS[n % len(LOCATIONS)].upper(),
                LOCATIONS[n % len(LOCATIONS)].replace(", ", ",\n"),
            )[i % 3]
        elif category == "CREDIT_CARD":
            base = CARDS[n % len(CARDS)]
            variant = (base, base.replace(" ", "-"), base.replace(" ", ""))[i % 3]
        elif category == "US_SSN":
            base = SSNS[n % len(SSNS)]
            variant = (base, base.replace("-", " "), base.replace("-", "."))[i % 3]
        elif category == "IBAN_CODE":
            base = IBANS[n % len(IBANS)]
            variant = (base, base.lower(), base.replace(" ", ""))[i % 3]
        elif category == "API_CREDENTIAL":
            base = value_for(category, n)
            variant = (base, base.upper(), base.replace("sk-", "sk - "))[i % 3]
        else:
            variant = (
                "-----BEGIN PRIVATE KEY-----\nFAKE ONLY\n-----END PRIVATE KEY-----",
                "-----begin private key-----\nFAKE ONLY\n-----end private key-----",
                "-----BEGIN PRIVATE KEY----- FAKE ONLY",
            )[i % 3]
        cases.append(
            record(
                "adversarial",
                i,
                [f"Unusual input {i + 1:04d}: <", (category, variant), ">. Review carefully."],
                ["adversarial", category.lower(), "ascii_obfuscation"],
            )
        )

    UNSUPPORTED = (
        "Résumé contains an accent and must not be classified as ASCII.",
        "Client message: mañana revisaremos los permisos.",
        "Non-English note: Привет, проверка локальной модели.",
        "Request: שלום, זאת הודעת בדיקה.",
        "Example instruction: 東京で会いましょう.",
        "A Unicode dash – replaces the ASCII hyphen.",
        "Non-ASCII quote: “testing secure forwarding”.",
        "Emoji is present: 🔒 and must be handled conservatively.",
        "Customer message includes café on the receipt.",
        "Phrase: naïve approach to input handling.",
    )
    for i in range(COUNTS["unsupported"]):
        cases.append(
            record(
                "unsupported",
                i,
                [f"Unsupported example {i + 1:04d}: {UNSUPPORTED[i % len(UNSUPPORTED)]}"],
                ["unsupported", "non_ascii"],
                in_scope=False,
            )
        )

    assert len(cases) == sum(COUNTS.values()) == 1200
    assert len({c["text"] for c in cases}) == len(cases)
    return cases


def write_dataset(root: Path = ROOT) -> None:
    root.mkdir(parents=True, exist_ok=True)
    cases = generate()
    data = "".join(
        json.dumps(c, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
        for c in cases
    ).encode("utf-8")
    (root / "cases.jsonl").write_bytes(data)
    manifest = {
        "schema_version": 1,
        "name": "sovereign-synthetic-v1",
        "dataset_version": VERSION,
        "generator_revision": "deterministic-templates-20261119-v1",
        "case_count": len(cases),
        "distribution": COUNTS,
        "split_counts": {
            s: sum(c["split"] == s for c in cases)
            for s in ("development", "validation", "evaluation")
        },
        "cases_sha256": hashlib.sha256(data).hexdigest(),
        "notes": "Synthetic only; no real credentials, personal records, or model outputs.",
    }
    (root / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    write_dataset()
