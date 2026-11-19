"""Versioned, integrity-checked ground truth for evaluation; independent of production."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_DATASET = Path(__file__).parent / "datasets" / "v1"
CATEGORY_RE = re.compile(r"[A-Z][A-Z0-9_]*\Z")
CASE_ID_RE = re.compile(r"[A-Z_]+-[0-9]{4}\Z")
SPLITS = frozenset({"development", "validation", "evaluation"})
STATUSES = frozenset({"PRIVATE", "NO_PRIVATE_DETECTED", "UNKNOWN"})
GROUPS = frozenset({"standard_sensitive", "clean", "hard_negative", "mixed_entities",
                    "adversarial", "unsupported"})


class DatasetError(ValueError):
    """Ground truth or its manifest is invalid, altered, or unsupported."""


@dataclass(frozen=True)
class Entity:
    category: str
    start: int
    end: int


@dataclass(frozen=True)
class Case:
    id: str
    text: str
    entities: tuple[Entity, ...]
    expected_status: str
    in_scope: bool
    group: str
    tags: tuple[str, ...]
    split: str


@dataclass(frozen=True)
class Dataset:
    cases: tuple[Case, ...]
    manifest: dict[str, Any]

    def select(self, split: str) -> tuple[Case, ...]:
        if split == "all":
            return self.cases
        if split not in SPLITS:
            raise DatasetError(f"Unknown dataset split: {split}")
        return tuple(c for c in self.cases if c.split == split)


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise DatasetError(message)


def _case(raw: Any) -> Case:
    _assert(isinstance(raw, dict) and set(raw) == {
        "id", "text", "expected_entities", "expected_status", "in_scope", "group", "tags", "split"
    }, "Invalid case fields")
    cid = raw["id"]
    _assert(isinstance(cid, str) and bool(CASE_ID_RE.fullmatch(cid)), "Invalid case ID")
    source = raw["text"]
    _assert(isinstance(source, str) and bool(source.strip()), f"{cid}: empty prompt")
    _assert(isinstance(raw["in_scope"], bool), f"{cid}: in_scope is not a boolean")
    inscope = raw["in_scope"]
    _assert(isinstance(raw["expected_status"], str) and raw["expected_status"] in STATUSES,
            f"{cid}: invalid status")
    expected = raw["expected_status"]
    _assert(isinstance(raw["group"], str) and raw["group"] in GROUPS, f"{cid}: invalid group")
    _assert(isinstance(raw["split"], str) and raw["split"] in SPLITS, f"{cid}: invalid split")
    _assert(isinstance(raw["tags"], list) and bool(raw["tags"]) and
            all(isinstance(t, str) and bool(t) for t in raw["tags"]) and
            len(set(raw["tags"])) == len(raw["tags"]), f"{cid}: invalid tags")
    _assert(isinstance(raw["expected_entities"], list), f"{cid}: entities must be a list")
    entities: list[Entity] = []
    for item in raw["expected_entities"]:
        _assert(isinstance(item, dict) and set(item) == {"category", "start", "end"},
                f"{cid}: invalid entity structure")
        category, start, end = item["category"], item["start"], item["end"]
        _assert(isinstance(category, str) and bool(CATEGORY_RE.fullmatch(category)) and
                type(start) is int and type(end) is int and 0 <= start < end <= len(source),
                f"{cid}: invalid entity coordinates")
        entities.append(Entity(category, start, end))
    ordered = sorted(entities, key=lambda e: (e.start, e.end, e.category))
    _assert(all(a.end <= b.start for a, b in zip(ordered, ordered[1:])),
            f"{cid}: overlapping ground-truth spans")
    _assert(inscope == source.isascii(), f"{cid}: in_scope must match ASCII input contract")
    if not inscope:
        _assert(expected == "UNKNOWN" and not entities and raw["group"] == "unsupported",
                f"{cid}: unsupported case is not UNKNOWN")
    else:
        _assert(expected == ("PRIVATE" if entities else "NO_PRIVATE_DETECTED"),
                f"{cid}: expected status disagrees with entity labels")
    return Case(cid, source, tuple(entities), expected, inscope, raw["group"],
                tuple(raw["tags"]), raw["split"])


def load_dataset(root: Path = DEFAULT_DATASET) -> Dataset:
    """Verify the raw content digest before parsing; never trust changed labels silently."""
    try:
        manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
        data = (root / "cases.jsonl").read_bytes()
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise DatasetError("Cannot open dataset and manifest") from exc
    _assert(isinstance(manifest, dict) and manifest.get("schema_version") == 1 and
            manifest.get("dataset_version") == "1.0.0", "Unknown dataset schema/version")
    if manifest.get("cases_sha256") != hashlib.sha256(data).hexdigest():
        # Git for Windows may convert line endings when the patch is applied.
        # Keep strict raw-byte integrity; suggest an exact deterministic repair.
        if hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest() == manifest.get(
            "cases_sha256"
        ):
            raise DatasetError(
                "Dataset has Windows CRLF line endings; run "
                "'python -m evaluation.generate_dataset' to restore canonical LF bytes"
            )
        raise DatasetError("Dataset checksum mismatch")
    try:
        lines = data.decode("utf-8").splitlines()
        cases = tuple(_case(json.loads(line)) for line in lines)
    except (UnicodeError, ValueError, TypeError, KeyError) as exc:
        raise DatasetError("Invalid dataset case") from exc
    _assert(len(cases) == manifest.get("case_count") and len(cases) > 0,
            "Case count mismatch")
    _assert(len({c.id for c in cases}) == len(cases), "Duplicate case IDs")
    _assert(len({c.text for c in cases}) == len(cases), "Duplicate prompt texts")
    _assert(dict(Counter(c.group for c in cases)) == manifest.get("distribution"),
            "Group distribution mismatch")
    _assert(dict(Counter(c.split for c in cases)) == manifest.get("split_counts"),
            "Split distribution mismatch")
    return Dataset(cases, manifest)
