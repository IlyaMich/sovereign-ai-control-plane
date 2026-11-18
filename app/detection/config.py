"""Validated, build-time detector rules; changes require a new approved artifact."""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from pathlib import Path

from app.domain.contracts import Sensitivity

RULES_PATH = Path(__file__).with_name("rules.json")
CATEGORY = re.compile(r"^[A-Z][A-Z0-9_]{0,79}$")


@dataclass(frozen=True)
class DetectorConfig:
    threshold: float
    entity_categories: tuple[str, ...]
    required_coverage: frozenset[str]
    sensitivity_mapping: tuple[tuple[str, Sensitivity], ...]
    patterns: tuple[tuple[str, tuple[tuple[str, str, float], ...]], ...]

    @classmethod
    def load(cls) -> DetectorConfig:
        try:
            return cls.from_dict(json.loads(RULES_PATH.read_bytes()))
        except (OSError, ValueError, TypeError, KeyError) as exc:
            raise ValueError("Invalid detector rules configuration") from exc

    @classmethod
    def from_dict(cls, raw: dict) -> DetectorConfig:
        if not isinstance(raw, dict) or set(raw) != {
            "threshold",
            "entity_categories",
            "required_coverage",
            "sensitivity_mapping",
            "patterns",
        }:
            raise ValueError("Invalid detector configuration fields")

        def score(value: object) -> float:
            if (
                not isinstance(value, (int, float))
                or isinstance(value, bool)
                or not math.isfinite(value)
                or not 0 <= value <= 1
            ):
                raise ValueError("Detector scores must be finite numbers between zero and one")
            return float(value)

        def categories(value: object) -> tuple[str, ...]:
            if (
                not isinstance(value, list)
                or not value
                or any(not isinstance(x, str) or not CATEGORY.fullmatch(x) for x in value)
                or len(set(value)) != len(value)
            ):
                raise ValueError("Detector categories must be nonempty unique identifiers")
            return tuple(value)

        entities = categories(raw["entity_categories"])
        required = frozenset(categories(raw["required_coverage"]))
        mapping = raw["sensitivity_mapping"]
        if (
            not required.issubset(entities)
            or not isinstance(mapping, dict)
            or set(mapping) != set(entities)
            or any(v not in {"MEDIUM", "HIGH"} for v in mapping.values())
        ):
            raise ValueError(
                "Detector coverage and sensitivity mapping must match selected entities"
            )
        patterns = raw["patterns"]
        if not isinstance(patterns, dict) or not set(patterns).issubset(entities):
            raise ValueError("Patterns must target configured entities")
        checked = []
        for category, entries in sorted(patterns.items()):
            if not isinstance(entries, list) or not entries:
                raise ValueError("Pattern groups must not be empty")
            group = []
            names: set[str] = set()
            for entry in entries:
                if (
                    not isinstance(entry, list)
                    or len(entry) != 3
                    or not isinstance(entry[0], str)
                    or not entry[0]
                    or entry[0] in names
                    or not isinstance(entry[1], str)
                    or not entry[1]
                ):
                    raise ValueError("Invalid detector pattern")
                try:
                    re.compile(entry[1])
                except re.error as exc:
                    raise ValueError("Invalid detector regular expression") from exc
                names.add(entry[0])
                group.append((entry[0], entry[1], score(entry[2])))
            checked.append((category, tuple(group)))
        return cls(
            score(raw["threshold"]),
            entities,
            required,
            tuple((k, Sensitivity(v)) for k, v in sorted(mapping.items())),
            tuple(checked),
        )

    def to_dict(self) -> dict:
        return {
            "min_score": self.threshold,
            "entity_categories": self.entity_categories,
            "required_coverage": sorted(self.required_coverage),
            "sensitivity_mapping": {k: v.value for k, v in self.sensitivity_mapping},
            "patterns": dict(self.patterns),
        }


DEFAULT_CONFIG = DetectorConfig.load()
