"""Versioned, strict benchmark profiles; source files are tracked, results are not."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from pathlib import Path

from tools.concurrency_performance import SCENARIOS

PROFILE_DIR = Path(__file__).resolve().parent / "profiles"


@dataclass(frozen=True)
class Profile:
    name: str
    digest: str
    description: str
    levels: tuple[int, ...]
    duration_s: float
    runs: int
    interval_s: float
    scenarios: tuple[str, ...]
    allow_overload: bool
    arrival_rate_rps: float | None = None


def load_profile(name: str) -> Profile:
    if not name or not name.replace("-", "").isalnum() or len(name) > 40:
        raise ValueError("Invalid profile name")
    path = PROFILE_DIR / f"{name}.json"
    raw = path.read_bytes()
    value = json.loads(raw)
    if (
        not isinstance(value, dict)
        or value.get("schema_version") not in (1, 2)
        or set(value)
        != {
            "schema_version",
            "description",
            "levels",
            "duration_s",
            "runs",
            "interval_s",
            "scenarios",
            "allow_overload",
            *(["arrival_rate_rps"] if value.get("schema_version") == 2 else []),
        }
    ):
        raise ValueError("Unsupported profile schema")
    levels = value["levels"]
    scenarios = value["scenarios"]
    duration = value["duration_s"]
    interval = value["interval_s"]
    runs = value["runs"]
    if (
        not isinstance(levels, list)
        or not levels
        or len(levels) > 16
        or any(type(v) is not int or not 1 <= v <= 64 for v in levels)
        or len(set(levels)) != len(levels)
    ):
        raise ValueError("Invalid concurrency levels")
    if (
        not isinstance(scenarios, list)
        or not scenarios
        or any(type(v) is not str or v not in SCENARIOS for v in scenarios)
        or len(set(scenarios)) != len(scenarios)
    ):
        raise ValueError("Invalid scenarios")
    rate = value.get("arrival_rate_rps")
    if value["schema_version"] == 2 and (
        type(rate) not in (int, float)
        or not math.isfinite(rate)
        or not 0.1 <= rate <= 64
        or type(duration) not in (int, float)
        or not math.isfinite(duration)
        or math.ceil(rate * duration) > 50_000
    ):
        raise ValueError("Invalid open-loop arrival rate or request budget")
    if (
        type(runs) is not int
        or not 1 <= runs <= 10
        or type(duration) not in (int, float)
        or not math.isfinite(duration)
        or not 1 <= duration <= 3600
        or type(interval) not in (int, float)
        or not math.isfinite(interval)
        or not 0.1 <= interval <= 30
        or type(value["allow_overload"]) is not bool
        or type(value["description"]) is not str
    ):
        raise ValueError("Invalid profile values")
    return Profile(
        name,
        hashlib.sha256(raw).hexdigest(),
        value["description"],
        tuple(levels),
        float(duration),
        runs,
        float(interval),
        tuple(scenarios),
        value["allow_overload"],
        float(rate) if rate is not None else None,
    )
