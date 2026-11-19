"""Fast, offline tests: no container, credentials, or reviewer kit required."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from performance.config import load_profile
from performance.reporting import aggregate, compare, number
from performance.resources import _parse_one


def test_shipped_profiles_are_valid() -> None:
    for name in ("baseline", "saturation", "scenario-catalog"):
        config = load_profile(name)
        assert config.runs == 3
        assert config.digest and config.scenarios
        assert len(set(config.levels)) == len(config.levels)
    assert load_profile("saturation").allow_overload


def test_profile_name_rejects_traversal() -> None:
    with pytest.raises(ValueError):
        load_profile("../secrets")


def test_metric_validation() -> None:
    for bad in (-1, float("nan"), float("inf"), True, None):
        with pytest.raises(ValueError):
            number(bad)
    assert number(0) == 0


def test_aggregate_repetitions() -> None:
    rows = [
        {"level": 8, "scenario": "local_permit", "goodput_rps": rate,
         "p50_ms": 40, "p95_ms": p95, "p99_ms": 200}
        for rate, p95 in ((10, 100), (20, 120), (30, 140))
    ]
    output = aggregate(rows)
    assert output[0]["goodput_rps"] == 20
    assert output[0]["p95_ms"] == 120
    assert output[0]["p95_ms_min"] == 100


def test_failed_manifest_cannot_be_compared(tmp_path: Path) -> None:
    for name in ("a", "b"):
        folder = tmp_path / name
        folder.mkdir()
        (folder / "manifest.json").write_text(json.dumps({
            "schema_version": 1, "status": "failed"
        }), encoding="utf-8")
    with pytest.raises(ValueError, match="incomplete or failed"):
        compare(tmp_path / "a", tmp_path / "b")


def test_resource_parser_allowlist() -> None:
    assert _parse_one({"Name": "other-secret", "CPUPerc": "10%"}) is None
    assert _parse_one({"Name": "sovereign-ai-control-plane-control-plane-1",
                       "CPUPerc": "12.5%", "MemUsage": "120MiB / 4GiB"}) == {
        "service": "control-plane", "cpu_pct": 12.5, "memory_usage": "120MiB / 4GiB"
    }
