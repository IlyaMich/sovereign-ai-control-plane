"""Fast, offline tests: no container, credentials, or reviewer kit required."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from performance.cli import explain_failed_capture
from performance.config import load_profile
from performance.reporting import SIGNALS, aggregate, compare, number
from performance.resources import _parse_one


def test_shipped_profiles_are_valid() -> None:
    for name in ("smoke", "baseline", "saturation", "scenario-catalog"):
        config = load_profile(name)
        assert config.runs == (1 if name == "smoke" else 3)
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
    for row in rows:
        row.update({key: None for key in SIGNALS})
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

def test_podman_native_json_snake_case() -> None:
    record = _parse_one({
        "name": "sovereign-ai-control-plane-control-plane-1",
        "cpu_percent": "12.5%",
        "mem_usage": "120MiB / 4GiB",
    })
    assert record == {
        "service": "control-plane", "cpu_pct": 12.5, "memory_usage": "120MiB / 4GiB"
    }
    unavailable_stats = _parse_one({
        "name": "sovereign-ai-control-plane-opa-1",
        "cpu_percent": "--",
        "mem_usage": "-- / --",
    })
    assert unavailable_stats is not None
    assert unavailable_stats["cpu_pct"] is None

def test_failure_reports_missing_artifacts_and_integrity_issue(tmp_path: Path) -> None:
    directory = tmp_path / "suite"
    scenario = directory / "local_permit"
    scenario.mkdir(parents=True)
    for name in ("after.json", "assertions.json"):
        (scenario / name).write_text("{}", encoding="utf-8")
    (directory / "m7_9_diagnostics.json").write_text(json.dumps({
        "benchmark_exit_code": 0,
        "benchmark_integrity_issues": ["local_permit_missing_report"],
        "poll_errors": 0,
        "process_counter_reset": False
    }), encoding="utf-8")
    message = explain_failed_capture(directory, ("local_permit",))
    assert "missing local_permit/before.json" in message
    assert "missing local_permit/summary.json" in message
    assert "missing local_permit/requests.jsonl" in message
    assert "local_permit_missing_report" in message
    assert "benchmark_nonzero_exit" not in message


def test_failure_diagnostic_does_not_echo_untrusted_json_strings(tmp_path: Path) -> None:
    (tmp_path / "m7_9_diagnostics.json").write_text(json.dumps({
        "benchmark_integrity_issues": ["foo; inject", "suite_reported_failures"],
        "benchmark_exit_code": 1,
    }), encoding="utf-8")
    message = explain_failed_capture(tmp_path, ())
    assert "foo; inject" not in message
    assert "suite_reported_failures" in message
    assert "benchmark_nonzero_exit" in message
