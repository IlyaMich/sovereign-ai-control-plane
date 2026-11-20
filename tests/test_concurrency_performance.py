"""M7.9: synthetic-only profiling and signed-audit correctness gates."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import httpx
import pytest

from tools.concurrency_performance import (
    benchmark_integrity,
    capture_command,
    counter_changes,
    load_api_key,
    loopback_url,
    max_for_phase,
    render_report,
    safe_snapshot,
)


def diagnostics() -> dict:
    return {
        "scope": "process",
        "http_ingress": {"limit": 32, "active": 1, "rejected": 0},
        "admission": {"limit": 8, "active": 1, "rejected": 0},
        "detector": {
            "capacity": 8,
            "active_jobs": 1,
            "submitted": 3,
            "completed": 2,
            "queue_wait": {"samples": 2, "p95_ms": 15.0},
            "secret_prompt": "do not persist",
        },
        "audit": {
            "capacity": 16,
            "active_jobs": 1,
            "submitted": 3,
            "completed": 2,
            "queue_wait": {"samples": 2, "p95_ms": 25.0},
        },
        "event_loop": {"samples": 2, "p95_ms": 2.0, "max_ms": 3.0},
        "audit_limits": {"maximum_waiters": 8, "waiting_for_slot": 1},
        "integrity": {"active_jobs": 1, "readiness_running": True},
        "unexpected": {"api_key": "top secret"},
    }


def test_allowlist_drops_private_and_unknown_fields():
    result = safe_snapshot(diagnostics())
    saved = json.dumps(result)
    assert "secret_prompt" not in saved
    assert "top secret" not in saved
    assert "do not persist" not in saved
    assert result["audit"]["queue_wait"]["p95_ms"] == 25.0
    assert result["integrity"]["readiness_running"] is True


@pytest.mark.parametrize(
    "url",
    [
        "https://localhost:8000",
        "http://otherhost:8000",
        "http://127.0.0.1:8000/path",
        "http://user:pw@localhost:8000",
        "http://localhost:8000?token=secret",
    ],
)
def test_only_local_diagnostics_allowed(url):
    with pytest.raises(ValueError):
        loopback_url(url)


def test_only_valid_process_metrics_accepted():
    payload = diagnostics()
    payload["scope"] = "cluster"
    with pytest.raises(ValueError):
        safe_snapshot(payload)
    payload = diagnostics()
    payload["audit"] = "not a mapping"
    with pytest.raises(ValueError):
        safe_snapshot(payload)


def test_secret_loaded_from_env_file_not_serialized(tmp_path, monkeypatch):
    monkeypatch.delenv("BENCH_API_KEY", raising=False)
    monkeypatch.delenv("CONTROL_PLANE_API_KEY", raising=False)
    (tmp_path / ".env").write_text(
        'CONTROL_PLANE_API_KEY="a-synthetic-test-key-long-enough"\n', encoding="utf-8"
    )
    assert load_api_key(tmp_path / ".env") == "a-synthetic-test-key-long-enough"


def test_counter_restarts_detected_and_not_treated_as_negative_events():
    sample = safe_snapshot(diagnostics())
    newer = safe_snapshot(diagnostics())
    newest = safe_snapshot(diagnostics())
    sample["audit"]["submitted"] = 10
    newer["audit"]["submitted"] = 12
    newest["audit"]["submitted"] = 1
    rows = [{"metrics": s, "phase": "local_permit"} for s in (sample, newer, newest)]
    deltas, restarted = counter_changes(rows)
    assert restarted
    assert deltas["audit.submitted"] == 2
    assert max_for_phase(rows, "local_permit", "audit.queue_wait.p95_ms") == 25.0


@pytest.mark.asyncio
async def test_capture_is_safe_and_tracks_scenario(capsys):
    counter = 0

    def handler(request):
        nonlocal counter
        assert request.url.path == "/v1/diagnostics/concurrency"
        assert request.headers["X-API-Key"] == "only-in-header"
        counter += 1
        data = diagnostics()
        data["audit"]["submitted"] = counter
        return httpx.Response(200, json=data)

    script = (
        "import time; "
        "print('[demo] local_permit: 1 clients x 1s',flush=True); "
        "time.sleep(0.23); "
        "print('local_permit: 1.0 responses/s, p95=1ms',flush=True)"
    )
    async with httpx.AsyncClient(
        base_url="http://test",
        transport=httpx.MockTransport(handler),
        headers={"X-API-Key": "only-in-header"},
    ) as client:
        profile, exit_code = await capture_command(
            [sys.executable, "-c", script],
            client,
            interval=0.1,
            label="demo-r01",
            git_commit="a" * 40,
        )
    assert exit_code == 0
    assert profile["poll_errors"] == 0
    assert any(s["phase"] == "local_permit" for s in profile["samples"])
    assert "only-in-header" not in json.dumps(profile)
    assert "do not persist" not in json.dumps(profile)
    assert "local_permit:" in capsys.readouterr().out


def save_run(root: Path, label: str, *, passed: bool = True) -> None:
    folder = root / label
    scene = folder / "local_permit"
    scene.mkdir(parents=True)
    (folder / "suite.json").write_text(
        json.dumps(
            {
                "errors": [],
                "clients": 8,
                "duration_s": 60.0,
            }
        ),
        encoding="utf-8",
    )
    (scene / "assertions.json").write_text(json.dumps({"passed": passed}), encoding="utf-8")
    (scene / "summary.json").write_text(
        json.dumps(
            {
                "scenario": "local_permit",
                "clients": 8,
                "duration_configured_s": 60.0,
                "goodput_per_test_second": 4.0,
                "latency_ms": {"p95": 2000.0},
                "transport_errors": 0,
                "functional_validation_failures": 0,
                "evidence_validation_failures": 0,
            }
        ),
        encoding="utf-8",
    )
    (folder / "m7_9_diagnostics.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "label": label,
                "git_commit": "a" * 40,
                "benchmark_exit_code": 0,
                "poll_errors": 0,
                "process_counter_reset": False,
                "samples": [{"metrics": safe_snapshot(diagnostics()), "phase": "local_permit"}],
            }
        ),
        encoding="utf-8",
    )


def test_report_passes_only_with_complete_audit_assertions(tmp_path):
    save_run(tmp_path, "sample-r01")
    save_run(tmp_path, "sample-r02")
    save_run(tmp_path, "sample-r03")
    rendered, ok = render_report(tmp_path, "sample", 3, ["local_permit"])
    assert ok
    assert "4.000" in rendered
    assert "PASS" in rendered
    (tmp_path / "sample-r02" / "local_permit" / "assertions.json").write_text(
        '{"passed":false}', encoding="utf-8"
    )
    assert "local_permit_audit_integrity_failed" in benchmark_integrity(
        tmp_path / "sample-r02", ["local_permit"]
    )
    rendered, ok = render_report(tmp_path, "sample", 3, ["local_permit"])
    assert not ok
    assert "FAIL" in rendered


def test_report_fails_on_incomplete_diagnostics(tmp_path):
    save_run(tmp_path, "sample-r01")
    profile_path = tmp_path / "sample-r01" / "m7_9_diagnostics.json"
    profile = json.loads(profile_path.read_text(encoding="utf-8"))
    profile["poll_errors"] = 1
    profile_path.write_text(json.dumps(profile), encoding="utf-8")
    report, ok = render_report(tmp_path, "sample", 1, ["local_permit"])
    assert not ok
    assert "invalid_or_incomplete_profile" in report
