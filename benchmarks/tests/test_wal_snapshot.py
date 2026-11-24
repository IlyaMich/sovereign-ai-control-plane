"""WAL snapshot tests; requires neither Podman nor production audit material."""

import json
import sqlite3
import subprocess
import sys
from contextlib import closing
from pathlib import Path

import pytest

from benchmarks.audit_snapshot import (
    CREATE_SNAPSHOT_CODE,
    DELETE_SNAPSHOT_CODE,
    snapshot_paths,
)
from benchmarks.compose_audit import AuditPaths, resolve_control_audit_paths
from benchmarks.suite import audit_head


def test_online_backup_includes_uncheckpointed_wal_commits(tmp_path: Path):
    source = tmp_path / "audit.sqlite"
    target = tmp_path / (".bench-audit-snapshot-" + "0" * 32 + ".sqlite")
    live = sqlite3.connect(source)
    try:
        live.execute("PRAGMA journal_mode=WAL")
        live.execute("CREATE TABLE events (n INTEGER)")
        live.execute("INSERT INTO events VALUES (10)")
        live.commit()
        # Hold the live connection open to keep WAL frames uncheckpointed.
        assert Path(str(source) + "-wal").is_file()
        completed = subprocess.run(
            [sys.executable, "-c", CREATE_SNAPSHOT_CODE, str(source), str(target)],
            capture_output=True,
            text=True,
            check=True,
        )
        assert completed.stdout.strip() == "SNAPSHOT_READY"
        with closing(sqlite3.connect(f"file:{target}?mode=ro", uri=True)) as copy:
            assert copy.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
            assert copy.execute("SELECT n FROM events").fetchall() == [(10,)]
        live.execute("INSERT INTO events VALUES (20)")
        live.commit()
        with closing(sqlite3.connect(f"file:{target}?mode=ro", uri=True)) as copy:
            assert copy.execute("SELECT n FROM events").fetchall() == [(10,)]
        cleaned = subprocess.run(
            [sys.executable, "-c", DELETE_SNAPSHOT_CODE, str(source), str(target)],
            capture_output=True,
            text=True,
            check=True,
        )
        assert cleaned.stdout.strip() == "SNAPSHOT_REMOVED"
        assert not target.exists()
        assert source.exists()
    finally:
        live.close()


def test_snapshot_paths_translate_two_mounts():
    control, reviewer = snapshot_paths(
        "/var/lib/sovereign/audit.sqlite",
        "/readonly/audit/audit.sqlite",
        identifier="a" * 32,
    )
    assert control == "/var/lib/sovereign/.bench-audit-snapshot-" + "a" * 32 + ".sqlite"
    assert reviewer == "/readonly/audit/.bench-audit-snapshot-" + "a" * 32 + ".sqlite"
    with pytest.raises(ValueError):
        snapshot_paths("relative.sqlite", "/absolute/audit.sqlite")
    with pytest.raises(ValueError):
        snapshot_paths("/absolute/audit.sqlite", "/absolute/audit.sqlite", identifier="bad")


def test_control_paths_from_environment():
    config = {
        "services": {
            "control-plane": {
                "environment": {
                    "AUDIT_DB_PATH": "/data/custom.sqlite",
                    "AUDIT_SIGNING_KEY_PATH": "/data/key.pem",
                }
            }
        }
    }
    assert resolve_control_audit_paths(config) == AuditPaths(
        "/data/custom.sqlite", "/data/key.pub.pem"
    )


def test_audit_head_uses_temp_snapshot_and_always_cleans(monkeypatch, tmp_path):
    called = []

    def fake_command(argv, *, cwd):
        called.append(argv)
        if "tools.verify_audit" in argv:
            return json.dumps(
                {
                    "status": "VERIFIED",
                    "verified_events": 4,
                    "latest_sequence": 4,
                    "latest_hash": "a" * 64,
                }
            )
        return "OK"

    monkeypatch.setattr("benchmarks.suite.command", fake_command)
    head = audit_head(
        ["podman", "compose"],
        tmp_path,
        AuditPaths("/readonly/audit.sqlite", "/readonly/key.pub.pem"),
        "/writer/audit.sqlite",
    )
    assert head["verified_events"] == 4
    assert "exec" in called[0] and CREATE_SNAPSHOT_CODE in called[0]
    assert "audit-reviewer" in called[1] and "tools.verify_audit" in called[1]
    assert "exec" in called[2] and DELETE_SNAPSHOT_CODE in called[2]
    assert called[1][called[1].index("--db") + 1].startswith("/readonly/.bench-audit-snapshot-")
    called.clear()

    def fail_on_verifier(argv, *, cwd):
        called.append(argv)
        if "tools.verify_audit" in argv:
            raise RuntimeError("verifier failed")
        return "OK"

    monkeypatch.setattr("benchmarks.suite.command", fail_on_verifier)
    with pytest.raises(RuntimeError, match="verifier failed"):
        audit_head(
            ["podman", "compose"],
            tmp_path,
            AuditPaths("/readonly/audit.sqlite", "/readonly/key.pub.pem"),
            "/writer/audit.sqlite",
        )
    assert DELETE_SNAPSHOT_CODE in called[-1]
