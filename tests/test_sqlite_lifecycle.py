"""Keep connection references alive to verify closure without garbage collection."""

import sqlite3
from contextlib import closing

import pytest

from app.audit.evidence_package import export_package, verify_package
from app.audit.sqlite_store import AuditUnavailable, SQLiteAuditStore
from app.audit.verify import verify_database


@pytest.fixture
def connections(monkeypatch):
    opened: list[sqlite3.Connection] = []
    original = sqlite3.connect

    def connect(*args, **kwargs):
        connection = original(*args, **kwargs)
        opened.append(connection)
        return connection

    monkeypatch.setattr(sqlite3, "connect", connect)
    return opened


def assert_closed(connections):
    assert connections
    for connection in connections:
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            connection.execute("SELECT 1")


def test_audit_store_closes_initialization_and_request_connections(tmp_path, connections):
    store = SQLiteAuditStore(str(tmp_path / "audit.sqlite"), str(tmp_path / "key.pem"))
    assert_closed(connections)
    store.commit("r", "t", "OUTCOME", {"status": "BLOCKED"})
    store.check_writable()
    assert len(store.get_events("r", "t")) == 1
    public = str(store.key_path.with_suffix(".pub.pem"))
    assert verify_database(str(store.db_path), public)["verified_events"] == 1
    assert_closed(connections)


def test_export_and_review_close_every_database_handle(audit, tmp_path, connections):
    audit.commit("r", "t", "OUTCOME", {"status": "BLOCKED"})
    bundle = tmp_path / "evidence.zip"
    result = export_package(
        str(audit.db_path),
        str(audit.key_path.with_suffix(".pub.pem")),
        str(tmp_path / "policies"),
        str(tmp_path / "detectors"),
        str(bundle),
    )
    assert result["events"] == 1
    assert_closed(connections)
    report = verify_package(str(bundle))
    assert report["audit"]["verified_events"] == 1
    assert_closed(connections)
    # Snapshot normalization must not change the live writer's WAL mode.
    with closing(sqlite3.connect(audit.db_path)) as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert_closed(connections)


def test_export_query_failure_closes_handles_and_preserves_original_error(
    audit, tmp_path, connections
):
    empty = tmp_path / "empty.sqlite"
    with closing(sqlite3.connect(empty)):
        pass
    with pytest.raises(sqlite3.OperationalError, match="no such table"):
        export_package(
            str(empty),
            str(audit.key_path.with_suffix(".pub.pem")),
            str(tmp_path / "policies"),
            str(tmp_path / "detectors"),
            str(tmp_path / "invalid.zip"),
        )
    assert_closed(connections)


def test_failed_commit_rolls_back_and_closes_connection(audit, connections):
    with pytest.raises(AuditUnavailable):
        audit.commit("bad", "t", "DECISION", {"invalid": float("nan")})
    assert_closed(connections)
    public = str(audit.key_path.with_suffix(".pub.pem"))
    assert verify_database(str(audit.db_path), public)["verified_events"] == 0
    audit.commit("good", "t", "OUTCOME", {"status": "BLOCKED"})
    assert verify_database(str(audit.db_path), public)["verified_events"] == 1
    assert_closed(connections)
