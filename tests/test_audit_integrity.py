import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
import pytest

from app.audit.verify import VerificationError, verify_database


def test_verified_chain_detects_modification_and_truncation(audit, tmp_path):
    audit.commit("req-1", "tenant-1", "DECISION", {"classification": "PRIVATE"})
    audit.commit("req-1", "tenant-1", "OUTCOME", {"status": "BLOCKED"})
    public_key = str(audit.key_path.with_suffix(".pub.pem"))
    before = verify_database(str(audit.db_path), public_key)
    assert before["verified_events"] == 2

    checkpoint = tmp_path / "checkpoint.json"
    checkpoint.write_text(json.dumps(before))
    assert verify_database(str(audit.db_path), public_key, str(checkpoint)) == before

    with sqlite3.connect(audit.db_path) as conn:
        conn.execute("UPDATE events SET event_json=? WHERE sequence=1", ('{"changed":"yes"}',))
    with pytest.raises(VerificationError):
        verify_database(str(audit.db_path), public_key)

    # Tampering is detected independently of a checkpoint.


def test_truncation_detected_by_independent_checkpoint(audit, tmp_path):
    audit.commit("req-1", "t", "DECISION", {"allowed": False})
    audit.commit("req-2", "t", "DECISION", {"allowed": True})
    public_key = str(audit.key_path.with_suffix(".pub.pem"))
    before = verify_database(str(audit.db_path), public_key)
    checkpoint = tmp_path / "checkpoint.json"
    checkpoint.write_text(json.dumps(before))
    with sqlite3.connect(audit.db_path) as conn:
        conn.execute("DELETE FROM events WHERE sequence=2")
    assert verify_database(str(audit.db_path), public_key)["verified_events"] == 1
    with pytest.raises(VerificationError, match="checkpoint"):
        verify_database(str(audit.db_path), public_key, str(checkpoint))


def test_concurrent_audit_writes_form_one_valid_chain(audit):
    def record(i):
        return audit.commit(f"req-{i}", "t", "DECISION", {"n": i}).sequence
    with ThreadPoolExecutor(max_workers=8) as executor:
        sequences = list(executor.map(record, range(30)))
    assert sorted(sequences) == list(range(1, 31))
    result = verify_database(str(audit.db_path), str(audit.key_path.with_suffix(".pub.pem")))
    assert result["verified_events"] == 30
