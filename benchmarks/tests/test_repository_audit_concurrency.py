"""Run when kit is copied into repository root with app/ importable.

Exercises independent SQLiteAuditStore instances (analogous to separate workers)
without requiring spaCy, OPA or a containerized deployment.
"""
from concurrent.futures import ThreadPoolExecutor

import pytest

pytest.importorskip("app.audit.sqlite_store")
from app.audit.sqlite_store import SQLiteAuditStore  # noqa: E402
from app.audit.verify import verify_database  # noqa: E402


def test_independent_store_instances_share_one_signed_chain(tmp_path):
    db = str(tmp_path / "audit.sqlite")
    key = str(tmp_path / "audit-key.pem")
    stores = [SQLiteAuditStore(db, key) for _ in range(8)]

    def worker(index: int) -> list[int]:
        result = []
        for n in range(12):
            receipt = stores[index].commit(
                f"synthetic-{index}-{n}", "local-tenant", "DECISION",
                {"synthetic": True, "worker": index, "n": n},
            )
            result.append(receipt.sequence)
        return result

    with ThreadPoolExecutor(max_workers=8) as pool:
        sequences = [x for result in pool.map(worker, range(8)) for x in result]
    assert sorted(sequences) == list(range(1, 97))
    public_key = str(tmp_path / "audit-key.pub.pem")
    verified = verify_database(db, public_key)
    assert verified["verified_events"] == 96
    assert verified["latest_sequence"] == 96
