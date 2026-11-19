"""Read-only report of unresolved idempotent requests backed by signed audit history.

Use a consistent SQLite snapshot for external offline review, or run locally
against an accessible DB. No retry, cleanup, or synthetic OUTCOME is performed.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from app.audit.idempotency import audit_state
from app.audit.verify import VerificationError, verify_database


def inspect(db_path: str, public_key: str, *, min_age_seconds: float = 0) -> dict:
    signed = verify_database(db_path, public_key)
    unresolved: list[dict] = []
    stats = {"OUTCOME_RECORDED": 0, "UNRESOLVED": 0, "INVALID_AUDIT_LIFECYCLE": 0}
    with closing(sqlite3.connect(f"file:{Path(db_path).resolve()}?mode=ro", uri=True)) as conn:
        rows = conn.execute(
            "SELECT tenant_id, request_id, created_utc FROM request_idempotency "
            "ORDER BY created_utc"
        ).fetchall()
        for tenant_id, request_id, created_utc in rows:
            entries = conn.execute(
                "SELECT event_json FROM events WHERE tenant_id=? AND request_id=? "
                "ORDER BY sequence",
                (tenant_id, request_id),
            ).fetchall()
            events = [{"event": json.loads(item[0])} for item in entries]
            status, _ = audit_state(events)
            stats[status] = stats.get(status, 0) + 1
            if status == "OUTCOME_RECORDED":
                continue
            age = (datetime.now(timezone.utc) - datetime.fromisoformat(created_utc)).total_seconds()
            if age >= min_age_seconds:
                unresolved.append(
                    {
                        "request_id": request_id,
                        "audit_state": status,
                        "age_seconds": int(max(age, 0)),
                        "recorded_events": len(events),
                    }
                )
    return {"audit_verification": signed, "claim_counts": stats, "unresolved": unresolved}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", required=True)
    parser.add_argument("--public-key", required=True)
    parser.add_argument("--min-age-seconds", type=float, default=60.0)
    args = parser.parse_args()
    if args.min_age_seconds < 0:
        parser.error("--min-age-seconds must be non-negative")
    try:
        print(
            json.dumps(
                inspect(args.db, args.public_key, min_age_seconds=args.min_age_seconds), indent=2
            )
        )
    except (VerificationError, sqlite3.Error, OSError, ValueError, KeyError) as exc:
        print(f"LIFECYCLE INSPECTION FAILED: {type(exc).__name__}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
