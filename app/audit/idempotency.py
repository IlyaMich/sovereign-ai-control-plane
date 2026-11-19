"""Durable, privacy-preserving idempotency claims for local AI requests.

Claims are intentionally conservative: once a key is claimed, no automatic
replay of that operation is permitted, even after a crash or client disconnect.
The cryptographically signed audit log, not this auxiliary table, remains the
authoritative evidence of policy decisions and model outcomes.
"""

from __future__ import annotations

import json
import re
import sqlite3
import uuid
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path

from app.audit.sqlite_store import AuditUnavailable, SQLiteAuditStore

KEY_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{7,127}\Z", re.ASCII)


class IdempotencyUnavailable(AuditUnavailable):
    """Claims cannot be stored or read reliably; refuse inference."""


class ClaimState(StrEnum):
    CREATED = "CREATED"
    EXISTING = "EXISTING"
    CONFLICT = "CONFLICT"


@dataclass(frozen=True)
class ClaimResult:
    state: ClaimState
    request_id: str


def validate_key(value: str | None) -> str:
    if value is None or not KEY_PATTERN.fullmatch(value):
        raise ValueError("Invalid Idempotency-Key")
    return value


def audit_state(events: list[dict]) -> tuple[str, str | None]:
    """Infer status from recorded audit metadata; do not assume retry is safe."""
    types = [entry["event"]["event_type"] for entry in events]
    if not types:
        return "UNRESOLVED", None
    if types == ["DECISION"]:
        return "UNRESOLVED", None
    if types == ["DECISION", "OUTCOME"]:
        outcome = events[-1]["event"].get("payload", {}).get("execution_status")
        return "OUTCOME_RECORDED", outcome if isinstance(outcome, str) else None
    return "INVALID_AUDIT_LIFECYCLE", None


class IdempotencyStore:
    """SQLite-backed claim registry shared across API processes on one host.

    The key and input are HMACed with domain separators. Neither the plaintext
    idempotency key nor the plaintext prompt is stored in this table.
    """

    def __init__(self, audit: SQLiteAuditStore) -> None:
        self._audit = audit
        self.db_path = Path(audit.db_path)
        try:
            with closing(self._connect()) as conn, conn:
                conn.execute(
                    """CREATE TABLE IF NOT EXISTS request_idempotency (
                        tenant_id TEXT NOT NULL,
                        principal_id TEXT NOT NULL,
                        key_hmac TEXT NOT NULL,
                        input_hmac TEXT NOT NULL,
                        request_id TEXT NOT NULL UNIQUE,
                        created_utc TEXT NOT NULL,
                        PRIMARY KEY (tenant_id, principal_id, key_hmac)
                    )"""
                )
                conn.commit()
        except (sqlite3.Error, OSError) as exc:
            raise IdempotencyUnavailable("Idempotency initialization unavailable") from exc

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=5.0)
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA synchronous=FULL")
        return conn

    def _key_hmac(self, key: str) -> str:
        return self._audit.fingerprint("sovereign-idempotency-key-v1\x00" + validate_key(key))

    def _input_hmac(self, prompt: str, destination_id: str, purpose: str) -> str:
        canonical = json.dumps(
            [prompt, destination_id, purpose],
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        return self._audit.fingerprint("sovereign-idempotency-input-v1\x00" + canonical)

    def claim(
        self,
        *,
        tenant_id: str,
        principal_id: str,
        key: str,
        prompt: str,
        destination_id: str,
        purpose: str,
        request_id: str,
    ) -> ClaimResult:
        """Atomically reserve one logical request; never execute an existing key.

        BEGIN IMMEDIATE serializes claim-versus-claim races across API workers.
        Caller must execute only when ClaimState.CREATED is returned.
        """
        uuid.UUID(request_id)
        key_hmac = self._key_hmac(key)
        input_hmac = self._input_hmac(prompt, destination_id, purpose)
        try:
            with closing(self._connect()) as conn, conn:
                conn.execute("BEGIN IMMEDIATE")
                existing = conn.execute(
                    """SELECT request_id, input_hmac FROM request_idempotency
                       WHERE tenant_id=? AND principal_id=? AND key_hmac=?""",
                    (tenant_id, principal_id, key_hmac),
                ).fetchone()
                if existing is not None:
                    conn.commit()
                    return ClaimResult(
                        ClaimState.EXISTING if existing[1] == input_hmac else ClaimState.CONFLICT,
                        existing[0],
                    )
                conn.execute(
                    """INSERT INTO request_idempotency
                       (tenant_id, principal_id, key_hmac, input_hmac, request_id, created_utc)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        tenant_id,
                        principal_id,
                        key_hmac,
                        input_hmac,
                        request_id,
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
                conn.commit()
                return ClaimResult(ClaimState.CREATED, request_id)
        except (sqlite3.Error, OSError) as exc:
            raise IdempotencyUnavailable("Idempotency claim unavailable") from exc

    def lookup(self, *, tenant_id: str, principal_id: str, key: str) -> str | None:
        key_hmac = self._key_hmac(key)
        try:
            with closing(self._connect()) as conn, conn:
                row = conn.execute(
                    """SELECT request_id FROM request_idempotency
                       WHERE tenant_id=? AND principal_id=? AND key_hmac=?""",
                    (tenant_id, principal_id, key_hmac),
                ).fetchone()
            return str(row[0]) if row is not None else None
        except (sqlite3.Error, OSError) as exc:
            raise IdempotencyUnavailable("Idempotency lookup unavailable") from exc
