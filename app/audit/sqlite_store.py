"""Synchronous durable, signed audit chain (single-writer-by-transaction SQLite M1).

Canonical encoding here is tightly scoped deterministic Python JSON, NOT RFC 8785.
The verifier intentionally lives in a separate module and does not trust DB hashes.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sqlite3
import uuid
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.domain.contracts import AuditReceipt

GENESIS_HASH = "00" * 32
DOMAIN_PREFIX = b"sovereign-audit-event-v1\x00"


class AuditUnavailable(Exception):
    pass


def canonical_bytes(event: dict[str, Any]) -> bytes:
    # No NaN / Infinity. Schemas only use strings, integers, finite floats, arrays, maps.
    return json.dumps(
        event, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def calculate_hash(previous_hash: str, sequence: int, event: dict[str, Any]) -> str:
    return hashlib.sha256(
        DOMAIN_PREFIX
        + bytes.fromhex(previous_hash)
        + sequence.to_bytes(8, "big")
        + canonical_bytes(event)
    ).hexdigest()


class SQLiteAuditStore:
    def __init__(self, db_path: str, private_key_path: str):
        self.db_path = Path(db_path)
        self.key_path = Path(private_key_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize_db()
        self._key = self._load_or_create_key()
        self._hmac_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"sovereign-input-fingerprint-v1",
        ).derive(
            self._key.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
        )
        public_path = self.key_path.with_suffix(".pub.pem")
        if not public_path.exists():
            public_path.write_bytes(
                self._key.public_key().public_bytes(
                    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=5.0, isolation_level=None)
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA busy_timeout = 5000")
            connection.execute("PRAGMA synchronous = FULL")
        except sqlite3.Error:
            connection.close()
            raise
        return connection

    def _initialize_db(self) -> None:
        with closing(self._connect()) as conn, conn:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    sequence INTEGER PRIMARY KEY,
                    event_id TEXT UNIQUE NOT NULL,
                    request_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    event_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL,
                    signature TEXT NOT NULL
                )
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS ix_events_request ON events(request_id, tenant_id)"
            )

    def _load_or_create_key(self) -> Ed25519PrivateKey:
        if self.key_path.exists():
            key = serialization.load_pem_private_key(self.key_path.read_bytes(), password=None)
            if not isinstance(key, Ed25519PrivateKey):
                raise AuditUnavailable("Invalid signing key type")
            return key
        with closing(self._connect()) as conn, conn:
            count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        if count:
            raise AuditUnavailable("Existing audit history but signing key is missing")
        key = Ed25519PrivateKey.generate()
        data = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        try:
            fd = os.open(str(self.key_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            return self._load_or_create_key()
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        return key

    def check_writable(self) -> None:
        """Non-mutating readiness probe; a later commit can still fail."""
        try:
            with closing(self._connect()) as conn, conn:
                conn.execute("BEGIN IMMEDIATE")
                conn.rollback()
        except sqlite3.Error as exc:
            raise AuditUnavailable("Audit database is unavailable") from exc

    def fingerprint(self, prompt: str) -> str:
        return hmac.new(self._hmac_key, prompt.encode("utf-8"), hashlib.sha256).hexdigest()

    def commit(
        self, request_id: str, tenant_id: str, event_type: str, payload: dict[str, Any]
    ) -> AuditReceipt:
        event = {
            "schema_version": "1",
            "event_id": str(uuid.uuid4()),
            "request_id": request_id,
            "tenant_id": tenant_id,
            "event_type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "payload": payload,
        }
        try:
            with closing(self._connect()) as conn, conn:
                conn.execute("BEGIN IMMEDIATE")
                previous = conn.execute(
                    "SELECT sequence, event_hash FROM events ORDER BY sequence DESC LIMIT 1"
                ).fetchone()
                sequence = int(previous["sequence"]) + 1 if previous else 1
                previous_hash = str(previous["event_hash"]) if previous else GENESIS_HASH
                digest = calculate_hash(previous_hash, sequence, event)
                signature = base64.b64encode(self._key.sign(bytes.fromhex(digest))).decode("ascii")
                conn.execute(
                    """INSERT INTO events
                    (sequence, event_id, request_id, tenant_id, event_type,
                     event_json, previous_hash, event_hash, signature)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        sequence,
                        event["event_id"],
                        request_id,
                        tenant_id,
                        event_type,
                        canonical_bytes(event).decode("utf-8"),
                        previous_hash,
                        digest,
                        signature,
                    ),
                )
                conn.commit()
            return AuditReceipt(sequence, digest, signature)
        except (sqlite3.Error, OSError, ValueError) as exc:
            raise AuditUnavailable("Durable audit commit failed") from exc

    def get_events(self, request_id: str, tenant_id: str) -> list[dict[str, Any]]:
        with closing(self._connect()) as conn, conn:
            rows = conn.execute(
                "SELECT sequence, event_json, event_hash, signature FROM events "
                "WHERE request_id=? AND tenant_id=? ORDER BY sequence ASC",
                (request_id, tenant_id),
            ).fetchall()
        return [
            {
                "sequence": row["sequence"],
                "event": json.loads(row["event_json"]),
                "receipt": {
                    "sequence": row["sequence"],
                    "event_hash": row["event_hash"],
                    "signature": row["signature"],
                },
            }
            for row in rows
        ]
