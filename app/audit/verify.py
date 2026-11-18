"""Independent audit verifier; never imports or uses the writer's private key."""
from __future__ import annotations

import base64
import json
from pathlib import Path
import sqlite3
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from app.audit.sqlite_store import GENESIS_HASH, calculate_hash, canonical_bytes


class VerificationError(Exception):
    pass


def load_public_key(path: str | Path) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(Path(path).read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise VerificationError("Expected an Ed25519 public key")
    return key


def verify_database(db_path: str, public_key_path: str, checkpoint_path: str | None = None) -> dict[str, Any]:
    public_key = load_public_key(public_key_path)
    previous_hash = GENESIS_HASH
    expected_sequence = 1
    with sqlite3.connect(f"file:{Path(db_path).resolve()}?mode=ro", uri=True) as conn:
        records = conn.execute(
            "SELECT sequence, event_id, request_id, tenant_id, event_type, event_json, previous_hash, "
            "event_hash, signature FROM events ORDER BY sequence ASC"
        ).fetchall()
    for sequence, event_id, request_id, tenant_id, event_type, raw_event, previous, digest, signature in records:
        if sequence != expected_sequence or previous != previous_hash:
            raise VerificationError(f"Chain gap or incorrect predecessor at sequence {sequence}")
        try:
            event = json.loads(raw_event)
            if (canonical_bytes(event).decode("utf-8") != raw_event
                    or event["event_id"] != event_id
                    or event["request_id"] != request_id
                    or event["tenant_id"] != tenant_id
                    or event["event_type"] != event_type):
                raise VerificationError(f"Event metadata mismatch at sequence {sequence}")
            actual_hash = calculate_hash(previous, sequence, event)
            if actual_hash != digest:
                raise VerificationError(f"Event content tampered at sequence {sequence}")
            public_key.verify(base64.b64decode(signature, validate=True), bytes.fromhex(digest))
        except (KeyError, TypeError, ValueError, InvalidSignature) as exc:
            raise VerificationError(f"Invalid record/signature at sequence {sequence}") from exc
        previous_hash = digest
        expected_sequence += 1

    result = {"verified_events": len(records), "latest_sequence": expected_sequence - 1, "latest_hash": previous_hash}
    if checkpoint_path is not None:
        checkpoint = json.loads(Path(checkpoint_path).read_text(encoding="utf-8"))
        # Checkpoint is an independently retained full-chain head. Event signatures cover the head hash.
        if checkpoint != result:
            raise VerificationError("Database does not match the trusted checkpoint (truncation/rewrite?)")
    return result
