"""Verify approval references from signed audit records against archived releases.

Verification of the audit chain must run BEFORE this function; references alone
are not trustworthy. Without a separately pinned release public key this can
only establish archive consistency, not who approved the deployment.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path

from app.release.approvals import HEX64, ReleaseIntegrityError, load_approval, summary


def verify_release_references(
    db_path: str, archive: str | Path | None, trusted_key: str | Path | None = None
) -> dict:
    count = 0
    authenticated = 0
    legacy = 0
    unique: set[str] = set()
    with (
        closing(sqlite3.connect(f"file:{Path(db_path).resolve()}?mode=ro", uri=True)) as conn,
        conn,
    ):
        rows = conn.execute(
            "SELECT sequence,event_json FROM events WHERE event_type='DECISION' ORDER BY sequence"
        ).fetchall()
    for seq, serialized in rows:
        try:
            event = json.loads(serialized)["payload"]
            version = event.get("release_evidence_version")
            if version is None:
                if "release_snapshot" in event:
                    raise ReleaseIntegrityError("Unsigned release marker in evidence")
                legacy += 1
                continue
            if version != "1" or archive is None:
                raise ReleaseIntegrityError("Unsupported release evidence or archive unavailable")
            reference = event["release_snapshot"]
            if not isinstance(reference, dict) or set(reference) != {
                "release_id",
                "generation",
                "policy_digest",
                "detector_digest",
                "signer_key_id",
            }:
                raise ReleaseIntegrityError("Malformed release reference")
            if not isinstance(reference["release_id"], str) or not HEX64.fullmatch(
                reference["release_id"]
            ):
                raise ReleaseIntegrityError("Invalid release id in signed audit reference")
            rel = Path(archive) / (reference["release_id"] + ".json")
            doc = load_approval(rel)
            if summary(doc) != reference:
                raise ReleaseIntegrityError("Audit release reference does not match archive")
            class_digest = (
                event.get("policy_input", {}).get("classification", {}).get("artifact_digest")
            )
            if class_digest and class_digest != reference["detector_digest"]:
                raise ReleaseIntegrityError(
                    "Classification detector differs from approved detector"
                )
            opa = event.get("policy_evaluation")
            if opa is not None and opa.get("policy_digest") != reference["policy_digest"]:
                raise ReleaseIntegrityError("OPA used policy not approved by recorded release")
            if trusted_key is not None:
                from app.release.approvals import verify_approval

                # Trust directory assembled by independent verifier; never from the ZIP.
                verify_approval(doc, trusted_key)
                authenticated += 1
            count += 1
            unique.add(reference["release_id"])
        except (KeyError, TypeError, ValueError, OSError, json.JSONDecodeError) as exc:
            raise ReleaseIntegrityError(
                f"Invalid release reference at decision sequence {seq}"
            ) from exc
    return {
        "release_references_checked": count,
        "release_approvals_authenticated": authenticated,
        "legacy_decisions_without_release_approval": legacy,
        "unique_releases": len(unique),
    }
