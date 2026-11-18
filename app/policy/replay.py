"""Independent policy replay using signed evidence, archived bytes, and OPA CLI.

Replays *OPA policy evaluation* from the recorded structured policy input.
This does not re-run private-data detection or prove an external model's
actual behavior. Legacy M1-M3 events have no content-bound policy identity.
"""
from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import subprocess
import tempfile
from typing import Callable, Any

from app.audit.verify import verify_database
from app.detection.evidence import verify_detector_references, DetectorEvidenceError
from app.policy.opa import parse_decision
from app.policy.snapshots import PolicySnapshotStore, SnapshotError


class ReplayError(Exception):
    pass


def run_opa(opa_binary: str, snapshot_path: Path, policy_input: dict) -> dict:
    with tempfile.TemporaryDirectory(prefix="policy-replay-") as directory:
        input_path = Path(directory) / "input.json"
        input_path.write_text(
            json.dumps(policy_input, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
            encoding="utf-8",
        )
        try:
            result = subprocess.run(
                [opa_binary, "eval", "--format=json", "--data", str(snapshot_path),
                 "--input", str(input_path), "data.sovereign.authz.decision"],
                capture_output=True, text=True, timeout=15, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ReplayError("OPA executable unavailable or evaluation timed out") from exc
        if result.returncode != 0:
            raise ReplayError("Archived Rego evaluation failed")
        try:
            obj = json.loads(result.stdout)
            raw = obj["result"][0]["expressions"][0]["value"]
            parse_decision(raw)
        except (ValueError, KeyError, TypeError, IndexError) as exc:
            raise ReplayError("OPA produced an invalid replay result") from exc
        return raw


def replay_database(
    db_path: str, public_key_path: str, archive_root: str,
    checkpoint_path: str | None = None, opa_binary: str = "opa",
    evaluator: Callable[[Path, dict], dict] | None = None,
    detector_archive_root: str | None = None,
) -> dict[str, Any]:
    """Verify signed events first, then evaluate all content-bound decisions."""
    chain = verify_database(db_path, public_key_path, checkpoint_path)
    provenance = verify_detector_references(db_path, detector_archive_root)
    archive = PolicySnapshotStore("/unused-active", archive_root)
    replayed = 0
    legacy = 0
    local_fail_closed = 0
    seen: set[str] = set()

    # This is read-only and must be a consistent SQLite snapshot, not a live
    # WAL database copied without its companion files.
    with sqlite3.connect(f"file:{Path(db_path).resolve()}?mode=ro", uri=True) as connection:
        rows = connection.execute(
            "SELECT sequence,event_json FROM events WHERE event_type='DECISION' ORDER BY sequence"
        ).fetchall()
    for sequence, serialized in rows:
        try:
            payload = json.loads(serialized)["payload"]
            decision = payload["decision"]
        except (ValueError, KeyError, TypeError) as exc:
            raise ReplayError(f"Invalid decision evidence at sequence {sequence}") from exc
        if "policy_evaluation" not in payload:
            if payload.get("policy_evidence_version") == "2":
                raise ReplayError(f"Missing M4 policy evidence at sequence {sequence}")
            legacy += 1
            continue
        recorded = payload["policy_evaluation"]
        if recorded is None:
            # An OPA outage or detector-unknown request may never invoke OPA.
            # Such a decision can be integrity-checked but cannot be Rego-replayed.
            if decision.get("effect") != "DENY" or decision.get("reason_codes") not in (
                ["POLICY_UNAVAILABLE"], ["DETECTION_UNKNOWN"], ["POLICY_INTEGRITY_FAILURE"],
                ["UNTRUSTED_RELEASE"]
            ):
                raise ReplayError(f"Invalid local fallback at sequence {sequence}")
            local_fail_closed += 1
            continue
        try:
            expected = parse_decision(recorded)
            digest = expected.policy_digest
            if not digest:
                raise ReplayError("Missing content-bound policy digest")
            snapshot = payload["policy_snapshot"]
            if snapshot != {"sha256": digest, "revision": expected.policy_revision}:
                raise ReplayError("Policy snapshot metadata differs from OPA decision")
            policy_input = payload["policy_input"]
            if not isinstance(policy_input, dict):
                raise ReplayError("Recorded policy input must be a document")
            location = archive.find(digest)
            replay = (evaluator(location, policy_input) if evaluator is not None else
                      run_opa(opa_binary, location, policy_input))
            if replay != expected.to_dict():
                raise ReplayError("Archived policy produced a different decision")
            final = parse_decision(decision)
            if final.effect == "PERMIT" and final.to_dict() != expected.to_dict():
                raise ReplayError("Final permit was not the actual OPA permit")
            if final.to_dict() != expected.to_dict():
                # The local enforcer may tighten a PERMIT into a DENY, never
                # turn a DENY into a PERMIT. The reason must be explicit.
                reasons = {
                    "INVALID_POLICY_PLAN", "REDACTION_FAILED",
                    "TRANSFORMATION_VERIFICATION_UNAVAILABLE",
                }
                if (final.effect != "DENY" or expected.effect != "PERMIT" or
                    len(final.reason_codes) != 1 or final.reason_codes[0] not in reasons):
                    raise ReplayError("Unexpected enforcement override of OPA result")
            seen.add(digest)
            replayed += 1
        except (KeyError, ValueError, TypeError, SnapshotError) as exc:
            raise ReplayError(f"Cannot replay decision at sequence {sequence}") from exc
    return {
        "status": "REPLAY_VERIFIED",
        **provenance,
        "verified_events": chain["verified_events"],
        "policy_decisions_replayed": replayed,
        "legacy_decisions_integrity_only": legacy,
        "local_fail_closed_decisions": local_fail_closed,
        "unique_policy_snapshots": len(seen),
    }
