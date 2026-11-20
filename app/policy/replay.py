"""Independent policy replay using signed evidence, archived bytes, and OPA CLI.

Replays *OPA policy evaluation* from the recorded structured policy input.
This does not re-run private-data detection or prove an external model's
actual behavior. Legacy M1-M3 events have no content-bound policy identity.
"""

from __future__ import annotations

import json
import sqlite3
import subprocess  # nosec B404 # Required for explicit operator-owned CLI commands.
import tempfile
from contextlib import closing
from pathlib import Path
from typing import Any, Callable

from app.audit.verify import verify_database
from app.detection.evidence import verify_detector_references
from app.policy.opa import parse_decision
from app.policy.snapshots import PolicySnapshotStore, SnapshotError


class ReplayError(Exception):
    pass


def run_opa(
    opa_binary: str,
    snapshot_path: Path,
    policy_input: dict,
    entrypoint: str = "data.sovereign.authz.decision",
) -> dict:
    with tempfile.TemporaryDirectory(prefix="policy-replay-") as directory:
        input_path = Path(directory) / "input.json"
        input_path.write_text(
            json.dumps(policy_input, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
            encoding="utf-8",
        )
        try:
            result = subprocess.run(  # nosec B603 # Operator-selected OPA binary; shell is disabled.
                [
                    opa_binary,
                    "eval",
                    "--format=json",
                    "--data",
                    str(snapshot_path),
                    "--input",
                    str(input_path),
                    entrypoint,
                ],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
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


def _event_rows(db_path: str, event_type: str):
    """Iterate signed event JSON without retaining the full history in memory."""
    if event_type not in {"DECISION", "OUTCOME"}:
        raise ValueError("Unsupported audit event type")
    with closing(
        sqlite3.connect(f"file:{Path(db_path).resolve()}?mode=ro", uri=True)
    ) as connection:
        yield from connection.execute(
            "SELECT sequence,event_json FROM events WHERE event_type=? ORDER BY sequence",
            (event_type,),
        )


def _decision_for_output(db_path: str, request_id: str, tenant_id: str) -> dict | None:
    """Use the audit request index to retrieve only this output's input decision."""
    with closing(
        sqlite3.connect(f"file:{Path(db_path).resolve()}?mode=ro", uri=True)
    ) as connection:
        row = connection.execute(
            "SELECT event_json FROM events "
            "WHERE request_id=? AND tenant_id=? AND event_type='DECISION' "
            "ORDER BY sequence LIMIT 1",
            (request_id, tenant_id),
        ).fetchone()
    return json.loads(row[0])["payload"] if row is not None else None


def replay_database(
    db_path: str,
    public_key_path: str,
    archive_root: str,
    checkpoint_path: str | None = None,
    opa_binary: str = "opa",
    evaluator: Callable[[Path, dict], dict] | None = None,
    detector_archive_root: str | None = None,
    output_evaluator: Callable[[Path, dict], dict] | None = None,
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
    for sequence, serialized in _event_rows(db_path, "DECISION"):
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
                ["POLICY_UNAVAILABLE"],
                ["DETECTION_UNKNOWN"],
                ["POLICY_INTEGRITY_FAILURE"],
                ["UNTRUSTED_RELEASE"],
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
            replay = (
                evaluator(location, policy_input)
                if evaluator is not None
                else run_opa(opa_binary, location, policy_input)
            )
            if replay != expected.to_dict():
                raise ReplayError("Archived policy produced a different decision")
            final = parse_decision(decision)
            if final.effect == "PERMIT" and final.to_dict() != expected.to_dict():
                raise ReplayError("Final permit was not the actual OPA permit")
            if final.to_dict() != expected.to_dict():
                # The local enforcer may tighten a PERMIT into a DENY, never
                # turn a DENY into a PERMIT. The reason must be explicit.
                # EXTERNAL_CONTENT_UNVERIFIED is emitted by the pre-egress
                # guard. Since the original prompt is not retained, this
                # validates the recorded override, not the underlying scan.
                reasons = {
                    "INVALID_POLICY_PLAN",
                    "REDACTION_FAILED",
                    "TRANSFORMATION_VERIFICATION_UNAVAILABLE",
                    "EXTERNAL_CONTENT_UNVERIFIED",
                }
                if (
                    final.effect != "DENY"
                    or expected.effect != "PERMIT"
                    or len(final.reason_codes) != 1
                    or final.reason_codes[0] not in reasons
                ):
                    raise ReplayError("Unexpected enforcement override of OPA result")
            seen.add(digest)
            replayed += 1
        except (KeyError, ValueError, TypeError, SnapshotError) as exc:
            raise ReplayError(f"Cannot replay decision at sequence {sequence}") from exc
    # Output-stage decisions are part of signed OUTCOME events. Reconstruct the
    # recorded OPA result using its exact archived policy; never rerun NLP
    # classification because plaintext model responses are intentionally absent.
    output_replayed = 0
    output_local_denials = 0
    for sequence, serialized in _event_rows(db_path, "OUTCOME"):
        try:
            outcome_event = json.loads(serialized)
            payload = outcome_event["payload"]
            if "output_dlp" not in payload:
                continue  # Historical outcomes precede output DLP v1.
            original = _decision_for_output(
                db_path, outcome_event["request_id"], outcome_event["tenant_id"]
            )
            if original is None or original.get("decision", {}).get("effect") != "PERMIT":
                raise ReplayError(f"Output evidence without input permit at sequence {sequence}")
            dlp = payload["output_dlp"]
            recorded = dlp["policy_evaluation"]
            final = parse_decision(dlp["decision"])
            classified = dlp["classification"]
            policy_input = dlp["policy_input"]
            if (
                dlp["schema_version"] not in (1, 2)
                or not isinstance(policy_input, dict)
                or policy_input.get("stage") != "OUTPUT"
                or policy_input.get("classification") != classified
                or payload.get("model_invoked") is not True
                or payload.get("execution_status") != "COMPLETED"
                or policy_input.get("request") != original.get("policy_input", {}).get("request")
                or policy_input.get("principal")
                != original.get("policy_input", {}).get("principal")
                or policy_input.get("request", {}).get("destination_id")
                != payload.get("destination_id")
                or (dlp["schema_version"] == 1 and final.obligations)
                or dlp["released"] is not (final.effect == "PERMIT")
            ):
                raise ReplayError(f"Invalid output enforcement evidence at sequence {sequence}")
            # Legacy v1 permits only unmodified clean outputs. Version 2
            # records an explicit REDACT permit with post-mask verification.
            if (
                dlp["schema_version"] == 1
                and final.effect == "PERMIT"
                and (
                    classified.get("status") != "NO_PRIVATE_DETECTED"
                    or classified.get("findings") != []
                )
            ):
                raise ReplayError(f"Unsafe output permit at sequence {sequence}")
            if recorded is None:
                if final.effect != "DENY" or final.reason_codes not in (
                    ("OUTPUT_INVALID_CONTENT",),
                    ("OUTPUT_DETECTION_UNKNOWN",),
                    ("OUTPUT_POLICY_UNAVAILABLE",),
                    ("OUTPUT_UNTRUSTED_RELEASE",),
                ):
                    raise ReplayError(f"Invalid output local fallback at sequence {sequence}")
                output_local_denials += 1
                continue
            expected = parse_decision(recorded)
            mask_plan = (
                expected.effect == "PERMIT"
                and len(expected.obligations) == 1
                and expected.obligations[0].type == "REDACT"
                and set(expected.obligations[0].categories) == {"EMAIL_ADDRESS", "PHONE_NUMBER"}
            )
            if dlp["schema_version"] == 2:
                if (
                    not mask_plan
                    or policy_input.get("masking_enabled") is not True
                    or classified.get("status") != "PRIVATE"
                    or not isinstance(classified.get("findings"), list)
                    or not classified["findings"]
                    or any(
                        f.get("category") not in {"EMAIL_ADDRESS", "PHONE_NUMBER"}
                        for f in classified["findings"]
                        if isinstance(f, dict)
                    )
                    or any(not isinstance(f, dict) for f in classified["findings"])
                ):
                    raise ReplayError(f"Invalid mask authorization at sequence {sequence}")
                transform = dlp.get("transformation")
                if (
                    not isinstance(transform, dict)
                    or set(transform) != {"applied", "verification", "masked_hmac_sha256"}
                    or type(transform["applied"]) is not bool
                ):
                    raise ReplayError(f"Invalid output transformation at sequence {sequence}")
                if transform["applied"]:
                    checked = transform["verification"]
                    fingerprint = transform["masked_hmac_sha256"]
                    if (
                        not isinstance(checked, dict)
                        or checked.get("status") != "NO_PRIVATE_DETECTED"
                        or checked.get("findings") != []
                        or checked.get("artifact_digest", "")
                        != classified.get("artifact_digest", "")
                        or not isinstance(fingerprint, str)
                        or len(fingerprint) != 64
                        or any(ch not in "0123456789abcdef" for ch in fingerprint)
                    ):
                        raise ReplayError(
                            f"Mask verification evidence invalid at sequence {sequence}"
                        )
                elif transform["masked_hmac_sha256"] is not None:
                    raise ReplayError(f"Unapplied mask has fingerprint at sequence {sequence}")
                if final.effect == "PERMIT" and (
                    not transform["applied"] or final.to_dict() != expected.to_dict()
                ):
                    raise ReplayError(f"Unverified mask permitted at sequence {sequence}")
            elif mask_plan or final.obligations:
                raise ReplayError(f"Legacy output cannot mask at sequence {sequence}")
            digest = expected.policy_digest
            if not digest or dlp["policy_snapshot"] != {
                "sha256": digest,
                "revision": expected.policy_revision,
            }:
                raise ReplayError(f"Invalid output policy snapshot at sequence {sequence}")
            approved = original.get("release_snapshot")
            if approved is not None and (
                approved.get("policy_digest") != digest
                or approved.get("detector_digest") != classified.get("artifact_digest")
            ):
                raise ReplayError(
                    f"Output artifacts diverge from signed release at sequence {sequence}"
                )
            snapshot = archive.find(digest)
            answer = (
                output_evaluator(snapshot, policy_input)
                if output_evaluator is not None
                else run_opa(
                    opa_binary,
                    snapshot,
                    policy_input,
                    "data.sovereign.authz.output_decision",
                )
            )
            if answer != expected.to_dict():
                raise ReplayError(f"Output Rego replay mismatch at sequence {sequence}")
            if final.to_dict() != expected.to_dict() and (
                final.effect != "DENY"
                or expected.effect != "PERMIT"
                or final.reason_codes
                not in (
                    ("OUTPUT_INVALID_POLICY_PLAN",),
                    ("OUTPUT_UNTRUSTED_RELEASE",),
                    ("OUTPUT_MASK_VERIFICATION_FAILED",),
                )
            ):
                raise ReplayError(f"Unexpected output policy override at sequence {sequence}")
            output_replayed += 1
            seen.add(digest)
        except (KeyError, TypeError, ValueError, SnapshotError, AttributeError) as exc:
            raise ReplayError(f"Invalid output evidence at sequence {sequence}") from exc

    return {
        "status": "REPLAY_VERIFIED",
        **provenance,
        "verified_events": chain["verified_events"],
        "policy_decisions_replayed": replayed,
        "output_policy_decisions_replayed": output_replayed,
        "output_local_fail_closed_decisions": output_local_denials,
        "legacy_decisions_integrity_only": legacy,
        "local_fail_closed_decisions": local_fail_closed,
        "unique_policy_snapshots": len(seen),
    }
