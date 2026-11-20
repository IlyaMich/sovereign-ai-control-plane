"""Independent verification of detector references in already signed decisions.

A valid provenance reference is NOT an NLP classification replay: no plaintext
prompt, installed model binary, or claim of detection completeness is supplied.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path

from app.detection.provenance import DetectorIntegrityError, find_archived


class DetectorEvidenceError(Exception):
    pass


def verify_detector_references(db_path: str, archive_root: str | None) -> dict:
    count = 0
    legacy = 0
    seen: set[str] = set()
    with (
        closing(sqlite3.connect(f"file:{Path(db_path).resolve()}?mode=ro", uri=True)) as connection,
        connection,
    ):
        events = connection.execute(
            "SELECT sequence,event_json FROM events WHERE event_type='DECISION' ORDER BY sequence"
        )
        for seq, raw in events:
            try:
                evidence = json.loads(raw)["payload"]
                marker = evidence.get("detector_evidence_version")
                if marker is None:
                    # Older signed decisions retain integrity but have no provenance.
                    if "detector_snapshot" in evidence:
                        raise DetectorEvidenceError("Unexpected detector snapshot without version")
                    legacy += 1
                    continue
                if marker != "1":
                    raise DetectorEvidenceError("Unsupported detector evidence version")
                cls = evidence["policy_input"]["classification"]
                digest = cls["artifact_digest"]
                if evidence["detector_snapshot"] != {"sha256": digest, "schema_version": 1}:
                    raise DetectorEvidenceError("Detector evidence does not match classification")
                if not archive_root:
                    raise DetectorEvidenceError("Detector archive is required for M5 decisions")
                if digest not in seen:
                    find_archived(archive_root, digest)
                    seen.add(digest)
                transform = evidence.get("transformation")
                if isinstance(transform, dict) and transform.get("applied"):
                    checked = transform.get("verification")
                    if not isinstance(checked, dict) or checked.get("artifact_digest") != digest:
                        raise DetectorEvidenceError(
                            "Post-redaction scan changed detector artifacts"
                        )
                count += 1
            except (KeyError, TypeError, ValueError, DetectorIntegrityError) as exc:
                raise DetectorEvidenceError(f"Detector evidence invalid at sequence {seq}") from exc
    return {
        "detector_provenance_verified": count,
        "legacy_decisions_without_detector_provenance": legacy,
        "unique_detector_manifests": len(seen),
        "classification_replayed": 0,
    }
