"""Portable, privacy-conscious audit evidence packages.

Packages hold signed metadata, model *manifests*, and versioned Rego source,
not plaintext prompts, model weights, private signing keys, or external attestations.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import sqlite3
import stat
import tempfile
from typing import Callable
import zipfile

from app.audit.verify import verify_database
from app.detection.provenance import canonical, find_archived
from app.policy.replay import replay_database
from app.policy.snapshots import PolicySnapshotStore

MAX_FILES = 2000
MAX_UNCOMPRESSED = 128 * 1024 * 1024


class EvidencePackageError(Exception):
    pass


def _snapshot(source_path: str, target_path: Path) -> None:
    # SQLite backup preserves WAL mode. Normalize the *copy* for a read-only
    # reviewer; never modify the journal mode of the live audit database.
    with sqlite3.connect(f"file:{Path(source_path).resolve()}?mode=ro", uri=True) as source:
        with sqlite3.connect(str(target_path)) as target:
            source.backup(target)
            mode = target.execute("PRAGMA journal_mode=DELETE").fetchone()[0]
            if mode.lower() != "delete":
                raise EvidencePackageError("Cannot finalize read-only SQLite snapshot")


def _decision_refs(path: Path) -> tuple[set[str], set[str]]:
    policies: set[str] = set()
    detectors: set[str] = set()
    with sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True) as conn:
        entries = conn.execute("SELECT event_json FROM events WHERE event_type='DECISION'").fetchall()
    for (raw,) in entries:
        payload = json.loads(raw)["payload"]
        if payload.get("policy_snapshot") is not None:
            policies.add(payload["policy_snapshot"]["sha256"])
        if payload.get("detector_evidence_version") == "1":
            detectors.add(payload["detector_snapshot"]["sha256"])
    return policies, detectors


def _safe_path(name: str) -> bool:
    p = PurePosixPath(name)
    return (bool(name) and not name.startswith("/") and "\\" not in name
            and not name.endswith("/") and all(part not in {"", ".", ".."} for part in p.parts)
            and not (":" in p.parts[0]))


def _manifest_of(folder: Path) -> dict:
    entries = []
    for path in sorted(folder.rglob("*")):
        if path.is_symlink():
            raise EvidencePackageError("Symlink in evidence package source")
        if path.is_file():
            name = path.relative_to(folder).as_posix()
            if name == "package-manifest.json":
                continue
            raw = path.read_bytes()
            entries.append({"path": name, "sha256": hashlib.sha256(raw).hexdigest(),
                            "size": len(raw)})
    if len(entries) > MAX_FILES or sum(x["size"] for x in entries) > MAX_UNCOMPRESSED:
        raise EvidencePackageError("Evidence package exceeds safety limits")
    return {"schema_version": 1, "format": "sovereign-evidence-package",
            "files": entries,
            "trust_note": "Checkpoint generated with this export; independent witnessing is required for truncation resistance"}


def export_package(db_path: str, public_key: str, policy_archive: str,
                   detector_archive: str, output_path: str,
                   witnessed_checkpoint: str | None = None) -> dict:
    """Create a self-contained bundle; input database is read-only throughout."""
    with tempfile.TemporaryDirectory(prefix="sovereign-export-") as tmp:
        root = Path(tmp)
        snapshot = root / "audit.sqlite"
        _snapshot(db_path, snapshot)
        head = verify_database(str(snapshot), public_key, witnessed_checkpoint)
        policies, detectors = _decision_refs(snapshot)
        archive = PolicySnapshotStore("/unused-active", policy_archive)
        for digest in sorted(policies):
            folder = archive.find(digest)
            shutil.copytree(folder, root / "policy-archive" / digest,
                            symlinks=False)
        for digest in sorted(detectors):
            find_archived(detector_archive, digest)
            dest = root / "detector-archive" / (digest + ".json")
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(Path(detector_archive) / (digest + ".json"), dest)
        shutil.copyfile(public_key, root / "audit-key.pub.pem")
        (root / "checkpoint.json").write_bytes(canonical(head) + b"\n")
        if witnessed_checkpoint:
            shutil.copyfile(witnessed_checkpoint, root / "witnessed-checkpoint.json")
        manifest = _manifest_of(root)
        (root / "package-manifest.json").write_bytes(canonical(manifest) + b"\n")
        dest = Path(output_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(dest, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as bundle:
            for path in sorted(root.rglob("*")):
                if path.is_file():
                    bundle.write(path, arcname=path.relative_to(root).as_posix())
    return {"status": "EXPORTED", "path": output_path,
            "events": head["verified_events"], "policy_snapshots": len(policies),
            "detector_manifests": len(detectors)}


def verify_package(package_path: str, *, opa_binary: str = "opa",
                   evaluator: Callable | None = None,
                   trusted_public_key: str | None = None,
                   trusted_checkpoint: str | None = None) -> dict:
    """Verify files, signed audit chain, detector manifests, and Rego decisions."""
    with tempfile.TemporaryDirectory(prefix="sovereign-verify-") as tmp:
        root = Path(tmp)
        with zipfile.ZipFile(package_path, "r") as z:
            infos = z.infolist()
            if (not infos or len(infos) > MAX_FILES or
                sum(info.file_size for info in infos) > MAX_UNCOMPRESSED):
                raise EvidencePackageError("Evidence ZIP exceeds safety limits")
            names: set[str] = set()
            for info in infos:
                if (not _safe_path(info.filename) or info.filename in names
                    or info.is_dir() or ((info.external_attr >> 16) & 0o170000) == stat.S_IFLNK):
                    raise EvidencePackageError("Unsafe file name or type in evidence ZIP")
                names.add(info.filename)
            if "package-manifest.json" not in names:
                raise EvidencePackageError("Evidence manifest missing")
            z.extractall(root)
        try:
            declared = json.loads((root / "package-manifest.json").read_bytes())
        except (OSError, ValueError) as exc:
            raise EvidencePackageError("Invalid evidence manifest") from exc
        if declared != _manifest_of(root):
            raise EvidencePackageError("Evidence file hash or content mismatch")
        # A key or checkpoint included IN the ZIP is not independently trusted.
        # External verifier-provided anchors cannot be substituted by the exporter.
        if trusted_public_key and Path(trusted_public_key).read_bytes() != (root / "audit-key.pub.pem").read_bytes():
            raise EvidencePackageError("Bundle signing key differs from independently pinned key")
        checkpoint = (Path(trusted_checkpoint) if trusted_checkpoint else root / "checkpoint.json")
        result = replay_database(
            str(root / "audit.sqlite"), str(root / "audit-key.pub.pem"),
            str(root / "policy-archive"), str(checkpoint), opa_binary,
            evaluator=evaluator, detector_archive_root=str(root / "detector-archive"),
        )
        return {
            "status": ("EVIDENCE_PACKAGE_VERIFIED" if trusted_public_key
                       else "EVIDENCE_PACKAGE_SELF_CONSISTENT"),
            "audit": result,
            "public_key_trusted_externally": bool(trusted_public_key),
            "checkpoint_trusted_externally": bool(trusted_checkpoint),
        }
