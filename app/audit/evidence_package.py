"""Portable, privacy-conscious audit evidence packages.

Packages hold signed metadata, model *manifests*, and versioned Rego source,
not plaintext prompts, model weights, private signing keys, or external attestations.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import stat
import tempfile
import zipfile
from contextlib import closing
from pathlib import Path, PurePosixPath
from typing import Callable, TypedDict

from app.audit.verify import verify_database
from app.detection.provenance import canonical, find_archived
from app.policy.replay import replay_database
from app.policy.snapshots import PolicySnapshotStore
from app.release.approvals import load_approval
from app.release.evidence import verify_release_references

MAX_FILES = 2000
MAX_UNCOMPRESSED = 128 * 1024 * 1024
MAX_CUSTOM_UNCOMPRESSED_MIB = 1024
MIB = 1024 * 1024
_HASH_CHUNK_BYTES = 1024 * 1024


def _uncompressed_limit(max_uncompressed_mib: int) -> int:
    """Bound explicit export/reviewer overrides; default keeps legacy guard."""
    if (
        type(max_uncompressed_mib) is not int
        or not 1 <= max_uncompressed_mib <= MAX_CUSTOM_UNCOMPRESSED_MIB
    ):
        raise EvidencePackageError("Evidence limit must be an integer from 1 to 1024 MiB")
    return max_uncompressed_mib * MIB


def _hash_file(path: Path) -> str:
    """Hash evidence bytes in bounded memory, including large SQLite snapshots."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(_HASH_CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()



class PackageEntry(TypedDict):
    path: str
    sha256: str
    size: int


class EvidencePackageError(Exception):
    pass


def _snapshot(source_path: str, target_path: Path) -> None:
    # SQLite backup preserves WAL mode. Normalize the *copy* for a read-only
    # reviewer; never modify the journal mode of the live audit database.
    with (
        closing(sqlite3.connect(f"file:{Path(source_path).resolve()}?mode=ro", uri=True)) as source,
        source,
    ):
        with closing(sqlite3.connect(str(target_path))) as target, target:
            source.backup(target)
            mode = target.execute("PRAGMA journal_mode=DELETE").fetchone()[0]
            if mode.lower() != "delete":
                raise EvidencePackageError("Cannot finalize read-only SQLite snapshot")


def _decision_refs(path: Path) -> tuple[set[str], set[str], set[str]]:
    policies: set[str] = set()
    detectors: set[str] = set()
    releases: set[str] = set()
    with closing(sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)) as conn, conn:
        entries = conn.execute(
            "SELECT event_type,event_json FROM events WHERE event_type IN ('DECISION', 'OUTCOME')"
        ).fetchall()
    for event_type, raw in entries:
        payload = json.loads(raw)["payload"]
        if event_type == "OUTCOME":
            dlp = payload.get("output_dlp")
            if isinstance(dlp, dict) and dlp.get("policy_snapshot") is not None:
                policies.add(dlp["policy_snapshot"]["sha256"])
            continue
        if payload.get("policy_snapshot") is not None:
            policies.add(payload["policy_snapshot"]["sha256"])
        if payload.get("detector_evidence_version") == "1":
            detectors.add(payload["detector_snapshot"]["sha256"])
        if payload.get("release_evidence_version") == "1":
            releases.add(payload["release_snapshot"]["release_id"])
    return policies, detectors, releases


def _safe_path(name: str) -> bool:
    p = PurePosixPath(name)
    return (
        bool(name)
        and not name.startswith("/")
        and "\\" not in name
        and not name.endswith("/")
        and all(part not in {"", ".", ".."} for part in p.parts)
        and ":" not in p.parts[0]
    )


def _manifest_of(
    folder: Path, *, max_uncompressed_bytes: int = MAX_UNCOMPRESSED
) -> dict:
    entries: list[PackageEntry] = []
    total_bytes = 0
    for path in sorted(folder.rglob("*")):
        if path.is_symlink():
            raise EvidencePackageError("Symlink in evidence package source")
        if path.is_file():
            name = path.relative_to(folder).as_posix()
            if name == "package-manifest.json":
                continue
            size = path.stat().st_size
            total_bytes += size
            if len(entries) >= MAX_FILES or total_bytes > max_uncompressed_bytes:
                raise EvidencePackageError(
                    "Evidence package exceeds configured file count or uncompressed size limit"
                )
            entries.append({"path": name, "sha256": _hash_file(path), "size": size})
    return {
        "schema_version": 1,
        "format": "sovereign-evidence-package",
        "files": entries,
        "trust_note": "Checkpoint generated with this export; independent witnessing is required for truncation resistance",
    }


def export_package(
    db_path: str,
    public_key: str,
    policy_archive: str,
    detector_archive: str,
    output_path: str,
    witnessed_checkpoint: str | None = None,
    release_archive: str | None = None,
    *,
    max_uncompressed_mib: int = 128,
) -> dict:
    """Create a self-contained bundle; input database is read-only throughout."""
    limit = _uncompressed_limit(max_uncompressed_mib)
    with tempfile.TemporaryDirectory(prefix="sovereign-export-") as tmp:
        root = Path(tmp)
        snapshot = root / "audit.sqlite"
        _snapshot(db_path, snapshot)
        head = verify_database(str(snapshot), public_key, witnessed_checkpoint)
        policies, detectors, releases = _decision_refs(snapshot)
        archive = PolicySnapshotStore("/unused-active", policy_archive)
        for digest in sorted(policies):
            folder = archive.find(digest)
            shutil.copytree(folder, root / "policy-archive" / digest, symlinks=False)
        for digest in sorted(detectors):
            find_archived(detector_archive, digest)
            dest = root / "detector-archive" / (digest + ".json")
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(Path(detector_archive) / (digest + ".json"), dest)
        if releases and release_archive is None:
            raise EvidencePackageError("Release archive required for signed-release decisions")
        for identity in sorted(releases):
            assert release_archive is not None  # Required above when releases are present.
            source = Path(release_archive) / (identity + ".json")
            doc = load_approval(
                source
            )  # Verifies identity; authentication uses external trust anchor.
            if doc["release_id"] != identity:
                raise EvidencePackageError("Archived release identity mismatch")
            dest = root / "release-archive" / (identity + ".json")
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, dest)
        shutil.copyfile(public_key, root / "audit-key.pub.pem")
        (root / "checkpoint.json").write_bytes(canonical(head) + b"\n")
        if witnessed_checkpoint:
            shutil.copyfile(witnessed_checkpoint, root / "witnessed-checkpoint.json")
        manifest = _manifest_of(root, max_uncompressed_bytes=limit)
        (root / "package-manifest.json").write_bytes(canonical(manifest) + b"\n")
        dest = Path(output_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(
            dest, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6
        ) as bundle:
            for path in sorted(root.rglob("*")):
                if path.is_file():
                    bundle.write(path, arcname=path.relative_to(root).as_posix())
    return {
        "status": "EXPORTED",
        "path": output_path,
        "events": head["verified_events"],
        "policy_snapshots": len(policies),
        "detector_manifests": len(detectors),
        "release_approvals": len(releases),
    }


def verify_package(
    package_path: str,
    *,
    opa_binary: str = "opa",
    evaluator: Callable | None = None,
    output_evaluator: Callable | None = None,
    trusted_public_key: str | None = None,
    trusted_checkpoint: str | None = None,
    trusted_release_public_key: str | None = None,
    max_uncompressed_mib: int = 128,
) -> dict:
    """Verify files, signed audit chain, detector manifests, and Rego decisions."""
    limit = _uncompressed_limit(max_uncompressed_mib)
    with tempfile.TemporaryDirectory(prefix="sovereign-verify-") as tmp:
        root = Path(tmp)
        with zipfile.ZipFile(package_path, "r") as z:
            infos = z.infolist()
            if (
                not infos
                or len(infos) > MAX_FILES
                or sum(info.file_size for info in infos) > limit
            ):
                raise EvidencePackageError("Evidence ZIP exceeds safety limits")
            names: set[str] = set()
            for info in infos:
                if (
                    not _safe_path(info.filename)
                    or info.filename in names
                    or info.is_dir()
                    or ((info.external_attr >> 16) & 0o170000) == stat.S_IFLNK
                ):
                    raise EvidencePackageError("Unsafe file name or type in evidence ZIP")
                names.add(info.filename)
            if "package-manifest.json" not in names:
                raise EvidencePackageError("Evidence manifest missing")
            z.extractall(root)
        try:
            declared = json.loads((root / "package-manifest.json").read_bytes())
        except (OSError, ValueError) as exc:
            raise EvidencePackageError("Invalid evidence manifest") from exc
        if declared != _manifest_of(root, max_uncompressed_bytes=limit):
            raise EvidencePackageError("Evidence file hash or content mismatch")
        # A key or checkpoint included IN the ZIP is not independently trusted.
        # External verifier-provided anchors cannot be substituted by the exporter.
        if (
            trusted_public_key
            and Path(trusted_public_key).read_bytes() != (root / "audit-key.pub.pem").read_bytes()
        ):
            raise EvidencePackageError("Bundle signing key differs from independently pinned key")
        checkpoint = Path(trusted_checkpoint) if trusted_checkpoint else root / "checkpoint.json"
        # The archive references are derived only after signed-audit verification.
        release_trust = None
        if trusted_release_public_key is not None:
            source_key = Path(trusted_release_public_key)
            if not source_key.is_file() or source_key.is_symlink():
                raise EvidencePackageError("External release public key unavailable")
            release_trust = root / "external-release-trust"
            release_trust.mkdir()
            shutil.copyfile(source_key, release_trust / "trusted.pem")
        result = replay_database(
            str(root / "audit.sqlite"),
            str(root / "audit-key.pub.pem"),
            str(root / "policy-archive"),
            str(checkpoint),
            opa_binary,
            evaluator=evaluator,
            detector_archive_root=str(root / "detector-archive"),
            output_evaluator=output_evaluator,
        )
        release_info = verify_release_references(
            str(root / "audit.sqlite"),
            str(root / "release-archive"),
            str(release_trust) if release_trust is not None else None,
        )
        return {
            "status": (
                "EVIDENCE_PACKAGE_VERIFIED"
                if trusted_public_key
                else "EVIDENCE_PACKAGE_SELF_CONSISTENT"
            ),
            "audit": {**result, **release_info},
            "release_signer_trusted_externally": bool(trusted_release_public_key),
            "public_key_trusted_externally": bool(trusted_public_key),
            "checkpoint_trusted_externally": bool(trusted_checkpoint),
        }
