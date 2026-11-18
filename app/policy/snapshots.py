"""Content-addressed Rego policy snapshots and deterministic integrity checks.

A snapshot identifies exact source bytes. Generated OPA metadata is explicitly
excluded from its digest to avoid a recursive hash; it is checked separately.
This is an integrity mechanism, NOT a signature or a trusted release pipeline.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import shutil
import tempfile
from dataclasses import dataclass

DOMAIN = b"sovereign-policy-snapshot-v1\x00"
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
REVISION_RE = re.compile(r'^revision\s*:=\s*"([a-zA-Z0-9_.-]{1,80})"\s*$', re.M)
GENERATED = {"manifest.json", "snapshot.rego"}


class SnapshotError(Exception):
    pass


@dataclass(frozen=True)
class SnapshotInfo:
    policy_digest: str
    policy_revision: str
    files: tuple[tuple[str, str, int], ...]

    def manifest(self) -> dict:
        return {
            "schema_version": 1,
            "policy_digest": self.policy_digest,
            "policy_revision": self.policy_revision,
            "files": [
                {"path": name, "sha256": digest, "size": size}
                for name, digest, size in self.files
            ],
        }


def _files(root: Path) -> list[tuple[str, bytes]]:
    if not root.is_dir():
        raise SnapshotError("Policy snapshot directory missing")
    files: list[tuple[str, bytes]] = []
    for path in root.rglob("*"):
        if path.is_symlink():
            raise SnapshotError("Policy snapshot cannot contain symbolic links")
        if path.is_dir():
            continue
        name = path.relative_to(root).as_posix()
        if name in GENERATED:
            continue
        if path.suffix not in {".rego", ".json"}:
            raise SnapshotError("Unexpected file in policy snapshot")
        files.append((name, path.read_bytes()))
    files.sort(key=lambda item: item[0])
    if not any(name == "decision.rego" for name, _ in files):
        raise SnapshotError("Missing decision.rego")
    return files


def _digest(files: list[tuple[str, bytes]]) -> str:
    hasher = hashlib.sha256(DOMAIN)
    for name, content in files:
        name_bytes = name.encode("utf-8")
        hasher.update(len(name_bytes).to_bytes(4, "big"))
        hasher.update(name_bytes)
        hasher.update(len(content).to_bytes(8, "big"))
        hasher.update(content)
    return hasher.hexdigest()


def _metadata(digest: str) -> bytes:
    return (
        "# Generated from the content-addressed policy snapshot; do not edit.\n"
        "package sovereign.policy_meta\nimport rego.v1\n"
        f'digest := "{digest}"\n'
    ).encode("utf-8")


def calculate_snapshot(source: str | Path) -> SnapshotInfo:
    files = _files(Path(source))
    source_map = dict(files)
    source_text = source_map["decision.rego"].decode("utf-8")
    matched = REVISION_RE.findall(source_text)
    if len(matched) != 1:
        raise SnapshotError("Expected exactly one literal revision in decision.rego")
    if "data.sovereign.policy_meta.digest" not in source_text:
        raise SnapshotError("Decision policy must bind snapshot digest in every decision")
    return SnapshotInfo(
        _digest(files), matched[0],
        tuple((name, hashlib.sha256(content).hexdigest(), len(content)) for name, content in files),
    )


def verify_snapshot(folder: str | Path, expected_digest: str | None = None) -> SnapshotInfo:
    root = Path(folder)
    if root.is_symlink():
        raise SnapshotError("Snapshot directory must not be a symlink")
    try:
        manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
        metadata = (root / "snapshot.rego").read_bytes()
        info = calculate_snapshot(root)
    except (OSError, UnicodeError, ValueError, TypeError, KeyError) as exc:
        raise SnapshotError("Cannot read valid snapshot") from exc
    if manifest != info.manifest():
        raise SnapshotError("Policy snapshot manifest does not match source bytes")
    if metadata != _metadata(info.policy_digest):
        raise SnapshotError("Generated OPA policy metadata was modified")
    if expected_digest is not None and info.policy_digest != expected_digest:
        raise SnapshotError("Policy snapshot digest mismatch")
    return info


def build_snapshot(source: str | Path, archive: str | Path, active: str | Path) -> SnapshotInfo:
    """Create an archive and activate it. Must be run while OPA is stopped/recreated.

    The activation directory is replaced (non-atomically on Windows); any race
    with active requests fails closed through the runtime's snapshot validation.
    """
    source_root = Path(source)
    archive_root = Path(archive)
    active_root = Path(active)
    info = calculate_snapshot(source_root)
    archive_root.mkdir(parents=True, exist_ok=True)
    archive_dir = archive_root / info.policy_digest
    if archive_dir.exists():
        verify_snapshot(archive_dir, info.policy_digest)
    else:
        with tempfile.TemporaryDirectory(prefix=".snapshot-", dir=archive_root) as temp:
            staged = Path(temp) / "bundle"
            staged.mkdir()
            for name, content in _files(source_root):
                dest = staged / name
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(content)
            (staged / "snapshot.rego").write_bytes(_metadata(info.policy_digest))
            (staged / "manifest.json").write_text(
                json.dumps(info.manifest(), sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            verify_snapshot(staged, info.policy_digest)
            staged.rename(archive_dir)
    if active_root.resolve() != archive_dir.resolve():
        # A separate active copy makes activation independent of host symlink
        # privileges (important for Windows + Podman). Recreate OPA afterward.
        if active_root.is_symlink():
            raise SnapshotError("Active policy path must not be a symlink")
        if active_root.exists():
            shutil.rmtree(active_root)
        shutil.copytree(archive_dir, active_root)
    verify_snapshot(active_root, info.policy_digest)
    return info


class PolicySnapshotStore:
    def __init__(self, active: str | Path, archive: str | Path):
        self.active = Path(active)
        self.archive = Path(archive)

    def verify_active(self) -> SnapshotInfo:
        active = verify_snapshot(self.active)
        verify_snapshot(self.archive / active.policy_digest, active.policy_digest)
        return active

    def find(self, digest: str) -> Path:
        if not DIGEST_RE.fullmatch(digest):
            raise SnapshotError("Invalid policy digest")
        folder = self.archive / digest
        verify_snapshot(folder, digest)
        return folder
