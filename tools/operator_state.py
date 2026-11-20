"""Operator-owned host state, deliberately separate from Git-tracked example files.

The host-side tools must run from the repository root. Container paths remain
/policy-active, /policy-archive, /release-active, etc., via Compose mounts.
"""

from __future__ import annotations

import shutil
import uuid
from pathlib import Path

from app.policy.snapshots import PolicySnapshotStore
from app.release.approvals import ReleaseStore, summary

STATE_ROOT = Path(".runtime")
STATE_FOLDERS = (
    "policy-active",
    "policy-archive",
    "release-active",
    "release-archive",
    "release-candidates",
    "release-trust",
)


def state_path(name: str) -> Path:
    if name not in STATE_FOLDERS:
        raise ValueError("Unknown operator state directory")
    return STATE_ROOT / name


def verify_operator_state(root: Path) -> dict:
    """Authenticate approval and immutable archives before/after migration."""
    store = ReleaseStore(
        root / "release-active" / "release.json",
        root / "release-archive",
        root / "release-trust",
        PolicySnapshotStore(root / "policy-active", root / "policy-archive"),
    )
    return summary(store.verify_active())


def _check_no_symlinks(root: Path) -> None:
    for name in STATE_FOLDERS:
        folder = root / name
        if not folder.is_dir() or folder.is_symlink():
            raise ValueError(f"Missing or unsafe legacy state directory: {name}")
        for entry in folder.rglob("*"):
            if entry.is_symlink():
                raise ValueError(f"Symlink inside legacy state directory: {name}")


def migrate_legacy_state(repo_root: Path, *, apply: bool = False) -> dict:
    """Copy verified legacy state to an ignored folder, never altering originals.

    Does not migrate audit-data: the existing named Compose volume is reused.
    Refuse partially populated/new states to avoid overwriting deployed identity.
    """
    root = repo_root.resolve()
    target = root / STATE_ROOT
    if target.exists() or target.is_symlink():
        raise ValueError("Destination .runtime already exists; never overwrite existing state")
    _check_no_symlinks(root)
    original = verify_operator_state(root)
    result = {
        "status": "READY_TO_MIGRATE",
        "release_id": original["release_id"],
        "generation": original["generation"],
        "policy_digest": original["policy_digest"],
        "destination": str(target),
        "audit_volume": "UNCHANGED",
    }
    if not apply:
        return result

    # All source bytes are copied without opening files in text mode.
    # Stage and verify before publishing the new root, fail closed on mismatch.
    stage = root / (".runtime-migration-" + uuid.uuid4().hex)
    try:
        stage.mkdir()
        for name in STATE_FOLDERS:
            shutil.copytree(root / name, stage / name)
        copied = verify_operator_state(stage)
        if copied != original:
            raise ValueError("Copied release identity differs from original")
        if target.exists() or target.is_symlink():
            raise ValueError("Destination created concurrently; refusing to overwrite it")
        stage.rename(target)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    if verify_operator_state(target) != original:
        raise RuntimeError("Published state verification failed; do not start services")
    return {**result, "status": "MIGRATED_AND_VERIFIED"}
