"""Regression tests for safe migration away from Git-tracked runtime artifacts."""

from pathlib import Path

import pytest

from app.detection.provenance import canonical
from app.policy.snapshots import build_snapshot
from app.release.approvals import make_payload, new_keypair, sign_approval
from tools.operator_state import migrate_legacy_state, verify_operator_state


def sample_legacy_state(tmp_path: Path) -> Path:
    root = tmp_path / "checkout"
    root.mkdir()
    for directory in ("release-active", "release-archive", "release-trust", "release-candidates"):
        (root / directory).mkdir()
    policies = root / "policies"
    policies.mkdir()
    (policies / "decision.rego").write_bytes(
        b"package sovereign.authz\n"
        b"import rego.v1\n"
        b'revision := "migration-test-v1"\n'
        b'decision := {"policy_digest": data.sovereign.policy_meta.digest}\n'
    )
    info = build_snapshot(policies, root / "policy-archive", root / "policy-active")
    private = tmp_path / "private.pem"
    public = root / "release-trust" / "release-signing.pub.pem"
    new_keypair(private, public)
    payload = make_payload(info.policy_digest, info.policy_revision, "a" * 64, 1, None)
    approval = sign_approval(payload, private)
    raw = canonical(approval) + b"\n"
    (root / "release-active" / "release.json").write_bytes(raw)
    (root / "release-archive" / (approval["release_id"] + ".json")).write_bytes(raw)
    (root / "release-candidates" / "release-g1.json").write_bytes(raw)
    return root


def test_operator_state_migration_preserves_approved_identity(tmp_path):
    root = sample_legacy_state(tmp_path)
    before = verify_operator_state(root)
    audit_volume = tmp_path / "audit-volume"
    audit_volume.mkdir()
    (audit_volume / "audit.sqlite").write_bytes(b"unchanged")

    dry = migrate_legacy_state(root)
    assert dry["status"] == "READY_TO_MIGRATE"
    assert not (root / ".runtime").exists()

    applied = migrate_legacy_state(root, apply=True)
    assert applied["status"] == "MIGRATED_AND_VERIFIED"
    assert applied["audit_volume"] == "UNCHANGED"
    assert verify_operator_state(root / ".runtime") == before
    assert verify_operator_state(root) == before
    assert (audit_volume / "audit.sqlite").read_bytes() == b"unchanged"
    for name in (
        "policy-active",
        "policy-archive",
        "release-active",
        "release-archive",
        "release-candidates",
        "release-trust",
    ):
        source = root / name
        copied = root / ".runtime" / name
        source_files = sorted(p for p in source.rglob("*") if p.is_file())
        copied_files = sorted(p for p in copied.rglob("*") if p.is_file())
        assert [p.relative_to(source) for p in source_files] == [
            p.relative_to(copied) for p in copied_files
        ]
        assert [p.read_bytes() for p in source_files] == [p.read_bytes() for p in copied_files]


def test_operator_state_migration_refuses_existing_destination(tmp_path):
    root = sample_legacy_state(tmp_path)
    state = root / ".runtime"
    state.mkdir()
    (state / "sentinel").write_text("protect")
    with pytest.raises(ValueError, match="never overwrite"):
        migrate_legacy_state(root, apply=True)
    assert (state / "sentinel").read_text() == "protect"
    assert verify_operator_state(root)["generation"] == 1


def test_operator_state_migration_refuses_invalid_legacy_approval(tmp_path):
    root = sample_legacy_state(tmp_path)
    (root / "release-active" / "release.json").write_bytes(b"{}")
    with pytest.raises(Exception):
        migrate_legacy_state(root, apply=True)
    assert not (root / ".runtime").exists()


def test_operator_state_migration_refuses_corrupt_policy(tmp_path):
    root = sample_legacy_state(tmp_path)
    with (root / "policy-active" / "decision.rego").open("ab") as stream:
        stream.write(b"tampered")
    with pytest.raises(Exception):
        migrate_legacy_state(root, apply=True)
    assert not (root / ".runtime").exists()


def test_operator_state_migration_checks_every_archived_file(tmp_path, monkeypatch):
    """A corrupted historical candidate must not be silently copied."""
    from tools import operator_state

    root = sample_legacy_state(tmp_path)
    real_copy = operator_state.shutil.copytree

    def corrupt_one_copy(source, destination, *args, **kwargs):
        # shutil.copytree recursively calls its module-level name on Windows,
        # passing positional options during nested directory traversal.
        result = real_copy(source, destination, *args, **kwargs)
        if Path(source).name == "release-candidates":
            (Path(destination) / "release-g1.json").write_bytes(b"changed")
        return result

    monkeypatch.setattr(operator_state.shutil, "copytree", corrupt_one_copy)
    with pytest.raises(ValueError, match="archive bytes differ"):
        migrate_legacy_state(root, apply=True)
    assert not (root / ".runtime").exists()
    assert verify_operator_state(root)["generation"] == 1


def test_compose_never_mounts_git_tracked_signed_artifacts():
    """Fail CI if live services are wired back to the legacy tracked folders."""
    root = Path(__file__).resolve().parents[2]
    compose = (root / "deploy" / "compose.yaml").read_text(encoding="utf-8")
    for name in (
        "policy-active",
        "policy-archive",
        "release-active",
        "release-archive",
        "release-trust",
    ):
        assert f"source: ../.runtime/{name}" in compose
        assert f"- ../{name}:" not in compose
    assert compose.count("create_host_path: false") == 8
