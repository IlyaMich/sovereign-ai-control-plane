"""M7.8 crash-safe key publication; local synthetic material only."""

from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography.hazmat.primitives import serialization

from app.audit.sqlite_store import AuditUnavailable, SQLiteAuditStore
from app.infrastructure.atomic_files import publish_new_bytes, read_regular_bytes
from app.release.approvals import (
    ReleaseIntegrityError,
    new_keypair,
    recover_public_key,
)


def test_competing_publications_cannot_overwrite_winner(tmp_path):
    target = tmp_path / "private.pem"

    def attempt(i):
        try:
            publish_new_bytes(target, (f"valid-payload-{i}" * 200).encode())
            return True
        except FileExistsError:
            return False

    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(attempt, range(12)))
    assert sum(results) == 1
    assert target.read_bytes().startswith(b"valid-payload-")
    assert len(target.read_bytes()) > 2000
    assert not list(tmp_path.glob(".private.pem.*"))


def test_existing_or_symlink_target_is_not_replaced(tmp_path):
    destination = tmp_path / "material.pem"
    destination.write_bytes(b"original")
    with pytest.raises(FileExistsError):
        publish_new_bytes(destination, b"replacement")
    assert destination.read_bytes() == b"original"
    link = tmp_path / "linked.pem"
    try:
        link.symlink_to(destination)
    except (NotImplementedError, OSError):
        pytest.skip("Symlinks not available in this environment")
    with pytest.raises(ValueError):
        read_regular_bytes(link)
    with pytest.raises(FileExistsError):
        publish_new_bytes(link, b"replacement")
    assert destination.read_bytes() == b"original"


def test_audit_key_publication_matches_across_contending_startups(tmp_path):
    db = tmp_path / "events.sqlite"
    private = tmp_path / "audit-key.pem"
    initial = SQLiteAuditStore(str(db), str(private))
    # A new installation with no events: exercise concurrent first-publisher
    # publication using a schema that is already created.
    private.unlink()

    def initialize(_):
        return (
            initial._load_or_create_key()
            .public_key()
            .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        keys = list(pool.map(initialize, range(8)))
    assert len(set(keys)) == 1
    assert private.is_file()
    assert not list(tmp_path.glob(".audit-key.pem.*"))


def test_legacy_partial_audit_key_is_never_regenerated(tmp_path):
    private = tmp_path / "audit-key.pem"
    store = SQLiteAuditStore(str(tmp_path / "events.sqlite"), str(private))
    private.write_bytes(b"INCOMPLETE PRIVATE KEY")
    with pytest.raises(AuditUnavailable):
        store._load_or_create_key()
    assert private.read_bytes() == b"INCOMPLETE PRIVATE KEY"


def test_existing_wrong_audit_public_key_fails_closed(tmp_path):
    private = tmp_path / "audit-key.pem"
    SQLiteAuditStore(str(tmp_path / "events.sqlite"), str(private))
    private.with_suffix(".pub.pem").write_bytes(b"wrong verifier")
    with pytest.raises(AuditUnavailable):
        SQLiteAuditStore(str(tmp_path / "events.sqlite"), str(private))


def test_release_public_recovery_does_not_replace_private(tmp_path):
    private = tmp_path / "secret" / "release.pem"
    public = tmp_path / "trust" / "release.pub.pem"
    signer = new_keypair(private, public)
    original_private = private.read_bytes()
    original_public = public.read_bytes()
    public.unlink()
    assert recover_public_key(private, public) == signer
    assert private.read_bytes() == original_private
    assert public.read_bytes() == original_public
    public.write_bytes(b"wrong")
    with pytest.raises(ReleaseIntegrityError, match="does not match"):
        recover_public_key(private, public)
    assert private.read_bytes() == original_private
    with pytest.raises(ReleaseIntegrityError):
        new_keypair(private, public)


def test_staged_policy_fsync_requires_writable_handle_on_windows(tmp_path, monkeypatch):
    """Emulate Windows _commit rejecting a read-only fd, even on POSIX."""
    import os
    import stat

    from app.infrastructure import atomic_files

    stage = tmp_path / "staged-policy"
    stage.mkdir()
    policy = stage / "decision.rego"
    original = b"package sovereign\n"
    policy.write_bytes(original)
    native_fsync = os.fsync

    def require_writable_fd(fd):
        # A zero-byte write tests descriptor permissions without changing bytes.
        # A read-only descriptor raises EBADF, as Windows _commit would.
        if stat.S_ISREG(os.fstat(fd).st_mode):
            assert os.write(fd, b"") == 0
        native_fsync(fd)

    monkeypatch.setattr(atomic_files.os, "fsync", require_writable_fd)
    atomic_files.fsync_tree(stage)
    assert policy.read_bytes() == original
