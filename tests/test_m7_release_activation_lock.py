"""M7.8 serialized release activation and staged-policy rollback tests."""

import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from app.detection.provenance import canonical
from app.infrastructure.atomic_files import interprocess_lock
from app.policy.snapshots import build_snapshot
from app.release.approvals import ReleaseIntegrityError, make_payload, sign_approval
from tests.test_policy_snapshots import SOURCE
from tests.test_release_approvals import D, approval_fixture


def test_activation_lock_excludes_a_separate_process(tmp_path):
    lock = tmp_path / "lockfile"
    marker = tmp_path / "started"
    code = (
        "from pathlib import Path; import time; "
        "from app.infrastructure.atomic_files import interprocess_lock; "
        f"with interprocess_lock(Path({str(lock)!r}), timeout_seconds=2):\n"
        f"    Path({str(marker)!r}).write_text('ready')\n"
        "    time.sleep(1.5)\n"
    )
    # Compound `with` must start a new statement, rather than follow a semicolon.
    code = code.replace("; with interprocess_lock", "\nwith interprocess_lock")
    process = subprocess.Popen([sys.executable, "-c", code])
    try:
        deadline = time.monotonic() + 5
        while not marker.exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.02)
        assert marker.exists(), "Worker never acquired OS file lock"
        with pytest.raises(TimeoutError):
            with interprocess_lock(lock, timeout_seconds=0.05):
                pass
    finally:
        process.wait(timeout=8)
    with interprocess_lock(lock, timeout_seconds=0.5):
        pass


def test_same_generation_competing_activations_only_one_wins(tmp_path):
    private, _, store, genesis_path, genesis = approval_fixture(tmp_path)
    store.activate(genesis_path)
    info = store.policy_store.verify_active()
    candidates = []
    for i in range(2):
        document = sign_approval(
            make_payload(
                info.policy_digest,
                info.policy_revision,
                f"{i + 1:x}" * 64,
                2,
                genesis["release_id"],
            ),
            private,
        )
        candidate = tmp_path / f"candidate-{i}.json"
        candidate.write_bytes(canonical(document) + b"\n")
        candidates.append(candidate)

    def activate(path):
        try:
            return store.activate(path)["release_id"]
        except ReleaseIntegrityError:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(activate, candidates))
    assert sum(x is not None for x in outcomes) == 1
    assert store.verify_active()["release_id"] in outcomes
    assert store.verify_active()["payload"]["generation"] == 2


def test_failed_release_metadata_publication_restores_old_active_policy(tmp_path, monkeypatch):
    private, _, store, genesis_path, genesis = approval_fixture(tmp_path)
    store.activate(genesis_path)
    previous_digest = store.policy_store.verify_active().policy_digest

    different_source = tmp_path / "new-policy-source"
    different_source.mkdir()
    (different_source / "decision.rego").write_text(SOURCE + "\n# synthetic new policy bytes\n")
    new_snapshot = build_snapshot(
        different_source,
        store.policy_store.archive,
        tmp_path / "unused-new-policy-active",
    )
    changed = sign_approval(
        make_payload(
            new_snapshot.policy_digest, new_snapshot.policy_revision, D, 2, genesis["release_id"]
        ),
        private,
    )
    candidate = tmp_path / "new-release.json"
    candidate.write_bytes(canonical(changed) + b"\n")

    def fail_metadata(*_):
        raise OSError("Synthetic metadata publication failure")

    monkeypatch.setattr("app.release.approvals._atomic_replace", fail_metadata)
    with pytest.raises(OSError, match="Synthetic metadata"):
        store.activate(candidate)
    assert store.verify_active()["release_id"] == genesis["release_id"]
    assert store.policy_store.verify_active().policy_digest == previous_digest
    assert not list(store.policy_store.active.parent.glob(".policy-backup-*"))


def test_activation_rejects_stale_predecessor_even_with_existing_archive(tmp_path):
    private, _, store, genesis_path, genesis = approval_fixture(tmp_path)
    store.activate(genesis_path)
    policy = store.policy_store.verify_active()
    second = sign_approval(
        make_payload(policy.policy_digest, policy.policy_revision, D, 2, genesis["release_id"]),
        private,
    )
    candidate = tmp_path / "second.json"
    candidate.write_bytes(canonical(second) + b"\n")
    store.activate(candidate)
    with pytest.raises(ReleaseIntegrityError, match="Rollback/reorder"):
        store.activate(candidate)
    assert store.verify_active()["payload"]["generation"] == 2
