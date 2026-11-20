"""Release existence checks use a fixed HTTPS host and fail closed on other statuses."""

import http.client
import runpy
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.mark.parametrize("status", [200, 204, 301, 302, 401, 403, 500, 404])
def test_release_lookup_accepts_only_not_found(monkeypatch, status):
    if sys.platform == "win32":
        monkeypatch.setitem(sys.modules, "fcntl", SimpleNamespace())
    signer = runpy.run_path(str(Path(".github/scripts/sign_release_ci.py")))
    monkeypatch.setenv("GITHUB_REPOSITORY", "example/project")
    monkeypatch.setenv("GH_TOKEN", "synthetic-token")
    calls = []

    class Connection:
        closed = False

        def request(self, method, path, *, headers):
            calls.append((method, path, headers))

        def getresponse(self):
            return SimpleNamespace(status=status)

        def close(self):
            self.closed = True

    connection = Connection()

    def connect(host, *, timeout):
        assert host == "api.github.com"
        assert timeout == 30
        return connection

    monkeypatch.setattr(http.client, "HTTPSConnection", connect)
    if status == 404:
        signer["release_does_not_exist"]("release-g2")
    else:
        with pytest.raises(RuntimeError):
            signer["release_does_not_exist"]("release-g2")
    assert connection.closed
    assert calls[0][0:2] == ("GET", "/repos/example/project/releases/tags/release-g2")


def test_signer_advances_verified_history_without_subprocesses(tmp_path, monkeypatch):
    import hashlib
    import json
    import shutil
    import subprocess

    from app.detection.provenance import canonical
    from app.policy.snapshots import PolicySnapshotStore, build_snapshot
    from app.release.approvals import ReleaseStore, make_payload, new_keypair, sign_approval

    if sys.platform == "win32":
        monkeypatch.setitem(sys.modules, "fcntl", SimpleNamespace(LOCK_EX=2, flock=lambda *a: None))
    signer = runpy.run_path(str(Path(".github/scripts/sign_release_ci.py")))
    authority, workspace = tmp_path / "authority", tmp_path / "workspace"
    authority.mkdir()
    workspace.mkdir()
    trust = authority / "release-trust"
    trust.mkdir()
    private, pinned = tmp_path / "private.pem", tmp_path / "pinned.pem"
    new_keypair(private, pinned)
    shutil.copyfile(pinned, trust / "release-signing.pub.pem")
    snapshots = PolicySnapshotStore(authority / "policy-active", authority / "policy-archive")
    policy = build_snapshot("policies", snapshots.archive, snapshots.active)
    store = ReleaseStore(
        authority / "release-active/release.json", authority / "release-archive", trust, snapshots
    )
    digest = "d" * 64
    initial = sign_approval(
        make_payload(policy.policy_digest, policy.policy_revision, digest, 1, None), private
    )
    first = tmp_path / "first.json"
    first.write_bytes(canonical(initial))
    store.activate(first, detector_digest=digest)
    (authority / "release-candidates").mkdir()
    inputs = workspace / "release-input"
    inputs.mkdir()
    for name in [
        "application-image.tar.gz",
        "reviewer-image.tar.gz",
        "opa-image.tar.gz",
        "image.sha256",
    ]:
        (inputs / name).write_bytes(b"synthetic build artifact")
    (inputs / "detector-manifest.json").write_text(json.dumps({"digest": digest}))
    for key, value in {
        "SOVEREIGN_SIGNER_STATE_DIR": str(authority),
        "SOVEREIGN_RELEASE_PRIVATE_KEY_PATH": str(private),
        "SOVEREIGN_RELEASE_PUBLIC_KEY_PATH": str(pinned),
        "EXPECTED_PUBLIC_SHA256": hashlib.sha256(pinned.read_bytes()).hexdigest(),
        "GITHUB_WORKSPACE": str(workspace),
        "GITHUB_OUTPUT": str(tmp_path / "github-output"),
        "GITHUB_SHA": "a" * 40,
        "DETECTOR_DIGEST": digest,
    }.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setitem(
        signer["sign_release"].__globals__, "release_does_not_exist", lambda tag: None
    )
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **k: pytest.fail("Signer must use Python APIs")
    )
    signer["sign_release"]()
    activated = store.verify_active(detector_digest=digest)
    assert activated["payload"]["generation"] == 2
    assert activated["payload"]["previous_release_id"] == initial["release_id"]
    assert (workspace / "signed-package/release-state.tar.gz").is_file()
