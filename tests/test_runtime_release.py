"""Deployment preflight must reject an image that lacks a matching approval."""

import json
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from app.detection.provenance import DetectorIntegrityError
from app.infrastructure.config import Settings
from tests.test_m6_release_approvals import D, approval_fixture
from tools import verify_runtime_release


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    _, _, store, candidate, _ = approval_fixture(tmp_path)
    store.activate(candidate)
    settings = Settings(
        api_key="a-secret-for-tests-that-is-long-enough",
        active_policy_path=str(store.policy_store.active),
        policy_archive_path=str(store.policy_store.archive),
        release_active_path=str(store.active),
        release_archive_path=str(store.archive),
        release_trust_path=str(store.trust),
        detector_manifest_path=str(tmp_path / "manifest.json"),
    )
    monkeypatch.setattr(Settings, "from_env", classmethod(lambda cls: settings))
    # Only the installed artifact scan needs NLP dependencies. Exercise real signatures
    # and policy/release verification against temporary approved fixture artifacts.
    monkeypatch.setattr(verify_runtime_release, "load_verified", lambda *a, **k: {"digest": D})
    monkeypatch.setattr("app.release.approvals.load_verified", lambda *a, **k: {"digest": D})
    return settings


def test_matching_release_passes(runtime, capsys):
    assert verify_runtime_release.main() == 0
    assert json.loads(capsys.readouterr().out)["status"] == "RELEASE_VERIFIED"


def test_rebuilt_image_requires_successor_approval(runtime, monkeypatch, capsys):
    monkeypatch.setattr(
        verify_runtime_release, "load_verified", lambda *a, **k: {"digest": "a" * 64}
    )
    assert verify_runtime_release.main() == 1
    message = capsys.readouterr().err
    assert "not approved" in message
    assert "-UseExistingKey -SkipBuild" in message
    assert runtime.api_key not in message


def test_image_integrity_failure_is_not_bypassed(runtime, monkeypatch, capsys):
    def broken(*args, **kwargs):
        raise DetectorIntegrityError("Installed detector artifacts differ from build manifest")

    monkeypatch.setattr(verify_runtime_release, "load_verified", broken)
    assert verify_runtime_release.main() == 1
    assert "differ from build manifest" in capsys.readouterr().err


def test_missing_approval_is_rejected(runtime, capsys):
    Path(runtime.release_active_path).unlink()
    assert verify_runtime_release.main() == 1
    assert "release envelope" in capsys.readouterr().err


def test_explicit_unsigned_developer_mode(runtime, monkeypatch, capsys):
    settings = replace(runtime, require_signed_release=False)
    monkeypatch.setattr(Settings, "from_env", classmethod(lambda cls: settings))
    assert verify_runtime_release.main() == 0
    assert json.loads(capsys.readouterr().out)["status"] == "SIGNED_RELEASE_DISABLED"


@pytest.mark.parametrize("target", ["up", "restart"])
def test_make_startup_checks_release_without_building(target):
    result = subprocess.run(
        ["make", "--no-print-directory", "-n", target], capture_output=True, text=True, timeout=10
    )
    assert result.returncode == 0, result.stderr
    commands = result.stdout.splitlines()
    assert "tools.verify_runtime_release" in commands[0]
    assert "--pull never" in commands[0]
    assert "up --no-build" in commands[-1]
    assert "--build" not in result.stdout
