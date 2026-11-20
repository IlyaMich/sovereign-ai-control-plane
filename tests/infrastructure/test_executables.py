"""Executable selection cannot implicitly launch files from the working directory."""

import os
import sys
from pathlib import Path

import pytest

from app.infrastructure.executables import resolve_executable
from app.policy.replay import ReplayError, run_opa
from tools.run_control_plane import server_host


@pytest.mark.parametrize("command", ["", "-eval", "bad\x00name", "relative/opa.exe"])
def test_invalid_executable_is_rejected(command):
    with pytest.raises(ValueError):
        resolve_executable(command)


def test_current_directory_is_excluded_even_if_path_lists_it(tmp_path, monkeypatch):
    name = "audit-test.exe" if os.name == "nt" else "audit-test"
    untrusted = tmp_path / name
    untrusted.write_bytes(b"untrusted")
    untrusted.chmod(0o755)
    trusted = tmp_path / "trusted"
    trusted.mkdir()
    executable = trusted / name
    executable.write_bytes(b"trusted")
    executable.chmod(0o755)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PATH", os.pathsep.join(["", ".", str(tmp_path), str(trusted)]))
    assert resolve_executable(name) == str(executable)
    executable.unlink()
    with pytest.raises(FileNotFoundError):
        resolve_executable(name)


@pytest.mark.parametrize("suffix", [".cmd", ".bat", ".ps1"])
def test_shell_launchers_are_rejected(tmp_path, suffix):
    script = tmp_path / ("opa" + suffix)
    script.write_text("echo test")
    script.chmod(0o755)
    with pytest.raises(ValueError, match="Shell script"):
        resolve_executable(str(script))


def test_python_invocation_keeps_venv_path():
    assert resolve_executable(sys.executable) == str(Path(sys.executable).absolute())


def test_replay_rejects_arbitrary_expressions_before_starting_a_process(tmp_path):
    with pytest.raises(ReplayError, match="Unsupported policy replay entrypoint"):
        run_opa(sys.executable, tmp_path, {}, "data; arbitrary expression")


def test_local_listener_defaults_to_loopback(monkeypatch):
    monkeypatch.delenv("CONTROL_PLANE_LISTEN_HOST", raising=False)
    assert server_host() == "127.0.0.1"


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "0.0.0.0"])
def test_explicit_literal_listener_address_is_supported(monkeypatch, host):
    monkeypatch.setenv("CONTROL_PLANE_LISTEN_HOST", host)
    assert server_host() == host


@pytest.mark.parametrize("host", ["example.com", "", "127.0.0.1:8000", "not-an-ip"])
def test_invalid_listener_addresses_are_rejected(monkeypatch, host):
    monkeypatch.setenv("CONTROL_PLANE_LISTEN_HOST", host)
    with pytest.raises(ValueError, match="literal IP address"):
        server_host()
