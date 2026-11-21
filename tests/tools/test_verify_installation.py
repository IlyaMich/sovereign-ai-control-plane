"""Focused tests of the unified verification command's operator safety."""

from pathlib import Path

import pytest

from tools.verify_installation import check_runtime


def test_runtime_check_rejects_missing_key(tmp_path):
    env = tmp_path / ".env"
    env.write_text("API_PORT=8001\n")
    with pytest.raises(RuntimeError, match="API key/port"):
        check_runtime(env)


def test_runtime_check_never_uses_external_destination(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text(
        "CONTROL_PLANE_API_KEY=secret-for-testing-only\n"
        "API_PORT=8001\n"
        "OPA_URL=https://untrusted.example\n"
    )
    observed = []

    class Ready:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    def opener(request, *, timeout):
        observed.append((request.full_url, request.get_header("X-api-key"), timeout))
        return Ready()

    monkeypatch.setattr("tools.verify_installation.urllib.request.urlopen", opener)
    result = check_runtime(Path(env))
    assert result["status"] == "VERIFIED"
    assert observed == [
        ("http://127.0.0.1:8001/health/ready", "secret-for-testing-only", 5)
    ]
