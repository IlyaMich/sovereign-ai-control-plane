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
