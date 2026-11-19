"""Startup failure diagnosis must be actionable without exposing prompt data."""
from __future__ import annotations

from importlib import metadata

import pytest

from evaluation.adapters import control_plane
from evaluation.cli import main


def test_missing_model_has_exact_install_command(monkeypatch):
    def version(dist: str) -> str:
        if dist == "en-core-web-sm":
            raise metadata.PackageNotFoundError(dist)
        return "installed"

    monkeypatch.setattr(control_plane.metadata, "version", version)
    with pytest.raises(control_plane.DetectorSetupError, match="not installed") as caught:
        control_plane.ControlPlaneAdapter.create()
    assert "en_core_web_sm-3.8.0" in str(caught.value)


def test_wrong_model_version_has_actionable_error(monkeypatch):
    monkeypatch.setattr(control_plane.metadata, "version", lambda dist: "3.8.1")
    with pytest.raises(control_plane.DetectorSetupError, match="expected 3.8.0"):
        control_plane.ControlPlaneAdapter.create()


def test_missing_dependency_has_actionable_error(monkeypatch):
    def missing(dist: str) -> str:
        raise metadata.PackageNotFoundError(dist)

    monkeypatch.setattr(control_plane.metadata, "version", missing)
    with pytest.raises(control_plane.DetectorSetupError, match="pip install"):
        control_plane.ControlPlaneAdapter.create()


def test_cli_prints_safe_setup_diagnostic(monkeypatch, capsys):
    def fake_create(cls):
        raise control_plane.DetectorSetupError("Missing pinned spaCy model")

    monkeypatch.setattr(control_plane.ControlPlaneAdapter, "create", classmethod(fake_create))
    assert main(["detect", "--split", "evaluation"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.strip() == "Evaluation setup failed: Missing pinned spaCy model"
