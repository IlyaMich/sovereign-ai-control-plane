"""Offline tests for the fresh-reviewer release bootstrap."""

import io
import json
import tarfile

import pytest

from tools.submission_bootstrap import (
    REGISTRY_ROOT,
    STATE_DIRS,
    check_external_route,
    compose_command,
    create_environment,
    extract_public_state,
    image_reference,
    verify_images,
    verify_package,
)


def make_archive(path, *, unsafe_name=None):
    with tarfile.open(path, "w:gz") as archive:
        for name in [".runtime", *(f".runtime/{directory}" for directory in STATE_DIRS)]:
            entry = tarfile.TarInfo(name)
            entry.type = tarfile.DIRTYPE
            entry.mode = 0o755
            archive.addfile(entry)
        data = b'{"release_id":"test"}'
        entry = tarfile.TarInfo(unsafe_name or ".runtime/release-active/release.json")
        entry.size = len(data)
        archive.addfile(entry, io.BytesIO(data))


def test_extracts_only_public_state(tmp_path):
    archive = tmp_path / "release-state.tar.gz"
    make_archive(archive)
    result = extract_public_state(archive, tmp_path / "out")
    assert (result / "release-active" / "release.json").exists()
    assert set(p.name for p in result.iterdir()) == STATE_DIRS


@pytest.mark.parametrize(
    "bad_path",
    [
        "../escape.json",
        ".runtime/../escape.json",
        ".runtime/private-key.pem",
        "/etc/passwd",
    ],
)
def test_rejects_unsafe_archive_members(tmp_path, bad_path):
    archive = tmp_path / "release-state.tar.gz"
    make_archive(archive, unsafe_name=bad_path)
    with pytest.raises(RuntimeError, match="Unsafe release-state archive member"):
        extract_public_state(archive, tmp_path / "out")


def test_registry_images_must_match_expected_digest_and_repository():
    digest = "sha256:" + "a" * 64
    reference = f"{REGISTRY_ROOT}@{digest}"
    image = {
        "repository": REGISTRY_ROOT,
        "digest": digest,
        "pull_by_digest": reference,
    }
    assert image_reference(image, REGISTRY_ROOT) == reference
    with pytest.raises(RuntimeError):
        image_reference({**image, "repository": "ghcr.io/other/app"}, REGISTRY_ROOT)
    with pytest.raises(RuntimeError):
        image_reference({**image, "pull_by_digest": f"{REGISTRY_ROOT}:latest"}, REGISTRY_ROOT)


def test_environment_keeps_secrets_local_and_images_immutable(tmp_path):
    env_path = tmp_path / ".env"
    refs = {
        "application": REGISTRY_ROOT + "@sha256:" + "a" * 64,
        "audit_reviewer": REGISTRY_ROOT + "-audit-reviewer@sha256:" + "b" * 64,
        "opa": REGISTRY_ROOT + "-opa@sha256:" + "c" * 64,
    }
    create_environment(env_path, refs, "redaction-response-dlp-v5", "review-case", 8001)
    text = env_path.read_text()
    assert "COMPOSE_PROJECT_NAME=review-case" in text
    assert "API_PORT=8001" in text
    assert "REQUIRE_SIGNED_RELEASE=true" in text
    assert "ENABLE_EXTERNAL_SIMULATOR=true" in text
    assert "CONTROL_PLANE_IMAGE=" + refs["application"] in text
    assert "CONTROL_PLANE_API_KEY=" in text
    assert "replace-with-a-random-key" not in text
    with pytest.raises(FileExistsError):
        create_environment(env_path, refs, "redaction-response-dlp-v5", "review-case", 8001)


def test_manifest_checksum_is_checked_before_extraction(tmp_path, monkeypatch):
    def fake_download(_tag, asset, destination):
        destination.write_bytes(b"{}" if asset == "registry-images.json" else b"bad-tar")

    monkeypatch.setattr("tools.submission_bootstrap.fetch_asset", fake_download)
    with pytest.raises(RuntimeError, match="independently pinned checksum"):
        verify_package(tmp_path, "signed-g8", "a" * 64, "0" * 64)


@pytest.mark.parametrize("engine", ["podman", "docker"])
@pytest.mark.parametrize("sovereign_only", [False, True])
def test_deployment_modes(tmp_path, sovereign_only, engine):
    refs = {
        "application": REGISTRY_ROOT + "@sha256:" + "a" * 64,
        "audit_reviewer": REGISTRY_ROOT + "-audit-reviewer@sha256:" + "b" * 64,
        "opa": REGISTRY_ROOT + "-opa@sha256:" + "c" * 64,
    }
    env_path = tmp_path / ".env"
    create_environment(
        env_path, refs, "revision", "review-case", 8001, sovereign_only=sovereign_only
    )
    assert f"ENABLE_EXTERNAL_SIMULATOR={str(not sovereign_only).lower()}" in env_path.read_text()
    command = compose_command(tmp_path, "review-case", sovereign_only=sovereign_only, engine=engine)
    assert command[:2] == [engine, "compose"]
    assert ("egress-test" in command) is (not sovereign_only)
    assert ("--profile" in command) is (not sovereign_only)
    assert str(tmp_path / "deploy/compose.ghcr.yaml") in command


def test_external_route_smoke_check(monkeypatch):
    def fake_open(request, timeout):
        assert request.full_url == "http://127.0.0.1:8001/v1/prompts"
        assert timeout == 30
        assert json.loads(request.data)["destination_id"] == "external-simulator"
        return io.BytesIO(b'{"status":"COMPLETED","model_id":"external-simulator"}')

    monkeypatch.setattr("tools.submission_bootstrap.urllib.request.urlopen", fake_open)
    check_external_route(8001, "test-key")


def test_external_route_rejects_wrong_model(monkeypatch):
    def fake_open(_request, timeout):
        return io.BytesIO(b'{"status":"COMPLETED","model_id":"sovereign-model"}')

    monkeypatch.setattr("tools.submission_bootstrap.urllib.request.urlopen", fake_open)
    with pytest.raises(RuntimeError, match="expected route"):
        check_external_route(8001, "test-key")


@pytest.mark.parametrize("engine", ["podman", "docker"])
def test_image_verification_uses_selected_engine(tmp_path, monkeypatch, engine):
    (tmp_path / "release-active").mkdir()
    (tmp_path / "release-active" / "release.json").write_text(
        json.dumps({"payload": {"detector_digest": "approved"}})
    )
    refs = {"application": "app", "audit_reviewer": "reviewer", "opa": "opa"}
    calls = []

    def fake_run(*args, capture=False):
        calls.append(args)
        if args[1:3] == ("image", "inspect"):
            return json.dumps(
                [{"Config": {"Labels": {"org.opencontainers.image.revision": "rev"}}}]
            )
        if capture:
            return json.dumps({"detector_artifact_digest": "approved"})
        return ""

    monkeypatch.setattr("tools.submission_bootstrap.run", fake_run)
    verify_images(tmp_path, refs, {"commit": "rev"}, engine=engine)
    assert all(args[0] == engine for args in calls)
    assert [args[2] for args in calls if args[1] == "pull"] == list(refs.values())
    verification_runs = [args for args in calls if args[1] == "run"]
    assert len(verification_runs) == 2
    assert all("--network" in args and "none" in args for args in verification_runs)
    assert len([args for args in calls if args[1:3] == ("image", "inspect")]) == 3
