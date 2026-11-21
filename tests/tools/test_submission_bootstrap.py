"""Offline tests for the fresh-reviewer release bootstrap."""

import io
import tarfile

import pytest

from tools.submission_bootstrap import (
    REGISTRY_ROOT,
    STATE_DIRS,
    create_environment,
    extract_public_state,
    image_reference,
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
        entry = tarfile.TarInfo(
            unsafe_name or ".runtime/release-active/release.json"
        )
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
