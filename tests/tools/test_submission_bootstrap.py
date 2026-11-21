"""Offline tests for the fresh-reviewer release bootstrap."""

import hashlib
import io
import json
import tarfile

import pytest

from tools.submission_bootstrap import (
    REGISTRY_ROOT,
    STATE_DIRS,
    create_environment,
    extract_public_state,
    image_reference,
    load_lock,
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
    create_environment(env_path, refs, "review-case", 8001)
    text = env_path.read_text()
    assert "COMPOSE_PROJECT_NAME=review-case" in text
    assert "API_PORT=8001" in text
    assert "REQUIRE_SIGNED_RELEASE=true" in text
    assert "EXPECTED_POLICY_REVISION" not in text
    assert "CONTROL_PLANE_IMAGE=" + refs["application"] in text
    assert "CONTROL_PLANE_API_KEY=" in text
    assert "replace-with-a-random-key" not in text
    with pytest.raises(FileExistsError):
        create_environment(env_path, refs, "review-case", 8001)


def example_lock():
    return {
        "release_tag": "signed-g8",
        "release_id": "d" * 64,
        "trusted_key_sha256": "e" * 64,
        "images": {
            "application": REGISTRY_ROOT + "@sha256:" + "a" * 64,
            "audit_reviewer": REGISTRY_ROOT + "-audit-reviewer@sha256:" + "b" * 64,
            "opa": REGISTRY_ROOT + "-opa@sha256:" + "c" * 64,
        },
    }


def test_load_lock_requires_exact_immutable_image_references(tmp_path):
    lock = example_lock()
    path = tmp_path / "lock.json"
    path.write_text(json.dumps(lock))
    assert load_lock(path) == lock
    for broken in (
        {**lock, "images": {**lock["images"], "opa": "ghcr.io/other@sha256:" + "c" * 64}},
        {**lock, "images": {**lock["images"], "opa": REGISTRY_ROOT + "-opa:latest"}},
        {**lock, "release_id": "not-a-digest"},
        {**lock, "registry_sha256": "f" * 64},
    ):
        path.write_text(json.dumps(broken))
        with pytest.raises(RuntimeError):
            load_lock(path)


def test_published_image_digest_mismatch_rejected(tmp_path, monkeypatch):
    lock = example_lock()
    key = b"trusted-key"
    lock["trusted_key_sha256"] = hashlib.sha256(key).hexdigest()
    state = tmp_path / "state"
    (state / "release-trust").mkdir(parents=True)
    (state / "release-active").mkdir()
    (state / "release-trust" / "release-signing.pub.pem").write_bytes(key)
    (state / "release-active" / "release.json").write_text(
        json.dumps({"release_id": lock["release_id"], "payload": {"generation": 8}})
    )
    images = {"release_id": lock["release_id"], "generation": 8, "commit": "f" * 40}
    for name, reference in lock["images"].items():
        repository, digest = reference.split("@")
        images[name] = {
            "repository": repository,
            "digest": digest,
            "pull_by_digest": reference,
        }
    images["opa"]["digest"] = "sha256:" + "1" * 64
    images["opa"]["pull_by_digest"] = images["opa"]["repository"] + "@" + images["opa"]["digest"]

    def fake_download(_tag, asset, destination):
        destination.write_bytes(
            json.dumps(images).encode() if asset == "registry-images.json" else b"stub"
        )

    monkeypatch.setattr("tools.submission_bootstrap.fetch_asset", fake_download)
    monkeypatch.setattr("tools.submission_bootstrap.extract_public_state", lambda *_: state)
    with pytest.raises(RuntimeError, match="do not match trusted submission lock"):
        verify_package(tmp_path, lock)

    images["opa"]["digest"] = lock["images"]["opa"].split("@")[1]
    images["opa"]["pull_by_digest"] = lock["images"]["opa"]
    assert verify_package(tmp_path, lock)[1] == lock["images"]

