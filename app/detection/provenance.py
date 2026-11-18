"""Content-addressed detector provenance without retaining private prompt text.

The image-build manifest covers model *file bytes*, selected local classifier code
and installed dependency versions. It does not attest the host or entire image.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

DOMAIN = b"sovereign-detector-manifest-v1\0"
SCHEMA = 1
SOURCE_PATHS = (
    "app/detection/aggregation.py",
    "app/detection/presidio_detector.py",
    "app/detection/provenance.py",
    "app/domain/contracts.py",
)
PACKAGES = (
    "presidio-analyzer",
    "spacy",
    "en-core-web-sm",
    "tldextract",
    "thinc",
    "numpy",
    "srsly",
    "spacy-legacy",
    "spacy-loggers",
)


class DetectorIntegrityError(RuntimeError):
    """No classification may be trusted if its provenance cannot be verified."""


def canonical(data: Any) -> bytes:
    return json.dumps(
        data, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_payload(payload: dict) -> str:
    return sha256(DOMAIN + canonical(payload))


def _regular_file(path: Path) -> bool:
    return path.is_file() and not path.is_symlink()


def live_payload(root: Path | str = "/service") -> dict:
    """Collect bytes from the installed package, not from an editable source model."""
    root = Path(root)
    spec = importlib.util.find_spec("en_core_web_sm")
    if spec is None or not spec.origin:
        raise DetectorIntegrityError("Installed spaCy model package unavailable")
    model_root = Path(spec.origin).resolve().parent
    items = []
    for file in sorted(model_root.rglob("*")):
        if "__pycache__" in file.parts or file.suffix in {".pyc", ".pyo"}:
            continue
        if file.is_symlink():
            raise DetectorIntegrityError("Symlink inside spaCy model artifacts")
        if not _regular_file(file):
            continue
        rel = file.relative_to(model_root).as_posix()
        raw = file.read_bytes()
        items.append({"path": "model/" + rel, "size": len(raw), "sha256": sha256(raw)})
    if not items:
        raise DetectorIntegrityError("Empty spaCy model artifact set")
    for rel in SOURCE_PATHS:
        file = root / rel
        if not _regular_file(file):
            raise DetectorIntegrityError("Detector source file missing or linked: " + rel)
        raw = file.read_bytes()
        items.append({"path": "source/" + rel, "size": len(raw), "sha256": sha256(raw)})
    versions = {}
    for package in PACKAGES:
        try:
            versions[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError as exc:
            raise DetectorIntegrityError(
                "Required detection dependency missing: " + package
            ) from exc
    from app.detection.presidio_detector import MODEL_NAME, MODEL_VERSION, VERSION

    if versions["en-core-web-sm"] != MODEL_VERSION:
        raise DetectorIntegrityError("Installed spaCy model has wrong version")
    return {
        "schema_version": SCHEMA,
        "detector_version": VERSION,
        "model": {"name": MODEL_NAME, "version": MODEL_VERSION},
        "python": f"{sys.version_info.major}.{sys.version_info.minor}",
        "dependency_versions": versions,
        "files": sorted(items, key=lambda x: x["path"]),
    }


def create_manifest(root: Path | str = "/service") -> dict:
    payload = live_payload(root)
    return {**payload, "digest": digest_payload(payload)}


def verify_manifest(document: dict) -> str:
    """Verify an untrusted archived manifest without installed spaCy packages."""
    if not isinstance(document, dict) or set(document) != {
        "schema_version",
        "detector_version",
        "model",
        "python",
        "dependency_versions",
        "files",
        "digest",
    }:
        raise DetectorIntegrityError("Malformed detector manifest")
    if document["schema_version"] != SCHEMA:
        raise DetectorIntegrityError("Unsupported detector manifest schema")
    files = document["files"]
    if not isinstance(files, list) or not files or len(files) > 20000:
        raise DetectorIntegrityError("Invalid detector artifact list")
    previous = ""
    for item in files:
        if (
            not isinstance(item, dict)
            or set(item) != {"path", "size", "sha256"}
            or not isinstance(item["path"], str)
            or not item["path"].startswith(("model/", "source/"))
            or ".." in Path(item["path"]).parts
            or item["path"] <= previous
            or type(item["size"]) is not int
            or item["size"] < 0
            or not isinstance(item["sha256"], str)
            or len(item["sha256"]) != 64
        ):
            raise DetectorIntegrityError("Invalid detector artifact entry")
        try:
            bytes.fromhex(item["sha256"])
        except ValueError as exc:
            raise DetectorIntegrityError("Invalid artifact SHA-256") from exc
        previous = item["path"]
    digest = document["digest"]
    if not isinstance(digest, str) or len(digest) != 64:
        raise DetectorIntegrityError("Detector manifest digest missing")
    payload = {k: v for k, v in document.items() if k != "digest"}
    try:
        expected = digest_payload(payload)
    except (ValueError, TypeError) as exc:
        raise DetectorIntegrityError("Detector manifest is not canonicalizable") from exc
    if digest != expected:
        raise DetectorIntegrityError("Detector manifest contents do not match digest")
    return digest


def load_verified(
    path: Path | str, *, verify_live: bool = False, root: Path | str = "/service"
) -> dict:
    try:
        raw = Path(path).read_bytes()
        obj = json.loads(raw)
    except (OSError, ValueError) as exc:
        raise DetectorIntegrityError("Detector manifest unreadable") from exc
    verify_manifest(obj)
    if verify_live and obj != create_manifest(root):
        raise DetectorIntegrityError("Installed detector artifacts differ from build manifest")
    return obj


def write_build_manifest(path: Path | str, root: Path | str = "/service") -> dict:
    dest = Path(path)
    data = create_manifest(root)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(canonical(data) + b"\n")
    return data


def archive_manifest(manifest: dict, archive_root: Path | str) -> Path:
    """Persist a verified manifest before serving requests. Never overwrite history."""
    digest = verify_manifest(manifest)
    root = Path(archive_root)
    root.mkdir(parents=True, exist_ok=True)
    dest = root / (digest + ".json")
    data = canonical(manifest) + b"\n"
    if dest.is_symlink():
        raise DetectorIntegrityError("Detector archive must not be a symbolic link")
    if dest.exists():
        if dest.read_bytes() != data:
            raise DetectorIntegrityError("Archived detector manifest was modified")
        return dest
    fd, name = tempfile.mkstemp(prefix=".detector-", dir=root)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        # Atomic, non-replacing link: concurrent startups cannot overwrite history.
        try:
            os.link(name, dest)
        except FileExistsError:
            if dest.read_bytes() != data:
                raise DetectorIntegrityError("Detector archive race with different bytes")
        # Ensure directory entry is durable before a signed decision refers to it.
        if hasattr(os, "O_DIRECTORY"):
            directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        return dest
    finally:
        if os.path.exists(name):
            os.unlink(name)


def find_archived(archive_root: Path | str, digest: str) -> dict:
    if not isinstance(digest, str) or len(digest) != 64:
        raise DetectorIntegrityError("Invalid detector archive reference")
    try:
        bytes.fromhex(digest)
    except ValueError as exc:
        raise DetectorIntegrityError("Invalid detector archive digest") from exc
    manifest = load_verified(Path(archive_root) / (digest + ".json"))
    if manifest["digest"] != digest:
        raise DetectorIntegrityError("Detector archive reference mismatch")
    return manifest
