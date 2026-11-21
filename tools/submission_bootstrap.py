"""Install an independently pinned signed GHCR release on a fresh Podman host.

Standard library only: no source build, private signer, or host pip dependencies.
This is deliberately a fresh-install operation, not an upgrade/migration tool.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess  # nosec B404 - fixed podman executable, argument-array invocation
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import NoReturn

REPOSITORY = "IlyaMich/sovereign-ai-control-plane"
REGISTRY_ROOT = "ghcr.io/ilyamich/sovereign-ai-control-plane"
HEX64 = re.compile(r"[a-f0-9]{64}", re.ASCII)
TAG = re.compile(r"signed-g[1-9][0-9]*", re.ASCII)
PROJECT = re.compile(r"[a-z][a-z0-9_-]{2,48}", re.ASCII)
MAX_DOWNLOAD_BYTES = {
    "registry-images.json": 64 * 1024,
    "release-state.tar.gz": 128 * 1024 * 1024,
}
MAX_EXTRACTED_BYTES = 256 * 1024 * 1024
STATE_DIRS = {
    "policy-active",
    "policy-archive",
    "release-active",
    "release-archive",
    "release-candidates",
    "release-trust",
}


def fail(message: str) -> NoReturn:
    raise RuntimeError(message)


def run(*arguments: str, capture: bool = False) -> str:
    print("+ " + " ".join(arguments[:3]) + (" ..." if len(arguments) > 3 else ""), flush=True)
    result = subprocess.run(  # nosec B603 - no shell; registry refs and project values validated
        arguments,
        capture_output=capture,
        text=True,
        check=False,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode:
        detail = (result.stderr or result.stdout or "").strip() if capture else ""
        fail(f"Command failed (exit {result.returncode}): {arguments[0]} {arguments[1]} {detail}")
    return result.stdout.strip() if capture else ""


def fetch_asset(tag: str, asset: str, output: Path) -> None:
    url = f"https://github.com/{REPOSITORY}/releases/download/{tag}/{asset}"
    request = urllib.request.Request(url, headers={"User-Agent": "sovereign-submission-bootstrap"})
    size = 0
    try:
        # Fixed HTTPS GitHub Releases URL; the signed tag is strictly validated.
        response = urllib.request.urlopen(request, timeout=90)  # nosec B310
        with response, output.open("wb") as dest:
            while chunk := response.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_DOWNLOAD_BYTES[asset]:
                    fail(f"Release asset exceeds size cap: {asset}")
                dest.write(chunk)
    except urllib.error.HTTPError as exc:
        fail(
            f"Cannot download {asset} from {tag} (HTTP {exc.code}); "
            "check that the release is public and complete"
        )
    if not size:
        fail(f"Empty release asset: {asset}")


def extract_public_state(archive_path: Path, destination: Path) -> Path:
    destination.mkdir(parents=True, exist_ok=False)
    with tarfile.open(archive_path, "r:gz") as archive:
        members = archive.getmembers()
        total = 0
        for member in members:
            p = Path(member.name)
            parts = p.parts
            if (
                not parts
                or parts[0] != ".runtime"
                or any(part in (".", "..") for part in parts)
                or p.is_absolute()
                or "\\" in member.name
                or (len(parts) > 1 and parts[1] not in STATE_DIRS)
                or not (member.isfile() or member.isdir())
            ):
                fail(f"Unsafe release-state archive member: {member.name}")
            total += member.size
            if total > MAX_EXTRACTED_BYTES:
                fail("Release-state archive exceeds extracted-size cap")
        archive.extractall(destination, members=members, filter="data")
    root = destination / ".runtime"
    for name in STATE_DIRS:
        if not (root / name).is_dir():
            fail(f"Signed package missing runtime directory: {name}")
    if not (root / "release-active" / "release.json").is_file():
        fail("Signed package missing active release")
    return root


def image_reference(entry: object, expected_repository: str) -> str:
    if not isinstance(entry, dict):
        fail("Invalid image entry in registry-images.json")
    digest = entry.get("digest")
    expected = f"{expected_repository}@{digest}"
    if (
        entry.get("repository") != expected_repository
        or not isinstance(digest, str)
        or not digest.startswith("sha256:")
        or not HEX64.fullmatch(digest.removeprefix("sha256:"))
        or entry.get("pull_by_digest") != expected
    ):
        fail(f"Unexpected or unpinned image reference for {expected_repository}")
    return expected


def verify_package(
    stage: Path,
    tag: str,
    trusted_key_sha256: str,
    registry_sha256: str,
) -> tuple[Path, dict[str, str], dict]:
    images_file = stage / "registry-images.json"
    archive = stage / "release-state.tar.gz"
    fetch_asset(tag, "registry-images.json", images_file)
    fetch_asset(tag, "release-state.tar.gz", archive)
    actual_registry_sha = hashlib.sha256(images_file.read_bytes()).hexdigest()
    if actual_registry_sha != registry_sha256:
        fail("registry-images.json does not match the independently pinned checksum")
    state = extract_public_state(archive, stage / "unpacked")
    public_key = state / "release-trust" / "release-signing.pub.pem"
    if not public_key.is_file():
        fail("Release public verification key is missing")
    if hashlib.sha256(public_key.read_bytes()).hexdigest() != trusted_key_sha256:
        fail("Release signing public key differs from independently trusted fingerprint")

    images = json.loads(images_file.read_text(encoding="utf-8"))
    approval = json.loads((state / "release-active" / "release.json").read_text(encoding="utf-8"))
    if not isinstance(images, dict) or not isinstance(approval, dict):
        fail("Invalid release metadata")
    if (
        images.get("release_id") != approval.get("release_id")
        or images.get("generation") != approval.get("payload", {}).get("generation")
        or tag != f"signed-g{images.get('generation')}"
        or not isinstance(images.get("commit"), str)
        or not re.fullmatch(r"[a-f0-9]{40}", images["commit"])
    ):
        fail("Release tag, signed approval, and image metadata disagree")
    refs = {
        "application": image_reference(images.get("application"), REGISTRY_ROOT),
        "audit_reviewer": image_reference(
            images.get("audit_reviewer"), REGISTRY_ROOT + "-audit-reviewer"
        ),
        "opa": image_reference(images.get("opa"), REGISTRY_ROOT + "-opa"),
    }
    return state, refs, images


def make_public_state_readable(state: Path) -> None:
    """Allow the non-root reviewer container to read public approval artifacts."""
    for entry in [state, *state.rglob("*")]:
        if entry.is_symlink():
            fail("Refusing symlink in extracted public state")
        entry.chmod(0o755 if entry.is_dir() else 0o644)


def podman_verify(state: Path, refs: dict[str, str], images: dict) -> None:
    for ref in refs.values():
        run("podman", "pull", ref)
    # A separate pinned reviewer image verifies signatures and archived policy
    # without installing any Python dependencies onto the host.
    mount = f"type=bind,source={state.resolve()},target=/release-state,readonly"
    run(
        "podman",
        "run",
        "--rm",
        "--mount",
        mount,
        "--entrypoint",
        "python",
        refs["audit_reviewer"],
        "-m",
        "tools.verify_release",
        "--trust",
        "/release-state/release-trust",
        "--active",
        "/release-state/release-active/release.json",
        "--archive",
        "/release-state/release-archive",
        "--policy-active",
        "/release-state/policy-active",
        "--policy-archive",
        "/release-state/policy-archive",
    )
    verified = json.loads(
        run(
            "podman",
            "run",
            "--rm",
            "--entrypoint",
            "python",
            refs["application"],
            "-m",
            "tools.verify_detector_manifest",
            "--manifest",
            "/service/detector-active/manifest.json",
            capture=True,
        )
    )
    release = json.loads((state / "release-active" / "release.json").read_text(encoding="utf-8"))
    if verified.get("detector_artifact_digest") != release["payload"]["detector_digest"]:
        fail("Installed detector manifest does not match the signed release approval")
    for ref in refs.values():
        inspection = json.loads(run("podman", "image", "inspect", ref, capture=True))
        if not inspection or not isinstance(inspection, list):
            fail(f"Podman returned no image details for {ref}")
        labels = (inspection[0].get("Config") or {}).get("Labels") or {}
        if labels.get("org.opencontainers.image.revision") != images["commit"]:
            fail(f"Image source revision differs from release commit for {ref}")


def create_environment(
    path: Path,
    refs: dict[str, str],
    revision: str,
    project: str,
    api_port: int,
) -> None:
    lines = [
        f"COMPOSE_PROJECT_NAME={project}",
        f"CONTROL_PLANE_API_KEY={secrets.token_hex(32)}",
        "API_HOST=127.0.0.1",
        f"API_PORT={api_port}",
        "ENABLE_EXTERNAL_SIMULATOR=false",
        "OUTPUT_MASKING_ENABLED=false",
        "REQUIRE_SIGNED_RELEASE=true",
        f"EXPECTED_POLICY_REVISION={revision}",
        f"CONTROL_PLANE_IMAGE={refs['application']}",
        f"AUDIT_REVIEWER_IMAGE={refs['audit_reviewer']}",
        f"OPA_IMAGE={refs['opa']}",
    ]
    handle = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
        stream.write("\n".join(lines) + "\n")


def check_readiness(api_port: int, key: str) -> None:
    url = f"http://127.0.0.1:{api_port}/health/ready"
    deadline = time.monotonic() + 90
    reason = ""
    while time.monotonic() < deadline:
        try:
            request = urllib.request.Request(url, headers={"X-API-Key": key})
            # Fixed loopback-only health endpoint; never a user-supplied URL.
            response = urllib.request.urlopen(request, timeout=5)  # nosec B310
            with response:
                if response.status == 200:
                    print(f"READY: {url}", flush=True)
                    return
        except (OSError, urllib.error.URLError) as exc:
            reason = type(exc).__name__
        time.sleep(2)
    fail(
        f"Application did not become ready ({reason}). "
        "Inspect podman compose logs; preserve .runtime and .env"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-tag", required=True, help="e.g. signed-g8")
    parser.add_argument(
        "--trusted-key-sha256", required=True, help="Pinned SHA-256 of release-signing.pub.pem"
    )
    parser.add_argument(
        "--registry-sha256", required=True, help="Pinned SHA-256 of registry-images.json"
    )
    parser.add_argument("--project", default="sovereign-review", help="Isolated Compose project")
    parser.add_argument("--api-port", default=8000, type=int)
    parser.add_argument("--root", default=".", help="Repository checkout root")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    if not TAG.fullmatch(args.release_tag):
        fail("Release tag must have the form signed-gN")
    for name, value in (
        ("trusted-key-sha256", args.trusted_key_sha256),
        ("registry-sha256", args.registry_sha256),
    ):
        if not HEX64.fullmatch(value):
            fail(f"Invalid {name}: expected 64 lowercase SHA-256 hex characters")
    if not PROJECT.fullmatch(args.project):
        fail(
            "Project name must start with a lowercase letter and use only "
            "lowercase letters, digits, _ or -"
        )
    if not 1 <= args.api_port <= 65535:
        fail("API port must be within 1..65535")
    for filename in ("deploy/compose.yaml", "deploy/compose.ghcr.yaml"):
        if not (root / filename).is_file():
            fail(f"Repository root is missing {filename}")
    if any(p.exists() or p.is_symlink() for p in (root / ".runtime", root / ".env")):
        fail(
            "Fresh-install only: .runtime or .env already exists. "
            "Never overwrite existing signed state"
        )
    if not shutil.which("podman"):
        fail("Install Podman and its Compose provider before running this script")
    run("podman", "info", capture=True)
    run("podman", "compose", "version", capture=True)
    existing_volumes = run(
        "podman", "volume", "ls", "--format", "{{.Name}}", capture=True
    ).splitlines()
    if f"{args.project}_audit-data" in existing_volumes:
        fail(
            "The selected Compose project already has an audit-data volume; "
            "choose a fresh project name rather than reusing existing audit history"
        )

    with tempfile.TemporaryDirectory(prefix=".submission-bootstrap-", dir=root) as folder:
        state, refs, images = verify_package(
            Path(folder), args.release_tag, args.trusted_key_sha256, args.registry_sha256
        )
        make_public_state_readable(state)
        Path(folder).chmod(0o755)
        (Path(folder) / "unpacked").chmod(0o755)
        podman_verify(state, refs, images)
        release_file = state / "release-active" / "release.json"
        release = json.loads(release_file.read_text(encoding="utf-8"))
        revision = release["payload"]["policy_revision"]
        if not isinstance(revision, str) or not re.fullmatch(r"[a-zA-Z0-9._-]{1,128}", revision):
            fail("Unsupported policy revision in approval")
        # Publish only after all preflights have succeeded. No private signer is ever created.
        if any(p.exists() or p.is_symlink() for p in (root / ".runtime", root / ".env")):
            fail("Deployment state appeared during bootstrap; refusing to overwrite it")
        shutil.move(str(state), str(root / ".runtime"))
        create_environment(root / ".env", refs, revision, args.project, args.api_port)

    compose = [
        "podman",
        "compose",
        "-p",
        args.project,
        "-f",
        str(root / "deploy/compose.yaml"),
        "-f",
        str(root / "deploy/compose.ghcr.yaml"),
        "--env-file",
        str(root / ".env"),
    ]
    run(*compose, "config", "--quiet")
    run(*compose, "up", "--no-build", "--force-recreate", "-d")
    env = dict(
        line.split("=", 1)
        for line in (root / ".env").read_text(encoding="utf-8").splitlines()
        if "=" in line and not line.startswith("#")
    )
    check_readiness(args.api_port, env["CONTROL_PLANE_API_KEY"])
    print(f"Installation complete: signed release {args.release_tag}, project {args.project}")
    print(f"API docs: http://127.0.0.1:{args.api_port}/docs")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, OSError, ValueError, json.JSONDecodeError, tarfile.TarError) as exc:
        print(f"BOOTSTRAP REFUSED: {exc}", file=sys.stderr)
        sys.exit(1)
