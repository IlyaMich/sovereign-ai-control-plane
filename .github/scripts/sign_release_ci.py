"""Manual GH Actions signer: use protected, non-Git authoritative release state.

The job must be approved, execute only on an isolated release-signer runner,
and never operate on a deployment's live state. This advances the signer's
release ledger, not a running local control plane or audit volume.
"""

from __future__ import annotations

import fcntl
import hashlib
import http.client
import json
import os
import re
import shutil
import sys
import tarfile
import tempfile
from pathlib import Path

from app.detection.provenance import canonical
from app.infrastructure.atomic_files import publish_new_bytes
from app.policy.snapshots import PolicySnapshotStore, build_snapshot
from app.release.approvals import ReleaseStore, make_payload, sign_approval

HEX64 = re.compile(r"^[a-f0-9]{64}$")


def required_path(name: str, *, directory: bool = False) -> Path:
    value = os.environ.get(name, "")
    if not value or not Path(value).is_absolute():
        raise RuntimeError(f"{name} must be a provisioned absolute path")
    p = Path(value).resolve(strict=True)
    if not (p.is_dir() if directory else p.is_file()):
        raise RuntimeError(f"{name} is unavailable")
    return p


def release_does_not_exist(tag: str) -> None:
    repo = os.environ["GITHUB_REPOSITORY"]
    token = os.environ["GH_TOKEN"]
    connection = http.client.HTTPSConnection("api.github.com", timeout=30)
    try:
        connection.request(
            "GET",
            f"/repos/{repo}/releases/tags/{tag}",
            headers={
                "Authorization": "Bearer " + token,
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "sovereign-release-signer",
            },
        )
        status = connection.getresponse().status
        if status == 404:
            return
        if status == 200:
            raise RuntimeError("A GitHub Release already exists for this generation")
        raise RuntimeError("Unexpected GitHub release lookup response")
    finally:
        connection.close()


def copy_public_state(authority: Path, output: Path, candidate: Path) -> None:
    root = output / ".runtime"
    root.mkdir(parents=True)
    for folder in ("policy-active", "policy-archive", "release-archive", "release-trust"):
        source = authority / folder
        for entry in source.rglob("*"):
            if entry.is_symlink():
                raise RuntimeError("Refusing symbolic links in protected release state")
            if (
                folder == "release-trust"
                and entry.is_file()
                and entry.suffix != ".pem"
                and entry.name != ".gitkeep"
            ):
                raise RuntimeError("Unexpected non-public-key file in release trust")
            if (
                folder == "release-archive"
                and entry.is_file()
                and entry.suffix != ".json"
                and entry.name != ".gitkeep"
            ):
                raise RuntimeError("Unexpected file in release archive")
        shutil.copytree(source, root / folder, symlinks=False)
    (root / "release-active").mkdir()
    shutil.copy2(
        authority / "release-active" / "release.json", root / "release-active" / "release.json"
    )
    (root / "release-candidates").mkdir()
    shutil.copy2(candidate, root / "release-candidates" / candidate.name)
    with tarfile.open(output / "release-state.tar.gz", "w:gz") as archive:
        archive.add(root, arcname=".runtime", recursive=True)
    # The uncompressed state is transient: only release-state.tar.gz is distributed.
    shutil.rmtree(root)


def sign_release() -> None:
    authority = required_path("SOVEREIGN_SIGNER_STATE_DIR", directory=True)
    private_key = required_path("SOVEREIGN_RELEASE_PRIVATE_KEY_PATH")
    pinned_key = required_path("SOVEREIGN_RELEASE_PUBLIC_KEY_PATH")
    expected_pin = os.environ.get("EXPECTED_PUBLIC_SHA256", "")
    if not HEX64.fullmatch(expected_pin):
        raise RuntimeError("Set independently trusted RELEASE_SIGNER_PUBLIC_KEY_SHA256")
    if hashlib.sha256(pinned_key.read_bytes()).hexdigest() != expected_pin:
        raise RuntimeError("Release authority key does not match the pinned fingerprint")
    workspace = Path(os.environ["GITHUB_WORKSPACE"]).resolve()
    if authority == workspace or workspace in authority.parents or authority in workspace.parents:
        raise RuntimeError("Signing state must be outside the Git checkout")
    if (
        private_key == pinned_key
        or workspace in private_key.parents
        or authority in private_key.parents
    ):
        raise RuntimeError("Signing key must be outside Git and the release state")
    trust = authority / "release-trust"
    trusted_pub = trust / "release-signing.pub.pem"
    if trusted_pub.read_bytes() != pinned_key.read_bytes():
        raise RuntimeError("Authoritative trust key differs from independent pinned key")
    digest = os.environ["DETECTOR_DIGEST"]
    if not HEX64.fullmatch(digest):
        raise RuntimeError("Invalid verified detector digest")
    package = workspace / "signed-package"
    if package.exists():
        raise RuntimeError("Signed package already exists")

    # Serialize predecessor lookup, N+1 signing, activation, and package snapshot.
    # The release activation code takes its own narrower cross-process lock too.
    with (authority / ".signing.lock").open("a+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        store = ReleaseStore(
            authority / "release-active" / "release.json",
            authority / "release-archive",
            trust,
            PolicySnapshotStore(authority / "policy-active", authority / "policy-archive"),
        )
        predecessor = store.verify_active()
        next_generation = predecessor["payload"]["generation"] + 1
        release_does_not_exist(f"signed-g{next_generation}")
        candidate = authority / "release-candidates" / f"release-g{next_generation}.json"
        if candidate.exists() or candidate.is_symlink():
            raise RuntimeError(
                "Next generation candidate already exists; investigate before signing"
            )
        with tempfile.TemporaryDirectory(prefix="sovereign-release-policy-") as tmp:
            proposed_policy = Path(tmp) / "proposed"
            # Add content-addressed snapshot to signer's protected archive without
            # changing its active policy until release activation validates it.
            proposal = build_snapshot("policies", authority / "policy-archive", proposed_policy)
            approval = sign_approval(
                make_payload(
                    proposal.policy_digest,
                    proposal.policy_revision,
                    digest,
                    next_generation,
                    predecessor["release_id"],
                ),
                private_key,
            )
            publish_new_bytes(candidate, canonical(approval) + b"\n", mode=0o600)
            store.activate(candidate, detector_digest=digest)
            verified = store.verify_active(
                detector_digest=digest, policy_digest=proposal.policy_digest
            )

        package.mkdir(mode=0o700)
        inp = workspace / "release-input"
        for filename in (
            "application-image.tar.gz",
            "reviewer-image.tar.gz",
            "opa-image.tar.gz",
            "detector-manifest.json",
            "image.sha256",
        ):
            shutil.copy2(inp / filename, package / filename)
        manifest = json.loads((package / "detector-manifest.json").read_text())
        if manifest["digest"] != digest:
            raise RuntimeError("Frozen image manifest differs from signed detector")
        shutil.copy2(authority / "release-active" / "release.json", package / "release.json")
        copy_public_state(authority, package, candidate)
        release_id = verified["release_id"]
        (package / "RELEASE.txt").write_text(
            f"Commit: {os.environ['GITHUB_SHA']}\n"
            f"Generation: {next_generation}\nRelease ID: {release_id}\n"
            "Images: application-image.tar.gz, reviewer-image.tar.gz, opa-image.tar.gz\n"
            "Authority: protected signer state (not Git examples)\n"
            "Activation: signer ledger only; no deployment updated\n",
            encoding="utf-8",
        )
        with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as fh:
            fh.write(f"generation={next_generation}\nrelease_id={release_id}\n")


if __name__ == "__main__":
    try:
        sign_release()
    except Exception as exc:
        print("Signing refused: " + type(exc).__name__ + ": " + str(exc), file=sys.stderr)
        raise SystemExit(1) from None
