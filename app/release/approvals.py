"""Offline Ed25519 approval for precise policy + detector release identities.

The public trust root must be provisioned independently of any evidence ZIP.
This is a RELEASE key: it MUST NOT reuse the runtime audit signing key.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from app.detection.provenance import canonical, load_verified
from app.policy.snapshots import PolicySnapshotStore, SnapshotError

RELEASE_DOMAIN = b"sovereign-release-approval-v1\x00"
RELEASE_ID_DOMAIN = b"sovereign-release-id-v1\x00"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
REVISION = re.compile(r"^[a-zA-Z0-9_.-]{1,80}$")


class ReleaseIntegrityError(RuntimeError):
    pass


def _valid_hash(value: object) -> bool:
    return isinstance(value, str) and HEX64.fullmatch(value) is not None


def key_id(key: Ed25519PublicKey) -> str:
    binary = key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(binary).hexdigest()


def new_keypair(private_path: str | Path, public_path: str | Path) -> str:
    """Development keypair; key path must be OUTSIDE repo and protected by OS ACLs."""
    priv, pub = Path(private_path), Path(public_path)
    if priv.exists() or pub.exists():
        raise ReleaseIntegrityError("Refusing to overwrite signing key")
    priv.parent.mkdir(parents=True, exist_ok=True)
    pub.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    fd = os.open(str(priv), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(fd, "wb") as writer:
            writer.write(raw)
    except BaseException:
        priv.unlink(missing_ok=True)
        raise
    pub.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    return key_id(key.public_key())


def make_payload(
    policy_digest: str,
    policy_revision: str,
    detector_digest: str,
    generation: int,
    previous_release_id: str | None,
) -> dict:
    payload = {
        "schema_version": 1,
        "purpose": "ACTIVATE",
        "policy_digest": policy_digest,
        "policy_revision": policy_revision,
        "detector_digest": detector_digest,
        "generation": generation,
        "previous_release_id": previous_release_id,
    }
    validate_payload(payload)
    return payload


def validate_payload(payload: object) -> None:
    required = {
        "schema_version",
        "purpose",
        "policy_digest",
        "policy_revision",
        "detector_digest",
        "generation",
        "previous_release_id",
    }
    if (
        not isinstance(payload, dict)
        or set(payload) != required
        or type(payload["schema_version"]) is not int
        or payload["schema_version"] != 1
        or payload["purpose"] != "ACTIVATE"
        or not _valid_hash(payload["policy_digest"])
        or not _valid_hash(payload["detector_digest"])
        or not isinstance(payload["policy_revision"], str)
        or not REVISION.fullmatch(payload["policy_revision"])
        or type(payload["generation"]) is not int
        or not (1 <= payload["generation"] <= 2**63 - 1)
        or (
            payload["previous_release_id"] is not None
            and not _valid_hash(payload["previous_release_id"])
        )
    ):
        raise ReleaseIntegrityError("Malformed release payload")
    if (payload["generation"] == 1) != (payload["previous_release_id"] is None):
        raise ReleaseIntegrityError("Genesis and successor releases must have correct predecessor")


def release_id(payload: dict) -> str:
    validate_payload(payload)
    return hashlib.sha256(RELEASE_ID_DOMAIN + canonical(payload)).hexdigest()


def sign_approval(payload: dict, private_key_path: str | Path) -> dict:
    try:
        private = serialization.load_pem_private_key(
            Path(private_key_path).read_bytes(), password=None
        )
    except (OSError, ValueError, TypeError) as exc:
        raise ReleaseIntegrityError("Release signing key unavailable or unreadable") from exc
    if not isinstance(private, Ed25519PrivateKey):
        raise ReleaseIntegrityError("Release signer must be Ed25519")
    sig = private.sign(RELEASE_DOMAIN + canonical(payload))
    return {
        "payload": payload,
        "release_id": release_id(payload),
        "signer_key_id": key_id(private.public_key()),
        "signature": base64.b64encode(sig).decode("ascii"),
    }


def _parse_approval(document: object) -> dict:
    if not isinstance(document, dict) or set(document) != {
        "payload",
        "release_id",
        "signer_key_id",
        "signature",
    }:
        raise ReleaseIntegrityError("Unexpected approval fields")
    payload = document["payload"]
    validate_payload(payload)
    if document["release_id"] != release_id(payload) or not _valid_hash(document["signer_key_id"]):
        raise ReleaseIntegrityError("Signed release identity mismatch")
    try:
        signature = base64.b64decode(document["signature"], validate=True)
    except (ValueError, TypeError) as exc:
        raise ReleaseIntegrityError("Malformed release signature") from exc
    if len(signature) != 64 or base64.b64encode(signature).decode("ascii") != document["signature"]:
        raise ReleaseIntegrityError("Noncanonical release signature")
    return document


def verify_approval(document: dict, trust_directory: str | Path) -> dict:
    document = _parse_approval(document)
    trust = Path(trust_directory)
    if not trust.is_dir() or trust.is_symlink():
        raise ReleaseIntegrityError("Release public-key trust directory missing")
    matches = 0
    for file in trust.glob("*.pem"):
        if file.is_symlink() or not file.is_file():
            raise ReleaseIntegrityError("Unsafe release trust material")
        try:
            public = serialization.load_pem_public_key(file.read_bytes())
        except (ValueError, OSError, TypeError) as exc:
            raise ReleaseIntegrityError("Invalid trusted release public key") from exc
        if not isinstance(public, Ed25519PublicKey):
            raise ReleaseIntegrityError("Only Ed25519 release public keys supported")
        if key_id(public) != document["signer_key_id"]:
            continue
        try:
            public.verify(
                base64.b64decode(document["signature"]),
                RELEASE_DOMAIN + canonical(document["payload"]),
            )
        except InvalidSignature as exc:
            raise ReleaseIntegrityError("Release signature failed verification") from exc
        matches += 1
    if matches != 1:
        raise ReleaseIntegrityError("Release signer not in independently provisioned trust root")
    return document


def load_approval(path: str | Path, trust_directory: str | Path | None = None) -> dict:
    try:
        path = Path(path)
        if path.is_symlink() or path.stat().st_size > 16384:
            raise ReleaseIntegrityError("Unsafe release envelope file")
        doc = json.loads(path.read_bytes())
    except (OSError, ValueError, TypeError) as exc:
        raise ReleaseIntegrityError("Missing or malformed release envelope") from exc
    if trust_directory is None:
        return _parse_approval(doc)  # integrity only; NOT signer authentication
    return verify_approval(doc, trust_directory)


def summary(envelope: dict) -> dict:
    p = envelope["payload"]
    return {
        "release_id": envelope["release_id"],
        "generation": p["generation"],
        "policy_digest": p["policy_digest"],
        "detector_digest": p["detector_digest"],
        "signer_key_id": envelope["signer_key_id"],
    }


def _atomic_replace(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=".release-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(raw)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temp, path)
    finally:
        Path(temp).unlink(missing_ok=True)


@dataclass
class ReleaseStore:
    active: Path
    archive: Path
    trust: Path
    policy_store: PolicySnapshotStore
    detector_manifest: Path | None = None

    def find(self, identity: str, *, authenticate: bool = True) -> dict:
        if not _valid_hash(identity):
            raise ReleaseIntegrityError("Invalid release identity")
        return_doc = load_approval(
            self.archive / (identity + ".json"), self.trust if authenticate else None
        )
        if return_doc["release_id"] != identity:
            raise ReleaseIntegrityError("Release archive name does not match contents")
        return return_doc

    def verify_active(
        self, *, detector_digest: str | None = None, policy_digest: str | None = None
    ) -> dict:
        approval = load_approval(self.active, self.trust)
        archived = self.find(approval["release_id"])
        if archived != approval:
            raise ReleaseIntegrityError("Active release differs from immutable archive")
        info = self.policy_store.verify_active()
        payload = approval["payload"]
        if (
            payload["policy_digest"] != info.policy_digest
            or payload["policy_revision"] != info.policy_revision
        ):
            raise ReleaseIntegrityError("Signed release does not approve active Rego snapshot")
        if policy_digest is not None and policy_digest != payload["policy_digest"]:
            raise ReleaseIntegrityError("Evaluated policy is not approved by release")
        if self.detector_manifest is not None:
            doc = load_verified(self.detector_manifest)
            if doc["digest"] != payload["detector_digest"]:
                raise ReleaseIntegrityError("Installed detector identity is not approved")
        if detector_digest is not None and detector_digest != payload["detector_digest"]:
            raise ReleaseIntegrityError("Classified detector identity is not approved")
        return approval

    def activate(self, candidate: Path | str, *, detector_digest: str | None = None) -> dict:
        """Offline operator operation; cannot be initiated by an API caller."""
        proposed = load_approval(candidate, self.trust)
        policy = proposed["payload"]
        location = self.policy_store.find(policy["policy_digest"])
        snapshot = location
        from app.policy.snapshots import verify_snapshot

        if verify_snapshot(snapshot).policy_revision != policy["policy_revision"]:
            raise ReleaseIntegrityError("Approved policy revision mismatch")
        if detector_digest is not None and detector_digest != policy["detector_digest"]:
            raise ReleaseIntegrityError("Candidate does not approve chosen detector")
        if self.active.exists():
            prior = load_approval(self.active, self.trust)
            if (
                policy["previous_release_id"] != prior["release_id"]
                or policy["generation"] != prior["payload"]["generation"] + 1
            ):
                raise ReleaseIntegrityError(
                    "Rollback/reorder rejected: sign new successor generation"
                )
        elif policy["generation"] != 1 or policy["previous_release_id"] is not None:
            raise ReleaseIntegrityError("First release must be generation 1")
        archive_item = self.archive / (proposed["release_id"] + ".json")
        self.archive.mkdir(parents=True, exist_ok=True)
        if self.archive.is_symlink():
            raise ReleaseIntegrityError("Release archive must not be a symlink")
        raw = canonical(proposed) + b"\n"
        if archive_item.is_symlink():
            raise ReleaseIntegrityError("Release archive entry cannot be a symlink")
        if archive_item.exists():
            if archive_item.read_bytes() != raw:
                raise ReleaseIntegrityError("Immutable release archive collision")
        else:
            # Do not overwrite previously archived release identities.
            fd, tmp = tempfile.mkstemp(prefix=".approval-", dir=self.archive)
            try:
                with os.fdopen(fd, "wb") as f:
                    f.write(raw)
                    f.flush()
                    os.fsync(f.fileno())
                os.link(tmp, archive_item)
            except FileExistsError:
                if archive_item.read_bytes() != raw:
                    raise ReleaseIntegrityError("Concurrent conflicting release")
            finally:
                Path(tmp).unlink(missing_ok=True)
        # The active policy and release metadata are two filesystem entries.
        # During a crash/race the service fails closed on a mismatch.
        # Avoid rewriting an identical mounted policy (especially on Windows).
        active_policy = self.policy_store.active
        if active_policy.is_symlink():
            raise ReleaseIntegrityError("Active policy directory cannot be a symlink")
        from app.policy.snapshots import verify_snapshot

        current_matches = False
        if active_policy.exists():
            try:
                current_matches = (
                    verify_snapshot(active_policy, policy["policy_digest"]).policy_digest
                    == policy["policy_digest"]
                )
            except (SnapshotError, OSError):
                current_matches = False
        if not current_matches:
            if active_policy.exists():
                shutil.rmtree(active_policy)
            shutil.copytree(location, active_policy)
        _atomic_replace(self.active, raw)
        return proposed
