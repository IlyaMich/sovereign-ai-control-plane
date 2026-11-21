"""Read-only operator verification of signed host state and optional runtime/evidence.

Checks active policy and release by default. Detector, audit and live readiness
are explicit options because the model is installed inside the container and
the audit SQLite volume is not normally accessible from a Windows host.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

from app.audit.verify import VerificationError, verify_database
from app.detection.provenance import DetectorIntegrityError, load_verified
from app.policy.snapshots import PolicySnapshotStore, SnapshotError
from app.release.approvals import ReleaseIntegrityError, ReleaseStore, summary
from tools.operator_state import state_path


def check_runtime(env_file: Path) -> dict:
    """Check the localhost API without printing or sending the API key elsewhere."""
    try:
        env = {}
        for line in env_file.read_text(encoding="utf-8").splitlines():
            if line.strip() and not line.lstrip().startswith("#") and "=" in line:
                name, value = line.split("=", 1)
                env[name.strip()] = value.strip()
        key = env["CONTROL_PLANE_API_KEY"]
        port = int(env.get("API_PORT", "8000"))
    except (KeyError, OSError, UnicodeError, ValueError) as exc:
        raise RuntimeError("Cannot read API key/port from local .env") from exc
    if not key or not (1 <= port <= 65535):
        raise RuntimeError("Invalid API key or port in local .env")
    # Never send a credential to an operator-supplied remote URL.
    url = f"http://127.0.0.1:{port}/health/ready"
    request = urllib.request.Request(url, headers={"X-API-Key": key})
    with urllib.request.urlopen(request, timeout=5) as response:  # nosec B310
        if response.status != 200:
            raise RuntimeError("API readiness failed")
    return {"status": "VERIFIED", "url": url}


def verify_installation(args: argparse.Namespace) -> dict:
    policy_store = PolicySnapshotStore(args.policy_active, args.policy_archive)
    policy = policy_store.verify_active()
    store = ReleaseStore(
        active=Path(args.release_active),
        archive=Path(args.release_archive),
        trust=Path(args.release_trust),
        policy_store=policy_store,
        detector_manifest=Path(args.detector_manifest) if args.detector_manifest else None,
    )
    approval = store.verify_active()
    result = {
        "policy": {"status": "VERIFIED", "digest": policy.policy_digest},
        "release": {"status": "VERIFIED", **summary(approval)},
    }
    if args.detector_manifest:
        detector = load_verified(args.detector_manifest, verify_live=True, root=args.detector_root)
        if detector["digest"] != approval["payload"]["detector_digest"]:
            raise RuntimeError("Installed detector is not approved by signed release")
        result["detector"] = {"status": "VERIFIED", "digest": detector["digest"]}
    else:
        result["detector"] = {"status": "NOT_CHECKED", "reason": "Requires installed model"}

    if bool(args.audit_db) != bool(args.audit_public_key):
        raise ValueError("Supply both --audit-db and --audit-public-key")
    if args.audit_checkpoint and not args.audit_db:
        raise ValueError("--audit-checkpoint requires audit database and trusted public key")
    if args.audit_db:
        audit = verify_database(args.audit_db, args.audit_public_key, args.audit_checkpoint)
        result["audit"] = {"status": "VERIFIED", **audit}
        result["audit"]["checkpoint_witnessed"] = bool(args.audit_checkpoint)
    else:
        result["audit"] = {"status": "NOT_CHECKED", "reason": "No audit DB/key supplied"}

    result["runtime"] = check_runtime(Path(args.env_file)) if args.runtime else {
        "status": "NOT_CHECKED", "reason": "Use --runtime for loopback readiness"
    }
    result["status"] = "INSTALLATION_VERIFIED" if args.runtime else "HOST_STATE_VERIFIED"
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy-active", default=str(state_path("policy-active")))
    parser.add_argument("--policy-archive", default=str(state_path("policy-archive")))
    parser.add_argument("--release-active", default=str(state_path("release-active") / "release.json"))
    parser.add_argument("--release-archive", default=str(state_path("release-archive")))
    parser.add_argument("--release-trust", default=str(state_path("release-trust")))
    parser.add_argument("--detector-manifest", help="Installed manifest (only inside model environment)")
    parser.add_argument("--detector-root", default="/service")
    parser.add_argument("--audit-db", help="Accessible consistent SQLite snapshot")
    parser.add_argument("--audit-public-key", help="Independently trusted audit signing public PEM")
    parser.add_argument("--audit-checkpoint", help="Optional independently witnessed checkpoint")
    parser.add_argument("--runtime", action="store_true", help="Check loopback API using local .env")
    parser.add_argument("--env-file", default=".env", help="Local .env containing API key and port")
    args = parser.parse_args()
    try:
        print(json.dumps(verify_installation(args), indent=2))
    except (
        OSError,
        RuntimeError,
        ValueError,
        VerificationError,
        SnapshotError,
        ReleaseIntegrityError,
        DetectorIntegrityError,
        urllib.error.URLError,
    ) as exc:
        print(f"INSTALLATION VERIFICATION FAILED: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
