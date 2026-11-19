"""Read-only deployment preflight against the image and its mounted signed release."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from app.detection.provenance import DetectorIntegrityError, load_verified
from app.infrastructure.config import Settings
from app.policy.snapshots import PolicySnapshotStore, SnapshotError
from app.release.approvals import ReleaseIntegrityError, ReleaseStore, summary


def main() -> int:
    try:
        settings = Settings.from_env()
        detector = load_verified(settings.detector_manifest_path, verify_live=True)
        policy = PolicySnapshotStore(settings.active_policy_path, settings.policy_archive_path)
        policy.verify_active()
        if settings.require_signed_release:
            release = ReleaseStore(
                active=Path(settings.release_active_path),
                archive=Path(settings.release_archive_path),
                trust=Path(settings.release_trust_path),
                policy_store=policy,
                detector_manifest=Path(settings.detector_manifest_path),
            ).verify_active(detector_digest=detector["digest"])
            result = {"status": "RELEASE_VERIFIED", **summary(release)}
        else:
            result = {"status": "SIGNED_RELEASE_DISABLED", "detector_digest": detector["digest"]}
    except (
        DetectorIntegrityError,
        SnapshotError,
        ReleaseIntegrityError,
        OSError,
        ValueError,
        RuntimeError,
    ) as exc:
        print(f"Release preflight failed: {exc}", file=sys.stderr)
        print(
            "For an intended image change, approve it using the existing release signer:\n"
            "  .\\Approve-And-ActivateRelease.ps1 -UseExistingKey -SkipBuild\n"
            "Then run make up again. A missing image must be built before approval.",
            file=sys.stderr,
        )
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
