"""Compare installed model and classifier bytes with build-time provenance."""

from __future__ import annotations

import argparse
import json
import os

from app.detection.provenance import load_verified
from app.infrastructure.config import Settings


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument(
        "--manifest",
        default=os.environ.get("DETECTOR_MANIFEST_PATH", Settings.detector_manifest_path),
    )
    p.add_argument("--root", default="/service")
    args = p.parse_args()
    result = load_verified(args.manifest, verify_live=True, root=args.root)
    print(
        json.dumps(
            {
                "status": "VERIFIED",
                "detector_artifact_digest": result["digest"],
                "artifact_files": len(result["files"]),
                "model": result["model"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
