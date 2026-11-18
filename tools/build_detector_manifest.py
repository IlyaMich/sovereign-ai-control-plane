"""Create image-local detector provenance after pinned NLP artifacts are installed."""

from __future__ import annotations

import argparse
import json
import os

from app.detection.provenance import write_build_manifest
from app.infrastructure.config import Settings


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument(
        "--output",
        default=os.environ.get("DETECTOR_MANIFEST_PATH", Settings.detector_manifest_path),
    )
    p.add_argument("--root", default="/service")
    args = p.parse_args()
    result = write_build_manifest(args.output, args.root)
    print(
        json.dumps(
            {
                "status": "BUILT",
                "detector_artifact_digest": result["digest"],
                "artifact_files": len(result["files"]),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
