"""Create image-local detector provenance after pinned NLP artifacts are installed."""
from __future__ import annotations
import argparse
import json
from app.detection.provenance import write_build_manifest


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--output", default="/service/detector-active/manifest.json")
    p.add_argument("--root", default="/service")
    args = p.parse_args()
    result = write_build_manifest(args.output, args.root)
    print(json.dumps({"status": "BUILT", "detector_artifact_digest": result["digest"],
                      "artifact_files": len(result["files"])}, sort_keys=True))


if __name__ == "__main__":
    main()
