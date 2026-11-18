"""Export a signed-audit snapshot and immutable policy/detector references."""

import argparse
import json
import sys

from app.audit.evidence_package import export_package


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", default="/var/lib/sovereign/audit.sqlite")
    parser.add_argument("--public-key", default="/var/lib/sovereign/audit-key.pub.pem")
    parser.add_argument("--policy-archive", default="/policy-archive")
    parser.add_argument("--detector-archive", default="/var/lib/sovereign/detector-archive")
    parser.add_argument("--release-archive", default="/release-archive")
    parser.add_argument("--out", required=True)
    parser.add_argument("--witnessed-checkpoint")
    args = parser.parse_args()
    try:
        result = export_package(
            args.db,
            args.public_key,
            args.policy_archive,
            args.detector_archive,
            args.out,
            args.witnessed_checkpoint,
            release_archive=args.release_archive,
        )
    except Exception as exc:
        print(f"EXPORT FAILED: {type(exc).__name__}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
