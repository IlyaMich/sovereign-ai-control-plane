"""Offline verification against a trusted public key and optional external checkpoint."""

import argparse
import json
import sys

from app.audit.verify import VerificationError, verify_database


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", required=True, help="Path to local SQLite audit database")
    parser.add_argument(
        "--public-key", required=True, help="Independently trusted Ed25519 public key PEM"
    )
    parser.add_argument("--checkpoint", help="Trusted external JSON chain-head checkpoint")
    args = parser.parse_args()
    try:
        result = verify_database(args.db, args.public_key, args.checkpoint)
        print(json.dumps({"status": "VERIFIED", **result}, indent=2))
        return 0
    except (VerificationError, OSError, ValueError) as exc:
        print(f"VERIFICATION FAILED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
