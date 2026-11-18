"""Independently verify a signed audit snapshot and replay recorded OPA results."""
from __future__ import annotations

import argparse
import json
import sys

from app.audit.verify import VerificationError
from app.policy.replay import ReplayError, replay_database
from app.detection.evidence import DetectorEvidenceError


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", required=True)
    parser.add_argument("--public-key", required=True)
    parser.add_argument("--archive", required=True)
    parser.add_argument("--checkpoint")
    parser.add_argument("--detector-archive", default="/var/lib/sovereign/detector-archive")
    parser.add_argument("--opa-bin", default="opa")
    args = parser.parse_args()
    try:
        result = replay_database(args.db, args.public_key, args.archive,
                                 args.checkpoint, args.opa_bin,
                                 detector_archive_root=args.detector_archive)
    except (VerificationError, ReplayError, DetectorEvidenceError, OSError, ValueError) as exc:
        # Tool is offline, but avoid echoing external evaluator error strings
        # which can conceivably contain sensitive inputs.
        print(f"REPLAY FAILED: {type(exc).__name__}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
