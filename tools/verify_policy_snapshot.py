"""Verify active snapshot and archived source; does not contact OPA."""

import argparse
import json
import sys

from app.policy.snapshots import PolicySnapshotStore, SnapshotError
from tools.operator_state import state_path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--active", default=str(state_path("policy-active")))
    parser.add_argument("--archive", default=str(state_path("policy-archive")))
    args = parser.parse_args()
    try:
        result = PolicySnapshotStore(args.active, args.archive).verify_active()
    except (OSError, SnapshotError) as exc:
        print(f"INVALID: {type(exc).__name__}", file=sys.stderr)
        return 1
    print(json.dumps({"status": "VERIFIED", **result.manifest()}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
