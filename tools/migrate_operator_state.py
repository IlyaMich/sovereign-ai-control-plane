"""Safely migrate a verified existing signed installation out of Git-tracked paths.

Run from repository root after stopping control-plane and OPA.
By default prints preflight only; --apply copies and verifies all artifacts.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from app.policy.snapshots import SnapshotError
from tools.operator_state import migrate_legacy_state


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true", help="Copy and verify state")
    args = parser.parse_args()
    try:
        result = migrate_legacy_state(Path.cwd(), apply=args.apply)
    except (OSError, ValueError, RuntimeError, SnapshotError) as exc:
        print(f"STATE MIGRATION REFUSED: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
