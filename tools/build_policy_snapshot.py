"""Build/activate a content-addressed Rego snapshot from policy source."""

import argparse
import json

from app.policy.snapshots import build_snapshot
from tools.operator_state import state_path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", default="policies")
    parser.add_argument("--archive", default=str(state_path("policy-archive")))
    parser.add_argument("--active", default=str(state_path("policy-active")))
    args = parser.parse_args()
    info = build_snapshot(args.source, args.archive, args.active)
    print(json.dumps(info.manifest(), indent=2))
    print("Recreate OPA after activation: podman compose ... up -d --force-recreate opa")


if __name__ == "__main__":
    main()
