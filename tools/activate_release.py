"""Verify offline approval against pinned public keys, then activate archived Rego."""

import argparse
import json
import sys
from pathlib import Path

from app.infrastructure.logging import configure_logging
from app.policy.snapshots import PolicySnapshotStore
from app.release.approvals import ReleaseStore, summary
from tools.operator_state import state_path


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--candidate", required=True)
    p.add_argument("--detector-digest", required=True)
    p.add_argument("--trust", default=str(state_path("release-trust")))
    p.add_argument("--release-active", default=str(state_path("release-active") / "release.json"))
    p.add_argument("--release-archive", default=str(state_path("release-archive")))
    p.add_argument("--policy-active", default=str(state_path("policy-active")))
    p.add_argument("--policy-archive", default=str(state_path("policy-archive")))
    args = p.parse_args()
    configure_logging(stream=sys.stderr)
    store = ReleaseStore(
        Path(args.release_active),
        Path(args.release_archive),
        Path(args.trust),
        PolicySnapshotStore(args.policy_active, args.policy_archive),
    )
    # ReleaseStore.activate holds a cross-process lock across validation,
    # archive publication and active release/policy publication.
    envelope = store.activate(args.candidate, detector_digest=args.detector_digest)
    print(json.dumps({"status": "ACTIVATED", **summary(envelope)}, indent=2))
    print("Recreate control-plane and OPA to load the new signed release and Rego policy.")


if __name__ == "__main__":
    main()
