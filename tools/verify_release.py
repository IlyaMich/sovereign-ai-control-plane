"""Verify the currently approved release without accessing any private key."""
import argparse
import json
from pathlib import Path

from app.policy.snapshots import PolicySnapshotStore
from app.release.approvals import ReleaseStore, summary


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--trust', default='release-trust')
    p.add_argument('--active', default='release-active/release.json')
    p.add_argument('--archive', default='release-archive')
    p.add_argument('--policy-active', default='policy-active')
    p.add_argument('--policy-archive', default='policy-archive')
    p.add_argument('--detector-manifest', default=None)
    args = p.parse_args()
    store = ReleaseStore(Path(args.active), Path(args.archive), Path(args.trust),
                         PolicySnapshotStore(args.policy_active, args.policy_archive),
                         Path(args.detector_manifest) if args.detector_manifest else None)
    doc = store.verify_active()
    print(json.dumps({'status': 'RELEASE_VERIFIED', **summary(doc)}, indent=2))


if __name__ == '__main__':
    main()
