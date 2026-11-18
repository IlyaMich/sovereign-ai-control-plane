"""Verify offline approval against pinned public keys, then activate archived Rego."""
import argparse
import json
from pathlib import Path

from app.policy.snapshots import PolicySnapshotStore
from app.release.approvals import ReleaseStore, summary


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--candidate', required=True)
    p.add_argument('--detector-digest', required=True)
    p.add_argument('--trust', default='release-trust')
    p.add_argument('--release-active', default='release-active/release.json')
    p.add_argument('--release-archive', default='release-archive')
    p.add_argument('--policy-active', default='policy-active')
    p.add_argument('--policy-archive', default='policy-archive')
    args = p.parse_args()
    store = ReleaseStore(Path(args.release_active), Path(args.release_archive), Path(args.trust),
                         PolicySnapshotStore(args.policy_active, args.policy_archive))
    envelope = store.activate(args.candidate, detector_digest=args.detector_digest)
    print(json.dumps({'status': 'ACTIVATED', **summary(envelope)}, indent=2))
    print('Recreate control-plane and OPA to load the new signed release and Rego policy.')


if __name__ == '__main__':
    main()
