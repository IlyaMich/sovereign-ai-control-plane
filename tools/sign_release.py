"""Sign a proposed deployment OFFLINE; not used by the running API container."""
import argparse
import json
from pathlib import Path

from app.detection.provenance import canonical
from app.policy.snapshots import verify_snapshot
from app.release.approvals import make_payload, sign_approval


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--private-key', required=True)
    parser.add_argument('--policy-snapshot', default='policy-active')
    parser.add_argument('--detector-digest', required=True)
    parser.add_argument('--generation', type=int, required=True)
    parser.add_argument('--previous-release-id', default=None)
    parser.add_argument('--out', required=True)
    args = parser.parse_args()
    policy = verify_snapshot(args.policy_snapshot)
    payload = make_payload(policy.policy_digest, policy.policy_revision,
                           args.detector_digest, args.generation, args.previous_release_id)
    approval = sign_approval(payload, args.private_key)
    dest = Path(args.out)
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        raise SystemExit('Refusing to overwrite existing approval candidate')
    dest.write_bytes(canonical(approval) + b'\n')
    print(json.dumps({'status': 'SIGNED', 'release_id': approval['release_id'],
                      'generation': payload['generation'], 'signer_key_id': approval['signer_key_id']}, indent=2))


if __name__ == '__main__':
    main()
