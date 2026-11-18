"""Create a development-only Ed25519 release key; never store the private key in git."""
import argparse
from app.release.approvals import new_keypair


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--private-key', required=True)
    parser.add_argument('--public-key', required=True)
    args = parser.parse_args()
    print('RELEASE_SIGNING_KEY_ID=' + new_keypair(args.private_key, args.public_key))
    print('Keep the PRIVATE key outside the repository and audit container.')
    print('Pin the PUBLIC key independently on any verifying host.')


if __name__ == '__main__':
    main()
