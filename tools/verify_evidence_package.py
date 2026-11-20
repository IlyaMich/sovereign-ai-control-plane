"""Read-only, network-free verifier of exported sovereign evidence ZIPs."""

import argparse
import json
import sys

from app.audit.evidence_package import EvidencePackageError, verify_package


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--opa-bin", default="opa")
    parser.add_argument("--trusted-public-key", help="Pinned signing public key OUTSIDE the bundle")
    parser.add_argument("--trusted-checkpoint", help="Witnessed chain head OUTSIDE the bundle")
    parser.add_argument(
        "--trusted-release-public-key", help="Pinned release-signer key OUTSIDE bundle"
    )
    parser.add_argument(
        "--max-uncompressed-mib", type=int, default=128,
        help="Explicit maximum evidence size in MiB (1-1024; default: 128)",
    )
    args = parser.parse_args()
    try:
        result = verify_package(
            args.bundle,
            opa_binary=args.opa_bin,
            trusted_public_key=args.trusted_public_key,
            trusted_checkpoint=args.trusted_checkpoint,
            trusted_release_public_key=args.trusted_release_public_key,
            max_uncompressed_mib=args.max_uncompressed_mib,
        )
    except EvidencePackageError as exc:
        print(f"EVIDENCE VERIFICATION FAILED: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"EVIDENCE VERIFICATION FAILED: {type(exc).__name__}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
