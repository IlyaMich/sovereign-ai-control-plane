"""Export a complete signed-and-verified chain head; retain outside writer's trust boundary.

IMPORTANT: exporting a checkpoint from a database that is already compromised
cannot establish past integrity. Export it at a known-good point and protect it.
"""
import argparse
import json
from pathlib import Path

from app.audit.verify import verify_database


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", required=True)
    parser.add_argument("--public-key", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    result = verify_database(args.db, args.public_key)
    output = Path(args.out)
    if output.exists():
        raise SystemExit("Refusing to overwrite an existing checkpoint")
    output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(f"Checkpoint saved to {output}")


if __name__ == "__main__":
    main()
