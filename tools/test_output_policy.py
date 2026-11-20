"""Run proposed Rego tests without touching active signed policy or release files.

Usage: python -m tools.test_output_policy [--opa-bin opa]
"""

from __future__ import annotations

import argparse
import subprocess  # nosec B404 # Required for explicit operator-owned CLI commands.
import tempfile
from pathlib import Path

from app.infrastructure.executables import resolve_executable
from app.policy.snapshots import build_snapshot


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--opa-bin", default="opa")
    args = parser.parse_args(argv)
    with tempfile.TemporaryDirectory(prefix="sovereign-output-rego-") as directory:
        root = Path(directory)
        build_snapshot(Path("policies"), root / "archive", root / "active")
        try:
            completed = subprocess.run(  # nosec B603 # Resolved executable and fixed test arguments; shell=False.
                [
                    resolve_executable(args.opa_bin),
                    "test",
                    str(root / "active"),
                    "tests/rego",
                    "tests/rego_output",
                ],
                shell=False,
                stdin=subprocess.DEVNULL,
                check=False,
                timeout=60,
            )
        except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError("OPA candidate tests unavailable") from exc
        return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
