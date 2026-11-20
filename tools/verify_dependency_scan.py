"""Require a Trivy filesystem report to include the frozen Python dependencies."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def verify_report(report: dict) -> None:
    results = report.get("Results", [])
    if not any(
        result.get("Type") == "pip" and Path(result.get("Target", "")).name == "requirements.txt"
        for result in results
    ):
        raise ValueError("Trivy did not scan requirements.txt; dependency coverage is missing")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    verify_report(json.loads(args.report.read_text(encoding="utf-8")))
    print("DEPENDENCY_SCAN_VERIFIED: requirements.txt was scanned")


if __name__ == "__main__":
    main()
