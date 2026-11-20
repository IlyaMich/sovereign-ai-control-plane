"""Run isolated orchestration regression tests or real-detector boundary replay.

python -m evaluation.enforcement.cli --mode controlled
python -m evaluation.enforcement.cli --mode replay --split all
python -m evaluation.enforcement.cli --mode controlled --policy opa-cli --opa-bin opa
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from evaluation.dataset import DEFAULT_DATASET, load_dataset
from evaluation.enforcement.core import replay_cases, run_suite
from evaluation.enforcement.policy import OPACliPolicy


def save_report(root: Path, report: dict[str, Any]) -> None:
    """Export metadata and case IDs only; never serialized prompts or forwarding payloads."""
    root.mkdir(parents=True, exist_ok=False)
    rows = report["rows"]
    metadata = {k: v for k, v in report.items() if k != "rows"}
    (root / "run.json").write_text(
        json.dumps(metadata, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    (root / "cases.jsonl").write_text(
        "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
    )
    with (root / "cases.csv").open("w", encoding="utf-8", newline="") as stream:
        keys = sorted(set().union(*(set(row) for row in rows))) if rows else ["case_id"]
        writer = csv.DictWriter(stream, fieldnames=keys)
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    k: json.dumps(v, separators=(",", ":")) if isinstance(v, (list, dict)) else v
                    for k, v in row.items()
                }
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Isolated enforcement-security evaluation")
    parser.add_argument("--mode", choices=["controlled", "replay"], default="controlled")
    parser.add_argument("--policy", choices=["fixture", "opa-cli"], default="fixture")
    parser.add_argument("--opa-bin", default="opa")
    parser.add_argument("--policy-active", type=Path, default=Path("policy-active"))
    parser.add_argument("--policy-archive", type=Path, default=Path("policy-archive"))
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument(
        "--split", choices=["all", "development", "validation", "evaluation"], default="all"
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Only for smoke replay; zero runs the entire chosen split",
    )
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args(argv)
    if args.limit < 0:
        parser.error("--limit must be nonnegative")
    try:
        policy = (
            OPACliPolicy(
                opa_executable=args.opa_bin, active=args.policy_active, archive=args.policy_archive
            )
            if args.policy == "opa-cli"
            else None
        )
        if args.mode == "controlled":
            report = asyncio.run(run_suite(policy))
        else:
            dataset = load_dataset(args.dataset)
            cases = dataset.select(args.split)
            if args.limit:
                cases = cases[: args.limit]
            report = asyncio.run(replay_cases(cases, policy))
            report["dataset_sha256"] = dataset.manifest["cases_sha256"]
            report["dataset_version"] = dataset.manifest["dataset_version"]
            report["split"] = args.split
            report["limit"] = args.limit or None
        report["timestamp_utc"] = datetime.now(timezone.utc).isoformat()
        if policy is not None:
            report["policy_digest"] = policy.pinned.policy_digest
            report["policy_revision"] = policy.pinned.policy_revision
        out = args.output_dir or Path("evaluation/runs") / (
            "enforcement-"
            + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            + "-"
            + uuid.uuid4().hex[:8]
        )
        save_report(out, report)
        result = {
            k: v
            for k, v in report.items()
            if k
            in (
                "evaluation_mode",
                "policy_mode",
                "cases",
                "passed",
                "failed",
                "unsafe_external_forward_count",
                "incomplete_or_unknown_cases",
                "issues",
            )
        }
        result["run_dir"] = str(out)
        print(json.dumps(result, indent=2))
        return (
            1
            if report.get("failed", 0)
            or report.get("unsafe_external_forward_count", 0)
            or report.get("incomplete_or_unknown_cases", 0)
            else 0
        )
    except Exception as exc:
        # Input and OPA error strings are not safe to echo; keep errors type-only.
        print(f"Enforcement evaluation failed: {type(exc).__name__}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
