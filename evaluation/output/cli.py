"""Developer-only response DLP benchmark: controlled faults or frozen synthetic outputs.

python -m evaluation.output.cli --mode controlled
python -m evaluation.output.cli --mode dataset --split development --limit 20
python -m evaluation.output.cli --mode controlled --policy opa-cli --opa-bin opa
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import hashlib
import html
import json
import shutil
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from evaluation.dataset import DEFAULT_DATASET, load_dataset
from evaluation.output.core import (
    OutputScenario,
    controlled_scenarios,
    evaluate_scenarios,
)

SPLITS = ("all", "development", "validation", "evaluation")


def dataset_scenarios(
    split: str = "all",
    *,
    limit: int = 0,
    dataset: Path = DEFAULT_DATASET,
) -> tuple[tuple[OutputScenario, ...], str]:
    frozen = load_dataset(dataset)
    cases = frozen.select(split)
    if limit:
        cases = cases[:limit]
    scenarios = tuple(
        OutputScenario(
            case,
            "OUTPUT_BLOCKED" if case.expected_status != "NO_PRIVATE_DETECTED" else "COMPLETED",
            "OUTPUT_DETECTION_UNKNOWN"
            if case.expected_status == "UNKNOWN"
            else "OUTPUT_PRIVATE_DATA_BLOCKED"
            if case.expected_status == "PRIVATE"
            else "OUTPUT_CONTENT_CLEARED",
        )
        for case in cases
    )
    return scenarios, frozen.manifest["cases_sha256"]


def _fixture_digest(scenarios: tuple[OutputScenario, ...]) -> str:
    # Synthetic fixture identity for reproducible comparisons, not a signature.
    raw = [
        {
            "id": spec.case.id,
            "output": spec.case.text,
            "entities": [[e.category, e.start, e.end] for e in spec.case.entities],
            "fault": spec.fault,
            "expected": spec.expected_outcome,
        }
        for spec in scenarios
    ]
    return hashlib.sha256(
        json.dumps(raw, sort_keys=True, ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def save_report(directory: Path, report: dict[str, Any]) -> None:
    """Export case IDs and status/score metadata, never generated response text."""
    directory.mkdir(parents=True, exist_ok=False)
    rows = report["rows"]
    header = {key: value for key, value in report.items() if key != "rows"}
    (directory / "run.json").write_bytes(
        (json.dumps(header, sort_keys=True, indent=2) + "\n").encode("utf-8")
    )
    (directory / "cases.jsonl").write_bytes(
        "".join(
            json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows
        ).encode("utf-8")
    )
    with (directory / "cases.csv").open("w", encoding="utf-8", newline="") as stream:
        fields = sorted({key for row in rows for key in row})
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    key: json.dumps(value, separators=(",", ":"))
                    if isinstance(value, (list, dict))
                    else value
                    for key, value in row.items()
                }
            )
    (directory / "report.html").write_text(_html(report), encoding="utf-8")


def _html(report: dict[str, Any]) -> str:
    def safe(value: Any) -> str:
        return html.escape(str(value), quote=True)

    metrics = report["metrics"]
    output_score = metrics["output_detection"]
    exact = output_score["entities_exact_full"]["overall"]
    table = "".join(
        "<tr><td>" + safe(label) + "</td><td>" + safe(value) + "</td></tr>"
        for label, value in (
            ("Total synthetic outputs", report["cases"]),
            ("Released", metrics["released_count"]),
            ("Output blocked", metrics["blocked_count"]),
            ("Execution/audit errors", metrics["error_count"]),
            ("Known-sensitive output released", metrics["unsafe_sensitive_release_count"]),
            ("False blocks (known benign, expected released)", metrics["false_block_count"]),
            ("Output detection exact recall", exact["recall"]),
            ("Output detection status accuracy", output_score["status_accuracy"]),
            ("Signed events verified", report["evidence"]["signed_events_verified"]),
            (
                "Output policy decisions replayed",
                report["evidence"]["output_policy_decisions_replayed"],
            ),
            ("Local output denials verified", report["evidence"]["output_local_denials_verified"]),
        )
    )
    case_rows = "".join(
        "<tr>"
        + "".join(
            "<td>" + safe(value) + "</td>"
            for value in (
                row["case_id"],
                row["group"],
                row["expected_detection_status"],
                row["observed_detection_status"],
                row["actual_outcome"],
                row["released"],
                ",".join(row["issues"]),
            )
        )
        + "</tr>"
        for row in report["rows"]
    )
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        "<title>Response DLP Evaluation</title>"
        "<style>body{max-width:1100px;margin:2rem auto;padding:1rem;font:15px system-ui,sans-serif}"
        "table{border-collapse:collapse;width:100%;margin:1rem 0 2rem}"
        "td,th{border-bottom:1px solid #ddd;padding:.5rem;text-align:left}"
        "th{background:#eee}code{overflow-wrap:anywhere}</style></head><body>"
        "<h1>Response-side DLP Evaluation</h1><p>Detector: "
        + safe(report["detector_mode"])
        + " · Policy: "
        + safe(report["policy_mode"])
        + "</p><table><tbody>"
        + table
        + "</tbody></table>"
        "<h2>Case-level results (no generated content)</h2><table><thead>"
        "<tr><th>ID</th><th>Group</th><th>Expected detection</th>"
        "<th>Observed detection</th><th>Outcome</th><th>Released</th><th>Issues</th></tr>"
        "</thead><tbody>"
        + case_rows
        + "</tbody></table><p>"
        + safe(report["limitations"])
        + "</p></body></html>"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Isolated response-side DLP evaluation")
    parser.add_argument("--mode", choices=("controlled", "dataset"), default="controlled")
    parser.add_argument("--policy", choices=("fixture", "opa-cli"), default="fixture")
    parser.add_argument("--opa-bin", default="opa")
    parser.add_argument("--split", choices=SPLITS, default="all")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args(argv)
    if args.limit < 0:
        parser.error("--limit must be nonnegative")
    if args.policy == "opa-cli" and shutil.which(args.opa_bin) is None:
        print(
            "Local OPA CLI not found. Install the pinned OPA 1.8.0 Windows "
            "executable, then provide its full path with --opa-bin.",
            file=sys.stderr,
        )
        return 2
    try:
        if args.mode == "controlled":
            scenarios = controlled_scenarios()
            if args.limit:
                scenarios = scenarios[: args.limit]
            detector_mode = "fixture"
            identity = _fixture_digest(scenarios)
        else:
            scenarios, identity = dataset_scenarios(
                args.split, limit=args.limit, dataset=args.dataset
            )
            detector_mode = "presidio"
        report = asyncio.run(
            evaluate_scenarios(
                scenarios,
                detector_mode=detector_mode,
                opa_bin=args.opa_bin if args.policy == "opa-cli" else None,
                dataset_sha256=identity,
            )
        )
        report["timestamp_utc"] = datetime.now(timezone.utc).isoformat()
        report["split"] = args.split if args.mode == "dataset" else "controlled"
        report["limit"] = args.limit or None
        root = args.output_dir or Path("evaluation/runs") / (
            "output-"
            + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            + "-"
            + uuid.uuid4().hex[:8]
        )
        save_report(root, report)
        print(
            json.dumps(
                {
                    "run_dir": str(root),
                    "cases": report["cases"],
                    "passed": report["passed"],
                    "failed": report["failed"],
                    "released": report["metrics"]["released_count"],
                    "blocked": report["metrics"]["blocked_count"],
                    "unsafe_sensitive_releases": report["metrics"][
                        "unsafe_sensitive_release_count"
                    ],
                    "false_blocks": report["metrics"]["false_block_count"],
                    "issues": report["metrics"]["issues"],
                    "signed_events_verified": report["evidence"]["signed_events_verified"],
                    "output_policy_replayed": report["evidence"][
                        "output_policy_decisions_replayed"
                    ],
                    "evidence_status": report["evidence"]["status"],
                },
                indent=2,
            )
        )
        return (
            1
            if (
                report["failed"]
                or report["metrics"]["unsafe_sensitive_release_count"]
                or report["metrics"]["issues"]
            )
            else 0
        )
    except Exception as exc:
        # Never print original generated text or third-party exception messages.
        print(f"Response DLP evaluation failed: {type(exc).__name__}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
