"""Check and publish aggregate-only results from the frozen CI detector benchmark.

The benchmark and paired comparator run first; this script checks safety/quality
invariants without touching production releases or exporting per-case predictions.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import shutil
import sys
from pathlib import Path
from typing import Any

FROZEN_V1_SHA256 = "766980e0e02f92931dac747a36bcddf915d8ef597e267d9c552fce03a4c74109"
FROZEN_V1_CASES = 1200


def _number(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (float, int)):
        raise ValueError("Non-numeric benchmark metric")
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("Non-finite benchmark metric")
    return result


def assess(
    stock: dict[str, Any], candidate: dict[str, Any], paired: dict[str, Any]
) -> dict[str, Any]:
    """Check paired runs, with independent safety and comparative quality gates."""
    failures: list[str] = []
    for label, run, adapter in (
        ("stock", stock, "presidio-stock"),
        ("candidate", candidate, "control-plane"),
    ):
        if (
            run.get("adapter") != adapter
            or run.get("split") != "all"
            or run.get("dataset_sha256") != FROZEN_V1_SHA256
            or run.get("dataset_version") != "1.0.0"
        ):
            failures.append(f"{label}: unexpected adapter, split, or frozen dataset identity")
        if run.get("metrics", {}).get("total_cases") != FROZEN_V1_CASES:
            failures.append(f"{label}: incorrect evaluated case count")
        if run.get("metrics", {}).get("detector_error_count") != 0:
            failures.append(f"{label}: detector execution errors")

    if (
        paired.get("comparison_spec") != "paired-detection-v1"
        or paired.get("dataset_sha256") != FROZEN_V1_SHA256
        or paired.get("split") != "all"
        or paired.get("cases") != FROZEN_V1_CASES
        or paired.get("baseline", {}).get("run_id") != stock.get("run_id")
        or paired.get("candidate", {}).get("run_id") != candidate.get("run_id")
        or paired.get("baseline", {}).get("adapter") != "presidio-stock"
        or paired.get("candidate", {}).get("adapter") != "control-plane"
    ):
        failures.append("comparison: runs, split, or dataset identity mismatch")

    stock_f1 = _number(stock["metrics"]["entities_exact_full"]["overall"]["f1"])
    candidate_f1 = _number(candidate["metrics"]["entities_exact_full"]["overall"]["f1"])
    stock_recall = _number(stock["metrics"]["entities_exact_full"]["overall"]["recall"])
    candidate_recall = _number(candidate["metrics"]["entities_exact_full"]["overall"]["recall"])
    unsafe_rate = _number(candidate["metrics"]["unsafe_negative_rate"])
    unknown_rate = _number(candidate["metrics"]["in_scope_unknown_rate"])
    new_unsafe = paired.get("new_unsafe_negative_cases")

    if unsafe_rate != 0:
        failures.append("candidate: sensitive prompts classified as NO_PRIVATE_DETECTED")
    if type(new_unsafe) is not int or new_unsafe != 0:
        failures.append("comparison: new unsafe-negative classifications")
    if candidate_f1 < stock_f1:
        failures.append("candidate: exact F1 below same-run stock Presidio")
    if candidate_recall < stock_recall:
        failures.append("candidate: exact recall below same-run stock Presidio")

    # UNKNOWN is a meaningful fail-closed classification, not a false negative;
    # display it, but do not turn it into a forced-permit incentive.
    return {
        "schema_version": 1,
        "passed": not failures,
        "failures": failures,
        "dataset_sha256": FROZEN_V1_SHA256,
        "cases": FROZEN_V1_CASES,
        "stock_exact_f1": stock_f1,
        "candidate_exact_f1": candidate_f1,
        "stock_exact_recall": stock_recall,
        "candidate_exact_recall": candidate_recall,
        "candidate_unsafe_negative_rate": unsafe_rate,
        "candidate_in_scope_unknown_rate": unknown_rate,
        "new_unsafe_negative_cases": new_unsafe,
        "note": (
            "Detector-only synthetic benchmark: a zero unsafe-negative rate is not "
            "proof of safe external forwarding, signed release approval, or real-world accuracy."
        ),
    }


def _markdown(result: dict[str, Any]) -> str:
    status = "PASS" if result["passed"] else "FAIL"
    lines = [
        f"## Detection evaluation: {status}",
        "",
        f"Frozen v1 dataset: **{result['cases']} synthetic cases** (all splits).",
        "",
        "| Metric | Stock Presidio | Control plane |",
        "| --- | ---: | ---: |",
        f"| Exact F1 | {result['stock_exact_f1']:.4f} | {result['candidate_exact_f1']:.4f} |",
        (
            "| Exact recall | "
            f"{result['stock_exact_recall']:.4f} | {result['candidate_exact_recall']:.4f} |"
        ),
        (
            "| Candidate unsafe-negative rate | — | "
            f"{result['candidate_unsafe_negative_rate']:.4f} |"
        ),
        (
            "| Candidate in-scope UNKNOWN rate | — | "
            f"{result['candidate_in_scope_unknown_rate']:.4f} |"
        ),
        "",
        f"New unsafe-negative classifications vs. stock: **{result['new_unsafe_negative_cases']}**.",
        "",
    ]
    if result["failures"]:
        lines.extend(["### Failed gates", ""])
        lines.extend(f"- {item}" for item in result["failures"])
        lines.append("")
    lines.extend([result["note"], ""])
    return "\n".join(lines)


def export_aggregate(
    root: Path,
    stock_dir: Path,
    candidate_dir: Path,
    paired_dir: Path,
    result: dict[str, Any],
) -> None:
    """Explicit allowlist. No predictions, raw prompts, or case-level CSVs."""
    root.mkdir(parents=True, exist_ok=False)
    for source, label in ((stock_dir, "stock"), (candidate_dir, "candidate")):
        for name in ("run.json", "categories.csv"):
            shutil.copyfile(source / name, root / f"{label}-{name}")
    for name in ("comparison.json", "categories.csv", "comparison.html"):
        shutil.copyfile(paired_dir / name, root / f"paired-{name}")
    (root / "gate.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    (root / "summary.md").write_text(_markdown(result), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate CI detector safety and quality gates")
    parser.add_argument("--stock", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--comparison", type=Path, required=True)
    parser.add_argument("--aggregate-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        stock = json.loads((args.stock / "run.json").read_text(encoding="utf-8"))
        candidate = json.loads((args.candidate / "run.json").read_text(encoding="utf-8"))
        paired = json.loads((args.comparison / "comparison.json").read_text(encoding="utf-8"))
        result = assess(stock, candidate, paired)
        export_aggregate(args.aggregate_dir, args.stock, args.candidate, args.comparison, result)
        summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary_path:
            with Path(summary_path).open("a", encoding="utf-8") as stream:
                stream.write(_markdown(result))
        print(json.dumps(result, indent=2))
        return 0 if result["passed"] else 1
    except (OSError, ValueError, KeyError, TypeError) as exc:
        # Reports are from synthetic-only evaluation, but avoid echoing JSON contents.
        print(f"Detection CI gate failed: {type(exc).__name__}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
