"""CLI for dataset validation, detector evaluation, and reproducible reports.

python -m evaluation.cli validate
python -m evaluation.cli detect --split all --output-dir evaluation/runs/example
python -m evaluation.cli report --run evaluation/runs/example
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from evaluation.adapters.control_plane import ControlPlaneAdapter, DetectorSetupError
from evaluation.adapters.presidio_stock import StockPresidioAdapter
from evaluation.comparison import ComparisonError, compare_runs, write_comparison
from evaluation.dataset import DEFAULT_DATASET, DatasetError, load_dataset
from evaluation.reporting import rerender
from evaluation.runner import evaluate, save_run


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Sovereign detection benchmarks and Stage 3 comparison"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    valid = commands.add_parser("validate", help="Validate dataset, labels and frozen SHA-256")
    valid.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    run = commands.add_parser("detect", help="Execute a detector-only benchmark")
    run.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    run.add_argument(
        "--adapter", choices=["control-plane", "presidio-stock"], default="control-plane"
    )
    run.add_argument(
        "--split", choices=["all", "development", "validation", "evaluation"], default="all"
    )
    run.add_argument("--output-dir", type=Path)
    report = commands.add_parser("report", help="Rebuild HTML from a saved run")
    report.add_argument("--run", type=Path, required=True)
    compare = commands.add_parser("compare", help="Compare two saved detector runs")
    compare.add_argument("--baseline", type=Path, required=True)
    compare.add_argument("--candidate", type=Path, required=True)
    compare.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    compare.add_argument("--output-dir", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "report":
            print(f"Report: {rerender(args.run)}")
            return 0
        dataset = load_dataset(args.dataset)
        if args.command == "validate":
            print(
                json.dumps(
                    {
                        "valid": True,
                        "cases": len(dataset.cases),
                        "dataset_version": dataset.manifest["dataset_version"],
                        "sha256": dataset.manifest["cases_sha256"],
                        "distribution": dataset.manifest["distribution"],
                        "splits": dataset.manifest["split_counts"],
                    },
                    indent=2,
                )
            )
            return 0
        if args.command == "compare":
            summary, categories, changes = compare_runs(args.baseline, args.candidate, dataset)
            output = args.output_dir or (
                Path("evaluation/runs")
                / (
                    "comparison-"
                    + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                    + "-"
                    + uuid.uuid4().hex[:8]
                )
            )
            write_comparison(output, summary, categories, changes)
            print(
                json.dumps(
                    {
                        "output_dir": str(output),
                        "cases": summary["cases"],
                        "changed_cases": summary["changed_case_count"],
                        "unsafe_negative_cases_resolved": summary["unsafe_negative_cases_resolved"],
                        "new_unsafe_negative_cases": summary["new_unsafe_negative_cases"],
                        "exact_f1_delta": summary["metrics"]["exact_f1"]["delta"],
                    },
                    indent=2,
                )
            )
            return 0
        # No production release or policy files are edited; standalone model setup only.
        detector = (
            StockPresidioAdapter.create()
            if args.adapter == "presidio-stock"
            else ControlPlaneAdapter.create()
        )
        summary, predictions = evaluate(dataset, detector, split=args.split)
        if hasattr(detector, "describe"):
            summary["adapter_metadata"] = detector.describe()
        output = args.output_dir or Path("evaluation/runs") / summary["run_id"]
        save_run(output, summary, dataset.select(args.split), predictions)
        m = summary["metrics"]
        print(
            json.dumps(
                {
                    "run_dir": str(output),
                    "cases": m["total_cases"],
                    "exact_metrics": m["entities_exact_full"]["overall"],
                    "unknown_count": m["in_scope_unknown_count"],
                    "detector_errors": m["detector_error_count"],
                },
                indent=2,
            )
        )
        return 2 if m["detector_error_count"] else 0
    except DetectorSetupError as exc:
        # Only validated, hard-coded setup guidance is printed; no prompts are evaluated.
        print(f"Evaluation setup failed: {exc}", file=sys.stderr)
        return 2
    except ComparisonError as exc:
        print(f"Comparison failed: {exc}", file=sys.stderr)
        return 2
    except DatasetError as exc:
        # The dataset validator emits only fixed messages and validated case IDs,
        # never the prompt or matched sensitive values.
        print(f"Evaluation failed: DatasetError: {exc}", file=sys.stderr)
        return 2
    except (OSError, ValueError, RuntimeError, ImportError) as exc:
        # Exception messages from the model could contain input. Print exception type only.
        print(f"Evaluation failed: {type(exc).__name__}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
