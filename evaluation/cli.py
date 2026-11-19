"""CLI for dataset validation, detector evaluation, and reproducible reports.

python -m evaluation.cli validate
python -m evaluation.cli detect --split all --output-dir evaluation/runs/example
python -m evaluation.cli report --run evaluation/runs/example
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from evaluation.adapters.control_plane import ControlPlaneAdapter, DetectorSetupError
from evaluation.dataset import DEFAULT_DATASET, DatasetError, load_dataset
from evaluation.reporting import rerender
from evaluation.runner import evaluate, save_run


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Sovereign synthetic detection benchmark (Stage 1)"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    valid = commands.add_parser("validate", help="Validate dataset, labels and frozen SHA-256")
    valid.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    run = commands.add_parser("detect", help="Execute a detector-only benchmark")
    run.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    run.add_argument("--adapter", choices=["control-plane"], default="control-plane")
    run.add_argument(
        "--split", choices=["all", "development", "validation", "evaluation"], default="all"
    )
    run.add_argument("--output-dir", type=Path)
    report = commands.add_parser("report", help="Rebuild HTML from a saved run")
    report.add_argument("--run", type=Path, required=True)
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
        # No production release or policy files are edited; standalone model setup only.
        detector = ControlPlaneAdapter.create()
        summary, predictions = evaluate(dataset, detector, split=args.split)
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
