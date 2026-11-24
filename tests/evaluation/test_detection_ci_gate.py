"""Regression checks for aggregate-only detection evaluation CI gates."""

from __future__ import annotations

import json
from copy import deepcopy

from evaluation.ci_gate import FROZEN_V1_CASES, FROZEN_V1_SHA256, assess, main


def _records():
    def run(adapter, run_id, f1, recall):
        return {
            "adapter": adapter,
            "run_id": run_id,
            "split": "all",
            "dataset_version": "1.0.0",
            "dataset_sha256": FROZEN_V1_SHA256,
            "metrics": {
                "total_cases": FROZEN_V1_CASES,
                "detector_error_count": 0,
                "entities_exact_full": {"overall": {"f1": f1, "recall": recall}},
                "unsafe_negative_rate": 0.0 if adapter == "control-plane" else 0.31,
                "in_scope_unknown_rate": 0.087 if adapter == "control-plane" else 0.0,
            },
        }

    stock = run("presidio-stock", "stock-run", 0.58, 0.51)
    candidate = run("control-plane", "candidate-run", 0.67, 0.655)
    paired = {
        "comparison_spec": "paired-detection-v1",
        "dataset_sha256": FROZEN_V1_SHA256,
        "split": "all",
        "cases": FROZEN_V1_CASES,
        "baseline": {"adapter": "presidio-stock", "run_id": "stock-run"},
        "candidate": {"adapter": "control-plane", "run_id": "candidate-run"},
        "new_unsafe_negative_cases": 0,
    }
    return stock, candidate, paired


def test_passes_comparable_runs_without_errors():
    result = assess(*_records())
    assert result["passed"] is True
    assert result["failures"] == []
    assert result["candidate_in_scope_unknown_rate"] > 0


def test_rejects_non_frozen_dataset_and_partial_coverage():
    stock, candidate, paired = deepcopy(_records())
    candidate["dataset_sha256"] = "0" * 64
    candidate["metrics"]["total_cases"] -= 1
    result = assess(stock, candidate, paired)
    assert not result["passed"]
    assert len(result["failures"]) == 2


def test_rejects_any_unsafe_negative_even_if_not_new_vs_stock():
    stock, candidate, paired = deepcopy(_records())
    candidate["metrics"]["unsafe_negative_rate"] = 0.001
    assert not assess(stock, candidate, paired)["passed"]


def test_rejects_new_unsafe_negative_classifications():
    stock, candidate, paired = deepcopy(_records())
    paired["new_unsafe_negative_cases"] = 1
    assert not assess(stock, candidate, paired)["passed"]


def test_rejects_detector_errors_in_either_run():
    stock, candidate, paired = deepcopy(_records())
    stock["metrics"]["detector_error_count"] = 1
    candidate["metrics"]["detector_error_count"] = 1
    assert len(assess(stock, candidate, paired)["failures"]) == 2


def test_requires_candidate_not_worse_than_stock():
    stock, candidate, paired = deepcopy(_records())
    candidate["metrics"]["entities_exact_full"]["overall"].update(f1=0.55, recall=0.40)
    failures = assess(stock, candidate, paired)["failures"]
    assert any("F1" in item for item in failures)
    assert any("recall" in item for item in failures)


def test_rejects_mismatched_comparison_runs():
    stock, candidate, paired = deepcopy(_records())
    paired["candidate"]["run_id"] = "different"
    assert not assess(stock, candidate, paired)["passed"]


def test_rejects_bad_adapter_or_split():
    stock, candidate, paired = deepcopy(_records())
    stock["adapter"] = "control-plane"
    candidate["split"] = "evaluation"
    assert len(assess(stock, candidate, paired)["failures"]) == 2


def test_exports_only_allowlisted_aggregate_files(tmp_path, monkeypatch):
    stock, candidate, paired = _records()
    stock_dir, candidate_dir, paired_dir = (
        tmp_path / "stock",
        tmp_path / "candidate",
        tmp_path / "paired",
    )
    for directory, data in ((stock_dir, stock), (candidate_dir, candidate)):
        directory.mkdir()
        (directory / "run.json").write_text(json.dumps(data))
        (directory / "categories.csv").write_text("category,tp\nPERSON,1\n")
        (directory / "predictions.jsonl").write_text("SENSITIVE_RAW_TEST_SENTINEL\n")
    paired_dir.mkdir()
    (paired_dir / "comparison.json").write_text(json.dumps(paired))
    (paired_dir / "categories.csv").write_text("category,tp\nPERSON,1\n")
    (paired_dir / "comparison.html").write_text("<html>Aggregate only</html>")
    (paired_dir / "changed_cases.csv").write_text("SENSITIVE_RAW_TEST_SENTINEL\n")
    step_summary = tmp_path / "step-summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(step_summary))
    aggregate = tmp_path / "aggregate"
    assert (
        main(
            [
                "--stock", str(stock_dir),
                "--candidate", str(candidate_dir),
                "--comparison", str(paired_dir),
                "--aggregate-dir", str(aggregate),
            ]
        )
        == 0
    )
    assert {p.name for p in aggregate.iterdir()} == {
        "stock-run.json",
        "stock-categories.csv",
        "candidate-run.json",
        "candidate-categories.csv",
        "paired-comparison.json",
        "paired-categories.csv",
        "paired-comparison.html",
        "gate.json",
        "summary.md",
    }
    assert step_summary.read_text().startswith("## Detection evaluation: PASS")
    assert "SENSITIVE_RAW_TEST_SENTINEL" not in "".join(
        item.read_text() for item in aggregate.iterdir()
    )


def test_failed_gate_returns_failure_but_writes_summary(tmp_path):
    stock, candidate, paired = _records()
    candidate["metrics"]["unsafe_negative_rate"] = 0.01
    sources = [tmp_path / name for name in ("stock", "candidate", "paired")]
    for directory, item in zip(sources, (stock, candidate, paired), strict=True):
        directory.mkdir()
        (directory / ("comparison.json" if directory == sources[2] else "run.json")).write_text(
            json.dumps(item)
        )
        (directory / "categories.csv").write_text("category\n")
    (sources[2] / "comparison.html").write_text("<html />")
    output = tmp_path / "aggregate"
    assert main([
        "--stock", str(sources[0]),
        "--candidate", str(sources[1]),
        "--comparison", str(sources[2]),
        "--aggregate-dir", str(output),
    ]) == 1
    assert json.loads((output / "gate.json").read_text())["passed"] is False
