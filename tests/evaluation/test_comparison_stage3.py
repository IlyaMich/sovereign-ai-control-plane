"""Paired Stage 3 reporting and stock-Presidio normalization without NLP downloads."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from evaluation.comparison import ComparisonError, compare_runs, write_comparison

from evaluation.adapters.presidio_stock import StockPresidioAdapter
from evaluation.cli import main
from evaluation.dataset import load_dataset
from evaluation.runner import evaluate, save_run


class Oracle:
    name = "oracle-test-fixture"

    def __init__(self, cases, *, miss: str | None = None):
        self.by_text = {case.text: case for case in cases}
        self.miss = miss

    def detect(self, prompt):
        case = self.by_text[prompt]
        if case.id == self.miss:
            return {
                "status": "NO_PRIVATE_DETECTED",
                "findings": [],
                "reason_codes": [],
                "detector_version": "oracle-v1",
                "config_digest": "fixture-digest",
            }
        return {
            "status": case.expected_status,
            "findings": [vars(e) for e in case.entities],
            "reason_codes": [],
            "detector_version": "oracle-v1",
            "config_digest": "fixture-digest",
        }


def _save_pair(tmp_path):
    dataset = load_dataset()
    cases = dataset.select("development")
    victim = next(case for case in cases if case.expected_status == "PRIVATE")
    paths = (tmp_path / "baseline", tmp_path / "candidate")
    for path, adapter in zip(paths, (Oracle(cases, miss=victim.id), Oracle(cases)), strict=True):
        run, predictions = evaluate(dataset, adapter, split="development", repo_root=tmp_path)
        save_run(path, run, cases, predictions)
    return dataset, paths, victim


def test_stock_presidio_normalizes_without_candidate_patterns():
    class Analyzer:
        def __init__(self):
            self.calls = []

        def analyze(self, **kwargs):
            self.calls.append(kwargs)
            return [SimpleNamespace(entity_type="EMAIL_ADDRESS", start=4, end=21)]

    analyzer = Analyzer()
    adapter = StockPresidioAdapter(
        analyzer,
        ("EMAIL_ADDRESS", "PERSON", "NOT_IN_BENCHMARK"),
        presidio_version="2.2.366",
    )
    data = adapter.detect("To: tester@example.com")
    assert data["status"] == "PRIVATE"
    assert data["findings"] == [{"category": "EMAIL_ADDRESS", "start": 4, "end": 21}]
    assert analyzer.calls[0]["entities"] == ["EMAIL_ADDRESS", "PERSON"]
    assert analyzer.calls[0]["score_threshold"] == 0.5
    assert adapter.describe()["unsupported_categories"]
    assert "API_CREDENTIAL" in adapter.describe()["unsupported_categories"]
    assert adapter.detect("caf\u00e9")["status"] == "UNKNOWN"
    assert len(analyzer.calls) == 1  # no NLP call for out-of-scope text
    assert adapter.describe()["config_digest"] == adapter.detect("test")["config_digest"]


def test_paired_comparison_uses_frozen_ground_truth_and_exports_no_prompt(tmp_path):
    dataset, (baseline, candidate), victim = _save_pair(tmp_path)
    summary, categories, changes = compare_runs(baseline, candidate, dataset)
    assert summary["cases"] == 240
    assert summary["unsafe_negative_cases_resolved"] == 1
    assert summary["new_unsafe_negative_cases"] == 0
    assert summary["metrics"]["exact_recall"]["delta"] > 0
    assert summary["metrics"]["unsafe_negative_rate"]["delta"] < 0
    assert {row["case_id"] for row in changes} == {victim.id}
    output = tmp_path / "comparison"
    write_comparison(output, summary, categories, changes)
    for filename in ("comparison.json", "comparison.html", "categories.csv", "changed_cases.csv"):
        assert (output / filename).exists()
        assert victim.text not in (output / filename).read_text(encoding="utf-8")
    assert victim.id in (output / "changed_cases.csv").read_text(encoding="utf-8")


def test_cli_compare_existing_saved_runs(tmp_path, capsys):
    _, (baseline, candidate), _ = _save_pair(tmp_path)
    output = tmp_path / "cli-comparison"
    assert (
        main(
            [
                "compare",
                "--baseline",
                str(baseline),
                "--candidate",
                str(candidate),
                "--output-dir",
                str(output),
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["unsafe_negative_cases_resolved"] == 1
    assert (output / "comparison.html").exists()


def test_refuses_mismatched_dataset_and_split(tmp_path):
    dataset, (baseline, candidate), _ = _save_pair(tmp_path)
    file = candidate / "run.json"
    record = json.loads(file.read_text())
    record["dataset_sha256"] = "0" * 64
    file.write_text(json.dumps(record))
    with pytest.raises(ComparisonError, match="dataset digest"):
        compare_runs(baseline, candidate, dataset)
    record["dataset_sha256"] = dataset.manifest["cases_sha256"]
    record["split"] = "evaluation"
    file.write_text(json.dumps(record))
    with pytest.raises(ComparisonError, match="splits differ"):
        compare_runs(baseline, candidate, dataset)


def test_rejects_missing_prediction_or_tampered_metrics(tmp_path):
    dataset, (baseline, candidate), _ = _save_pair(tmp_path)
    predictions = candidate / "predictions.jsonl"
    entries = predictions.read_text(encoding="utf-8").splitlines()
    predictions.write_text("\n".join(entries[:-1]) + "\n", encoding="utf-8")
    with pytest.raises(ComparisonError, match="Missing prediction"):
        compare_runs(baseline, candidate, dataset)
    predictions.write_text("\n".join(entries) + "\n", encoding="utf-8")
    run = candidate / "run.json"
    data = json.loads(run.read_text())
    data["metrics"]["unsafe_negative_rate"] = 0.999
    run.write_text(json.dumps(data))
    with pytest.raises(ComparisonError, match="Saved metrics disagree"):
        compare_runs(baseline, candidate, dataset)


def test_rejects_duplicate_prediction_ids(tmp_path):
    dataset, (baseline, candidate), _ = _save_pair(tmp_path)
    predictions = candidate / "predictions.jsonl"
    entries = predictions.read_text(encoding="utf-8").splitlines()
    entries[-1] = entries[0]
    predictions.write_text("\n".join(entries) + "\n", encoding="utf-8")
    with pytest.raises(ComparisonError, match="Duplicate prediction"):
        compare_runs(baseline, candidate, dataset)
