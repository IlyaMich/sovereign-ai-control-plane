"""Run/reports verified with controlled adapters (not assertions about model accuracy)."""
from __future__ import annotations

import json
from pathlib import Path


from evaluation.cli import main
from evaluation.dataset import load_dataset
from evaluation.reporting import rerender
from evaluation.runner import evaluate, save_run


class OracleAdapter:
    """Test fixture: echoes labels to exercise scoring, NOT a real detector baseline."""
    name = "truth-oracle-fixture"

    def __init__(self, cases):
        self.entries = {c.text: c for c in cases}

    def detect(self, text):
        case = self.entries[text]
        return {"status": case.expected_status,
                "findings": [dict(category=e.category, start=e.start, end=e.end)
                             for e in case.entities],
                "reason_codes": [], "detector_version": "fixture-v1",
                "config_digest": "fixture"}


class BrokenAdapter:
    name = "broken-fixture"

    def detect(self, text):
        raise RuntimeError("Secret request text: " + text)


def test_full_dataset_run_outputs_reports_without_prompt_text(tmp_path: Path):
    dataset = load_dataset()
    result, predictions = evaluate(dataset, OracleAdapter(dataset.cases),
                                   repo_root=tmp_path)
    assert result["metrics"]["total_cases"] == 1200
    assert result["metrics"]["entities_exact_full"]["overall"]["recall"] == 1.0
    assert result["metrics"]["in_scope_unknown_count"] == 0
    dest = tmp_path / "result"
    save_run(dest, result, dataset.cases, predictions)
    for filename in ("run.json", "predictions.jsonl", "cases.csv",
                     "categories.csv", "report.html"):
        assert (dest / filename).is_file()
    probe = dataset.cases[0].text
    for output_file in dest.iterdir():
        assert probe not in output_file.read_text(encoding="utf-8")
    assert len((dest / "cases.csv").read_text(encoding="utf-8").splitlines()) == 1201
    assert rerender(dest).exists()
    loaded = json.loads((dest / "run.json").read_text(encoding="utf-8"))
    assert loaded["dataset_sha256"] == dataset.manifest["cases_sha256"]


def test_detector_exception_is_reported_without_leaking_exception_text(tmp_path: Path):
    dataset = load_dataset()
    result, predictions = evaluate(dataset, BrokenAdapter(), split="development",
                                   repo_root=tmp_path)
    assert result["metrics"]["detector_error_count"] == 240
    assert all(p.status == "ERROR" and p.error_type == "RuntimeError" for p in predictions)
    dest = tmp_path / "run-errors"
    save_run(dest, result, dataset.select("development"), predictions)
    assert "Secret request text:" not in (dest / "predictions.jsonl").read_text()
    assert "Secret request text:" not in (dest / "cases.csv").read_text()


def test_cli_validation(capsys):
    assert main(["validate"]) == 0
    assert '"cases": 1200' in capsys.readouterr().out
