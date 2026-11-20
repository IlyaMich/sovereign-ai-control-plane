"""Case-level diagnostic analysis is pure and must never export prompt text."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from evaluation.dataset import Entity, load_dataset
from evaluation.diagnostics import DiagnosticsError, _coverage, analyze, save


def _run(tmp_path: Path):
    dataset = load_dataset()
    cases = dataset.select("development")
    (tmp_path / "run.json").write_text(
        json.dumps(
            {
                "run_id": "test",
                "split": "development",
                "dataset_sha256": dataset.manifest["cases_sha256"],
            }
        ),
        encoding="utf-8",
    )
    with (tmp_path / "predictions.jsonl").open("w", encoding="utf-8", newline="\n") as output:
        for c in cases:
            # All positive cases are deliberately misclassified as clean.
            output.write(
                json.dumps(
                    {
                        "case_id": c.id,
                        "status": "NO_PRIVATE_DETECTED",
                        "entities": [],
                        "reason_codes": [],
                    }
                )
                + "\n"
            )
    return dataset


def test_span_coverage_deduplicates_overlap():
    target = Entity("PRIVATE_KEY", 2, 12)
    assert _coverage(target, (Entity("PRIVATE_KEY", 2, 6), Entity("PRIVATE_KEY", 4, 8))) == 0.6
    assert _coverage(target, (Entity("PERSON", 2, 12),)) == 0


def test_case_ids_and_unsafe_negatives_only(tmp_path: Path):
    dataset = _run(tmp_path)
    report, rows = analyze(tmp_path, dataset)
    positives = [c for c in dataset.select("development") if c.entities]
    assert len(report["classification"]["unsafe_negative_case_ids"]) == len(positives)
    assert len(rows) == sum(len(c.entities) for c in dataset.select("development"))
    assert report["entity_outcomes"]["unsafe_negative"] == len(rows)
    target = tmp_path / "output"
    save(target, report, rows)
    assert "test.contact" not in (target / "diagnostics.json").read_text()
    assert "test.contact" not in (target / "entity_errors.csv").read_text()


def test_incompatible_run_digest_rejected(tmp_path: Path):
    dataset = _run(tmp_path)
    (tmp_path / "run.json").write_text(
        json.dumps({"run_id": "test", "split": "development", "dataset_sha256": "bad"}),
        encoding="utf-8",
    )
    with pytest.raises(DiagnosticsError, match="digest"):
        analyze(tmp_path, dataset)


def test_duplicate_prediction_id_rejected(tmp_path: Path):
    dataset = _run(tmp_path)
    file = tmp_path / "predictions.jsonl"
    first = file.read_text(encoding="utf-8").splitlines()[0]
    with file.open("a", encoding="utf-8") as stream:
        stream.write(first + "\n")
    with pytest.raises(DiagnosticsError):
        analyze(tmp_path, dataset)
