"""Offline, prompt-free diagnostics from an existing Stage 1 detection run.

Uses only frozen ground truth and saved predictions. Cannot infer recognizer
candidate scores or whether a finding was suppressed by the aggregator.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from evaluation.dataset import DEFAULT_DATASET, Case, Dataset, Entity, load_dataset
from evaluation.scoring import Prediction, _matched


class DiagnosticsError(ValueError):
    """Safe messages only: file or schema problem, never prompt content."""


def _predictions(path: Path, cases: tuple[Case, ...]) -> list[Prediction]:
    text = path.read_bytes()
    expected = {c.id: c for c in cases}
    seen: set[str] = set()
    result = []
    for line in text.splitlines():
        try:
            raw = json.loads(line)
            cid = raw["case_id"]
            if not isinstance(cid, str) or cid not in expected or cid in seen:
                raise DiagnosticsError("Unknown or duplicate prediction case ID")
            seen.add(cid)
            status = raw["status"]
            if status not in {"PRIVATE", "NO_PRIVATE_DETECTED", "UNKNOWN", "ERROR"}:
                raise DiagnosticsError("Invalid prediction status")
            items = raw["entities"]
            if not isinstance(items, list):
                raise DiagnosticsError("Invalid prediction entities")
            entities = []
            for item in items:
                cat, start, end = item["category"], item["start"], item["end"]
                if (
                    not isinstance(cat, str)
                    or not cat
                    or type(start) is not int
                    or type(end) is not int
                    or not 0 <= start < end <= len(expected[cid].text)
                ):
                    raise DiagnosticsError("Invalid prediction entity span")
                entities.append(Entity(cat, start, end))
            if status != "PRIVATE" and entities:
                raise DiagnosticsError("Non-PRIVATE prediction contains findings")
            if status == "PRIVATE" and not entities:
                raise DiagnosticsError("PRIVATE prediction has no findings")
            reasons = raw.get("reason_codes", [])
            if not isinstance(reasons, list) or any(not isinstance(x, str) for x in reasons):
                raise DiagnosticsError("Invalid prediction reason codes")
            result.append(Prediction(cid, status, tuple(entities), 0.0, tuple(reasons)))
        except (KeyError, ValueError, TypeError, json.JSONDecodeError) as exc:
            if isinstance(exc, DiagnosticsError):
                raise
            raise DiagnosticsError("Malformed prediction record") from exc
    if seen != set(expected):
        raise DiagnosticsError("Prediction IDs do not exactly match run split")
    return result


def _coverage(expected: Entity, predicted: tuple[Entity, ...]) -> float:
    """Fraction of annotated span covered by same-category findings (union, no duplicates)."""
    intervals = sorted(
        (max(expected.start, p.start), min(expected.end, p.end))
        for p in predicted
        if p.category == expected.category and p.start < expected.end and expected.start < p.end
    )
    if not intervals:
        return 0.0
    end = expected.start
    covered = 0
    for start, stop in intervals:
        if stop > end:
            covered += stop - max(start, end)
            end = stop
    return round(covered / (expected.end - expected.start), 6)


def analyze(run_dir: Path, dataset: Dataset) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Return aggregate report and one row per expected entity, no plaintext."""
    try:
        raw_run = (run_dir / "run.json").read_bytes()
        run = json.loads(raw_run)
        if run.get("dataset_sha256") != dataset.manifest["cases_sha256"]:
            raise DiagnosticsError("Run/dataset digest mismatch")
        split = run.get("split")
        cases = dataset.select(split)
        prediction_path = run_dir / "predictions.jsonl"
        preds = _predictions(prediction_path, cases)
    except (OSError, json.JSONDecodeError) as exc:
        raise DiagnosticsError("Cannot read saved run or predictions") from exc
    pred_by_id = {p.case_id: p for p in preds}
    counts: Counter[str] = Counter()
    by_cat: dict[str, Counter[str]] = {}
    rows: list[dict[str, Any]] = []
    unsafe_ids: list[str] = []
    prediction_rows: list[dict[str, Any]] = []
    prediction_counts: Counter[str] = Counter()
    for case in cases:
        pred = pred_by_id[case.id]
        if case.in_scope and case.entities and pred.status == "NO_PRIVATE_DETECTED":
            unsafe_ids.append(case.id)
        if not case.in_scope:
            continue
        matches = _matched(case.entities, pred.entities, relaxed=False)
        match = dict(matches)
        matched_predictions = {j for _, j in matches}
        for j, predicted in enumerate(pred.entities):
            if j in matched_predictions:
                continue
            same_overlap = any(
                e.category == predicted.category
                and e.start < predicted.end
                and predicted.start < e.end
                for e in case.entities
            )
            wrong_overlap = any(
                e.category != predicted.category
                and e.start < predicted.end
                and predicted.start < e.end
                for e in case.entities
            )
            kind = (
                "boundary_mismatch"
                if same_overlap
                else "wrong_category_overlap"
                if wrong_overlap
                else "unmatched_prediction"
            )
            prediction_counts[kind] += 1
            prediction_rows.append(
                {
                    "case_id": case.id,
                    "split": case.split,
                    "group": case.group,
                    "category": predicted.category,
                    "start": predicted.start,
                    "end": predicted.end,
                    "kind": kind,
                }
            )
        for i, entity in enumerate(case.entities):
            cov = _coverage(entity, pred.entities)
            same_overlap = any(
                p.category == entity.category and p.start < entity.end and entity.start < p.end
                for p in pred.entities
            )
            wrong_overlap = any(
                p.category != entity.category and p.start < entity.end and entity.start < p.end
                for p in pred.entities
            )
            if i in match:
                kind = "exact"
            elif pred.status == "UNKNOWN":
                kind = "abstained"
            elif pred.status == "ERROR":
                kind = "detector_error"
            elif same_overlap:
                kind = "partial_coverage" if cov < 1 else "boundary_mismatch_full_coverage"
            elif wrong_overlap:
                kind = "wrong_category"
            elif pred.status == "NO_PRIVATE_DETECTED":
                kind = "unsafe_negative"
            else:
                kind = "unmatched_in_private_prompt"
            counts[kind] += 1
            by_cat.setdefault(entity.category, Counter())[kind] += 1
            rows.append(
                {
                    "case_id": case.id,
                    "split": case.split,
                    "group": case.group,
                    "category": entity.category,
                    "start": entity.start,
                    "end": entity.end,
                    "actual_status": pred.status,
                    "kind": kind,
                    "span_coverage": cov,
                }
            )
    prediction_sha = hashlib.sha256(prediction_path.read_bytes()).hexdigest()
    summary = {
        "schema_version": 1,
        "diagnostic_version": "detection-errors-v1",
        "source_run_id": run["run_id"],
        "dataset_sha256": run["dataset_sha256"],
        "predictions_sha256": prediction_sha,
        "scoring_scope": "in-scope expected entities only",
        "classification": {
            "unsafe_negative_case_count": len(unsafe_ids),
            "unsafe_negative_case_ids": sorted(unsafe_ids),
        },
        "expected_entity_total": len(rows),
        "entity_outcomes": dict(sorted(counts.items())),
        "prediction_outcomes": dict(sorted(prediction_counts.items())),
        "prediction_errors": prediction_rows,
        "by_category": {k: dict(sorted(v.items())) for k, v in sorted(by_cat.items())},
        "limitation": (
            "Saved predictions cannot prove why a recognizer candidate is absent, "
            "and partial overlap does not prove full redaction."
        ),
    }
    return summary, rows


def save(output: Path, summary: dict[str, Any], rows: list[dict[str, Any]]) -> None:
    output.mkdir(parents=True, exist_ok=False)
    (output / "diagnostics.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    with (output / "entity_errors.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(
            stream,
            fieldnames=[
                "case_id",
                "split",
                "group",
                "category",
                "start",
                "end",
                "actual_status",
                "kind",
                "span_coverage",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)
    with (output / "prediction_errors.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(
            stream, fieldnames=["case_id", "split", "group", "category", "start", "end", "kind"]
        )
        writer.writeheader()
        writer.writerows(summary["prediction_errors"])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline case-level detector diagnostics")
    parser.add_argument("--run", required=True, type=Path)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args(argv)
    try:
        dataset = load_dataset(args.dataset)
        summary, rows = analyze(args.run, dataset)
        target = args.output_dir or args.run / "diagnostics"
        save(target, summary, rows)
        print(
            json.dumps(
                {
                    "output_dir": str(target),
                    "unsafe_negative_case_count": (
                        summary["classification"]["unsafe_negative_case_count"]
                    ),
                    "entity_outcomes": summary["entity_outcomes"],
                },
                indent=2,
            )
        )
        return 0
    except (DiagnosticsError, ValueError, OSError) as exc:
        # These diagnostics errors contain no prompt text or detector exception strings.
        print(f"Diagnostics failed: {type(exc).__name__}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
