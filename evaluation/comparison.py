"""Stage 3: strict, paired comparisons of immutable detector-only benchmark runs.

This module never calls a detector or an external service. Comparisons only
proceed with identical ground truth, split, scoring specification, and case IDs.
Reports contain case identifiers and spans, never original prompt contents.
"""

from __future__ import annotations

import csv
import html
import json
import math
from pathlib import Path
from typing import Any

from evaluation.dataset import Case, Dataset, Entity
from evaluation.scoring import Prediction, _matched, score


class ComparisonError(ValueError):
    """Invalid or noncomparable run metadata or prediction artifacts."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ComparisonError(message)


def _number(value: Any) -> float | None:
    return value if isinstance(value, (float, int)) and not isinstance(value, bool) else None


def _delta(old: Any, new: Any) -> float | None:
    a, b = _number(old), _number(new)
    return b - a if a is not None and b is not None else None


def _read_run(root: Path, dataset: Dataset) -> dict[str, Any]:
    try:
        run = json.loads((root / "run.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise ComparisonError("Cannot read run.json") from exc
    _require(isinstance(run, dict) and run.get("schema_version") == 1, "Invalid run schema")
    _require(
        run.get("dataset_sha256") == dataset.manifest["cases_sha256"]
        and run.get("dataset_version") == dataset.manifest["dataset_version"],
        "Run dataset digest/version does not match frozen ground truth",
    )
    _require(
        run.get("split") in ("all", "development", "validation", "evaluation"),
        "Invalid run split",
    )
    _require(run.get("scoring_spec") == "strict-and-overlap-v1", "Unknown scoring spec")
    _require(
        isinstance(run.get("adapter"), str) and isinstance(run.get("run_id"), str),
        "Missing run identity",
    )
    return run


def _read_predictions(root: Path, cases: tuple[Case, ...]) -> list[Prediction]:
    by_id = {c.id: c for c in cases}
    values: dict[str, Prediction] = {}
    try:
        with (root / "predictions.jsonl").open("r", encoding="utf-8") as source:
            for raw_line in source:
                row = json.loads(raw_line)
                _require(isinstance(row, dict), "Invalid prediction row")
                cid = row.get("case_id")
                _require(isinstance(cid, str) and cid in by_id, "Unexpected prediction case ID")
                _require(cid not in values, "Duplicate prediction case ID")
                status = row.get("status")
                _require(
                    status in ("PRIVATE", "NO_PRIVATE_DETECTED", "UNKNOWN", "ERROR"),
                    "Invalid prediction status",
                )
                latency = row.get("latency_ms")
                _require(
                    type(latency) in (int, float) and math.isfinite(latency) and latency >= 0,
                    "Invalid prediction latency",
                )
                raw_entities = row.get("entities")
                _require(isinstance(raw_entities, list), "Invalid prediction findings")
                findings: list[Entity] = []
                for item in raw_entities:
                    _require(isinstance(item, dict), "Invalid predicted finding")
                    cat, start, end = item.get("category"), item.get("start"), item.get("end")
                    _require(
                        isinstance(cat, str)
                        and cat.isupper()
                        and type(start) is int
                        and type(end) is int
                        and 0 <= start < end <= len(by_id[cid].text),
                        "Invalid predicted span",
                    )
                    findings.append(Entity(cat, start, end))
                _require(
                    (status == "PRIVATE" and bool(findings))
                    or (status != "PRIVATE" and not findings),
                    "Prediction status and findings disagree",
                )
                reasons = row.get("reason_codes", [])
                _require(
                    isinstance(reasons, (list, tuple)) and all(isinstance(r, str) for r in reasons),
                    "Invalid prediction reasons",
                )
                error_type = row.get("error_type")
                _require(
                    error_type is None or isinstance(error_type, str),
                    "Invalid error type",
                )
                values[cid] = Prediction(
                    cid, status, tuple(findings), float(latency), tuple(reasons), error_type
                )
    except (OSError, UnicodeError, ValueError) as exc:
        if isinstance(exc, ComparisonError):
            raise
        raise ComparisonError("Cannot read valid predictions.jsonl") from exc
    _require(set(values) == set(by_id), "Missing prediction case IDs")
    return [values[c.id] for c in cases]


def _metric_summary(metrics: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status_accuracy": metrics["status_accuracy"],
        "unsafe_negative_rate": metrics["unsafe_negative_rate"],
        "positive_detection_recall": metrics["positive_detection_recall"],
        "false_positive_rate_on_negatives": metrics["false_positive_rate_on_negatives"],
        "in_scope_unknown_rate": metrics["in_scope_unknown_rate"],
        "detector_error_count": metrics["detector_error_count"],
    }
    for method in ("exact", "overlap"):
        values = metrics[f"entities_{method}_full"]["overall"]
        for metric in ("tp", "fp", "fn", "precision", "recall", "f1"):
            result[f"{method}_{metric}"] = values[metric]
    return result


def compare_runs(
    baseline: Path, candidate: Path, dataset: Dataset
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    """Return a summary and per-category/per-case changes using one scorer."""
    old, new = _read_run(baseline, dataset), _read_run(candidate, dataset)
    _require(old["split"] == new["split"], "Run splits differ")
    _require(old["scoring_spec"] == new["scoring_spec"], "Run scoring specs differ")
    cases = dataset.select(old["split"])
    a = _read_predictions(baseline, cases)
    b = _read_predictions(candidate, cases)
    am, bm = score(cases, a), score(cases, b)
    # Re-score from frozen predictions rather than trusting copied run.json metrics.
    for run, observed in ((old, am), (new, bm)):
        _require(
            run.get("metrics") == observed,
            "Saved metrics disagree with predictions under the declared scoring spec",
        )
    x, y = _metric_summary(am), _metric_summary(bm)
    metrics = {
        key: {"baseline": value, "candidate": y[key], "delta": _delta(value, y[key])}
        for key, value in x.items()
    }
    categories: list[dict[str, Any]] = []
    a_cat = am["entities_exact_full"]["by_category"]
    b_cat = bm["entities_exact_full"]["by_category"]
    for cat in sorted(set(a_cat) | set(b_cat)):
        orig = a_cat.get(cat, {})
        curr = b_cat.get(cat, {})
        categories.append(
            {
                "category": cat,
                **{
                    f"baseline_{key}": orig.get(key)
                    for key in ("tp", "fp", "fn", "precision", "recall", "f1")
                },
                **{
                    f"candidate_{key}": curr.get(key)
                    for key in ("tp", "fp", "fn", "precision", "recall", "f1")
                },
                "recall_delta": _delta(orig.get("recall"), curr.get("recall")),
                "f1_delta": _delta(orig.get("f1"), curr.get("f1")),
            }
        )
    changes: list[dict[str, Any]] = []
    fixed_unsafe, new_unsafe = 0, 0
    for case, old_p, new_p in zip(cases, a, b, strict=True):
        unsafe_old = case.expected_status == "PRIVATE" and old_p.status == "NO_PRIVATE_DETECTED"
        unsafe_new = case.expected_status == "PRIVATE" and new_p.status == "NO_PRIVATE_DETECTED"
        fixed_unsafe += unsafe_old and not unsafe_new
        new_unsafe += unsafe_new and not unsafe_old
        if old_p.status == new_p.status and old_p.entities == new_p.entities:
            continue
        a_matches = len(_matched(case.entities, old_p.entities, relaxed=False))
        b_matches = len(_matched(case.entities, new_p.entities, relaxed=False))
        changes.append(
            {
                "case_id": case.id,
                "group": case.group,
                "split": case.split,
                "expected_status": case.expected_status,
                "baseline_status": old_p.status,
                "candidate_status": new_p.status,
                "baseline_exact_tp": a_matches,
                "candidate_exact_tp": b_matches,
                "expected_entities": len(case.entities),
                "baseline_found_entities": len(old_p.entities),
                "candidate_found_entities": len(new_p.entities),
                "unsafe_negative_resolved": bool(unsafe_old and not unsafe_new),
                "new_unsafe_negative": bool(unsafe_new and not unsafe_old),
            }
        )
    summary = {
        "schema_version": 1,
        "comparison_spec": "paired-detection-v1",
        "scoring_spec": old["scoring_spec"],
        "dataset_sha256": dataset.manifest["cases_sha256"],
        "dataset_version": dataset.manifest["dataset_version"],
        "split": old["split"],
        "cases": len(cases),
        "baseline": {
            key: old.get(key)
            for key in (
                "run_id",
                "adapter",
                "git_commit",
                "detector_config_digest",
                "detector_artifact_digest",
                "adapter_metadata",
                "runtime",
                "timing",
            )
        },
        "candidate": {
            key: new.get(key)
            for key in (
                "run_id",
                "adapter",
                "git_commit",
                "detector_config_digest",
                "detector_artifact_digest",
                "adapter_metadata",
                "runtime",
                "timing",
            )
        },
        "metrics": metrics,
        "changed_case_count": len(changes),
        "unsafe_negative_cases_resolved": fixed_unsafe,
        "new_unsafe_negative_cases": new_unsafe,
        "warning": (
            "These are detector-only results on synthetic prompts; unsafe-negative "
            "classifications are not proven external forwards. Check enforcement separately."
        ),
    }
    return summary, categories, changes


def _fmt(value: Any) -> str:
    if value is None:
        return "N/A"
    if isinstance(value, float):
        return f"{value:.4f}"
    return str(value)


def _html(summary: dict[str, Any], categories: list[dict[str, Any]]) -> str:
    def escape(obj: Any) -> str:
        return html.escape(_fmt(obj), quote=True)

    metric_rows = "\n".join(
        "<tr>"
        + "".join(
            f"<td>{escape(value)}</td>"
            for value in (name, data["baseline"], data["candidate"], data["delta"])
        )
        + "</tr>"
        for name, data in summary["metrics"].items()
    )
    cat_rows = "\n".join(
        "<tr>"
        + "".join(
            f"<td>{escape(row.get(field))}</td>"
            for field in (
                "category",
                "baseline_tp",
                "baseline_fp",
                "baseline_fn",
                "baseline_recall",
                "candidate_tp",
                "candidate_fp",
                "candidate_fn",
                "candidate_recall",
                "recall_delta",
            )
        )
        + "</tr>"
        for row in categories
    )
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>Paired Detector Evaluation</title>
<style>body{{max-width:1100px;margin:2rem auto;padding:1rem;font:15px system-ui,Arial,sans-serif;color:#18243a}}
table{{border-collapse:collapse;width:100%;margin:1rem 0 2rem}}td,th{{border-bottom:1px solid #d8e0e8;padding:.6rem;text-align:left}}
th{{background:#eff2f6}}.note{{color:#506075}}code{{overflow-wrap:anywhere}}</style></head><body>
<h1>Paired Detection Evaluation</h1><p>Baseline: <code>{escape(summary["baseline"]["run_id"])}</code>
({escape(summary["baseline"]["adapter"])}) · Candidate:
<code>{escape(summary["candidate"]["run_id"])}</code> ({escape(summary["candidate"]["adapter"])})</p>
<p>Dataset digest: <code>{escape(summary["dataset_sha256"])}</code>; split:
{escape(summary["split"])}; cases: {escape(summary["cases"])}</p>
<p class="note">{escape(summary["warning"])} Missing metrics are N/A. Deltas are candidate minus baseline.
UNKNOWN and ERROR remain separate. Run environments and adapter metadata are recorded in comparison.json.</p>
<h2>Metrics</h2><table><thead><tr><th>Metric</th><th>Baseline</th><th>Candidate</th><th>Delta</th></tr></thead>
<tbody>{metric_rows}</tbody></table>
<h2>Exact span scores by category</h2>
<table><thead><tr><th>Category</th><th>Base TP</th><th>Base FP</th><th>Base FN</th><th>Base recall</th><th>Candidate TP</th><th>Candidate FP</th><th>Candidate FN</th><th>Candidate recall</th><th>Delta</th></tr></thead><tbody>{cat_rows}</tbody></table>
<p class="note">Only case IDs, category names, span counts and scores are exported, never prompt text.</p>
</body></html>"""


def write_comparison(
    output: Path,
    summary: dict[str, Any],
    categories: list[dict[str, Any]],
    changes: list[dict[str, Any]],
) -> None:
    output.mkdir(parents=True, exist_ok=False)
    (output / "comparison.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    category_fields = (
        "category",
        "baseline_tp",
        "baseline_fp",
        "baseline_fn",
        "baseline_precision",
        "baseline_recall",
        "baseline_f1",
        "candidate_tp",
        "candidate_fp",
        "candidate_fn",
        "candidate_precision",
        "candidate_recall",
        "candidate_f1",
        "recall_delta",
        "f1_delta",
    )
    with (output / "categories.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=category_fields)
        writer.writeheader()
        writer.writerows(categories)
    fields = (
        "case_id",
        "group",
        "split",
        "expected_status",
        "baseline_status",
        "candidate_status",
        "baseline_exact_tp",
        "candidate_exact_tp",
        "expected_entities",
        "baseline_found_entities",
        "candidate_found_entities",
        "unsafe_negative_resolved",
        "new_unsafe_negative",
    )
    with (output / "changed_cases.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(changes)
    (output / "comparison.html").write_text(_html(summary, categories), encoding="utf-8")
