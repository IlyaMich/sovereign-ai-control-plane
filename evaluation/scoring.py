"""Strict/overlap span matching and abstention-aware classification metrics."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any

from evaluation.dataset import Case, Entity


@dataclass(frozen=True)
class Prediction:
    case_id: str
    status: str
    entities: tuple[Entity, ...]
    latency_ms: float
    reason_codes: tuple[str, ...] = ()
    error_type: str | None = None


def _fraction(a: int, b: int) -> float | None:
    return a / b if b else None


def _prf(tp: int, fp: int, fn: int) -> dict[str, Any]:
    precision = _fraction(tp, tp + fp)
    recall = _fraction(tp, tp + fn)
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and precision + recall > 0
        else None
    )
    return {"tp": tp, "fp": fp, "fn": fn, "precision": precision, "recall": recall, "f1": f1}


def _matched(
    expected: tuple[Entity, ...], actual: tuple[Entity, ...], *, relaxed: bool
) -> list[tuple[int, int]]:
    """Max-cardinality, deterministic one-to-one matching; never double-count a span."""

    def compatible(a: Entity, b: Entity) -> bool:
        if a.category != b.category:
            return False
        return (
            (a.start < b.end and b.start < a.end)
            if relaxed
            else (a.start == b.start and a.end == b.end)
        )

    links = [[j for j, p in enumerate(actual) if compatible(e, p)] for e in expected]
    # Check all augmenting paths, so greedy prediction order cannot undercount true positives.
    assigned: dict[int, int] = {}

    def visit(i: int, used: set[int]) -> bool:
        for j in links[i]:
            if j in used:
                continue
            used.add(j)
            if j not in assigned or visit(assigned[j], used):
                assigned[j] = i
                return True
        return False

    for i in range(len(expected)):
        visit(i, set())
    return sorted((i, j) for j, i in assigned.items())


def _entity_metrics(
    cases: tuple[Case, ...], predictions: dict[str, Prediction], *, relaxed: bool, selective: bool
) -> dict[str, Any]:
    by_cat: dict[str, Counter[str]] = defaultdict(Counter)
    overall: Counter[str] = Counter()
    for case in cases:
        if not case.in_scope:
            continue
        prediction = predictions[case.id]
        if selective and prediction.status not in ("PRIVATE", "NO_PRIVATE_DETECTED"):
            continue
        matched = _matched(case.entities, prediction.entities, relaxed=relaxed)
        expected_match = {i for i, _ in matched}
        predicted_match = {j for _, j in matched}
        for i, e in enumerate(case.entities):
            by_cat[e.category]["tp" if i in expected_match else "fn"] += 1
            overall["tp" if i in expected_match else "fn"] += 1
        for j, e in enumerate(prediction.entities):
            if j not in predicted_match:
                by_cat[e.category]["fp"] += 1
                overall["fp"] += 1
    categories = {key: _prf(x["tp"], x["fp"], x["fn"]) for key, x in sorted(by_cat.items())}
    return {"overall": _prf(overall["tp"], overall["fp"], overall["fn"]), "by_category": categories}


def score(cases: tuple[Case, ...], outcomes: list[Prediction]) -> dict[str, Any]:
    ids = {case.id for case in cases}
    if len(outcomes) != len(cases) or {o.case_id for o in outcomes} != ids:
        raise ValueError("Predictions must contain exactly one result per case")
    predictions = {o.case_id: o for o in outcomes}
    if len(predictions) != len(outcomes):
        raise ValueError("Duplicate prediction IDs")
    confusion: dict[str, Counter[str]] = defaultdict(Counter)
    unknown_reasons: Counter[str] = Counter()
    by_group: dict[str, Counter[str]] = defaultdict(Counter)
    in_scope = [c for c in cases if c.in_scope]
    positive = [c for c in in_scope if c.expected_status == "PRIVATE"]
    negative = [c for c in in_scope if c.expected_status == "NO_PRIVATE_DETECTED"]
    abstained = 0
    errors = 0
    correct = 0
    for c in cases:
        p = predictions[c.id]
        confusion[c.expected_status][p.status] += 1
        correct += p.status == c.expected_status
        by_group[c.group]["total"] += 1
        by_group[c.group]["correct"] += p.status == c.expected_status
        if c.in_scope and p.status == "UNKNOWN":
            abstained += 1
            unknown_reasons.update(p.reason_codes or ("UNKNOWN_NO_REASON",))
        if p.status == "ERROR":
            errors += 1
    return {
        "total_cases": len(cases),
        "in_scope_cases": len(in_scope),
        "unsupported_cases": len(cases) - len(in_scope),
        "status_accuracy": _fraction(correct, len(cases)),
        "status_confusion": {k: dict(v) for k, v in sorted(confusion.items())},
        "group_accuracy": {
            k: {
                "total": v["total"],
                "correct": v["correct"],
                "accuracy": _fraction(v["correct"], v["total"]),
            }
            for k, v in sorted(by_group.items())
        },
        "positive_detection_recall": _fraction(
            sum(predictions[c.id].status == "PRIVATE" for c in positive), len(positive)
        ),
        "unsafe_negative_rate": _fraction(
            sum(predictions[c.id].status == "NO_PRIVATE_DETECTED" for c in positive), len(positive)
        ),
        "negative_specificity": _fraction(
            sum(predictions[c.id].status == "NO_PRIVATE_DETECTED" for c in negative), len(negative)
        ),
        "false_positive_rate_on_negatives": _fraction(
            sum(predictions[c.id].status == "PRIVATE" for c in negative), len(negative)
        ),
        "in_scope_unknown_count": abstained,
        "in_scope_unknown_rate": _fraction(abstained, len(in_scope)),
        "unknown_reasons": dict(sorted(unknown_reasons.items())),
        "unsupported_unknown_rate": _fraction(
            sum(predictions[c.id].status == "UNKNOWN" for c in cases if not c.in_scope),
            len(cases) - len(in_scope),
        ),
        "detector_error_count": errors,
        "entities_exact_full": _entity_metrics(cases, predictions, relaxed=False, selective=False),
        "entities_exact_selective": _entity_metrics(
            cases, predictions, relaxed=False, selective=True
        ),
        "entities_overlap_full": _entity_metrics(cases, predictions, relaxed=True, selective=False),
    }
