"""Abstentions/errors, exact span boundaries, category errors, and metrics."""

from __future__ import annotations

from evaluation.dataset import Case, Entity
from evaluation.scoring import Prediction, _matched, score


def _case(name, text, spans=(), status="NO_PRIVATE_DETECTED", in_scope=True):
    return Case(
        name,
        text,
        tuple(spans),
        status,
        in_scope,
        "standard_sensitive" if spans else "clean",
        ("test",),
        "evaluation",
    )


def _outcome(name, status, spans=(), reasons=()):
    return Prediction(name, status, tuple(spans), 1.0, tuple(reasons))


def test_exact_match_does_not_reward_partial_redaction():
    expected = (Entity("EMAIL_ADDRESS", 1, 18),)
    partial = (Entity("EMAIL_ADDRESS", 5, 18),)
    assert _matched(expected, partial, relaxed=False) == []
    assert _matched(expected, partial, relaxed=True) == [(0, 0)]


def test_category_mismatch_is_both_false_positive_and_false_negative():
    cases = (_case("ONE-0001", "abcde", (Entity("PERSON", 0, 5),), "PRIVATE"),)
    outcomes = [_outcome("ONE-0001", "PRIVATE", (Entity("LOCATION", 0, 5),))]
    result = score(cases, outcomes)
    exact = result["entities_exact_full"]["overall"]
    assert exact["tp"] == 0 and exact["fp"] == 1 and exact["fn"] == 1


def test_unknown_does_not_inflate_recall_and_is_not_unsafe_negative():
    cases = (_case("ONE-0001", "secret", (Entity("API_CREDENTIAL", 0, 6),), "PRIVATE"),)
    result = score(cases, [_outcome("ONE-0001", "UNKNOWN", reasons=("LOW_CONFIDENCE",))])
    assert result["entities_exact_full"]["overall"]["fn"] == 1
    assert result["entities_exact_selective"]["overall"]["fn"] == 0
    assert result["in_scope_unknown_rate"] == 1.0
    assert result["unsafe_negative_rate"] == 0.0


def test_errors_are_not_silently_counted_as_unknown():
    cases = (_case("ONE-0001", "secret", (Entity("API_CREDENTIAL", 0, 6),), "PRIVATE"),)
    result = score(cases, [Prediction("ONE-0001", "ERROR", (), 1.0, (), "RuntimeError")])
    assert result["detector_error_count"] == 1
    assert result["in_scope_unknown_count"] == 0
    assert result["entities_exact_full"]["overall"]["fn"] == 1


def test_prompt_false_negative_rate_and_unsupported_count():
    cases = (
        _case("ONE-0001", "secret", (Entity("API_CREDENTIAL", 0, 6),), "PRIVATE"),
        _case("TWO-0001", "safe"),
        _case("THREE-0001", "café", (), "UNKNOWN", False),
    )
    outcomes = [
        _outcome("ONE-0001", "NO_PRIVATE_DETECTED"),
        _outcome("TWO-0001", "NO_PRIVATE_DETECTED"),
        _outcome("THREE-0001", "UNKNOWN"),
    ]
    result = score(cases, outcomes)
    assert result["unsafe_negative_rate"] == 1.0
    assert result["negative_specificity"] == 1.0
    assert result["unsupported_unknown_rate"] == 1.0


def test_bipartite_matching_never_double_counts_one_entity():
    expected = (Entity("EMAIL_ADDRESS", 0, 6), Entity("EMAIL_ADDRESS", 7, 13))
    actual = (Entity("EMAIL_ADDRESS", 0, 13),)
    assert len(_matched(expected, actual, relaxed=True)) == 1
