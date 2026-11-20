"""Regression coverage for response-side DLP evaluation and signed evidence.

All model responses are synthetic, and audit signing keys are temporary.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
from pathlib import Path

import pytest

from app.audit.sqlite_store import SQLiteAuditStore
from app.audit.verify import VerificationError, verify_database
from app.policy.replay import ReplayError
from evaluation.dataset import Entity
from evaluation.output.cli import _fixture_digest, dataset_scenarios, main, save_report
from evaluation.output.core import (
    OutputScenario,
    _make_case,
    controlled_scenarios,
    evaluate_scenarios,
)


@pytest.mark.asyncio
async def test_controlled_output_dlp_and_signed_offline_replay():
    report = await evaluate_scenarios(
        controlled_scenarios(),
        dataset_sha256=_fixture_digest(controlled_scenarios()),
    )

    assert report["cases"] == 15
    assert report["failed"] == 0, report["metrics"]["issues"]
    assert report["passed"] == 15
    metrics = report["metrics"]
    assert metrics["released_count"] == 2
    assert metrics["blocked_count"] == 11
    assert metrics["error_count"] == 2
    assert metrics["unsafe_sensitive_release_count"] == 0
    assert metrics["false_block_count"] == 0
    assert metrics["output_detection"]["entities_exact_full"]["overall"]["fn"] == 0

    evidence = report["evidence"]
    assert evidence["status"] == "EVIDENCE_PACKAGE_VERIFIED"
    assert evidence["signed_events_verified"] == 29
    assert evidence["input_policy_decisions_replayed"] == 15
    assert evidence["output_policy_decisions_replayed"] == 7
    assert evidence["output_local_denials_verified"] == 6
    assert evidence["audit_key_pinned_for_this_run"] is True
    assert evidence["checkpoint_pinned_for_this_run"] is True
    assert evidence["release_signer_trusted_externally"] is False


@pytest.mark.asyncio
async def test_known_sensitive_false_negative_is_counted_as_unsafe_release():
    case = _make_case(
        "OUTPUT-MISSED-EMAIL", "Synthetic contact alice@example.com",
        (("EMAIL_ADDRESS", "alice@example.com"),),
    )
    spec = OutputScenario(
        case, "OUTPUT_BLOCKED", "OUTPUT_PRIVATE_DATA_BLOCKED",
        "detector_false_negative",
    )
    report = await evaluate_scenarios((spec,))
    assert report["metrics"]["unsafe_sensitive_release_count"] == 1
    assert report["failed"] == 1
    assert report["metrics"]["output_detection"]["unsafe_negative_rate"] == 1.0
    assert "UNSAFE_SENSITIVE_OUTPUT_RELEASE" in report["rows"][0]["issues"]
    assert report["rows"][0]["released"] is True
    assert report["rows"][0]["observed_categories"] == []
    # A correctly signed audit record is not a guarantee of correct detection.
    assert report["evidence"]["signed_events_verified"] == 2


@pytest.mark.asyncio
async def test_false_positive_blocks_benign_output_and_is_reported():
    case = _make_case("OUTPUT-FP", "Safe synthetic explanation only")
    spec = OutputScenario(case, "COMPLETED", fault="detector_false_positive")
    report = await evaluate_scenarios((spec,))
    assert report["failed"] == 1
    assert report["metrics"]["false_block_count"] == 1
    assert report["metrics"]["released_count"] == 0
    assert report["metrics"]["output_detection"]["false_positive_rate_on_negatives"] == 1.0
    assert report["rows"][0]["observed_categories"] == ["PERSON"]
    assert report["rows"][0]["observed_recognizers"] == ["synthetic-output-fixture"]


@pytest.mark.asyncio
async def test_signed_but_semantically_false_output_evidence_fails_offline_review():
    spec = OutputScenario(
        _make_case("OUTPUT-FALSE-SIGNED-EVIDENCE", "Benign generated answer"),
        "COMPLETED",
        fault="signed_outcome_mismatch",
    )
    # FaultAudit signs a contradictory released marker with a legitimate
    # temporary audit key. The replay reviewer must reject semantics, not
    # merely accept the valid Ed25519 signature.
    with pytest.raises(ReplayError, match="output enforcement evidence"):
        await evaluate_scenarios((spec,))


def test_dataset_adapts_frozen_ground_truth_as_model_responses():
    cases, digest = dataset_scenarios("development", limit=12)
    assert len(cases) == 12
    assert len(digest) == 64
    assert all(spec.case.split == "development" for spec in cases)
    for spec in cases:
        if spec.case.entities:
            assert spec.expected_outcome == "OUTPUT_BLOCKED"
        elif spec.case.expected_status == "NO_PRIVATE_DETECTED":
            assert spec.expected_outcome == "COMPLETED"
        else:
            assert spec.expected_outcome == "OUTPUT_BLOCKED"


def test_report_writes_only_ids_and_structural_results(tmp_path: Path):
    report = asyncio.run(evaluate_scenarios(controlled_scenarios()))
    output = tmp_path / "report"
    save_report(output, report)

    all_saved = "\n".join(
        (output / name).read_text(encoding="utf-8")
        for name in ("run.json", "cases.jsonl", "cases.csv", "report.html")
    )
    for value in (
        "alice@example.com",
        "202-555-0102",
        "AKIAABCDEFGHIJKLMNOP",
        "-----BEGIN PRIVATE KEY-----",
        "Response detector temporarily unavailable",
    ):
        assert value not in all_saved
    assert json.loads((output / "run.json").read_text())["cases"] == 15
    assert len((output / "cases.jsonl").read_text().splitlines()) == 15


def test_report_refuses_overwrite(tmp_path: Path):
    report = asyncio.run(evaluate_scenarios(controlled_scenarios()[:1]))
    folder = tmp_path / "existing"
    save_report(folder, report)
    with pytest.raises(FileExistsError):
        save_report(folder, report)


def test_tampering_a_signed_output_event_is_rejected(tmp_path: Path):
    store = SQLiteAuditStore(
        str(tmp_path / "audit.sqlite"), str(tmp_path / "audit-key.pem")
    )
    store.commit("case-1", "eval", "DECISION", {"policy_evidence_version": "2"})
    store.commit(
        "case-1", "eval", "OUTCOME",
        {"output_dlp": {"released": False, "schema_version": 1}},
    )
    public = str(tmp_path / "audit-key.pub.pem")
    assert verify_database(str(store.db_path), public)["verified_events"] == 2
    with sqlite3.connect(store.db_path) as connection:
        connection.execute(
            "UPDATE events SET event_json = REPLACE(event_json, 'false', 'true') "
            "WHERE event_type = 'OUTCOME'"
        )
    with pytest.raises(VerificationError):
        verify_database(str(store.db_path), public)


def test_cli_controlled_smoke_and_failure_exit(tmp_path: Path, monkeypatch):
    output = tmp_path / "controlled"
    assert main(["--mode", "controlled", "--limit", "2", "--output-dir", str(output)]) == 0
    assert (output / "report.html").is_file()
    assert (output / "run.json").is_file()

    sensitive = _make_case(
        "OUTPUT-LEAK", "Email alice@example.com",
        (("EMAIL_ADDRESS", "alice@example.com"),),
    )
    unsafe = OutputScenario(
        sensitive, "OUTPUT_BLOCKED", fault="detector_false_negative"
    )
    monkeypatch.setattr("evaluation.output.cli.controlled_scenarios", lambda: (unsafe,))
    assert main([
        "--mode", "controlled",
        "--output-dir", str(tmp_path / "unsafe"),
    ]) == 1


def test_missing_host_opa_cli_reports_actionable_error(tmp_path: Path, capsys):
    missing = tmp_path / "absent-opa.exe"
    code = main([
        "--mode", "controlled",
        "--policy", "opa-cli",
        "--opa-bin", str(missing),
    ])
    assert code == 2
    assert "Local OPA CLI not found" in capsys.readouterr().err


def test_ground_truth_entity_offsets_are_exact():
    case = _make_case(
        "OUTPUT-SPAN", "Email alice@example.com",
        (("EMAIL_ADDRESS", "alice@example.com"),),
    )
    assert case.entities == (Entity("EMAIL_ADDRESS", 6, 23),)
