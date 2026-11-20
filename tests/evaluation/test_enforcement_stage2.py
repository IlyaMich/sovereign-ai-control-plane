"""These tests use real orchestrator, real SQLite audit, and fake policy/model/detector.

They never reach a live OPA, model, or external destination.
"""

from __future__ import annotations

import json

import pytest

from app.domain.contracts import DetectionResult, DetectionStatus, Finding, Sensitivity
from evaluation.dataset import Case, Entity
from evaluation.enforcement.cli import save_report
from evaluation.enforcement.core import (
    Scenario,
    _classify_safety,
    replay_cases,
    run_scenario,
    run_suite,
)


@pytest.mark.asyncio
async def test_controlled_security_suite_passes():
    report = await run_suite()
    assert report["cases"] >= 20
    assert report["failed"] == 0, [r for r in report["rows"] if not r["pass"]]
    assert report["passed"] == report["cases"]


@pytest.mark.asyncio
async def test_precommit_failure_never_calls_model():
    row = await run_scenario(
        Scenario(
            "audit_failure",
            "hello",
            (),
            (),
            injection="audit_decision",
            expected_status="EXCEPTION",
            expected_invocations=0,
        )
    )
    assert row["pass"]
    assert row["model_invocations"] == 0
    assert row["audit_event_count"] == 0


@pytest.mark.asyncio
async def test_second_scan_failure_prevents_forward():
    email = "alice@example.com"
    row = await run_scenario(
        Scenario(
            "rescan",
            f"Email {email}",
            (("EMAIL_ADDRESS", email),),
            (("EMAIL_ADDRESS", email),),
            "external-simulator",
            after_redaction="unknown",
            expected_status="BLOCKED",
            expected_invocations=0,
            expected_reason="REDACTION_FAILED",
        )
    )
    assert row["pass"]
    assert not row["model_invocations"]


def test_invariant_detects_partially_redacted_secret():
    # This is a negative control: suppressing just the PEM header can leave key bytes.
    raw = "-----BEGIN PRIVATE KEY-----SECRET_PAYLOAD-----END PRIVATE KEY-----"
    cls = DetectionResult(
        DetectionStatus.PRIVATE,
        Sensitivity.HIGH,
        (Finding("PRIVATE_KEY", 0, 27, "synthetic", 0.99),),
        ("PRIVATE_KEY",),
        "fixture",
        (),
        "digest",
    )
    safe, issues = _classify_safety(
        expected=(Entity("PRIVATE_KEY", 0, len(raw)),),
        classification=cls,
        actual_forward=True,
        destination="external-simulator",
        transformed=True,
    )
    assert not safe
    assert "UNSAFE_EXTERNAL_FORWARD" in issues


@pytest.mark.asyncio
async def test_replay_detects_unsafe_external_forward():
    text = "Contact alice@example.com"
    cid = "ADVERSARIAL-9999"
    c = Case(
        cid,
        text,
        (Entity("EMAIL_ADDRESS", 8, len(text)),),
        "PRIVATE",
        True,
        "adversarial",
        ("email",),
        "development",
    )

    class BlindDetector:
        def detect(self, prompt):
            return DetectionResult(
                DetectionStatus.NO_PRIVATE_DETECTED,
                Sensitivity.NONE,
                (),
                ("EMAIL_ADDRESS",),
                "fixture",
                (),
                "fixture-config",
            )

    report = await replay_cases((c,), detector=BlindDetector())
    assert report["cases"] == 1
    assert report["unsafe_external_forward_count"] == 1
    assert report["rows"][0]["status"] == "COMPLETED"
    assert "UNSAFE_EXTERNAL_FORWARD" in report["rows"][0]["issues"]


def test_saved_reports_do_not_contain_prompts(tmp_path):
    report = {
        "evaluation_mode": "controlled",
        "rows": [{"case_id": "CASE-001", "status": "BLOCKED", "issues": []}],
    }
    save_report(tmp_path / "report", report)
    txt = (tmp_path / "report" / "cases.jsonl").read_text()
    assert "CASE-001" in txt
    assert "prompt" not in txt
    assert (
        json.loads((tmp_path / "report" / "run.json").read_text())["evaluation_mode"]
        == "controlled"
    )


def test_checker_rejects_forwarded_payload_mismatch():
    text = "Contact alice@example.com"
    offset = text.index("alice@example.com")
    cls = DetectionResult(
        DetectionStatus.PRIVATE,
        Sensitivity.MEDIUM,
        (Finding("EMAIL_ADDRESS", offset, len(text), "synthetic", 0.99),),
        ("EMAIL_ADDRESS",),
        "fixture",
        (),
        "digest",
    )
    safe, issues = _classify_safety(
        expected=(Entity("EMAIL_ADDRESS", offset, len(text)),),
        classification=cls,
        actual_forward=True,
        destination="external-simulator",
        transformed=True,
        source_text=text,
        forwarded_text=text,
    )
    assert not safe
    assert "FORWARDED_PAYLOAD_MISMATCH" in issues
