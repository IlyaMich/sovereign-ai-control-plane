"""Instrumented end-to-end orchestrator evaluation, never live model egress.

All simulated model calls are in-memory; all audit data is written under a
TemporaryDirectory. Fixture-mode checks orchestration, not real Rego behavior.
"""

from __future__ import annotations

import tempfile
import uuid
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.application.orchestrator import RequestOrchestrator
from app.audit.sqlite_store import AuditUnavailable, SQLiteAuditStore
from app.domain.contracts import (
    DetectionResult,
    DetectionStatus,
    Effect,
    Finding,
    ModelResult,
    Obligation,
    PolicyDecision,
    Principal,
    PromptCommand,
    Sensitivity,
)
from app.enforcement.gateway import Destination, DestinationRegistry, EnforcementPlanner
from app.release.approvals import ReleaseIntegrityError
from evaluation.dataset import Case, Entity
from evaluation.enforcement.policy import FixturePolicy

DESTINATIONS = (
    Destination("sovereign-model", "http://sovereign-model:9000", "INTERNAL"),
    Destination("external-simulator", "http://egress-gateway:9010", "EXTERNAL_SIMULATED"),
)
PRINCIPAL = Principal("evaluation-only", "evaluation-only", ("tester",))


@dataclass(frozen=True)
class Scenario:
    id: str
    prompt: str
    findings: tuple[tuple[str, str], ...]
    ground_truth: tuple[tuple[str, str], ...]
    destination: str = "sovereign-model"
    purpose: str = "GENERAL"
    after_redaction: str = "clean"
    injection: str = ""
    expected_status: str = "COMPLETED"
    expected_invocations: int = 1
    expected_reason: str | None = None


class ScenarioDetector:
    """Deterministic, deliberately injectable classifications for failure testing."""

    def __init__(self, spec: Scenario):
        self.spec = spec

    def detect(self, prompt: str) -> DetectionResult:
        if self.spec.injection == "detector_failure":
            raise RuntimeError("Deliberate detector failure")
        if "[REDACTED_" in prompt:
            if self.spec.after_redaction == "unknown":
                return DetectionResult.unknown("LOW_CONFIDENCE_FINDING")
            if self.spec.after_redaction == "private":
                idx = prompt.index("[REDACTED_")
                return _private((Finding("PERSON", idx, idx + len("[REDACTED_"), "fixture", 0.99),))
            return _clean()
        if self.spec.injection == "unknown":
            return DetectionResult.unknown("LOW_CONFIDENCE_FINDING")
        if self.spec.injection == "unsupported":
            return DetectionResult.unknown("UNSUPPORTED_CHARACTER_SET")
        findings = tuple(_finding(prompt, cat, text) for cat, text in self.spec.findings)
        return _private(findings) if findings else _clean()


def _finding(text: str, category: str, value: str) -> Finding:
    begin = text.index(value)
    return Finding(category, begin, begin + len(value), "stage2-fixture", 0.99)


def _clean() -> DetectionResult:
    return DetectionResult(
        DetectionStatus.NO_PRIVATE_DETECTED,
        Sensitivity.NONE,
        (),
        (
            "EMAIL_ADDRESS",
            "PHONE_NUMBER",
            "PERSON",
            "CREDIT_CARD",
            "US_SSN",
            "API_CREDENTIAL",
            "PRIVATE_KEY",
        ),
        "presidio-spacy-v1",
        ("DETECTION_COMPLETE",),
        "stage2-fixture-config",
    )


def _private(findings: tuple[Finding, ...]) -> DetectionResult:
    high = {"CREDIT_CARD", "US_SSN", "API_CREDENTIAL", "PRIVATE_KEY", "IBAN_CODE"}
    sensitivity = (
        Sensitivity.HIGH if any(f.category in high for f in findings) else Sensitivity.MEDIUM
    )
    return DetectionResult(
        DetectionStatus.PRIVATE,
        sensitivity,
        findings,
        _clean().coverage,
        "presidio-spacy-v1",
        ("DETECTION_COMPLETE",),
        "stage2-fixture-config",
    )


class RecordingGateway:
    def __init__(self, audit: SQLiteAuditStore, *, fail: bool = False):
        self.audit = audit
        self.fail = fail
        self.calls: list[tuple[str, str, str]] = []
        self.decision_before_call = True

    async def invoke(self, request_id: str, prompt: str, destination_id: str) -> ModelResult:
        events = self.audit.get_events(request_id, PRINCIPAL.tenant_id)
        if not events or events[0]["event"]["event_type"] != "DECISION":
            self.decision_before_call = False
        self.calls.append((request_id, prompt, destination_id))
        if self.fail:
            raise TimeoutError("Deliberate model timeout")
        return ModelResult(destination_id, "stage2-simulated-output")


class FaultAudit:
    def __init__(self, store: SQLiteAuditStore, event_type: str):
        self.store = store
        self.event_type = event_type

    def fingerprint(self, prompt: str) -> str:
        return self.store.fingerprint(prompt)

    def commit(self, request_id: str, tenant_id: str, event_type: str, payload: dict):
        if event_type == self.event_type:
            raise AuditUnavailable("Injected audit failure")
        return self.store.commit(request_id, tenant_id, event_type, payload)


class FailingPolicy:
    async def evaluate(self, context):
        raise RuntimeError("Deliberate OPA outage")


class UnsafePolicy:
    async def evaluate(self, context):
        return PolicyDecision(
            Effect.PERMIT,
            (Obligation("ROUTE", "external-simulator"),),
            ("DELIBERATE_INVALID_POLICY_PLAN",),
            "fixture-v1",
        )


class BrokenRelease:
    def verify_active(self, **kwargs):
        raise ReleaseIntegrityError("Deliberate untrusted release")


def _gold(text: str, pairs: tuple[tuple[str, str], ...]) -> tuple[Entity, ...]:
    return tuple(
        Entity(cat, text.index(value), text.index(value) + len(value)) for cat, value in pairs
    )


def _is_span_covered(gt: Entity, redacted: tuple[Finding, ...]) -> bool:
    """Ground-truth bytes must all be in actually redacted recognizer spans."""
    intervals = sorted(
        (max(gt.start, f.start), min(gt.end, f.end))
        for f in redacted
        if f.start < gt.end and gt.start < f.end
    )
    cursor = gt.start
    for a, b in intervals:
        if a > cursor:
            return False
        cursor = max(cursor, b)
        if cursor >= gt.end:
            return True
    return False


def _expected_forwarded_text(
    source: str, classification: DetectionResult, transformed: bool
) -> str | None:
    """Independent reconstruction of what the gateway should receive."""
    if not transformed:
        return source
    previous = 0
    parts: list[str] = []
    for finding in sorted(classification.findings, key=lambda f: (f.start, f.end, f.category)):
        if not previous <= finding.start < finding.end <= len(source):
            return None
        parts.append(source[previous : finding.start])
        parts.append(f"[REDACTED_{finding.category}]")
        previous = finding.end
    parts.append(source[previous:])
    return "".join(parts)


def _classify_safety(
    *,
    expected: tuple[Entity, ...],
    classification: DetectionResult,
    actual_forward: bool,
    destination: str,
    transformed: bool,
    source_text: str | None = None,
    forwarded_text: str | None = None,
) -> tuple[bool, list[str]]:
    violations: list[str] = []
    if actual_forward and classification.status == DetectionStatus.UNKNOWN:
        violations.append("FORWARDED_UNKNOWN_CLASSIFICATION")
    if actual_forward and source_text is not None:
        expected_text = _expected_forwarded_text(source_text, classification, transformed)
        if expected_text is None or forwarded_text != expected_text:
            violations.append("FORWARDED_PAYLOAD_MISMATCH")
    if actual_forward and destination == "external-simulator" and expected:
        for entity in expected:
            if not transformed or not _is_span_covered(entity, classification.findings):
                violations.append("UNSAFE_EXTERNAL_FORWARD")
                break
    return not violations, violations


def _create_orchestrator(
    detector: Any,
    policy: Any,
    store: SQLiteAuditStore,
    model: RecordingGateway,
    *,
    audit_fault: str = "",
    release_failure: bool = False,
) -> RequestOrchestrator:
    registry = DestinationRegistry(DESTINATIONS)
    return RequestOrchestrator(
        detector=detector,
        policy=policy,
        audit=FaultAudit(store, audit_fault) if audit_fault else store,
        model=model,
        planner=EnforcementPlanner(frozenset(d.id for d in DESTINATIONS), registry),
        release_store=BrokenRelease() if release_failure else None,
    )


def scenario_cases() -> tuple[Scenario, ...]:
    email = "alice@example.com"
    credential = "AKIAABCDEFGHIJKLMNOP"
    card = "4111111111111111"
    key = "-----BEGIN PRIVATE KEY-----"
    return (
        Scenario("clean_internal", "Summarize local policy notes", (), ()),
        Scenario(
            "email_internal",
            "Email " + email,
            (("EMAIL_ADDRESS", email),),
            (("EMAIL_ADDRESS", email),),
        ),
        Scenario(
            "credential_internal",
            "Token " + credential,
            (("API_CREDENTIAL", credential),),
            (("API_CREDENTIAL", credential),),
            expected_status="BLOCKED",
            expected_invocations=0,
            expected_reason="CREDENTIAL_BLOCKED",
        ),
        Scenario(
            "private_key_internal",
            "Key " + key,
            (("PRIVATE_KEY", key),),
            (("PRIVATE_KEY", key),),
            expected_status="BLOCKED",
            expected_invocations=0,
            expected_reason="CREDENTIAL_BLOCKED",
        ),
        Scenario("clean_external", "Explain platform basics", (), (), "external-simulator"),
        Scenario(
            "email_external_redacted",
            "Email " + email,
            (("EMAIL_ADDRESS", email),),
            (("EMAIL_ADDRESS", email),),
            "external-simulator",
        ),
        Scenario(
            "creditcard_external_denied",
            "Card " + card,
            (("CREDIT_CARD", card),),
            (("CREDIT_CARD", card),),
            "external-simulator",
            expected_status="BLOCKED",
            expected_invocations=0,
            expected_reason="DEFAULT_DENY",
        ),
        Scenario(
            "mixed_external_denied",
            "Email " + email + " card " + card,
            (("EMAIL_ADDRESS", email), ("CREDIT_CARD", card)),
            (("EMAIL_ADDRESS", email), ("CREDIT_CARD", card)),
            "external-simulator",
            expected_status="BLOCKED",
            expected_invocations=0,
            expected_reason="DEFAULT_DENY",
        ),
        Scenario(
            "unsupported_denied",
            "Bonjour café",
            (),
            (),
            injection="unsupported",
            expected_status="BLOCKED",
            expected_invocations=0,
            expected_reason="DETECTION_UNKNOWN",
        ),
        Scenario(
            "unknown_denied",
            "Call 555-1234",
            (),
            (),
            injection="unknown",
            expected_status="BLOCKED",
            expected_invocations=0,
            expected_reason="DETECTION_UNKNOWN",
        ),
        Scenario(
            "bad_destination_denied",
            "Explain notes",
            (),
            (),
            "unregistered-model",
            expected_status="BLOCKED",
            expected_invocations=0,
            expected_reason="DEFAULT_DENY",
        ),
        Scenario(
            "disallowed_purpose_denied",
            "Explain notes",
            (),
            (),
            purpose="UNAUTHORIZED",
            expected_status="BLOCKED",
            expected_invocations=0,
            expected_reason="DEFAULT_DENY",
        ),
        Scenario(
            "redaction_second_scan_private_denied",
            "Email " + email,
            (("EMAIL_ADDRESS", email),),
            (("EMAIL_ADDRESS", email),),
            "external-simulator",
            after_redaction="private",
            expected_status="BLOCKED",
            expected_invocations=0,
            expected_reason="REDACTION_FAILED",
        ),
        Scenario(
            "redaction_second_scan_unknown_denied",
            "Email " + email,
            (("EMAIL_ADDRESS", email),),
            (("EMAIL_ADDRESS", email),),
            "external-simulator",
            after_redaction="unknown",
            expected_status="BLOCKED",
            expected_invocations=0,
            expected_reason="REDACTION_FAILED",
        ),
        Scenario(
            "detector_failure_denied",
            "Sensitive content",
            (),
            (),
            injection="detector_failure",
            expected_status="BLOCKED",
            expected_invocations=0,
            expected_reason="DETECTION_UNKNOWN",
        ),
        Scenario(
            "opa_failure_denied",
            "Local clean prompt",
            (),
            (),
            injection="policy_failure",
            expected_status="BLOCKED",
            expected_invocations=0,
            expected_reason="POLICY_UNAVAILABLE",
        ),
        Scenario(
            "unredacted_policy_plan_denied",
            "Email " + email,
            (("EMAIL_ADDRESS", email),),
            (("EMAIL_ADDRESS", email),),
            "external-simulator",
            injection="unsafe_policy",
            expected_status="BLOCKED",
            expected_invocations=0,
            expected_reason="INVALID_POLICY_PLAN",
        ),
        Scenario(
            "audit_precommit_failure",
            "Explain notes",
            (),
            (),
            injection="audit_decision",
            expected_status="EXCEPTION",
            expected_invocations=0,
        ),
        Scenario(
            "model_timeout",
            "Explain notes",
            (),
            (),
            injection="model_timeout",
            expected_status="ERROR",
            expected_invocations=1,
        ),
        Scenario(
            "untrusted_release_denied",
            "Explain notes",
            (),
            (),
            injection="untrusted_release",
            expected_status="BLOCKED",
            expected_invocations=0,
            expected_reason="UNTRUSTED_RELEASE",
        ),
        Scenario(
            "audit_outcome_failure",
            "Explain notes",
            (),
            (),
            injection="audit_outcome",
            expected_status="EXCEPTION",
            expected_invocations=1,
        ),
    )


async def run_scenario(spec: Scenario, policy: Any | None = None) -> dict[str, Any]:
    """Run one scenario against a real orchestrator and private temporary SQLite audit."""
    with tempfile.TemporaryDirectory(prefix="sovereign-enforcement-") as root:
        path = Path(root)
        store = SQLiteAuditStore(str(path / "audit.sqlite"), str(path / "audit-key.pem"))
        model = RecordingGateway(store, fail=spec.injection == "model_timeout")
        configured_policy = (
            FailingPolicy()
            if spec.injection == "policy_failure"
            else UnsafePolicy()
            if spec.injection == "unsafe_policy"
            else policy
            if policy is not None
            else FixturePolicy()
        )
        orchestrator = _create_orchestrator(
            ScenarioDetector(spec),
            configured_policy,
            store,
            model,
            audit_fault="DECISION"
            if spec.injection == "audit_decision"
            else "OUTCOME"
            if spec.injection == "audit_outcome"
            else "",
            release_failure=spec.injection == "untrusted_release",
        )
        request_id = str(uuid.uuid4())
        command = PromptCommand(request_id, spec.prompt, spec.destination, spec.purpose, PRINCIPAL)
        result = None
        exception = False
        try:
            result = await orchestrator.process(command)
        except AuditUnavailable:
            exception = True
        events = store.get_events(request_id, PRINCIPAL.tenant_id)
        decision_payload = (
            events[0]["event"]["payload"]
            if events and events[0]["event"]["event_type"] == "DECISION"
            else {}
        )
        transformed = decision_payload.get("transformation", {}).get("applied", False)
        if result is not None:
            cls = result.classification
        elif spec.injection == "detector_failure":
            cls = DetectionResult.unknown()
        else:
            cls = ScenarioDetector(spec).detect(spec.prompt)
        _safe, violations = _classify_safety(
            expected=_gold(spec.prompt, spec.ground_truth),
            classification=cls,
            actual_forward=bool(model.calls),
            destination=spec.destination,
            transformed=transformed,
            source_text=spec.prompt,
            forwarded_text=model.calls[0][1] if model.calls else None,
        )
        actual_status = "EXCEPTION" if exception else result.status.value if result else "ERROR"
        reason = (
            result.decision.reason_codes[0] if result and result.decision.reason_codes else None
        )
        issues: list[str] = list(violations)
        if actual_status != spec.expected_status:
            issues.append("STATUS_MISMATCH")
        if len(model.calls) != spec.expected_invocations:
            issues.append("INVOCATION_COUNT_MISMATCH")
        if spec.expected_reason and reason != spec.expected_reason:
            issues.append("REASON_MISMATCH")
        if model.calls and not model.decision_before_call:
            issues.append("FORWARD_BEFORE_DECISION")
        if model.calls and any(call[2] != spec.destination for call in model.calls):
            issues.append("WRONG_DESTINATION")
        if spec.injection == "audit_decision" and events:
            issues.append("AUDIT_PRECOMMIT_NOT_ATOMIC")
        if spec.injection == "audit_outcome" and [e["event"]["event_type"] for e in events] != [
            "DECISION"
        ]:
            issues.append("UNRESOLVED_AUDIT_STATE_NOT_PRESERVED")
        if (
            not exception
            and result is not None
            and [e["event"]["event_type"] for e in events] != ["DECISION", "OUTCOME"]
        ):
            issues.append("AUDIT_EVENTS_MISSING_OR_UNORDERED")
        return {
            "case_id": spec.id,
            "mode": "controlled",
            "expected_status": spec.expected_status,
            "actual_status": actual_status,
            "reason": reason,
            "model_invocations": len(model.calls),
            "transformed": transformed,
            "audit_event_count": len(events),
            "decision_precommitted": model.decision_before_call,
            "issues": sorted(set(issues)),
            "pass": not issues,
        }


async def run_suite(policy: Any | None = None) -> dict[str, Any]:
    cases = scenario_cases()
    rows = [await run_scenario(spec, policy) for spec in cases]
    return {
        "schema_version": 1,
        "evaluation_mode": "controlled-orchestrator",
        "policy_mode": getattr(policy, "name", "fixture-policy-not-opa"),
        "scope": "isolated in-process orchestrator and temporary SQLite; no live egress",
        "cases": len(rows),
        "passed": sum(r["pass"] for r in rows),
        "failed": sum(not r["pass"] for r in rows),
        "rows": rows,
    }


async def replay_cases(
    cases: tuple[Case, ...], policy: Any | None = None, *, detector: Any | None = None
) -> dict[str, Any]:
    """Real-detector replay to a recording external simulator (never live egress).

    Model invocation is intercepted; independently compare labeled spans with
    the initial redaction findings to catch partial secret removal.
    """
    if detector is None:
        from app.detection.presidio_detector import PresidioDetector

        detector = PresidioDetector.create()
    configured_policy = policy or FixturePolicy()
    rows: list[dict[str, Any]] = []
    # One isolated audit chain for the replay; no operator keys or volumes are read.
    with tempfile.TemporaryDirectory(prefix="sovereign-replay-") as root:
        store = SQLiteAuditStore(
            str(Path(root) / "audit.sqlite"), str(Path(root) / "audit-key.pem")
        )
        model = RecordingGateway(store)
        orchestrator = _create_orchestrator(detector, configured_policy, store, model)
        for case in cases:
            request_id = str(uuid.uuid4())
            command = PromptCommand(
                request_id, case.text, "external-simulator", "GENERAL", PRINCIPAL
            )
            before = len(model.calls)
            try:
                result = await orchestrator.process(command)
                events = store.get_events(request_id, PRINCIPAL.tenant_id)
                if [e["event"]["event_type"] for e in events] != ["DECISION", "OUTCOME"]:
                    issues = ["AUDIT_EVENTS_MISSING_OR_UNORDERED"]
                else:
                    issues = []
                transformation = events[0]["event"]["payload"]["transformation"] if events else {}
                transformed = transformation.get("applied", False)
                forwarded = len(model.calls) > before
                safe, violations = _classify_safety(
                    expected=case.entities,
                    classification=result.classification,
                    actual_forward=forwarded,
                    destination="external-simulator",
                    transformed=transformed,
                    source_text=case.text,
                    forwarded_text=model.calls[-1][1] if forwarded else None,
                )
                issues.extend(violations)
                if forwarded and not model.decision_before_call:
                    issues.append("FORWARD_BEFORE_DECISION")
                if forwarded and (model.calls[-1][2] != "external-simulator"):
                    issues.append("WRONG_DESTINATION")
                rows.append(
                    {
                        "case_id": case.id,
                        "split": case.split,
                        "group": case.group,
                        "expected_status": case.expected_status,
                        "classification": result.classification.status.value,
                        "effect": result.decision.effect.value,
                        "status": result.status.value,
                        "forwarded": forwarded,
                        "transformed": transformed,
                        "ground_truth_entity_count": len(case.entities),
                        "unsafe_external_forward": not safe,
                        "issues": sorted(set(issues)),
                    }
                )
            except Exception as exc:
                # Never export exception messages, including those from malformed detector output.
                rows.append(
                    {
                        "case_id": case.id,
                        "split": case.split,
                        "group": case.group,
                        "status": "ERROR",
                        "error_type": type(exc).__name__,
                        "unsafe_external_forward": None,
                        "issues": ["EXECUTION_ERROR"],
                    }
                )
    counts = Counter(issue for row in rows for issue in row["issues"])
    return {
        "schema_version": 1,
        "evaluation_mode": "real-detector-orchestrator-replay",
        "policy_mode": getattr(configured_policy, "name", "fixture-policy-not-opa"),
        "scope": "no live model/egress; isolated temporary audit; no signed-release verification",
        "cases": len(rows),
        "unsafe_external_forward_count": counts["UNSAFE_EXTERNAL_FORWARD"],
        "incomplete_or_unknown_cases": sum(row["unsafe_external_forward"] is None for row in rows),
        "issues": dict(sorted(counts.items())),
        "rows": rows,
    }
