"""Response-side DLP evaluation through the production RequestOrchestrator.

No HTTP model, live OPA, operational audit volume, or release key is used.
The output detector is a controlled fixture or standalone Presidio; the model
response is supplied by the synthetic test case, never generated remotely.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
import time
import uuid
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.application.orchestrator import RequestOrchestrator
from app.audit.evidence_package import export_package, verify_package
from app.audit.sqlite_store import AuditUnavailable, SQLiteAuditStore
from app.audit.verify import verify_database
from app.domain.contracts import (
    DetectionResult,
    DetectionStatus,
    Effect,
    Finding,
    ModelResult,
    Obligation,
    OutputPolicyContext,
    PolicyContext,
    PolicyDecision,
    Principal,
    PromptCommand,
    RequestStatus,
    Sensitivity,
)
from app.enforcement.gateway import EnforcementPlanner
from app.policy.replay import run_opa
from app.policy.snapshots import SnapshotInfo, build_snapshot
from evaluation.dataset import Case, Entity
from evaluation.runner import _git_head
from evaluation.scoring import Prediction, score

INPUT_PROMPT = "Explain the purpose of deterministic audit verification."
COVERAGE = (
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "PERSON",
    "CREDIT_CARD",
    "US_SSN",
    "API_CREDENTIAL",
    "PRIVATE_KEY",
)
PRINCIPAL = Principal("output-evaluation", "output-evaluation", ("tester",))


@dataclass(frozen=True)
class OutputScenario:
    case: Case
    expected_outcome: str
    expected_reason: str | None = None
    fault: str = ""
    max_output_bytes: int = 8192


def _make_case(
    cid: str,
    text: str,
    labeled: tuple[tuple[str, str], ...] = (),
    *,
    status: str | None = None,
    group: str = "output",
) -> Case:
    entities = tuple(
        Entity(category, text.index(value), text.index(value) + len(value))
        for category, value in labeled
    )
    expected = status or ("PRIVATE" if entities else "NO_PRIVATE_DETECTED")
    return Case(
        cid,
        text,
        entities,
        expected,
        text.isascii(),
        group,
        ("output_dlp",),
        "development",
    )


def controlled_scenarios() -> tuple[OutputScenario, ...]:
    """Synthetic output fixtures; all failures should fail closed."""
    email = "alice@example.com"
    phone = "202-555-0102"
    credential = "AKIAABCDEFGHIJKLMNOP"
    return (
        OutputScenario(_make_case("OUTPUT-CLEAN", "A safe generated explanation."), "COMPLETED"),
        OutputScenario(
            _make_case("OUTPUT-HARD-NEGATIVE", "The field name is EMAIL_ADDRESS."),
            "COMPLETED",
        ),
        OutputScenario(
            _make_case("OUTPUT-EMAIL", "Contact " + email, (("EMAIL_ADDRESS", email),)),
            "OUTPUT_BLOCKED",
            "OUTPUT_PRIVATE_DATA_BLOCKED",
        ),
        OutputScenario(
            _make_case("OUTPUT-PHONE", "Call " + phone, (("PHONE_NUMBER", phone),)),
            "OUTPUT_BLOCKED",
            "OUTPUT_PRIVATE_DATA_BLOCKED",
        ),
        OutputScenario(
            _make_case(
                "OUTPUT-MIXED",
                "Call " + phone + " or email " + email,
                (("PHONE_NUMBER", phone), ("EMAIL_ADDRESS", email)),
            ),
            "OUTPUT_BLOCKED",
            "OUTPUT_PRIVATE_DATA_BLOCKED",
        ),
        OutputScenario(
            _make_case(
                "OUTPUT-CREDENTIAL",
                "Token " + credential,
                (("API_CREDENTIAL", credential),),
            ),
            "OUTPUT_BLOCKED",
            "OUTPUT_PRIVATE_DATA_BLOCKED",
        ),
        OutputScenario(
            _make_case(
                "OUTPUT-KEY",
                "-----BEGIN PRIVATE KEY-----",
                (("PRIVATE_KEY", "-----BEGIN PRIVATE KEY-----"),),
            ),
            "OUTPUT_BLOCKED",
            "OUTPUT_PRIVATE_DATA_BLOCKED",
        ),
        OutputScenario(
            _make_case("OUTPUT-UNSUPPORTED", "Résumé generated", status="UNKNOWN"),
            "OUTPUT_BLOCKED",
            "OUTPUT_DETECTION_UNKNOWN",
        ),
        OutputScenario(
            _make_case("OUTPUT-DETECTOR-UNKNOWN", "Uninspectable generated answer"),
            "OUTPUT_BLOCKED",
            "OUTPUT_DETECTION_UNKNOWN",
            "detector_unknown",
        ),
        OutputScenario(
            _make_case("OUTPUT-DETECTOR-ERROR", "Response detector temporarily unavailable"),
            "OUTPUT_BLOCKED",
            "OUTPUT_DETECTION_UNKNOWN",
            "detector_error",
        ),
        OutputScenario(
            _make_case("OUTPUT-POLICY-ERROR", "Ordinary response with an unavailable policy"),
            "OUTPUT_BLOCKED",
            "OUTPUT_POLICY_UNAVAILABLE",
            "policy_error",
        ),
        OutputScenario(
            _make_case("OUTPUT-EMPTY", ""),
            "OUTPUT_BLOCKED",
            "OUTPUT_INVALID_CONTENT",
        ),
        OutputScenario(
            _make_case("OUTPUT-OVERSIZED", "Long synthetic response " * 12),
            "OUTPUT_BLOCKED",
            "OUTPUT_INVALID_CONTENT",
            max_output_bytes=64,
        ),
        OutputScenario(
            _make_case("OUTPUT-MODEL-ERROR", "Model unavailable"),
            "ERROR",
            fault="model_error",
        ),
        OutputScenario(
            _make_case("OUTPUT-AUDIT-ERROR", "Response after unavailable audit"),
            "EXCEPTION",
            fault="outcome_audit_error",
        ),
    )


def _classified(
    status: DetectionStatus, entities: tuple[Entity, ...] = ()
) -> DetectionResult:
    sensitivity = Sensitivity.HIGH if any(
        entity.category in {"API_CREDENTIAL", "PRIVATE_KEY", "CREDIT_CARD"}
        for entity in entities
    ) else Sensitivity.MEDIUM if entities else Sensitivity.NONE
    return DetectionResult(
        status,
        Sensitivity.UNKNOWN if status == DetectionStatus.UNKNOWN else sensitivity,
        tuple(
            Finding(e.category, e.start, e.end, "synthetic-output-fixture", 0.99)
            for e in entities
        ),
        COVERAGE if status != DetectionStatus.UNKNOWN else (),
        "presidio-spacy-v1",
        ("EVALUATION_FIXTURE",),
        "synthetic-fixture-not-provenance",
    )


class OutputDetector:
    """Fixture input classification, injected faults, or real output detection."""

    def __init__(self, spec: OutputScenario, real_detector: Any | None = None):
        self.spec = spec
        self.real = real_detector
        self.output_latency_ms: float | None = None

    def detect(self, text: str) -> DetectionResult:
        if text == INPUT_PROMPT:
            return _classified(DetectionStatus.NO_PRIVATE_DETECTED)
        started = time.perf_counter()
        try:
            return self._detect_output(text)
        finally:
            self.output_latency_ms = (time.perf_counter() - started) * 1000

    def _detect_output(self, text: str) -> DetectionResult:
        if self.spec.fault == "detector_error":
            raise RuntimeError("Deliberate response detector exception")
        if self.spec.fault == "detector_unknown":
            return DetectionResult.unknown("OUTPUT_UNINSPECTABLE")
        if self.spec.fault == "detector_false_negative":
            return _classified(DetectionStatus.NO_PRIVATE_DETECTED)
        if self.spec.fault == "detector_false_positive":
            return _classified(
                DetectionStatus.PRIVATE,
                (Entity("PERSON", 0, min(len(text), 6)),),
            )
        if self.real is not None:
            return self.real.detect(text)
        if self.spec.case.expected_status == "UNKNOWN":
            return DetectionResult.unknown("UNSUPPORTED_CHARACTER_SET")
        return _classified(
            DetectionStatus.PRIVATE if self.spec.case.entities
            else DetectionStatus.NO_PRIVATE_DETECTED,
            self.spec.case.entities,
        )


def _input_fixture(digest: str, revision: str) -> PolicyDecision:
    return PolicyDecision(
        Effect.PERMIT,
        (Obligation("ROUTE", "sovereign-model"),),
        ("APPROVED_INTERNAL_ROUTE", "PRESIDIO_DETECTION_COMPLETE"),
        revision,
        digest,
    )


def _output_fixture(status: str, digest: str, revision: str) -> PolicyDecision:
    if status == "PRIVATE":
        return PolicyDecision(
            Effect.DENY, (), ("OUTPUT_PRIVATE_DATA_BLOCKED",), revision, digest
        )
    if status == "NO_PRIVATE_DETECTED":
        return PolicyDecision(
            Effect.PERMIT, (), ("OUTPUT_CONTENT_CLEARED",), revision, digest
        )
    return PolicyDecision(Effect.DENY, (), ("OUTPUT_DEFAULT_DENY",), revision, digest)


class Evaluator:
    """Fixture policy or actual OPA CLI against an isolated verified snapshot."""

    def __init__(self, info: SnapshotInfo, active: Path, opa_bin: str | None):
        self.info = info
        self.active = active
        self.opa_bin = opa_bin

    def _evaluate(self, policy_input: dict[str, Any], output: bool) -> PolicyDecision:
        if self.opa_bin:
            raw = run_opa(
                self.opa_bin,
                self.active,
                policy_input,
                "data.sovereign.authz.output_decision"
                if output else "data.sovereign.authz.decision",
            )
            from app.policy.opa import parse_decision

            result = parse_decision(raw)
            if (result.policy_digest, result.policy_revision) != (
                self.info.policy_digest, self.info.policy_revision
            ):
                raise ValueError("OPA decision differs from pinned policy")
            return result
        if output:
            return _output_fixture(
                policy_input["classification"]["status"],
                self.info.policy_digest,
                self.info.policy_revision,
            )
        return _input_fixture(self.info.policy_digest, self.info.policy_revision)

    async def evaluate(self, context: PolicyContext) -> PolicyDecision:
        return self._evaluate(context.to_dict(), False)

    async def evaluate_output(self, context: OutputPolicyContext) -> PolicyDecision:
        return self._evaluate(context.to_dict(), True)

    def replay_input(self, folder: Path, policy_input: dict[str, Any]) -> dict[str, Any]:
        if folder.name != self.info.policy_digest:
            raise ValueError("Wrong archived policy")
        return self._evaluate(policy_input, False).to_dict()

    def replay_output(self, folder: Path, policy_input: dict[str, Any]) -> dict[str, Any]:
        if folder.name != self.info.policy_digest:
            raise ValueError("Wrong archived output policy")
        return self._evaluate(policy_input, True).to_dict()


class FailingOutputPolicy:
    async def evaluate_output(self, context: OutputPolicyContext) -> PolicyDecision:
        raise RuntimeError("Deliberate policy evaluator outage")


class SimulatedModel:
    def __init__(self, response: str, store: SQLiteAuditStore, *, fail: bool):
        self.response = response
        self.store = store
        self.fail = fail
        self.calls = 0
        self.precommitted = True

    async def invoke(self, request_id: str, prompt: str, destination_id: str) -> ModelResult:
        self.calls += 1
        events = self.store.get_events(request_id, PRINCIPAL.tenant_id)
        self.precommitted &= (
            len(events) == 1 and events[0]["event"]["event_type"] == "DECISION"
        )
        if self.fail:
            raise TimeoutError("Deliberate model failure")
        return ModelResult("sovereign-model", self.response)


class FaultAudit:
    def __init__(self, actual: SQLiteAuditStore, fault: str):
        self.actual = actual
        self.fault = fault

    def fingerprint(self, prompt: str) -> str:
        return self.actual.fingerprint(prompt)

    def commit(self, request_id: str, tenant_id: str, event_type: str, payload: dict):
        if event_type == "OUTCOME" and self.fault == "outcome_audit_error":
            raise AuditUnavailable("Deliberate outcome commit failure")
        if event_type == "OUTCOME" and self.fault == "signed_outcome_mismatch":
            # Sign deliberately inconsistent metadata. Cryptographic signatures
            # alone must NOT make an impossible output release acceptable.
            modified = dict(payload)
            dlp = dict(modified["output_dlp"])
            dlp["released"] = not dlp["released"]
            modified["output_dlp"] = dlp
            return self.actual.commit(request_id, tenant_id, event_type, modified)
        return self.actual.commit(request_id, tenant_id, event_type, payload)


def _inspect_evidence(
    spec: OutputScenario,
    result: Any,
    store: SQLiteAuditStore,
    request_id: str,
    model: SimulatedModel,
) -> tuple[dict[str, Any], list[str]]:
    events = store.get_events(request_id, PRINCIPAL.tenant_id)
    types = [e["event"]["event_type"] for e in events]
    issues: list[str] = []
    expected_types = (
        ["DECISION"] if spec.fault == "outcome_audit_error" else ["DECISION", "OUTCOME"]
    )
    if types != expected_types:
        issues.append("MISSING_OR_UNORDERED_SIGNED_EVENTS")
    if not model.precommitted:
        issues.append("MODEL_INVOKED_BEFORE_SIGNED_DECISION")

    dlp = None
    if spec.fault not in {"outcome_audit_error", "model_error"} and len(events) == 2:
        outcome = events[1]["event"]["payload"]
        dlp = outcome.get("output_dlp")
        if not isinstance(dlp, dict):
            issues.append("MISSING_OUTPUT_DLP_EVIDENCE")
        else:
            expected_hmac = (
                store.fingerprint("model-output-v1\x00" + spec.case.text)
                if spec.case.text
                and len(spec.case.text.encode("utf-8")) <= spec.max_output_bytes
                else None
            )
            if (
                dlp.get("schema_version") != 1
                or dlp.get("released") != (result.status == RequestStatus.COMPLETED)
                or dlp.get("output_hmac_sha256") != expected_hmac
                or dlp.get("classification")
                != (result.output_classification.to_dict() if result.output_classification else None)
                or dlp.get("decision")
                != (result.output_decision.to_dict() if result.output_decision else None)
                or dlp.get("policy_input", {}).get("stage") != "OUTPUT"
                or outcome.get("model_invoked") is not True
                or outcome.get("execution_status") != "COMPLETED"
            ):
                issues.append("OUTPUT_EVIDENCE_MISMATCH")
    if spec.case.text and any(
        spec.case.text in json.dumps(event["event"], ensure_ascii=False)
        for event in events
    ):
        issues.append("PLAINTEXT_MODEL_OUTPUT_IN_AUDIT")
    return {"audit_events": len(events), "output_evidence_present": dlp is not None}, issues


async def evaluate_scenarios(
    scenarios: tuple[OutputScenario, ...],
    *,
    detector_mode: str = "fixture",
    opa_bin: str | None = None,
    dataset_sha256: str | None = None,
) -> dict[str, Any]:
    """Run actual output enforcement, then verify its signed evidence offline."""
    if detector_mode not in {"fixture", "presidio"}:
        raise ValueError("Unsupported detector mode")
    if not scenarios:
        raise ValueError("Response-side evaluation requires at least one case")
    if len({s.case.id for s in scenarios}) != len(scenarios):
        raise ValueError("Duplicate response-side case ID")
    if opa_bin is not None:
        # A missing OPA CLI is a setup error, not a measured fail-closed
        # response scenario or an inaccurate detection regression finding.
        probe = subprocess.run(
            [opa_bin, "version"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        if not probe.stdout:
            raise RuntimeError("OPA version probe returned no output")
    real = None
    if detector_mode == "presidio":
        from app.detection.presidio_detector import PresidioDetector

        real = PresidioDetector.create()

    with tempfile.TemporaryDirectory(prefix="sovereign-output-eval-") as location:
        root = Path(location)
        info = build_snapshot(Path("policies"), root / "policy-archive", root / "policy-active")
        policy = Evaluator(info, root / "policy-active", opa_bin)
        store = SQLiteAuditStore(str(root / "audit.sqlite"), str(root / "audit-key.pem"))
        rows: list[dict[str, Any]] = []
        predictions: list[Prediction] = []
        detector_identities: set[tuple[str, str, str]] = set()
        for spec in scenarios:
            request_id = str(uuid.uuid4())
            model = SimulatedModel(
                spec.case.text, store, fail=spec.fault == "model_error"
            )
            detector = OutputDetector(spec, real)
            svc = RequestOrchestrator(
                detector=detector,
                policy=policy,
                audit=FaultAudit(store, spec.fault)
                if spec.fault in {"outcome_audit_error", "signed_outcome_mismatch"}
                else store,
                model=model,
                planner=EnforcementPlanner(),
                output_policy=FailingOutputPolicy()
                if spec.fault == "policy_error" else policy,
                max_model_output_bytes=spec.max_output_bytes,
            )
            command = PromptCommand(
                request_id, INPUT_PROMPT, "sovereign-model", "GENERAL", PRINCIPAL
            )
            result = None
            exception_type = None
            try:
                result = await svc.process(command)
            except Exception as exc:
                exception_type = type(exc).__name__  # Never export exception messages.
            actual_status = result.status.value if result else "EXCEPTION"
            expected_released = spec.expected_outcome == "COMPLETED"
            released = bool(result and result.output is not None)
            if result and result.output_classification is not None:
                classification = result.output_classification
                entities = tuple(
                    Entity(f.category, f.start, f.end) for f in classification.findings
                )
                observed = classification.status.value
                reasons = classification.reason_codes
                if classification.status != DetectionStatus.UNKNOWN:
                    detector_identities.add((
                        classification.detector_version,
                        classification.config_digest,
                        classification.artifact_digest,
                    ))
            else:
                entities, observed, reasons = (), "UNKNOWN", ()
            predictions.append(Prediction(
                spec.case.id,
                observed,
                entities,
                detector.output_latency_ms or 0.0,
                reasons,
            ))
            reason = (
                result.output_decision.reason_codes[0]
                if result and result.output_decision and result.output_decision.reason_codes
                else None
            )
            data, issues = _inspect_evidence(spec, result, store, request_id, model)
            if actual_status != spec.expected_outcome:
                issues.append("UNEXPECTED_OUTPUT_OUTCOME")
            if spec.expected_reason is not None and reason != spec.expected_reason:
                issues.append("UNEXPECTED_OUTPUT_REASON")
            if model.calls != 1:
                issues.append("UNEXPECTED_MODEL_INVOCATION_COUNT")
            if released != expected_released:
                issues.append("RELEASE_EXPECTATION_MISMATCH")
            if released and result and result.output != spec.case.text:
                issues.append("RELEASED_OUTPUT_CHANGED")
            if released and spec.case.entities:
                issues.append("UNSAFE_SENSITIVE_OUTPUT_RELEASE")
            if released and spec.case.expected_status == "UNKNOWN":
                issues.append("UNSAFE_UNSUPPORTED_OUTPUT_RELEASE")
            if released and observed != "NO_PRIVATE_DETECTED":
                issues.append("UNSAFE_UNCLEARED_OUTPUT_RELEASE")
            if spec.fault == "outcome_audit_error" and exception_type != "AuditUnavailable":
                issues.append("AUDIT_FAIL_CLOSED_VIOLATION")
            rows.append({
                "case_id": spec.case.id,
                "group": spec.case.group,
                "split": spec.case.split,
                "fault": spec.fault or None,
                "expected_detection_status": spec.case.expected_status,
                "observed_detection_status": observed,
                "expected_outcome": spec.expected_outcome,
                "actual_outcome": actual_status,
                "reason_code": reason,
                "released": released,
                "blocked": actual_status == "OUTPUT_BLOCKED",
                "model_invocations": model.calls,
                "output_detection_latency_ms": (
                    round(detector.output_latency_ms, 4)
                    if detector.output_latency_ms is not None else None
                ),
                "expected_entity_count": len(spec.case.entities),
                "observed_entity_count": len(entities),
                "exception_type": exception_type,
                **data,
                "issues": sorted(set(issues)),
            })

        # The public audit key is pinned outside the ZIP during verification.
        public_key = root / "audit-key.pub.pem"
        head = verify_database(str(root / "audit.sqlite"), str(public_key))
        checkpoint = root / "trusted-checkpoint.json"
        checkpoint.write_bytes(
            (json.dumps(head, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        )
        package = root / "output-evidence.zip"
        exported = export_package(
            str(root / "audit.sqlite"),
            str(public_key),
            str(root / "policy-archive"),
            str(root / "unused-detectors"),
            str(package),
            str(checkpoint),
        )
        verified = verify_package(
            str(package),
            trusted_public_key=str(public_key),
            trusted_checkpoint=str(checkpoint),
            evaluator=policy.replay_input if opa_bin is None else None,
            output_evaluator=policy.replay_output if opa_bin is None else None,
            opa_binary=opa_bin or "opa",
        )
        counts = Counter(issue for row in rows for issue in row["issues"])
        if len(detector_identities) > 1:
            counts["DETECTOR_IDENTITY_CHANGED_DURING_EVALUATION"] += 1
        labels = tuple(spec.case for spec in scenarios)
        detection = score(labels, predictions)
        expected_evaluations = sum(
            row["output_evidence_present"]
            and row["observed_detection_status"] in {"PRIVATE", "NO_PRIVATE_DETECTED"}
            and row["fault"] != "policy_error"
            for row in rows
        )
        if (
            verified["audit"]["verified_events"] != sum(row["audit_events"] for row in rows)
            or verified["audit"]["output_policy_decisions_replayed"] != expected_evaluations
            or not verified["public_key_trusted_externally"]
            or not verified["checkpoint_trusted_externally"]
            or verified["status"] != "EVIDENCE_PACKAGE_VERIFIED"
        ):
            counts["SIGNED_EVIDENCE_REPLAY_MISMATCH"] += 1
        sensitive = sum(bool(spec.case.entities) for spec in scenarios)
        benign = sum(
            not spec.case.entities and spec.case.expected_status == "NO_PRIVATE_DETECTED"
            for spec in scenarios
        )
        unsafe = sum("UNSAFE_SENSITIVE_OUTPUT_RELEASE" in row["issues"] for row in rows)
        false_blocks = sum(
            spec.expected_outcome == "COMPLETED" and row["blocked"]
            for spec, row in zip(scenarios, rows, strict=True)
        )
        clean_expected_release = sum(
            spec.expected_outcome == "COMPLETED" for spec in scenarios
        )
        injected = [row for row in rows if row["fault"]]
        failures_by_type: dict[str, dict[str, int]] = {}
        for fault in sorted({str(row["fault"]) for row in injected}):
            cohort = [row for row in injected if row["fault"] == fault]
            failures_by_type[fault] = {
                "cases": len(cohort),
                "withheld": sum(not row["released"] for row in cohort),
                "unexpected_release": sum(row["released"] for row in cohort),
                "violations": sum(bool(row["issues"]) for row in cohort),
            }
        evidence_mismatches = sum(
            any(
                issue in row["issues"]
                for issue in (
                    "MISSING_OR_UNORDERED_SIGNED_EVENTS",
                    "MISSING_OUTPUT_DLP_EVIDENCE",
                    "OUTPUT_EVIDENCE_MISMATCH",
                    "MODEL_INVOKED_BEFORE_SIGNED_DECISION",
                    "PLAINTEXT_MODEL_OUTPUT_IN_AUDIT",
                )
            )
            for row in rows
        )
        output_latencies = sorted(
            row["output_detection_latency_ms"]
            for row in rows if row["output_detection_latency_ms"] is not None
        )

        def latency_quantile(fraction: float) -> float | None:
            if not output_latencies:
                return None
            index = round((len(output_latencies) - 1) * fraction)
            return round(output_latencies[index], 4)

        return {
            "schema_version": 1,
            "evaluation_mode": "response-side-dlp",
            "detector_mode": detector_mode,
            "policy_mode": "opa-cli" if opa_bin else "fixture-policy-not-opa",
            "dataset_sha256": dataset_sha256,
            "git_commit": _git_head(Path(__file__).resolve().parents[2]),
            "detector_identities": [
                {"version": version, "config_digest": config, "artifact_digest": artifact}
                for version, config, artifact in sorted(detector_identities)
            ],
            "policy_digest": info.policy_digest,
            "policy_revision": info.policy_revision,
            "cases": len(rows),
            "passed": sum(not row["issues"] for row in rows),
            "failed": sum(bool(row["issues"]) for row in rows),
            "metrics": {
                "sensitive_cases": sensitive,
                "benign_cases": benign,
                "released_count": sum(row["released"] for row in rows),
                "blocked_count": sum(row["blocked"] for row in rows),
                "error_count": sum(row["actual_outcome"] in {"ERROR", "EXCEPTION"} for row in rows),
                "unsafe_sensitive_release_count": unsafe,
                "false_block_count": false_blocks,
                "unsafe_release_rate_on_sensitive": (
                    unsafe / sensitive if sensitive else None
                ),
                "false_block_rate_on_expected_releases": (
                    false_blocks / clean_expected_release
                    if clean_expected_release else None
                ),
                "blocked_rate": (
                    sum(row["blocked"] for row in rows) / len(rows)
                ),
                "failure_handling": {
                    "injected_cases": len(injected),
                    "withheld": sum(not row["released"] for row in injected),
                    "unexpected_release": sum(row["released"] for row in injected),
                    "by_fault": failures_by_type,
                },
                "output_detection_latency_ms": {
                    "count": len(output_latencies),
                    "p50": latency_quantile(0.5),
                    "p95": latency_quantile(0.95),
                },
                "output_detection": detection,
                "issues": dict(sorted(counts.items())),
            },
            "evidence": {
                "per_case_evidence_mismatches": evidence_mismatches,
                "output_evidence_cases": sum(
                    row["output_evidence_present"] for row in rows
                ),
                "exported_events": exported["events"],
                "signed_events_verified": verified["audit"]["verified_events"],
                "input_policy_decisions_replayed": verified["audit"]["policy_decisions_replayed"],
                "output_policy_decisions_replayed": verified["audit"]["output_policy_decisions_replayed"],
                "output_local_denials_verified": verified["audit"][
                    "output_local_fail_closed_decisions"
                ],
                "audit_key_pinned_for_this_run": verified["public_key_trusted_externally"],
                "checkpoint_pinned_for_this_run": verified["checkpoint_trusted_externally"],
                "status": verified["status"],
                "release_signer_trusted_externally": verified[
                    "release_signer_trusted_externally"
                ],
            },
            "limitations": (
                "Synthetic in-memory model outputs; local isolated signed audit; "
                "no production release signature, independent checkpoint witness, "
                "real inference, service API, or network egress tested"
            ),
            "rows": rows,
        }
