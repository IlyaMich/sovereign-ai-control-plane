"""Response-side DLP: generated text is not released before policy and audit.

All inputs here are synthetic. These tests run without a live OPA service.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.application.orchestrator import RequestOrchestrator
from app.audit.evidence_package import export_package, verify_package
from app.audit.sqlite_store import AuditUnavailable
from app.detection.demo import DemoPatternDetector
from app.domain.contracts import (
    DetectionResult,
    DetectionStatus,
    Effect,
    ModelResult,
    Obligation,
    PolicyDecision,
    Principal,
    PromptCommand,
    RequestStatus,
)
from app.enforcement.gateway import EnforcementPlanner
from app.policy.snapshots import build_snapshot


class InputPermit:
    def __init__(self, digest: str = ""):
        self.digest = digest

    async def evaluate(self, _context):
        return PolicyDecision(
            Effect.PERMIT,
            (Obligation("ROUTE", "sovereign-model"),),
            ("INPUT_OK",),
            "redaction-response-dlp-v5",
            self.digest,
        )


class OutputPolicy:
    def __init__(self, digest: str = "", *, fail: bool = False, permit_private: bool = False):
        self.digest = digest
        self.fail = fail
        self.permit_private = permit_private

    async def evaluate_output(self, context):
        if self.fail:
            raise RuntimeError("do not leak confidential output here")
        if context.classification.status == DetectionStatus.PRIVATE and not self.permit_private:
            return PolicyDecision(
                Effect.DENY,
                (),
                ("OUTPUT_PRIVATE_DATA_BLOCKED",),
                "redaction-response-dlp-v5",
                self.digest,
            )
        return PolicyDecision(
            Effect.PERMIT,
            (),
            ("OUTPUT_CONTENT_CLEARED",),
            "redaction-response-dlp-v5",
            self.digest,
        )


class LocalModel:
    def __init__(self, output: str, audit, tenant_id: str = "tenant"):
        self.output = output
        self.audit = audit
        self.tenant_id = tenant_id
        self.calls = 0

    async def invoke(self, request_id, prompt, destination_id):
        self.calls += 1
        assert len(self.audit.get_events(request_id, self.tenant_id)) == 1
        return ModelResult(destination_id, self.output)


def make_service(
    audit,
    output,
    *,
    detector=None,
    output_policy=None,
    max_output_bytes=8192,
    digest="",
    tenant_id="tenant",
    output_masking_enabled=False,
):
    detector = detector or DemoPatternDetector()
    model = LocalModel(output, audit, tenant_id=tenant_id)
    orchestrator = RequestOrchestrator(
        detector=detector,
        policy=InputPermit(digest),
        audit=audit,
        model=model,
        planner=EnforcementPlanner(),
        output_policy=output_policy or OutputPolicy(digest),
        max_model_output_bytes=max_output_bytes,
        output_masking_enabled=output_masking_enabled,
    )
    return orchestrator, model


def command():
    return PromptCommand(
        "output-dlp-case",
        "Explain deterministic policy decisions.",
        "sovereign-model",
        "GENERAL",
        Principal("tester", "tenant", ("tester",)),
    )


def signed_events(audit):
    return [entry["event"] for entry in audit.get_events("output-dlp-case", "tenant")]


@pytest.mark.asyncio
async def test_clean_output_is_returned_only_after_signed_outcome(audit):
    svc, model = make_service(audit, "Safe reply with no private content.")
    result = await svc.process(command())
    assert model.calls == 1
    assert result.status == RequestStatus.COMPLETED
    assert result.output == "Safe reply with no private content."
    assert result.output_decision is not None
    assert result.output_decision.effect == Effect.PERMIT
    events = signed_events(audit)
    assert [e["event_type"] for e in events] == ["DECISION", "OUTCOME"]
    dlp = events[-1]["payload"]["output_dlp"]
    assert dlp["released"] is True
    assert events[-1]["payload"]["model_invoked"] is True
    assert "Safe reply" not in str(events)


@pytest.mark.asyncio
async def test_private_output_blocked_after_real_model_invocation(audit):
    secret = "jane@example.com"
    svc, model = make_service(audit, f"Generated contact: {secret}")
    result = await svc.process(command())
    assert model.calls == 1
    assert result.status == RequestStatus.OUTPUT_BLOCKED
    assert result.output is None
    assert result.output_decision is not None
    assert result.output_decision.reason_codes == ("OUTPUT_PRIVATE_DATA_BLOCKED",)
    events = signed_events(audit)
    outcome = events[-1]["payload"]
    assert outcome["execution_status"] == "COMPLETED"
    assert outcome["model_invoked"] is True
    assert outcome["output_dlp"]["released"] is False
    assert outcome["output_dlp"]["classification"]["status"] == "PRIVATE"
    assert secret not in str(events)


@pytest.mark.asyncio
async def test_output_detector_unknown_fails_closed(audit):
    class UnknownOutputDetector(DemoPatternDetector):
        def detect(self, text):
            if "uninspectable" in text:
                return DetectionResult.unknown("OUTPUT_UNSUPPORTED")
            return super().detect(text)

    svc, _ = make_service(audit, "uninspectable", detector=UnknownOutputDetector())
    result = await svc.process(command())
    assert result.status == RequestStatus.OUTPUT_BLOCKED
    assert result.output is None
    assert result.output_decision is not None
    assert result.output_decision.reason_codes == ("OUTPUT_DETECTION_UNKNOWN",)


@pytest.mark.asyncio
async def test_output_detector_exception_fails_closed(audit):
    class FailingOutputDetector(DemoPatternDetector):
        def detect(self, text):
            if text == "uninspectable":
                raise RuntimeError("never log model text")
            return super().detect(text)

    svc, _ = make_service(audit, "uninspectable", detector=FailingOutputDetector())
    result = await svc.process(command())
    assert result.status == RequestStatus.OUTPUT_BLOCKED
    assert result.output is None
    assert "uninspectable" not in str(signed_events(audit))


@pytest.mark.asyncio
async def test_output_policy_failure_fails_closed(audit):
    svc, _ = make_service(audit, "normal output", output_policy=OutputPolicy(fail=True))
    result = await svc.process(command())
    assert result.status == RequestStatus.OUTPUT_BLOCKED
    assert result.output_decision is not None
    assert result.output_decision.reason_codes == ("OUTPUT_POLICY_UNAVAILABLE",)
    assert "confidential output" not in str(signed_events(audit))


@pytest.mark.asyncio
async def test_malicious_private_output_permit_overridden(audit):
    svc, _ = make_service(
        audit, "jane@example.com", output_policy=OutputPolicy(permit_private=True)
    )
    result = await svc.process(command())
    assert result.status == RequestStatus.OUTPUT_BLOCKED
    assert result.output_decision is not None
    assert result.output_decision.reason_codes == ("OUTPUT_INVALID_POLICY_PLAN",)
    dlp = signed_events(audit)[-1]["payload"]["output_dlp"]
    assert dlp["policy_evaluation"]["effect"] == "PERMIT"
    assert dlp["decision"]["effect"] == "DENY"


@pytest.mark.asyncio
async def test_output_size_limit_blocks_before_return(audit):
    svc, _ = make_service(audit, "abc" * 100, max_output_bytes=64)
    result = await svc.process(command())
    assert result.status == RequestStatus.OUTPUT_BLOCKED
    assert result.output_decision is not None
    assert result.output_decision.reason_codes == ("OUTPUT_INVALID_CONTENT",)


@pytest.mark.asyncio
async def test_output_audit_failure_never_releases_text(audit):
    class BrokenOutcomeAudit:
        def fingerprint(self, content):
            return audit.fingerprint(content)

        def commit(self, request_id, tenant_id, event_type, payload):
            if event_type == "OUTCOME":
                raise AuditUnavailable("output evidence unavailable")
            return audit.commit(request_id, tenant_id, event_type, payload)

    model = LocalModel("model result", audit)
    svc = RequestOrchestrator(
        DemoPatternDetector(),
        InputPermit(),
        BrokenOutcomeAudit(),
        model,
        EnforcementPlanner(),
        output_policy=OutputPolicy(),
    )
    with pytest.raises(AuditUnavailable):
        await svc.process(command())
    assert len(signed_events(audit)) == 1
    assert model.calls == 1


@pytest.mark.asyncio
async def test_output_policy_is_replayed_from_exported_signed_evidence(tmp_path, audit):
    source = tmp_path / "policies"
    source.mkdir()
    (source / "decision.rego").write_text(
        Path("policies/decision.rego").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    archive = tmp_path / "archive"
    info = build_snapshot(source, archive, tmp_path / "active")
    svc, _ = make_service(audit, "Safe generated answer.", digest=info.policy_digest)
    result = await svc.process(command())
    assert result.status == RequestStatus.COMPLETED
    bundle = tmp_path / "output-evidence.zip"
    export_package(
        str(audit.db_path),
        str(audit.key_path.with_suffix(".pub.pem")),
        str(archive),
        str(tmp_path / "unused-detectors"),
        str(bundle),
    )

    def input_replay(folder, policy_input):
        assert folder.name == info.policy_digest
        assert "stage" not in policy_input
        return PolicyDecision(
            Effect.PERMIT,
            (Obligation("ROUTE", "sovereign-model"),),
            ("INPUT_OK",),
            info.policy_revision,
            info.policy_digest,
        ).to_dict()

    def output_replay(folder, policy_input):
        assert folder.name == info.policy_digest
        assert policy_input["stage"] == "OUTPUT"
        assert policy_input["classification"]["status"] == "NO_PRIVATE_DETECTED"
        return PolicyDecision(
            Effect.PERMIT, (), ("OUTPUT_CONTENT_CLEARED",), info.policy_revision, info.policy_digest
        ).to_dict()

    verified = verify_package(str(bundle), evaluator=input_replay, output_evaluator=output_replay)
    assert verified["status"] == "EVIDENCE_PACKAGE_SELF_CONSISTENT"
    assert verified["audit"]["verified_events"] == 2
    assert verified["audit"]["policy_decisions_replayed"] == 1
    assert verified["audit"]["output_policy_decisions_replayed"] == 1
    assert "Safe generated answer." not in str(verified)

class OutputMaskPolicy(OutputPolicy):
    async def evaluate_output(self, context):
        if context.classification.status == DetectionStatus.PRIVATE:
            return PolicyDecision(
                Effect.PERMIT,
                (Obligation("REDACT", categories=("EMAIL_ADDRESS", "PHONE_NUMBER")),),
                ("OUTPUT_MASKING_REQUIRED",),
                "redaction-response-dlp-v5",
                self.digest,
            )
        return await super().evaluate_output(context)


@pytest.mark.asyncio
async def test_masking_is_disabled_by_default_even_for_opa_permit(audit):
    svc, _ = make_service(
        audit,
        "Reply jane@example.com",
        output_policy=OutputMaskPolicy(),
    )
    result = await svc.process(command())
    assert result.status == RequestStatus.OUTPUT_BLOCKED
    assert result.output is None
    assert result.output_decision.reason_codes == ("OUTPUT_INVALID_POLICY_PLAN",)


@pytest.mark.asyncio
async def test_operator_enabled_masking_is_verified_before_audited_release(audit):
    svc, _ = make_service(
        audit,
        "Reply jane@example.com",
        output_policy=OutputMaskPolicy(),
        output_masking_enabled=True,
    )
    result = await svc.process(command())
    assert result.status == RequestStatus.COMPLETED
    assert "jane@example.com" not in result.output
    assert "[REDACTED_EMAIL_ADDRESS]" in result.output
    evidence = signed_events(audit)[-1]["payload"]["output_dlp"]
    assert evidence["schema_version"] == 2
    assert evidence["transformation"]["applied"] is True
    assert evidence["transformation"]["verification"]["status"] == "NO_PRIVATE_DETECTED"
    assert len(evidence["transformation"]["masked_hmac_sha256"]) == 64
    assert evidence["released"] is True
    assert "jane@example.com" not in str(signed_events(audit))
    metrics = svc.dlp_metrics.snapshot()
    assert metrics["masked_responses"] == 1
    assert metrics["response_outcomes"]["COMPLETED"] == 1


@pytest.mark.asyncio
async def test_mask_verification_unknown_blocks_and_preserves_signed_evidence(audit):
    class UncertainAfterMask(DemoPatternDetector):
        def detect(self, prompt):
            if "[REDACTED_EMAIL_ADDRESS]" in prompt:
                return DetectionResult.unknown("UNKNOWN_AFTER_MASK")
            return super().detect(prompt)

    svc, _ = make_service(
        audit,
        "Reply jane@example.com",
        detector=UncertainAfterMask(),
        output_policy=OutputMaskPolicy(),
        output_masking_enabled=True,
    )
    result = await svc.process(command())
    assert result.status == RequestStatus.OUTPUT_BLOCKED
    assert result.output is None
    assert result.output_decision.reason_codes == ("OUTPUT_MASK_VERIFICATION_FAILED",)
    dlp = signed_events(audit)[-1]["payload"]["output_dlp"]
    assert dlp["schema_version"] == 2
    assert dlp["transformation"]["applied"] is False
    assert dlp["released"] is False
    assert svc.dlp_metrics.snapshot()["failures"]["OUTPUT_MASK_VERIFY_FAILED"] == 1


@pytest.mark.asyncio
async def test_mixed_secret_output_cannot_be_masked(audit):
    svc, _ = make_service(
        audit,
        "Reply jane@example.com and -----BEGIN PRIVATE KEY-----",
        output_policy=OutputMaskPolicy(),
        output_masking_enabled=True,
    )
    result = await svc.process(command())
    assert result.status == RequestStatus.OUTPUT_BLOCKED
    assert result.output is None
    assert result.output_decision.reason_codes == ("OUTPUT_INVALID_POLICY_PLAN",)


@pytest.mark.asyncio
async def test_masked_output_growth_over_limit_blocks(audit):
    svc, _ = make_service(
        audit,
        "jane@example.com",
        output_policy=OutputMaskPolicy(),
        output_masking_enabled=True,
        max_output_bytes=20,
    )
    result = await svc.process(command())
    assert result.status == RequestStatus.OUTPUT_BLOCKED
    assert result.output is None
    assert result.output_decision.reason_codes == ("OUTPUT_MASK_VERIFICATION_FAILED",)


@pytest.mark.asyncio
async def test_signed_masking_output_policy_is_replayed_without_plaintext(tmp_path, audit):
    archive = tmp_path / "archive"
    active = tmp_path / "active"
    info = build_snapshot(Path("policies"), archive, active)
    svc, _ = make_service(
        audit,
        "Email jane@example.com",
        digest=info.policy_digest,
        output_policy=OutputMaskPolicy(info.policy_digest),
        output_masking_enabled=True,
    )
    outcome = await svc.process(command())
    assert outcome.status == RequestStatus.COMPLETED
    package = tmp_path / "output-mask.zip"
    export_package(
        str(audit.db_path),
        str(audit.key_path.with_suffix(".pub.pem")),
        str(archive),
        str(tmp_path / "empty-detectors"),
        str(package),
    )

    def replay_input(_folder, _policy_input):
        return PolicyDecision(
            Effect.PERMIT,
            (Obligation("ROUTE", "sovereign-model"),),
            ("INPUT_OK",),
            info.policy_revision,
            info.policy_digest,
        ).to_dict()

    def replay_output(_folder, policy_input):
        assert policy_input["masking_enabled"] is True
        assert policy_input["classification"]["status"] == "PRIVATE"
        return PolicyDecision(
            Effect.PERMIT,
            (Obligation("REDACT", categories=("EMAIL_ADDRESS", "PHONE_NUMBER")),),
            ("OUTPUT_MASKING_REQUIRED",),
            info.policy_revision,
            info.policy_digest,
        ).to_dict()

    report = verify_package(str(package), evaluator=replay_input, output_evaluator=replay_output)
    assert report["audit"]["output_policy_decisions_replayed"] == 1
    assert report["audit"]["verified_events"] == 2
    assert report["status"] == "EVIDENCE_PACKAGE_SELF_CONSISTENT"
    assert "jane@example.com" not in str(report)


@pytest.mark.asyncio
async def test_signed_but_false_mask_verification_is_rejected_by_offline_replay(tmp_path, audit):
    from app.policy.replay import ReplayError

    class TamperSignedOutcome:
        def fingerprint(self, value):
            return audit.fingerprint(value)

        def commit(self, request_id, tenant_id, event_type, payload):
            if event_type == "OUTCOME":
                changed = dict(payload)
                dlp = dict(payload["output_dlp"])
                transform = dict(dlp["transformation"])
                verification = dict(transform["verification"])
                verification["status"] = "UNKNOWN"
                transform["verification"] = verification
                dlp["transformation"] = transform
                changed["output_dlp"] = dlp
                return audit.commit(request_id, tenant_id, event_type, changed)
            return audit.commit(request_id, tenant_id, event_type, payload)

    info = build_snapshot(
        Path("policies"), tmp_path / "archive", tmp_path / "active"
    )
    svc, _ = make_service(
        audit,
        "Email jane@example.com",
        digest=info.policy_digest,
        output_policy=OutputMaskPolicy(info.policy_digest),
        output_masking_enabled=True,
    )
    svc.audit = TamperSignedOutcome()
    result = await svc.process(command())
    assert result.status == RequestStatus.COMPLETED
    assert audit.get_events("output-dlp-case", "tenant")[-1]["event"]["payload"][
        "output_dlp"
    ]["transformation"]["verification"]["status"] == "UNKNOWN"

    package = tmp_path / "tampered-mask-evidence.zip"
    export_package(
        str(audit.db_path),
        str(audit.key_path.with_suffix(".pub.pem")),
        str(tmp_path / "archive"),
        str(tmp_path / "empty-detectors"),
        str(package),
    )
    with pytest.raises(ReplayError, match="Mask verification evidence"):
        verify_package(
            str(package),
            evaluator=lambda _folder, _input: PolicyDecision(
                Effect.PERMIT,
                (Obligation("ROUTE", "sovereign-model"),),
                ("INPUT_OK",),
                info.policy_revision,
                info.policy_digest,
            ).to_dict(),
            output_evaluator=lambda _folder, _input: PolicyDecision(
                Effect.PERMIT,
                (Obligation("REDACT", categories=("EMAIL_ADDRESS", "PHONE_NUMBER")),),
                ("OUTPUT_MASKING_REQUIRED",),
                info.policy_revision,
                info.policy_digest,
            ).to_dict(),
        )
