import pytest

from app.application.orchestrator import RequestOrchestrator
from app.audit.evidence_package import export_package, verify_package
from app.domain.contracts import (
    DetectionResult,
    DetectionStatus,
    Effect,
    Obligation,
    PolicyDecision,
    Principal,
    PromptCommand,
    RequestStatus,
    Sensitivity,
)
from app.enforcement.gateway import Destination, DestinationRegistry, EnforcementPlanner
from app.policy.replay import ReplayError, replay_database
from app.policy.snapshots import build_snapshot
from tests.policy.test_policy_snapshots import SOURCE


def setup_record(tmp_path, audit):
    source = tmp_path / "policies"
    source.mkdir()
    (source / "decision.rego").write_text(SOURCE, encoding="utf-8")
    archive, active = tmp_path / "archive", tmp_path / "active"
    info = build_snapshot(source, archive, active)
    decision = PolicyDecision(
        Effect.PERMIT,
        (Obligation("ROUTE", "sovereign-model"),),
        ("TEST_PERMIT",),
        info.policy_revision,
        info.policy_digest,
    )
    policy_input = {
        "request": {"destination_id": "sovereign-model", "purpose": "GENERAL"},
        "classification": {"status": "NO_PRIVATE_DETECTED"},
    }
    audit.commit(
        "req1",
        "tenant",
        "DECISION",
        {
            "input_hmac_sha256": audit.fingerprint("example"),
            "policy_input": policy_input,
            "policy_snapshot": {"sha256": info.policy_digest, "revision": info.policy_revision},
            "policy_evaluation": decision.to_dict(),
            "decision": decision.to_dict(),
        },
    )
    audit.commit(
        "req1", "tenant", "OUTCOME", {"execution_status": "COMPLETED", "model_invoked": True}
    )
    public = str(audit.key_path.with_suffix(".pub.pem"))
    return archive, public, info, decision


def test_replays_signed_decision_with_archived_policy(tmp_path, audit):
    archive, public, info, decision = setup_record(tmp_path, audit)
    invocations = []

    def evaluator(folder, inputs):
        invocations.append((folder, inputs))
        return decision.to_dict()

    result = replay_database(str(audit.db_path), public, str(archive), evaluator=evaluator)
    assert result["status"] == "REPLAY_VERIFIED"
    assert result["verified_events"] == 2
    assert result["policy_decisions_replayed"] == 1
    assert result["unique_policy_snapshots"] == 1
    assert invocations[0][0].name == info.policy_digest


def test_detects_archived_policy_tampering(tmp_path, audit):
    archive, public, info, decision = setup_record(tmp_path, audit)
    (archive / info.policy_digest / "decision.rego").write_text("tampered", encoding="utf-8")
    with pytest.raises(ReplayError):
        replay_database(
            str(audit.db_path), public, str(archive), evaluator=lambda *_: decision.to_dict()
        )


def test_cannot_accept_different_policy_replay_answer(tmp_path, audit):
    archive, public, info, decision = setup_record(tmp_path, audit)
    mismatch = dict(decision.to_dict())
    mismatch["effect"] = "DENY"
    mismatch["obligations"] = []
    with pytest.raises(ReplayError):
        replay_database(str(audit.db_path), public, str(archive), evaluator=lambda *_: mismatch)


def test_reports_legacy_events_without_claiming_replay(tmp_path, audit):
    audit.commit(
        "older",
        "tenant",
        "DECISION",
        {
            "decision": {
                "effect": "DENY",
                "obligations": [],
                "reason_codes": ["DEFAULT_DENY"],
                "policy_revision": "baseline-v1",
            },
            "policy_input": {},
        },
    )
    result = replay_database(
        str(audit.db_path),
        str(audit.key_path.with_suffix(".pub.pem")),
        str(tmp_path / "missing"),
        evaluator=lambda *_: {},
    )
    assert result["legacy_decisions_integrity_only"] == 1
    assert result["policy_decisions_replayed"] == 0


@pytest.mark.asyncio
async def test_pre_egress_denial_replays_from_exported_evidence(tmp_path, audit):
    """Use the actual orchestrator, not a hand-crafted positive audit event."""
    source = tmp_path / "egress_policy"
    source.mkdir()
    (source / "decision.rego").write_text(
        SOURCE.replace('"sovereign-model"', '"external-simulator"'),
        encoding="utf-8",
    )
    archive = tmp_path / "egress_archive"
    info = build_snapshot(source, archive, tmp_path / "egress_active")
    opa_permit = PolicyDecision(
        Effect.PERMIT,
        (Obligation("ROUTE", "external-simulator"),),
        ("TEST_PERMIT",),
        info.policy_revision,
        info.policy_digest,
    )

    class DetectorMissesSSN:
        def detect(self, _prompt):
            return DetectionResult(
                DetectionStatus.NO_PRIVATE_DETECTED,
                Sensitivity.NONE,
                (),
                ("US_SSN",),
                "fixture-detector",
            )

    class PermissivePolicy:
        async def evaluate(self, _context):
            return opa_permit

    class ForbiddenModel:
        async def invoke(self, *_args):
            pytest.fail("The external model must not be invoked")

    registry = DestinationRegistry(
        (Destination("external-simulator", "http://egress-gateway:9010", "EXTERNAL_SIMULATED"),)
    )
    orchestrator = RequestOrchestrator(
        DetectorMissesSSN(),
        PermissivePolicy(),
        audit,
        ForbiddenModel(),
        EnforcementPlanner(frozenset({"external-simulator"}), registry),
    )
    result = await orchestrator.process(
        PromptCommand(
            "pre-egress-denied",
            "Account reference: 123-45-6789",
            "external-simulator",
            "GENERAL",
            Principal("test-principal", "tenant", ("tester",)),
        )
    )
    assert result.status == RequestStatus.BLOCKED
    assert result.decision.reason_codes == ("EXTERNAL_CONTENT_UNVERIFIED",)

    events = audit.get_events("pre-egress-denied", "tenant")
    assert [entry["event"]["event_type"] for entry in events] == ["DECISION", "OUTCOME"]
    decision_payload = events[0]["event"]["payload"]
    assert decision_payload["policy_evaluation"] == opa_permit.to_dict()
    assert decision_payload["decision"]["reason_codes"] == ["EXTERNAL_CONTENT_UNVERIFIED"]
    assert events[1]["event"]["payload"] == {
        "execution_status": "BLOCKED",
        "model_invoked": False,
    }

    package = tmp_path / "pre-egress-evidence.zip"
    export_package(
        str(audit.db_path),
        str(audit.key_path.with_suffix(".pub.pem")),
        str(archive),
        str(tmp_path / "unused-detector-archive"),
        str(package),
    )

    def offline_evaluator(snapshot, policy_input):
        assert snapshot.name == info.policy_digest
        assert policy_input["request"]["destination_id"] == "external-simulator"
        return opa_permit.to_dict()

    verified = verify_package(str(package), evaluator=offline_evaluator)
    assert verified["status"] == "EVIDENCE_PACKAGE_SELF_CONSISTENT"
    assert verified["audit"]["verified_events"] == 2
    assert verified["audit"]["policy_decisions_replayed"] == 1


def test_replay_rejects_unrecognized_signed_override(tmp_path, audit):
    archive, public, info, opa_permit = setup_record(tmp_path, audit)
    audit.commit(
        "unexpected-override",
        "tenant",
        "DECISION",
        {
            "policy_input": {
                "request": {"destination_id": "sovereign-model", "purpose": "GENERAL"},
                "classification": {"status": "NO_PRIVATE_DETECTED"},
            },
            "policy_snapshot": {
                "sha256": info.policy_digest,
                "revision": info.policy_revision,
            },
            "policy_evaluation": opa_permit.to_dict(),
            "decision": PolicyDecision.deny("UNRECOGNIZED_OVERRIDE").to_dict(),
        },
    )
    with pytest.raises(ReplayError, match="Unexpected enforcement override"):
        replay_database(
            str(audit.db_path),
            public,
            str(archive),
            evaluator=lambda *_: opa_permit.to_dict(),
        )
