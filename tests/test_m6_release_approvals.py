"""Milestone 6: independent signer, anti-rollback, fail closed and evidence replay."""
from pathlib import Path
import json
import zipfile

import pytest

from app.audit.evidence_package import export_package, verify_package
from app.policy.snapshots import PolicySnapshotStore, build_snapshot
from app.release.approvals import (
    ReleaseIntegrityError, ReleaseStore, new_keypair, make_payload,
    sign_approval, verify_approval, load_approval, summary,
)
from app.release.evidence import verify_release_references
from app.detection.provenance import canonical
from tests.test_m4_policy_snapshots import SOURCE

D = "d" * 64


def approval_fixture(tmp_path):
    keys = tmp_path / "trust"
    keys.mkdir()
    private = tmp_path / "secret" / "private.pem"
    public = keys / "release.pub.pem"
    new_keypair(private, public)
    source = tmp_path / "policies"
    source.mkdir()
    (source / "decision.rego").write_text(SOURCE)
    snapshots = PolicySnapshotStore(tmp_path / "active-policy", tmp_path / "policy-archive")
    info = build_snapshot(source, snapshots.archive, snapshots.active)
    active = tmp_path / "active-release" / "release.json"
    store = ReleaseStore(active, tmp_path / "release-archive", keys, snapshots)
    candidate = tmp_path / "candidate.json"
    doc = sign_approval(make_payload(info.policy_digest, info.policy_revision, D, 1, None), private)
    candidate.write_bytes(canonical(doc) + b"\n")
    return private, public, store, candidate, doc


def test_genesis_signature_and_runtime_checks(tmp_path):
    private, public, store, candidate, doc = approval_fixture(tmp_path)
    assert verify_approval(doc, store.trust)["release_id"] == doc["release_id"]
    assert store.activate(candidate, detector_digest=D)["release_id"] == doc["release_id"]
    assert store.verify_active(detector_digest=D, policy_digest=doc["payload"]["policy_digest"]) == doc
    with pytest.raises(ReleaseIntegrityError, match="approved"):
        store.verify_active(detector_digest="a" * 64)
    with pytest.raises(ReleaseIntegrityError):
        store.verify_active(policy_digest="b" * 64)
    assert not private.is_relative_to(store.active.parent)


def test_unsigned_and_wrong_signer_fail_closed(tmp_path):
    _, _, store, candidate, doc = approval_fixture(tmp_path)
    tampered = json.loads(candidate.read_text())
    tampered["payload"]["detector_digest"] = "c" * 64
    with pytest.raises(ReleaseIntegrityError):
        verify_approval(tampered, store.trust)
    key2 = tmp_path / "another"
    key2.mkdir()
    priv2, pub2 = key2 / "private.pem", key2 / "public.pem"
    new_keypair(priv2, pub2)
    with pytest.raises(ReleaseIntegrityError):
        verify_approval(doc, key2)
    with pytest.raises(ReleaseIntegrityError):
        store.activate(candidate, detector_digest="c" * 64)
    assert not store.active.exists()


def test_activation_rejects_replay_and_requires_signed_successor(tmp_path):
    private, _, store, candidate, genesis = approval_fixture(tmp_path)
    store.activate(candidate)
    with pytest.raises(ReleaseIntegrityError):
        store.activate(candidate)
    info = store.policy_store.verify_active()
    second = sign_approval(make_payload(info.policy_digest, info.policy_revision, D, 2,
                                         genesis["release_id"]), private)
    p = tmp_path / "new.json"
    p.write_bytes(canonical(second) + b"\n")
    store.activate(p)
    assert store.verify_active()["payload"]["generation"] == 2
    with pytest.raises(ReleaseIntegrityError):
        store.activate(candidate)
    # A rollback needs a new signed generation > 2, not an old signed envelope.
    third = sign_approval(make_payload(info.policy_digest, info.policy_revision, D, 3,
                                        second["release_id"]), private)
    rollback = tmp_path / "rollback.json"
    rollback.write_bytes(canonical(third) + b"\n")
    store.activate(rollback)
    assert store.verify_active()["payload"]["generation"] == 3


def test_tampering_active_or_archived_release_is_detected(tmp_path):
    _, _, store, candidate, doc = approval_fixture(tmp_path)
    store.activate(candidate)
    store.active.write_text("{}")
    with pytest.raises(ReleaseIntegrityError):
        store.verify_active()
    store.active.write_bytes(canonical(doc) + b"\n")
    archive = store.archive / (doc["release_id"] + ".json")
    archive.write_text("{}")
    with pytest.raises(ReleaseIntegrityError):
        store.verify_active()


def test_policy_source_changes_are_not_silently_authorized(tmp_path):
    _, _, store, candidate, _ = approval_fixture(tmp_path)
    store.activate(candidate)
    (store.policy_store.active / "decision.rego").write_text("package attacker\n")
    with pytest.raises(Exception):
        store.verify_active()


def test_audit_release_refs_require_pinned_key(tmp_path, audit):
    _, public, store, candidate, doc = approval_fixture(tmp_path)
    store.activate(candidate)
    audit.commit("release-request", "t", "DECISION", {
        "policy_evidence_version": "2",
        "policy_input": {"classification": {"status": "UNKNOWN"}},
        "policy_evaluation": None,
        "decision": {"effect": "DENY", "obligations": [],
                     "reason_codes": ["DETECTION_UNKNOWN"],
                     "policy_revision": "local-fail-closed-v1"},
        "release_evidence_version": "1",
        "release_snapshot": summary(doc),
    })
    audit.commit("release-request", "t", "OUTCOME", {"execution_status": "BLOCKED", "model_invoked": False})
    public_audit = str(audit.key_path.with_suffix('.pub.pem'))
    package = tmp_path / "portable.zip"
    exported = export_package(str(audit.db_path), public_audit, str(store.policy_store.archive),
                              str(tmp_path / "empty-detector-archive"), str(package),
                              release_archive=str(store.archive))
    assert exported["release_approvals"] == 1
    with zipfile.ZipFile(package) as archive:
        assert "release-archive/" + doc["release_id"] + ".json" in archive.namelist()
        assert not any("private" in name for name in archive.namelist())
    unsigned = verify_package(str(package), evaluator=lambda *_: {})
    assert unsigned["audit"]["release_references_checked"] == 1
    assert unsigned["audit"]["release_approvals_authenticated"] == 0
    signed = verify_package(str(package), evaluator=lambda *_: {},
                            trusted_public_key=public_audit,
                            trusted_release_public_key=str(public))
    assert signed["audit"]["release_approvals_authenticated"] == 1
    assert signed["release_signer_trusted_externally"]
    bad = tmp_path / "unrelated.pem"
    priv2 = tmp_path / "another-private.pem"
    new_keypair(priv2, bad)
    with pytest.raises(ReleaseIntegrityError):
        verify_package(str(package), evaluator=lambda *_: {},
                       trusted_release_public_key=str(bad))


def test_malformed_release_reference_fails_even_without_trust(tmp_path, audit):
    _, _, store, candidate, doc = approval_fixture(tmp_path)
    store.activate(candidate)
    ref = summary(doc)
    ref["policy_digest"] = "e" * 64
    audit.commit("r", "t", "DECISION", {
        "release_evidence_version": "1", "release_snapshot": ref,
        "policy_input": {"classification": {"status": "UNKNOWN"}},
        "policy_evaluation": None, "decision": {"effect": "DENY", "reason_codes": ["DETECTION_UNKNOWN"]},
    })
    with pytest.raises(ReleaseIntegrityError):
        verify_release_references(str(audit.db_path), store.archive)

@pytest.mark.asyncio
async def test_request_with_untrusted_release_never_invokes_model(tmp_path, audit):
    from app.application.orchestrator import RequestOrchestrator
    from app.detection.demo import DemoPatternDetector
    from app.enforcement.gateway import EnforcementPlanner
    from app.domain.contracts import Principal, PromptCommand, RequestStatus
    from tests.conftest import RecordingModel, StaticPolicy

    class BadRelease:
        def verify_active(self, **_):
            raise ReleaseIntegrityError('release signer removed')
    model = RecordingModel(audit)
    runner = RequestOrchestrator(DemoPatternDetector(), StaticPolicy(), audit, model,
                                 EnforcementPlanner(), release_store=BadRelease())
    command = PromptCommand('bad-release', 'hello', 'sovereign-model', 'GENERAL',
                            Principal('tester', 'local-tenant', ('tester',)))
    result = await runner.process(command)
    assert result.status == RequestStatus.BLOCKED
    assert result.decision.reason_codes == ('UNTRUSTED_RELEASE',)
    assert model.calls == []
    events = audit.get_events('bad-release', 'local-tenant')
    assert len(events) == 2
    assert 'release_evidence_version' not in events[0]['event']['payload']


@pytest.mark.asyncio
async def test_valid_approved_release_stored_in_signed_decision(tmp_path, audit):
    from app.application.orchestrator import RequestOrchestrator
    from app.detection.demo import DemoPatternDetector
    from app.enforcement.gateway import EnforcementPlanner
    from app.domain.contracts import Principal, PromptCommand, PolicyDecision, Effect, Obligation, RequestStatus
    from tests.conftest import RecordingModel

    _, _, store, candidate, signed = approval_fixture(tmp_path)
    store.activate(candidate)
    policy_id = signed['payload']['policy_digest']

    class PermitPolicy:
        async def evaluate(self, _):
            return PolicyDecision(Effect.PERMIT, (Obligation('ROUTE', 'sovereign-model'),),
                                  ('TEST_PERMIT',), signed['payload']['policy_revision'], policy_id)

    model = RecordingModel(audit)
    runner = RequestOrchestrator(DemoPatternDetector(), PermitPolicy(), audit, model,
                                 EnforcementPlanner(), release_store=store)
    command = PromptCommand('ok-release', 'hello', 'sovereign-model', 'GENERAL',
                            Principal('tester', 'local-tenant', ('tester',)))
    response = await runner.process(command)
    assert response.status == RequestStatus.COMPLETED
    assert len(model.calls) == 1
    evidence = audit.get_events('ok-release', 'local-tenant')[0]['event']['payload']
    assert evidence['release_evidence_version'] == '1'
    assert evidence['release_snapshot'] == summary(signed)
    assert evidence['policy_snapshot']['sha256'] == policy_id


@pytest.mark.asyncio
async def test_opa_adapter_rejects_release_change_in_flight(tmp_path):
    import httpx
    from app.policy.opa import OPAPolicyEvaluator, PolicyIntegrityError
    from app.domain.contracts import DetectionResult, DetectionStatus, Sensitivity, PolicyContext, Principal, PromptCommand

    _, _, store, candidate, doc = approval_fixture(tmp_path)
    store.activate(candidate)
    snapshot = store.policy_store.verify_active()
    class FlappingRelease:
        def __init__(self): self.calls = 0
        def verify_active(self, **kwargs):
            self.calls += 1
            x = dict(doc)
            if self.calls == 2:
                x['release_id'] = 'f' * 64
            return x

    raw = {'effect': 'PERMIT', 'obligations': [{'type': 'ROUTE', 'destination_id': 'sovereign-model'}],
           'reason_codes': ['APPROVED_INTERNAL_ROUTE'], 'policy_revision': snapshot.policy_revision,
           'policy_digest': snapshot.policy_digest}
    context = PolicyContext(PromptCommand('req', 'hello', 'sovereign-model', 'GENERAL',
                                          Principal('tester', 'tenant', ('tester',))),
                            DetectionResult(DetectionStatus.NO_PRIVATE_DETECTED,
                                            Sensitivity.NONE, (), (), 'presidio-spacy-v1',
                                            artifact_digest=D))
    async with httpx.AsyncClient(transport=httpx.MockTransport(
            lambda _: httpx.Response(200, json={'result': raw}))) as client:
        with pytest.raises(PolicyIntegrityError):
            await OPAPolicyEvaluator(client, 'http://opa', store.policy_store,
                                     FlappingRelease()).evaluate(context)
