from pathlib import Path

import pytest

from app.domain.contracts import Effect, Obligation, PolicyDecision
from app.policy.replay import ReplayError, replay_database
from app.policy.snapshots import build_snapshot, SnapshotError
from tests.test_m4_policy_snapshots import SOURCE


def setup_record(tmp_path, audit):
    source = tmp_path / 'policies'
    source.mkdir()
    (source / 'decision.rego').write_text(SOURCE, encoding='utf-8')
    archive, active = tmp_path / 'archive', tmp_path / 'active'
    info = build_snapshot(source, archive, active)
    decision = PolicyDecision(Effect.PERMIT, (Obligation('ROUTE', 'sovereign-model'),),
                              ('TEST_PERMIT',), info.policy_revision, info.policy_digest)
    policy_input = {'request': {'destination_id': 'sovereign-model', 'purpose': 'GENERAL'},
                    'classification': {'status': 'NO_PRIVATE_DETECTED'}}
    audit.commit('req1', 'tenant', 'DECISION', {
        'input_hmac_sha256': audit.fingerprint('example'),
        'policy_input': policy_input,
        'policy_snapshot': {'sha256': info.policy_digest, 'revision': info.policy_revision},
        'policy_evaluation': decision.to_dict(),
        'decision': decision.to_dict(),
    })
    audit.commit('req1', 'tenant', 'OUTCOME', {'execution_status': 'COMPLETED', 'model_invoked': True})
    public = str(audit.key_path.with_suffix('.pub.pem'))
    return archive, public, info, decision


def test_replays_signed_decision_with_archived_policy(tmp_path, audit):
    archive, public, info, decision = setup_record(tmp_path, audit)
    invocations = []

    def evaluator(folder, inputs):
        invocations.append((folder, inputs))
        return decision.to_dict()

    result = replay_database(str(audit.db_path), public, str(archive), evaluator=evaluator)
    assert result['status'] == 'REPLAY_VERIFIED'
    assert result['verified_events'] == 2
    assert result['policy_decisions_replayed'] == 1
    assert result['unique_policy_snapshots'] == 1
    assert invocations[0][0].name == info.policy_digest


def test_detects_archived_policy_tampering(tmp_path, audit):
    archive, public, info, decision = setup_record(tmp_path, audit)
    (archive / info.policy_digest / 'decision.rego').write_text('tampered', encoding='utf-8')
    with pytest.raises(ReplayError):
        replay_database(str(audit.db_path), public, str(archive),
                        evaluator=lambda *_: decision.to_dict())


def test_cannot_accept_different_policy_replay_answer(tmp_path, audit):
    archive, public, info, decision = setup_record(tmp_path, audit)
    mismatch = dict(decision.to_dict())
    mismatch['effect'] = 'DENY'
    mismatch['obligations'] = []
    with pytest.raises(ReplayError):
        replay_database(str(audit.db_path), public, str(archive), evaluator=lambda *_: mismatch)


def test_reports_legacy_events_without_claiming_replay(tmp_path, audit):
    audit.commit('older', 'tenant', 'DECISION', {
        'decision': {'effect': 'DENY', 'obligations': [], 'reason_codes': ['DEFAULT_DENY'], 'policy_revision': 'baseline-v1'},
        'policy_input': {},
    })
    result = replay_database(str(audit.db_path), str(audit.key_path.with_suffix('.pub.pem')),
                             str(tmp_path / 'missing'), evaluator=lambda *_: {})
    assert result['legacy_decisions_integrity_only'] == 1
    assert result['policy_decisions_replayed'] == 0
