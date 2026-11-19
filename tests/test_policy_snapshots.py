import shutil

import httpx
import pytest

from app.domain.contracts import (
    DetectionResult,
    DetectionStatus,
    PolicyContext,
    Principal,
    PromptCommand,
    Sensitivity,
)
from app.policy.opa import OPAPolicyEvaluator, PolicyEvaluationError
from app.policy.snapshots import PolicySnapshotStore, SnapshotError, build_snapshot, verify_snapshot

SOURCE = """package sovereign.authz
import rego.v1
revision := "redaction-baseline-v3"
decision := {
 "effect": "PERMIT", "obligations": [{"type":"ROUTE", "destination_id":"sovereign-model"}],
 "reason_codes": ["TEST_PERMIT"], "policy_revision": revision,
 "policy_digest": data.sovereign.policy_meta.digest,
} if { true }
"""


def setup_snapshot(tmp_path):
    source = tmp_path / "policies"
    source.mkdir()
    (source / "decision.rego").write_text(SOURCE, encoding="utf-8")
    archive, active = tmp_path / "archive", tmp_path / "active"
    info = build_snapshot(source, archive, active)
    return source, archive, active, info


def context():
    return PolicyContext(
        PromptCommand("r", "plain", "sovereign-model", "GENERAL", Principal("u", "t", ())),
        DetectionResult(DetectionStatus.NO_PRIVATE_DETECTED, Sensitivity.NONE, (), (), "fixture"),
    )


def payload(info, digest=None):
    return {
        "effect": "PERMIT",
        "obligations": [{"type": "ROUTE", "destination_id": "sovereign-model"}],
        "reason_codes": ["TEST_PERMIT"],
        "policy_revision": info.policy_revision,
        "policy_digest": digest or info.policy_digest,
    }


def test_archive_is_reproducible_and_detects_tampering(tmp_path):
    source, archive, active, info = setup_snapshot(tmp_path)
    assert len(info.policy_digest) == 64
    assert verify_snapshot(active).policy_digest == info.policy_digest
    assert verify_snapshot(archive / info.policy_digest).policy_digest == info.policy_digest
    assert build_snapshot(source, archive, active) == info
    (active / "snapshot.rego").write_text("malicious", encoding="utf-8")
    with pytest.raises(SnapshotError):
        PolicySnapshotStore(active, archive).verify_active()
    build_snapshot(source, archive, active)
    (archive / info.policy_digest / "decision.rego").write_text("malicious", encoding="utf-8")
    with pytest.raises(SnapshotError):
        PolicySnapshotStore(active, archive).verify_active()


def test_changed_rego_same_revision_produces_distinct_snapshot(tmp_path):
    source, archive, active, info = setup_snapshot(tmp_path)
    (source / "decision.rego").write_text(SOURCE + "\n# business rule change\n", encoding="utf-8")
    changed = build_snapshot(source, archive, active)
    assert changed.policy_revision == info.policy_revision
    assert changed.policy_digest != info.policy_digest
    assert (archive / info.policy_digest / "decision.rego").read_text() == SOURCE
    assert PolicySnapshotStore(active, archive).verify_active() == changed


@pytest.mark.asyncio
async def test_opa_must_return_exact_content_digest(tmp_path):
    _, archive, active, info = setup_snapshot(tmp_path)
    snapshots = PolicySnapshotStore(active, archive)
    mismatch = payload(info, "f" * 64)
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json={"result": mismatch})
        )
    ) as client:
        with pytest.raises(PolicyEvaluationError):
            await OPAPolicyEvaluator(client, "http://opa", snapshots).evaluate(context())
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json={"result": payload(info)})
        )
    ) as client:
        result = await OPAPolicyEvaluator(client, "http://opa", snapshots).evaluate(context())
    assert result.policy_digest == info.policy_digest


@pytest.mark.asyncio
async def test_missing_archived_snapshot_fails_closed(tmp_path):
    _, archive, active, info = setup_snapshot(tmp_path)
    shutil.rmtree(archive / info.policy_digest)
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json={"result": payload(info)})
        )
    ) as client:
        with pytest.raises(PolicyEvaluationError):
            await OPAPolicyEvaluator(
                client, "http://opa", PolicySnapshotStore(active, archive)
            ).evaluate(context())
