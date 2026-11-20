"""API + actual OPA CLI + test-only signed release DLP integration scenarios.

No live operator state, Podman volumes, production keys or network egress.
Optional: OPA_BINARY=path/to/opa.exe to run on Windows.
"""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import replace
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from app.api.main import Components, create_app
from app.application.orchestrator import RequestOrchestrator
from app.audit.verify import verify_database
from app.detection.demo import DemoPatternDetector
from app.detection.provenance import canonical
from app.enforcement.gateway import (
    Destination,
    DestinationRegistry,
    EnforcementPlanner,
    HTTPModelGateway,
)
from app.infrastructure.config import Settings
from app.policy.opa import OPAPolicyEvaluator
from app.policy.replay import run_opa
from app.policy.snapshots import PolicySnapshotStore, build_snapshot
from app.release.approvals import ReleaseStore, make_payload, new_keypair, sign_approval
from app.release.evidence import verify_release_references


def opa_executable() -> str:
    binary = os.environ.get("OPA_BINARY", "opa")
    if shutil.which(binary) is None:
        pytest.skip("OPA CLI not on PATH; set OPA_BINARY to full executable path")
    return binary


def _signed_app(tmp_path: Path, audit, response_text: str, *, masking: bool):
    binary = opa_executable()
    snap = PolicySnapshotStore(tmp_path / "active-policy", tmp_path / "archive-policy")
    info = build_snapshot(Path("policies"), snap.archive, snap.active)
    trust = tmp_path / "release-trust"
    trust.mkdir()
    private = tmp_path / "offline-operator" / "release-key.pem"
    public = trust / "test-release.pem"
    new_keypair(private, public)
    digest = "d" * 64
    releases = ReleaseStore(
        tmp_path / "release-active" / "release.json",
        tmp_path / "release-archive",
        trust, snap,
    )
    doc = sign_approval(
        make_payload(info.policy_digest, info.policy_revision, digest, 1, None), private
    )
    candidate = tmp_path / "candidate.json"
    candidate.write_bytes(canonical(doc) + b"\n")
    releases.activate(candidate, detector_digest=digest)

    class SignedFixtureDetector:
        def detect(self, text: str):
            original = DemoPatternDetector().detect(text)
            return replace(
                original,
                detector_version="presidio-spacy-v1",
                config_digest="test-only-signed-classifier",
                artifact_digest=digest,
                coverage=(
                    "EMAIL_ADDRESS", "PHONE_NUMBER", "PERSON", "CREDIT_CARD",
                    "US_SSN", "API_CREDENTIAL", "PRIVATE_KEY",
                ),
            )

    calls = {"model": 0, "opa": 0}

    def transport(request: httpx.Request) -> httpx.Response:
        if request.url.host == "opa" and request.url.path.endswith("/decision"):
            calls["opa"] += 1
            data = json.loads(request.content)["input"]
            entry = (
                "data.sovereign.authz.output_decision"
                if request.url.path.endswith("output_decision")
                else "data.sovereign.authz.decision"
            )
            return httpx.Response(
                200, json={"result": run_opa(binary, snap.active, data, entry)}
            )
        if request.url.host == "model" and request.url.path == "/generate":
            calls["model"] += 1
            return httpx.Response(200, json={
                "model_id": "sovereign-model", "output": response_text,
            })
        raise AssertionError("Unexpected simulated network destination")

    client = httpx.AsyncClient(transport=httpx.MockTransport(transport), trust_env=False)
    registry = DestinationRegistry((Destination("sovereign-model", "http://model", "INTERNAL"),))
    evaluator = OPAPolicyEvaluator(client, "http://opa", snap, releases)
    runner = RequestOrchestrator(
        detector=SignedFixtureDetector(),
        policy=evaluator,
        output_policy=evaluator,
        audit=audit,
        model=HTTPModelGateway(client, "http://model", registry),
        planner=EnforcementPlanner(registry=registry),
        release_store=releases,
        output_masking_enabled=masking,
    )
    key = "synthetic-integration-api-key-of-sufficient-length"
    app = create_app(Components(Settings(api_key=key), runner, audit, client))
    return app, key, calls, public, releases


@pytest.mark.parametrize("response_text,masking,expected_status,expected_model_output", [
    ("A normal public answer.", False, "COMPLETED", True),
    ("Email jane@example.com", False, "OUTPUT_BLOCKED", False),
    ("Email jane@example.com", True, "COMPLETED", True),
    ("Email jane@example.com and -----BEGIN PRIVATE KEY-----", True, "OUTPUT_BLOCKED", False),
])
def test_signed_runtime_api_output_scenarios(
    tmp_path, audit, response_text, masking, expected_status, expected_model_output
):
    app, key, calls, public, releases = _signed_app(
        tmp_path, audit, response_text, masking=masking
    )
    with TestClient(app) as client:
        headers = {"X-API-Key": key}
        result = client.post(
            "/v1/prompts", headers=headers,
            json={"prompt": "Explain the purpose of the approved policy."},
        )
        assert result.status_code == (200 if expected_status == "COMPLETED" else 403)
        body = result.json()
        assert body["status"] == expected_status
        assert body["output"] is not None if expected_model_output else body["output"] is None
        assert calls["model"] == 1
        assert calls["opa"] >= 2
        assert "jane@example.com" not in result.text if response_text.startswith("Email") else True
        events = client.get(
            f"/v1/requests/{body['request_id']}", headers=headers
        )
        assert events.status_code == 200
        assert "jane@example.com" not in events.text
        assert [e["event"]["event_type"] for e in events.json()["events"]] == [
            "DECISION", "OUTCOME"
        ]
        if masking and expected_status == "COMPLETED" and "jane@" in response_text:
            assert "[REDACTED_EMAIL_ADDRESS]" in body["output"]
            assert events.json()["events"][-1]["event"]["payload"]["output_dlp"][
                "transformation"
            ]["applied"] is True

    audit_public = str(audit.key_path.with_suffix(".pub.pem"))
    assert verify_database(str(audit.db_path), audit_public)["verified_events"] == 2
    refs = verify_release_references(str(audit.db_path), releases.archive, public)
    assert refs["release_approvals_authenticated"] == 1
    assert releases.verify_active()["release_id"]
