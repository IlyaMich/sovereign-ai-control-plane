"""M7.7 integration: signed denials and nonblocking readiness with fake services."""

import asyncio
import threading
from dataclasses import replace
from typing import cast

import httpx
import pytest

from app.api.main import create_app
from app.application.orchestrator import RequestOrchestrator
from app.detection.demo import DemoPatternDetector
from app.domain.contracts import Principal, PromptCommand, ReleaseVerifier, RequestStatus
from app.enforcement.gateway import EnforcementPlanner
from app.infrastructure.integrity_executor import BoundedIntegrityExecutor
from tests.conftest import RecordingModel, StaticPolicy
from tests.test_api import app_with_fakes


@pytest.mark.asyncio
async def test_verification_capacity_denies_and_audits_before_any_inference(audit):
    started = threading.Event()
    release = threading.Event()

    def held():
        started.set()
        if not release.wait(5):
            raise RuntimeError("Synthetic gate timed out")

    executor = BoundedIntegrityExecutor(max_jobs=1, max_waiters=0, worker_threads=1)
    job = asyncio.create_task(executor.run(held))
    model = RecordingModel(audit)

    class Release:
        def verify_active(self, **kwargs):
            raise AssertionError("Capacity was saturated; verifier should never run")

    orchestrator = RequestOrchestrator(
        DemoPatternDetector(),
        StaticPolicy(),
        audit,
        model,
        EnforcementPlanner(),
        release_store=cast(ReleaseVerifier, Release()),
        integrity_executor=executor,
    )
    try:
        assert await asyncio.to_thread(started.wait, 2)
        result = await orchestrator.process(
            PromptCommand(
                "m7-7-capacity",
                "synthetic local content",
                "sovereign-model",
                "GENERAL",
                Principal("tester", "local-tenant", ("tester",)),
            )
        )
        assert result.status == RequestStatus.BLOCKED
        assert result.decision.reason_codes == ("UNTRUSTED_RELEASE",)
        assert model.calls == []
        assert [
            item["event"]["event_type"]
            for item in audit.get_events("m7-7-capacity", "local-tenant")
        ] == ["DECISION", "OUTCOME"]
    finally:
        release.set()
        await job
        await executor.aclose()


@pytest.mark.asyncio
async def test_readiness_file_scan_is_nonblocking_and_coalesced(audit):
    app = app_with_fakes(audit)
    deps = app.state.components
    started = threading.Event()
    release = threading.Event()
    calls = []

    def integrity_scan():
        calls.append(1)
        started.set()
        if not release.wait(5):
            raise RuntimeError("Synthetic gate timed out")

    setattr(deps.orchestrator.detector, "check_integrity", integrity_scan)
    deps.integrity_executor = BoundedIntegrityExecutor(max_jobs=2)

    def mock_response(request):
        if request.url.path == "/health":
            return httpx.Response(200, json={"status": "UP"})
        return httpx.Response(200, json={"result": {"policy_revision": "redaction-baseline-v3"}})

    async with httpx.AsyncClient(transport=httpx.MockTransport(mock_response)) as probe:
        deps.client = probe
        app = create_app(deps)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            first = asyncio.create_task(client.get("/health/ready"))
            try:
                assert await asyncio.to_thread(started.wait, 2)
                second = asyncio.create_task(client.get("/health/ready"))
                # Liveness remains responsive while installed-byte hashing blocks.
                assert (await asyncio.wait_for(client.get("/health/live"), 0.5)).status_code == 200
                await asyncio.sleep(0.02)
                assert len(calls) == 1
            finally:
                release.set()
            assert (await first).status_code == 200
            assert (await second).status_code == 200
            assert deps.integrity_executor.snapshot()["readiness_coalesced"] >= 1
    await deps.integrity_executor.aclose()


@pytest.mark.parametrize(
    "env_var,invalid",
    [
        ("MAX_INTEGRITY_JOBS", "1"),
        ("MAX_INTEGRITY_WAITERS", "-1"),
        ("MAX_INTEGRITY_WAITERS", "abc"),
        ("INTEGRITY_QUEUE_WAIT_SECONDS", "nan"),
    ],
)
def test_bad_integrity_environment_fails_startup(monkeypatch, env_var, invalid):
    from app.infrastructure.config import Settings

    monkeypatch.setenv("CONTROL_PLANE_API_KEY", "a-valid-synthetic-control-plane-test-secret")
    monkeypatch.setenv(env_var, invalid)
    with pytest.raises(ValueError):
        Settings.from_env()


def test_explicit_integrity_settings_are_injectable():
    from app.infrastructure.config import IntegrityExecutionLimits, Settings

    settings = replace(
        Settings(api_key="a-valid-synthetic-control-plane-test-secret"),
        integrity_execution=IntegrityExecutionLimits(4, 2, 0.5),
    )
    assert settings.integrity_execution.max_jobs == 4
    assert settings.integrity_execution.max_waiters == 2
