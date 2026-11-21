"""Transport contracts, management isolation and metrics privacy."""

import asyncio
import uuid

import httpx
import pytest
from fastapi.testclient import TestClient
from prometheus_client.parser import text_string_to_metric_families

from app.api.main import create_app
from app.api.schemas import ErrorResponse, PromptFailureResponse, PromptResponse
from app.audit.idempotency import IdempotencyStore
from app.domain.contracts import Effect
from app.infrastructure.config import APIOperations, Settings
from tests.api.test_api import app_with_fakes
from tests.conftest import StaticPolicy

HEADERS = {"X-API-Key": "a-secret-for-tests-that-is-long-enough"}


@pytest.mark.parametrize("name", ["REQUIRE_SIGNED_RELEASE", "ENABLE_EXTERNAL_SIMULATOR"])
@pytest.mark.parametrize("value", ["", "tru", "yes", "1", "falsee"])
def test_security_boolean_typos_fail(monkeypatch, name, value):
    monkeypatch.setenv("CONTROL_PLANE_API_KEY", HEADERS["X-API-Key"])
    monkeypatch.setenv(name, value)
    with pytest.raises(ValueError, match=f"{name} must be true or false"):
        Settings.from_env()


@pytest.mark.parametrize(
    "name,field",
    [
        ("REQUIRE_SIGNED_RELEASE", "require_signed_release"),
        ("ENABLE_EXTERNAL_SIMULATOR", "enable_external_simulator"),
    ],
)
@pytest.mark.parametrize("value,expected", [("true", True), ("FALSE", False), (" True ", True)])
def test_strict_boolean_supported_values(monkeypatch, name, field, value, expected):
    monkeypatch.setenv("CONTROL_PLANE_API_KEY", HEADERS["X-API-Key"])
    monkeypatch.setenv(name, value)
    assert getattr(Settings.from_env(), field) is expected


@pytest.mark.parametrize(
    "name,value",
    [
        ("MAX_OPERATIONS_REQUESTS", "0"),
        ("READINESS_CACHE_SECONDS", "nan"),
        ("PROBE_ATTEMPTS", "4"),
        ("PROBE_BACKOFF_SECONDS", "inf"),
        ("CIRCUIT_FAILURE_THRESHOLD", "0"),
        ("CIRCUIT_RESET_SECONDS", "-1"),
    ],
)
def test_operations_configuration_fails_closed(monkeypatch, name, value):
    monkeypatch.setenv(name, value)
    with pytest.raises(ValueError):
        APIOperations.from_env()


def assert_error(response, code):
    ErrorResponse.model_validate(response.json())
    assert response.json()["reason_codes"] == [code]
    assert response.headers["cache-control"] == "no-store"
    assert response.json()["correlation_id"] == response.headers["x-correlation-id"]


def test_sensitive_success_and_error_contracts(audit, monkeypatch):
    app = app_with_fakes(audit)
    with TestClient(app) as client:
        success = client.post("/v1/prompts", headers=HEADERS, json={"prompt": "synthetic"})
        PromptResponse.model_validate(success.json())
        assert success.headers["cache-control"] == "no-store"
        history = client.get(f"/v1/requests/{success.json()['request_id']}", headers=HEADERS)
        assert history.status_code == 200
        assert history.headers["cache-control"] == "no-store"
        for path, expected in [
            ("/v1/requests/not-a-uuid", "INVALID_BODY"),
            (f"/v1/requests/{uuid.uuid4()}", "NOT_FOUND"),
            ("/missing-secret-route", "NOT_FOUND"),
        ]:
            response = client.get(path, headers=HEADERS)
            assert_error(response, expected)
            assert "missing-secret-route" not in response.text
        assert_error(client.post("/v1/prompts", json={"prompt": "synthetic"}), "UNAUTHORIZED")
        assert_error(
            client.post("/v1/prompts", headers=HEADERS, json={"prompt": 9999}), "INVALID_BODY"
        )
        assert_error(
            client.post("/v1/prompts", headers=HEADERS, json={"prompt": "x" * 20000}),
            "REQUEST_TOO_LARGE",
        )

        async def broken(command):
            raise RuntimeError("PRIVATE exception text")

        monkeypatch.setattr(app.state.components.orchestrator, "process", broken)
        failure = client.post("/v1/prompts", headers=HEADERS, json={"prompt": "synthetic"})
        assert failure.status_code == 500
        assert_error(failure, "INTERNAL_ERROR")
        assert "PRIVATE" not in failure.text


@pytest.mark.parametrize(
    "failure,status,code",
    [
        ("policy", 503, "POLICY_UNAVAILABLE"),
        ("model", 502, "MODEL_UNAVAILABLE"),
        ("deny", 403, "TEST_DENY"),
        ("detector", 503, "DETECTION_UNAVAILABLE"),
    ],
)
def test_service_failure_is_distinct_from_policy_denial(audit, monkeypatch, failure, status, code):
    app = app_with_fakes(audit)
    service = app.state.components.orchestrator
    if failure == "policy":
        service.policy = StaticPolicy(raise_error=True)
    elif failure == "model":
        service.model.fail = True
    elif failure == "deny":
        service.policy = StaticPolicy(effect=Effect.DENY)
    else:

        def broken(prompt):
            raise RuntimeError("PRIVATE detector error")

        monkeypatch.setattr(service.detector, "detect", broken)
    with TestClient(app) as client:
        response = client.post("/v1/prompts", headers=HEADERS, json={"prompt": "synthetic"})
    assert response.status_code == status
    assert_error(response, code)
    result = PromptFailureResponse.model_validate(response.json())
    assert result.output is None
    assert result.status.value == ("BLOCKED" if failure == "deny" else "ERROR")
    events = audit.get_events(result.request_id, "local-tenant")
    assert [e["event"]["event_type"] for e in events] == ["DECISION", "OUTCOME"]
    if failure != "model":
        assert service.model.calls == []
        assert events[-1]["event"]["payload"]["model_invoked"] is False


def test_output_policy_failure_returns_503_without_disclosing_text(audit):
    app = app_with_fakes(audit)

    class BrokenOutputPolicy:
        async def evaluate_output(self, context):
            raise RuntimeError("PRIVATE policy exception")

    app.state.components.orchestrator.output_policy = BrokenOutputPolicy()
    with TestClient(app) as client:
        response = client.post("/v1/prompts", headers=HEADERS, json={"prompt": "synthetic"})
    assert response.status_code == 503
    assert_error(response, "OUTPUT_POLICY_UNAVAILABLE")
    assert response.json()["output"] is None
    assert "Fixture response" not in response.text
    outcome = audit.get_events(response.json()["request_id"], "local-tenant")[-1]
    assert outcome["event"]["payload"]["model_invoked"] is True
    assert outcome["event"]["payload"]["output_dlp"]["released"] is False


def test_openapi_security_and_response_contracts(audit):
    with TestClient(app_with_fakes(audit)) as client:
        schema = client.get("/openapi.json").json()
    assert schema["components"]["securitySchemes"]["ApiKeyAuth"] == {
        "type": "apiKey",
        "in": "header",
        "name": "X-API-Key",
    }
    for path in (
        "/v1/prompts",
        "/health/ready",
        "/metrics",
        "/v1/requests/{request_id}",
        "/v1/diagnostics/dlp",
    ):
        operation = schema["paths"][path]["post" if path == "/v1/prompts" else "get"]
        assert operation["security"] == [{"ApiKeyAuth": []}]
        assert not any(p["name"] == "X-API-Key" for p in operation.get("parameters", []))
        assert {"401", "408", "413", "422", "500", "503"} <= operation["responses"].keys()
    prompt = schema["paths"]["/v1/prompts"]["post"]["responses"]
    assert {"403", "409", "429", "502", "503"} <= prompt.keys()
    assert prompt["200"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "/PromptResponse"
    )
    assert "security" not in schema["paths"]["/health/live"]["get"]


@pytest.mark.asyncio
async def test_readiness_auth_cache_and_coalescing(audit):
    deps = app_with_fakes(audit).state.components
    entered, release = asyncio.Event(), asyncio.Event()
    calls = []

    async def upstream(request):
        calls.append(request.url.path)
        if request.method == "POST":
            entered.set()
            await release.wait()
            return httpx.Response(
                200, json={"result": {"policy_revision": "redaction-response-dlp-v5"}}
            )
        return httpx.Response(200, json={"status": "UP"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(upstream)) as probe:
        deps.client = probe
        app = create_app(deps)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            assert (await client.get("/health/ready")).status_code == 401
            assert calls == []
            first = asyncio.create_task(client.get("/health/ready", headers=HEADERS))
            await asyncio.wait_for(entered.wait(), 2)
            second = asyncio.create_task(client.get("/health/ready", headers=HEADERS))
            await asyncio.sleep(0)
            release.set()
            responses = await asyncio.gather(first, second)
            assert all(r.status_code == 200 for r in responses)
            assert len(calls) == 2
            assert (await client.get("/health/ready", headers=HEADERS)).status_code == 200
            assert len(calls) == 2
            app.state.readiness_probe.completed_at = float("-inf")
            assert (await client.get("/health/ready", headers=HEADERS)).status_code == 200
            assert len(calls) == 4


def test_separate_management_capacity_and_cheap_liveness(audit):
    app = app_with_fakes(audit)
    general, operations = app.state.http_admission, app.state.operations_admission
    for _ in range(general.limit):
        assert general.try_enter()
    with TestClient(app) as client:
        assert client.post("/v1/prompts", headers=HEADERS, json={"prompt": "x"}).status_code == 503
        assert client.get("/health/ready", headers=HEADERS).status_code == 200
        assert client.get("/metrics", headers=HEADERS).status_code == 200
        for _ in range(operations.limit):
            assert operations.try_enter()
        assert client.get("/health/ready", headers=HEADERS).status_code == 503
        assert client.get("/health/live").status_code == 200
    for _ in range(general.limit):
        general.leave()
    for _ in range(operations.limit):
        operations.leave()


def test_metrics_parse_without_user_content(audit):
    app = app_with_fakes(audit)
    idem = IdempotencyStore(audit)
    app.state.components.idempotency = idem
    pending_id = str(uuid.uuid4())
    idem.claim(
        tenant_id="local-tenant",
        principal_id="local-tester",
        key="private-pending-key",
        prompt="PRIVATE PROMPT",
        destination_id="sovereign-model",
        purpose="GENERAL",
        request_id=pending_id,
    )
    with TestClient(app) as client:
        assert client.get("/metrics").status_code == 401
        response = client.post("/v1/prompts", headers=HEADERS, json={"prompt": "synthetic"})
        client.get("/PRIVATE-user-path")
        client.request("PRIVATE-METHOD", "/PRIVATE-other-path")
        scrape = client.get("/metrics", headers=HEADERS)
        assert scrape.status_code == 200
        assert scrape.headers["cache-control"] == "no-store"
        samples = [
            s for family in text_string_to_metric_families(scrape.text) for s in family.samples
        ]
        assert next(s.value for s in samples if s.name == "sovereign_unresolved_requests") == 1
        http_samples = [s for s in samples if s.name == "sovereign_http_requests_total"]
        assert any(s.labels.get("route") == "/v1/prompts" for s in http_samples)
        assert any(
            s.labels.get("route") == "UNMATCHED" and s.labels.get("method") == "OTHER"
            for s in http_samples
        )
        assert (
            next(
                s.value
                for s in samples
                if s.name == "sovereign_capacity_limit" and s.labels["component"] == "http"
            )
            == 32
        )
        for private in (
            "PRIVATE",
            "private-pending-key",
            pending_id,
            response.json()["request_id"],
            HEADERS["X-API-Key"],
        ):
            assert private not in scrape.text
        audit.commit(str(uuid.uuid4()), "local-tenant", "DECISION", {})
        assert "sovereign_unresolved_requests 2.0" in client.get("/metrics", headers=HEADERS).text


@pytest.mark.parametrize(
    "reason,status",
    [
        ("RECOGNIZER_COVERAGE_INCOMPLETE", 503),
        ("DETECTION_RESULT_INVALID", 503),
        ("DETECTION_UNAVAILABLE", 503),
        ("UNSUPPORTED_CHARACTER_SET", 403),
        ("LOW_CONFIDENCE_FINDING", 403),
    ],
)
def test_detector_unknown_distinguishes_invalid_backend_from_unsupported_content(
    audit, monkeypatch, reason, status
):
    from app.domain.contracts import DetectionResult

    app = app_with_fakes(audit)
    monkeypatch.setattr(
        app.state.components.orchestrator.detector,
        "detect",
        lambda prompt: DetectionResult.unknown(reason),
    )
    with TestClient(app) as client:
        result = client.post("/v1/prompts", headers=HEADERS, json={"prompt": "synthetic"})
    assert result.status_code == status
    assert result.json()["output"] is None
    assert app.state.components.orchestrator.model.calls == []


def test_readiness_rejects_malformed_payload_and_caches_failures(audit):
    app = app_with_fakes(audit)
    calls = []

    def upstream(request):
        calls.append(1)
        return httpx.Response(200, json=["PRIVATE"])

    app.state.components.client = httpx.AsyncClient(transport=httpx.MockTransport(upstream))
    with TestClient(app) as client:
        first = client.get("/health/ready", headers=HEADERS)
        second = client.get("/health/ready", headers=HEADERS)
        assert first.status_code == second.status_code == 503
        assert_error(first, "POLICY_READINESS_FAILED")
        assert_error(second, "POLICY_READINESS_FAILED")
        assert first.headers["x-correlation-id"] != second.headers["x-correlation-id"]
        assert len(calls) == 1
        assert "PRIVATE" not in first.text + second.text


def test_metrics_db_failure_is_sanitized_503(audit, monkeypatch):
    from app.audit.sqlite_store import AuditUnavailable

    app = app_with_fakes(audit)

    def broken():
        raise AuditUnavailable("PRIVATE database path")

    monkeypatch.setattr(audit, "count_unresolved", broken)
    with TestClient(app) as client:
        response = client.get("/metrics", headers=HEADERS)
    assert response.status_code == 503
    assert_error(response, "AUDIT_UNAVAILABLE")
    assert "PRIVATE" not in response.text


def test_dlp_diagnostics_preserves_existing_metrics_and_security(audit):
    app = app_with_fakes(audit)
    with TestClient(app) as client:
        assert client.get("/v1/diagnostics/dlp").status_code == 401
        response = client.get("/v1/diagnostics/dlp", headers=HEADERS)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.json()["scope"] == "process"
    assert "masked_responses" in response.json()
