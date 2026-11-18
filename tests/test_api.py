from fastapi.testclient import TestClient

from app.api.main import Components, create_app
from app.application.orchestrator import RequestOrchestrator
from app.detection.demo import DemoPatternDetector
from app.enforcement.gateway import EnforcementPlanner
from app.infrastructure.config import Settings
from tests.conftest import RecordingModel, StaticPolicy


def app_with_fakes(audit):
    settings = Settings(api_key="a-secret-for-tests-that-is-long-enough")
    orchestrator = RequestOrchestrator(DemoPatternDetector(), StaticPolicy(), audit, RecordingModel(audit), EnforcementPlanner())
    return create_app(Components(settings, orchestrator, audit))


def test_api_requires_auth_and_sanitizes_invalid_body(audit):
    with TestClient(app_with_fakes(audit)) as client:
        assert client.post("/v1/prompts", json={"prompt": "hello"}).status_code == 401
        headers = {"X-API-Key": "a-secret-for-tests-that-is-long-enough"}
        invalid = client.post("/v1/prompts", headers=headers, json={"prompt": 9999})
        assert invalid.status_code == 422
        assert "9999" not in invalid.text


def test_large_payload_is_rejected_even_with_auth(audit):
    with TestClient(app_with_fakes(audit)) as client:
        response = client.post(
            "/v1/prompts",
            headers={"X-API-Key": "a-secret-for-tests-that-is-long-enough"},
            json={"prompt": "X" * 20000},
        )
        assert response.status_code == 413


def test_end_to_end_request_and_authorized_lookup(audit):
    with TestClient(app_with_fakes(audit)) as client:
        headers = {"X-API-Key": "a-secret-for-tests-that-is-long-enough"}
        result = client.post("/v1/prompts", headers=headers, json={"prompt": "hello"})
        assert result.status_code == 200
        body = result.json()
        assert body["status"] == "COMPLETED"
        assert body["decision_receipt"]["sequence"] == 1
        lookup = client.get(f"/v1/requests/{body['request_id']}", headers=headers)
        assert lookup.status_code == 200
        assert len(lookup.json()["events"]) == 2
        assert "hello" not in lookup.text
