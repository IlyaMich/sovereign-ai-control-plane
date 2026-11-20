"""API-level contract: output DLP denies disclosure after model execution."""

from fastapi.testclient import TestClient

from app.api.main import Components, create_app
from app.infrastructure.config import Settings
from tests.test_output_dlp import make_service


def _client(audit, generated):
    secret = "local-output-test-key-at-least-24-characters"
    orchestrator, model = make_service(audit, generated)
    app = create_app(Components(Settings(api_key=secret), orchestrator, audit))
    return TestClient(app), secret, model


def test_api_reports_output_blocked_without_leaking_generated_pii(audit):
    client, api_key, model = _client(audit, "Contact jane@example.com for details.")
    with client:
        response = client.post(
            "/v1/prompts",
            headers={"X-API-Key": api_key},
            json={"prompt": "Explain policy decisions."},
        )
        assert response.status_code == 403
        body = response.json()
        assert body["status"] == "OUTPUT_BLOCKED"
        assert body["decision"]["effect"] == "PERMIT"
        assert body["output_decision"]["effect"] == "DENY"
        assert body["output_classification"]["status"] == "PRIVATE"
        assert body["output"] is None
        assert body["model_id"] == "sovereign-model"
        assert "jane@example.com" not in response.text
        assert model.calls == 1

        evidence = client.get(
            f"/v1/requests/{body['request_id']}", headers={"X-API-Key": api_key}
        )
        assert evidence.status_code == 200
        assert "jane@example.com" not in evidence.text
        assert evidence.json()["events"][-1]["event"]["payload"]["model_invoked"] is True
        assert (
            evidence.json()["events"][-1]["event"]["payload"]["output_dlp"]["released"]
            is False
        )


def test_api_returns_clean_output_with_output_decision(audit):
    client, api_key, model = _client(audit, "Public generic response.")
    with client:
        response = client.post(
            "/v1/prompts",
            headers={"X-API-Key": api_key},
            json={"prompt": "Explain policy decisions."},
        )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "COMPLETED"
    assert body["output_decision"]["effect"] == "PERMIT"
    assert body["output_classification"]["status"] == "NO_PRIVATE_DETECTED"
    assert body["output"] == "Public generic response."
    assert model.calls == 1
