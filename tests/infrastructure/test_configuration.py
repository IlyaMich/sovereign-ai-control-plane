"""Configuration regression tests covering behavior and artifact trust boundaries."""

import json
import os
import subprocess
import sys
from dataclasses import replace
from types import SimpleNamespace

import httpx
import pytest
from fastapi.testclient import TestClient

from app.api.main import create_app
from app.detection.config import DEFAULT_CONFIG, RULES_PATH, DetectorConfig
from app.detection.presidio_detector import PresidioDetector
from app.detection.provenance import SOURCE_PATHS, DetectorIntegrityError
from app.domain.contracts import DetectionStatus, Sensitivity
from app.enforcement.gateway import HTTPModelGateway
from app.infrastructure.config import HTTPTimeouts, RequestLimits, Settings, simulator_upstream_url
from app.policy.opa import OPAPolicyEvaluator
from tests.api.test_api import app_with_fakes
from tests.detection.test_presidio_adapter import StubAnalyzer
from tests.policy.test_policy_adapter import context


def configured_app(audit, limits):
    components = app_with_fakes(audit).state.components
    components.settings = replace(components.settings, limits=limits)
    return create_app(components)


def test_api_limits_are_per_app_and_match_openapi(audit):
    headers = {"X-API-Key": "a-secret-for-tests-that-is-long-enough"}
    small = configured_app(audit, RequestLimits(10, 100, 20))
    large = configured_app(audit, RequestLimits(10000, 24000, 12000))
    with TestClient(small) as client:
        assert (
            client.post("/v1/prompts", headers=headers, json={"prompt": "x" * 10}).status_code
            == 200
        )
        assert (
            client.post("/v1/prompts", headers=headers, json={"prompt": "x" * 11}).status_code
            == 422
        )
        # Six two-byte characters pass the character bound, fail the UTF-8 byte bound.
        assert (
            client.post("/v1/prompts", headers=headers, json={"prompt": "\u00e9" * 6}).status_code
            == 422
        )
        assert client.post("/v1/prompts", headers=headers, json={"prompt": " "}).status_code == 422
        oversized = client.post("/v1/prompts", headers=headers, json={"prompt": "x" * 200})
        assert oversized.status_code == 413
        assert "x" * 20 not in oversized.text
        schema = client.get("/openapi.json").json()["components"]["schemas"]
        assert schema["ConfiguredPromptInput"]["properties"]["prompt"]["maxLength"] == 10
    with TestClient(large) as client:
        assert (
            client.post("/v1/prompts", headers=headers, json={"prompt": "x" * 9000}).status_code
            == 200
        )
        schema = client.get("/openapi.json").json()["components"]["schemas"]
        assert schema["ConfiguredPromptInput"]["properties"]["prompt"]["maxLength"] == 10000


def test_chunked_body_uses_configured_limit(audit):
    app = configured_app(audit, RequestLimits(10, 100, 20))
    with TestClient(app) as client:
        response = client.post(
            "/v1/prompts",
            content=iter([b'{"prompt":"', b"x" * 200, b'"}']),
            headers={
                "X-API-Key": "a-secret-for-tests-that-is-long-enough",
                "Content-Type": "application/json",
            },
        )
        assert response.status_code == 413


@pytest.mark.parametrize(
    "name,value",
    [
        ("MAX_PROMPT_BYTES", "0"),
        ("MAX_PROMPT_BYTES", "2.5"),
        ("MAX_REQUEST_BODY_BYTES", "8192"),
        ("MAX_FORWARDED_PROMPT_BYTES", "-1"),
        ("OPA_TIMEOUT_SECONDS", "nan"),
        ("MODEL_TIMEOUT_SECONDS", "inf"),
        ("READINESS_TIMEOUT_SECONDS", "0"),
        ("SIMULATOR_EGRESS_TIMEOUT_SECONDS", "-2"),
    ],
)
def test_bad_environment_fails_startup(monkeypatch, name, value):
    monkeypatch.setenv("CONTROL_PLANE_API_KEY", "a-secret-for-tests-that-is-long-enough")
    monkeypatch.setenv(name, value)
    with pytest.raises(ValueError):
        Settings.from_env()


def test_environment_reaches_settings(monkeypatch):
    monkeypatch.setenv("CONTROL_PLANE_API_KEY", "a-secret-for-tests-that-is-long-enough")
    monkeypatch.setenv("MAX_PROMPT_BYTES", "9000")
    monkeypatch.setenv("MAX_REQUEST_BODY_BYTES", "24000")
    monkeypatch.setenv("MAX_FORWARDED_PROMPT_BYTES", "18000")
    monkeypatch.setenv("OPA_TIMEOUT_SECONDS", "3.25")
    settings = Settings.from_env()
    assert settings.limits == RequestLimits(9000, 24000, 18000)
    assert settings.http.opa == 3.25


@pytest.mark.asyncio
async def test_configured_timeouts_reach_http_requests():
    observed = []

    def handler(request):
        observed.append(request.extensions["timeout"])
        if request.url.path == "/generate":
            return httpx.Response(200, json={"model_id": "sovereign-model", "output": "ok"})
        return httpx.Response(
            200,
            json={
                "result": {
                    "effect": "DENY",
                    "obligations": [],
                    "reason_codes": ["TEST_DENY"],
                    "policy_revision": "v1",
                }
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        await OPAPolicyEvaluator(client, "http://opa", timeout=3.25).evaluate(context())
        await HTTPModelGateway(client, "http://model", timeout=17.5).invoke(
            "r", "hello", "sovereign-model"
        )
    assert set(observed[0].values()) == {3.25}
    assert set(observed[1].values()) == {17.5}


def test_readiness_uses_configured_timeout(audit):
    observed = []

    def handler(request):
        observed.append(request.extensions["timeout"])
        return httpx.Response(
            200, json={"result": {"policy_revision": "redaction-response-dlp-v5"}}
        )

    components = app_with_fakes(audit).state.components
    components.settings = replace(components.settings, http=HTTPTimeouts(readiness=4.5))
    components.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    with TestClient(create_app(components)) as client:
        assert (
            client.get(
                "/health/ready", headers={"X-API-Key": "a-secret-for-tests-that-is-long-enough"}
            ).status_code
            == 200
        )
    assert len(observed) == 2
    assert all(set(item.values()) == {4.5} for item in observed)


def test_simulator_honors_larger_forwarded_limit_in_fresh_process():
    env = dict(os.environ, MAX_FORWARDED_PROMPT_BYTES="12000", PYTHONDONTWRITEBYTECODE="1")
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from simulator.main import GenerateRequest; "
            "from pydantic import ValidationError; "
            "GenerateRequest(request_id='r', prompt='x'*10000); "
            "GenerateRequest(request_id='r', prompt='\u00e9'*6000); "
            "print('accepted')",
        ],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "accepted"


def test_simulator_rejects_oversized_utf8_and_blank(monkeypatch):
    from pydantic import ValidationError

    from simulator import main

    monkeypatch.setattr(main, "limits", RequestLimits(10, 100, 10))
    with pytest.raises(ValidationError):
        main.GenerateRequest(request_id="r", prompt="\u00e9" * 6)
    with pytest.raises(ValidationError):
        main.GenerateRequest(request_id="r", prompt=" ")


@pytest.mark.parametrize(
    "url",
    [
        "file:///tmp/x",
        "http://user:pass@host",
        "http://host/path",
        "http://host:99999",
        "http://host?x=1",
    ],
)
def test_bad_simulator_origins_rejected(monkeypatch, url):
    monkeypatch.setenv("SIMULATOR_UPSTREAM_URL", url)
    with pytest.raises(ValueError):
        simulator_upstream_url()


def test_simulator_upstream_and_timeout(monkeypatch):
    from simulator import egress

    monkeypatch.setenv("SIMULATOR_UPSTREAM_URL", "http://alternate:9999/")
    monkeypatch.setattr(egress, "upstream_url", simulator_upstream_url())
    monkeypatch.setattr(egress, "timeouts", HTTPTimeouts(simulator_egress=7.5))
    observed = []

    def handler(request):
        observed.append(request)
        return httpx.Response(200, json={"model_id": "external-simulator", "output": "ok"})

    original = httpx.AsyncClient

    def factory(**kwargs):
        return original(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(egress.httpx, "AsyncClient", factory)
    with TestClient(egress.app) as client:
        assert (
            client.post("/generate", json={"request_id": "r", "prompt": "hello"}).status_code == 200
        )
    assert str(observed[0].url) == "http://alternate:9999/generate"
    assert set(observed[0].extensions["timeout"].values()) == {7.5}


def raw_rules():
    return json.loads(RULES_PATH.read_bytes())


@pytest.mark.parametrize(
    "mutate",
    [
        lambda r: r.update(threshold=float("nan")),
        lambda r: r.update(threshold=1.1),
        lambda r: r.update(threshold=True),
        lambda r: r.update(required_coverage=[]),
        lambda r: r.update(required_coverage=["MISSING"]),
        lambda r: r["sensitivity_mapping"].update(PERSON="NONE"),
        lambda r: r["patterns"]["API_CREDENTIAL"][0].__setitem__(1, "["),
        lambda r: r["patterns"]["API_CREDENTIAL"][0].__setitem__(2, -1),
    ],
)
def test_invalid_detector_rules_are_rejected(mutate):
    raw = raw_rules()
    mutate(raw)
    with pytest.raises(ValueError):
        DetectorConfig.from_dict(raw)


def test_threshold_sensitivity_and_digest_use_same_configuration():
    raw = raw_rules()
    raw["threshold"] = 0.8
    raw["sensitivity_mapping"]["EMAIL_ADDRESS"] = "HIGH"
    config = DetectorConfig.from_dict(raw)
    result = SimpleNamespace(
        entity_type="EMAIL_ADDRESS",
        start=0,
        end=3,
        score=0.7,
        recognition_metadata={},
        analysis_explanation=None,
    )
    default = PresidioDetector(StubAnalyzer([result])).detect("abc")
    changed = PresidioDetector(StubAnalyzer([result]), config=config).detect("abc")
    assert default.status == DetectionStatus.PRIVATE
    assert changed.status == DetectionStatus.UNKNOWN
    result.score = 0.9
    stub = StubAnalyzer([result])
    changed = PresidioDetector(stub, config=config).detect("abc")
    assert changed.sensitivity == Sensitivity.HIGH
    assert changed.config_digest != default.config_digest
    assert stub.calls[0]["score_threshold"] == 0.0
    raw["patterns"]["API_CREDENTIAL"][0][2] = 0.9
    other = PresidioDetector(StubAnalyzer([result]), config=DetectorConfig.from_dict(raw)).detect(
        "abc"
    )
    assert other.config_digest != changed.config_digest


def test_managed_detector_refuses_changed_configuration(monkeypatch):
    detector = PresidioDetector(
        StubAnalyzer(), provenance_path="manifest.json", artifact_digest="a" * 64
    )
    raw = raw_rules()
    raw["threshold"] = 0.9
    changed = DetectorConfig.from_dict(raw)
    monkeypatch.setattr(DetectorConfig, "load", classmethod(lambda cls: changed))
    with pytest.raises(DetectorIntegrityError, match="rules changed"):
        detector.detect("hello")
    with pytest.raises(DetectorIntegrityError, match="rules changed"):
        detector.check_integrity()


def test_provenance_includes_rules_and_loader():
    assert "app/detection/rules.json" in SOURCE_PATHS
    assert "app/detection/config.py" in SOURCE_PATHS
    assert DEFAULT_CONFIG == DetectorConfig.load()


def test_live_manifest_identity_covers_actual_installed_rules(tmp_path, monkeypatch):
    from app.detection import config, provenance

    model = tmp_path / "model"
    model.mkdir()
    (model / "__init__.py").write_text("# model")
    monkeypatch.setattr(
        provenance.importlib.util,
        "find_spec",
        lambda name: SimpleNamespace(origin=str(model / "__init__.py")),
    )
    monkeypatch.setattr(
        provenance.importlib.metadata,
        "version",
        lambda name: "3.8.0" if name == "en-core-web-sm" else "1.0",
    )
    root = tmp_path / "source"
    for name in SOURCE_PATHS:
        file = root / name
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text("# source")
    installed_rules = tmp_path / "installed-rules.json"
    installed_rules.write_bytes(RULES_PATH.read_bytes())
    monkeypatch.setattr(config, "RULES_PATH", installed_rules)
    first = provenance.create_manifest(root)
    raw = json.loads(installed_rules.read_bytes())
    raw["threshold"] = 0.9
    installed_rules.write_text(json.dumps(raw))
    second = provenance.create_manifest(root)
    assert first["digest"] != second["digest"]
    path = "source/app/detection/rules.json"
    assert (
        next(x for x in first["files"] if x["path"] == path)["sha256"]
        != next(x for x in second["files"] if x["path"] == path)["sha256"]
    )


def test_create_registers_configured_patterns(monkeypatch):
    from app.detection import presidio_detector

    raw = raw_rules()
    raw["patterns"]["API_CREDENTIAL"] = [["custom-marker", "CUSTOM-[0-9]+", 0.85]]
    config = DetectorConfig.from_dict(raw)
    monkeypatch.setattr(DetectorConfig, "load", classmethod(lambda cls: config))
    registered: list[dict] = []
    analyzer = SimpleNamespace(
        get_supported_entities=lambda **kwargs: list(config.required_coverage),
        registry=SimpleNamespace(add_recognizer=registered.append),
    )
    modules = {
        "spacy": SimpleNamespace(
            load=lambda name: SimpleNamespace(
                meta={"version": "3.8.0"},
                pipe_labels={"ner": ("PERSON", "CARDINAL")},
            )
        ),
        "tldextract": SimpleNamespace(extract=None, TLDExtract=lambda **kwargs: None),
        "presidio_analyzer": SimpleNamespace(
            AnalyzerEngine=lambda **kwargs: analyzer,
            Pattern=lambda **kwargs: kwargs,
            PatternRecognizer=lambda **kwargs: kwargs,
        ),
        "presidio_analyzer.nlp_engine": SimpleNamespace(
            NlpEngineProvider=lambda **kwargs: SimpleNamespace(
                create_engine=lambda: SimpleNamespace(
                    get_supported_entities=lambda: list(config.required_coverage),
                )
            ),
            NerModelConfiguration=lambda: SimpleNamespace(
                model_to_presidio_entity_mapping={"PERSON": "PERSON"}
            ),
        ),
        "presidio_analyzer.recognizer_registry": SimpleNamespace(
            RecognizerRegistryProvider=lambda **kwargs: SimpleNamespace(
                create_recognizer_registry=lambda: analyzer.registry
            ),
        ),
        "presidio_analyzer.recognizer_registry.recognizers_loader_utils": SimpleNamespace(
            RecognizerConfigurationLoader=SimpleNamespace(get=lambda: {"recognizers": []}),
        ),
    }
    for name, module in modules.items():
        monkeypatch.setitem(sys.modules, name, module)
    detector = presidio_detector.PresidioDetector.create()
    custom = next(r for r in registered if r["supported_entity"] == "API_CREDENTIAL")
    assert custom["patterns"] == [
        {"name": "custom-marker", "regex": "CUSTOM-[0-9]+", "score": 0.85}
    ]
    assert detector._config == config


@pytest.mark.parametrize(
    "tool,flag,function",
    [
        ("tools.build_detector_manifest", "--output", "write_build_manifest"),
        ("tools.verify_detector_manifest", "--manifest", "load_verified"),
    ],
)
@pytest.mark.parametrize("explicit", [False, True])
def test_manifest_tools_honor_environment_and_cli_override(
    monkeypatch, capsys, tool, flag, function, explicit
):
    import importlib

    module = importlib.import_module(tool)
    monkeypatch.setenv("DETECTOR_MANIFEST_PATH", "/custom/manifest.json")
    monkeypatch.setattr(
        sys, "argv", [tool] + ([flag, "/explicit/manifest.json"] if explicit else [])
    )
    observed = []

    def operation(path, *args, **kwargs):
        observed.append(path)
        return {"digest": "a" * 64, "files": [], "model": {"name": "test"}}

    monkeypatch.setattr(module, function, operation)
    module.main()
    assert observed == ["/explicit/manifest.json" if explicit else "/custom/manifest.json"]
    assert json.loads(capsys.readouterr().out)["detector_artifact_digest"] == "a" * 64
