"""Output policy entrypoint uses the same strict OPA adapter as ingress."""

import httpx
import pytest

from app.domain.contracts import (
    DetectionResult,
    DetectionStatus,
    Effect,
    OutputPolicyContext,
    PolicyDecision,
    Principal,
    PromptCommand,
    Sensitivity,
)
from app.policy.opa import OPAPolicyEvaluator, PolicyEvaluationError


def context():
    return OutputPolicyContext(
        PromptCommand(
            "test-output",
            "clean input",
            "sovereign-model",
            "GENERAL",
            Principal("tester", "tenant", ("tester",)),
        ),
        DetectionResult(
            DetectionStatus.NO_PRIVATE_DETECTED,
            Sensitivity.NONE,
            (),
            ("EMAIL_ADDRESS", "PHONE_NUMBER", "PERSON", "CREDIT_CARD", "US_SSN",
             "API_CREDENTIAL", "PRIVATE_KEY"),
            "presidio-spacy-v1",
            ("DETECTION_COMPLETE",),
            "test-config",
        ),
    )


@pytest.mark.asyncio
async def test_output_opa_adapter_posts_metadata_to_output_entrypoint():
    requests = []

    def handler(request):
        requests.append(request)
        assert request.url.path == "/v1/data/sovereign/authz/output_decision"
        assert b"clean input" not in request.content
        assert b'"stage":"OUTPUT"' in request.content
        return httpx.Response(200, json={
            "result": PolicyDecision(
                Effect.PERMIT,
                (),
                ("OUTPUT_CONTENT_CLEARED",),
                "redaction-response-dlp-v4",
            ).to_dict()
        })

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await OPAPolicyEvaluator(client, "http://opa").evaluate_output(context())
    assert result.effect == Effect.PERMIT
    assert len(requests) == 1


@pytest.mark.asyncio
async def test_output_opa_adapter_rejects_undefined_result():
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _request: httpx.Response(200, json={})),
    ) as client:
        with pytest.raises(PolicyEvaluationError):
            await OPAPolicyEvaluator(client, "http://opa").evaluate_output(context())
