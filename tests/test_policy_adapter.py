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
from app.policy.opa import OPAPolicyEvaluator, PolicyEvaluationError, parse_decision


def context():
    return PolicyContext(
        PromptCommand(
            "req1", "hello", "sovereign-model", "GENERAL", Principal("u", "t", ("tester",))
        ),
        DetectionResult(
            DetectionStatus.NO_PRIVATE_DETECTED,
            Sensitivity.NONE,
            (),
            ("EMAIL_ADDRESS",),
            "demo-patterns-v1",
        ),
    )


@pytest.mark.asyncio
async def test_opa_adapter_uses_the_expected_decision_contract():
    def handler(request):
        assert request.url.path == "/v1/data/sovereign/authz/decision"
        assert request.headers["content-type"] == "application/json"
        assert b'"tenant_id":"t"' in request.content
        return httpx.Response(
            200,
            json={
                "result": {
                    "effect": "PERMIT",
                    "obligations": [{"type": "ROUTE", "destination_id": "sovereign-model"}],
                    "reason_codes": ["TEST_PERMIT"],
                    "policy_revision": "baseline-v1",
                }
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await OPAPolicyEvaluator(client, "http://opa:8181").evaluate(context())
    assert result.effect.value == "PERMIT"


@pytest.mark.asyncio
async def test_opa_undefined_result_fails_closed():
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json={}))
    ) as client:
        with pytest.raises(PolicyEvaluationError):
            await OPAPolicyEvaluator(client, "http://opa").evaluate(context())


@pytest.mark.parametrize(
    "bad",
    [
        {"effect": "ALLOW", "obligations": [], "reason_codes": ["OK"], "policy_revision": "v1"},
        {
            "effect": "PERMIT",
            "obligations": [{"type": "EXEC", "destination_id": "x"}],
            "reason_codes": ["OK"],
            "policy_revision": "v1",
        },
        {
            "effect": "DENY",
            "obligations": [{"type": "ROUTE", "destination_id": "x"}],
            "reason_codes": ["OK"],
            "policy_revision": "v1",
        },
        {"effect": "PERMIT", "obligations": [], "reason_codes": [], "policy_revision": "v1"},
    ],
)
def test_reject_invalid_policy_output(bad):
    with pytest.raises(ValueError):
        parse_decision(bad)
