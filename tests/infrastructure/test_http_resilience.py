"""Retry and circuit boundaries using fake clocks and transports."""

import asyncio

import httpx
import pytest

from app.enforcement.gateway import HTTPModelGateway, ModelUnavailable
from app.infrastructure.api_metrics import APIMetrics
from app.infrastructure.config import APIOperations
from app.infrastructure.resilience import CircuitBreaker, CircuitOpen, ResilientHTTP
from app.policy.opa import OPAPolicyEvaluator, PolicyEvaluationError
from tests.policy.test_policy_adapter import context


@pytest.mark.asyncio
async def test_probe_retries_but_generation_is_never_retried():
    calls = []

    def upstream(request):
        calls.append(request.url.path)
        if len(calls) == 1 or request.url.path == "/generate":
            raise httpx.ReadTimeout("PRIVATE", request=request)
        return httpx.Response(200)

    http = ResilientHTTP(APIOperations(probe_backoff_seconds=0.000001), APIMetrics())
    async with httpx.AsyncClient(transport=httpx.MockTransport(upstream)) as client:
        await http.request(client, "model", "GET", "http://model/health", probe=True)
        assert calls == ["/health", "/health"]
        with pytest.raises(ModelUnavailable):
            await HTTPModelGateway(client, "http://model", resilient_http=http).invoke(
                "r", "x", "sovereign-model"
            )
        assert calls == ["/health", "/health", "/generate"]


@pytest.mark.asyncio
@pytest.mark.parametrize("status,expected", [(503, 2), (502, 2), (504, 2), (400, 1), (401, 1)])
async def test_probe_retry_allowlist_is_bounded(status, expected):
    calls = []

    def upstream(request):
        calls.append(request)
        return httpx.Response(status)

    http = ResilientHTTP(APIOperations(probe_backoff_seconds=0.000001))
    async with httpx.AsyncClient(transport=httpx.MockTransport(upstream)) as client:
        with pytest.raises(httpx.HTTPStatusError):
            await http.request(
                client, "opa", "POST", "http://opa/probe", probe=True, json={"input": {}}
            )
    assert len(calls) == expected


@pytest.mark.asyncio
async def test_policy_single_attempt_and_circuit_recovery(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr("app.infrastructure.resilience.time.monotonic", lambda: clock[0])
    calls, healthy = [], [False]

    def upstream(request):
        calls.append(request.url.path)
        if not healthy[0]:
            return httpx.Response(503)
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

    metrics = APIMetrics()
    http = ResilientHTTP(
        APIOperations(circuit_failure_threshold=2, circuit_reset_seconds=10), metrics
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(upstream)) as client:
        policy = OPAPolicyEvaluator(client, "http://opa", resilient_http=http)
        for _ in range(3):
            with pytest.raises(PolicyEvaluationError):
                await policy.evaluate(context())
        assert len(calls) == 2
        assert http.circuits["opa"].is_open
        assert not http.circuits["model"].is_open
        clock[0], healthy[0] = 11.0, True
        assert (await policy.evaluate(context())).reason_codes == ("TEST_DENY",)
        assert not http.circuits["opa"].is_open
        assert metrics.dependency_failures.labels("opa")._value.get() == 2
        assert metrics.circuit_rejections.labels("opa")._value.get() == 1


@pytest.mark.asyncio
async def test_half_open_single_probe_and_cancellation_recovery(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr("app.infrastructure.resilience.time.monotonic", lambda: clock[0])
    http = ResilientHTTP(APIOperations(circuit_failure_threshold=1, circuit_reset_seconds=1))
    circuit = http.circuits["model"]
    generation = circuit.enter()
    circuit.finish(generation, True)
    clock[0] = 2
    entered = asyncio.Event()

    async def upstream(request):
        entered.set()
        await asyncio.Event().wait()

    async with httpx.AsyncClient(transport=httpx.MockTransport(upstream)) as client:
        task = asyncio.create_task(http.request(client, "model", "GET", "http://model/health"))
        await asyncio.wait_for(entered.wait(), 1)
        with pytest.raises(CircuitOpen):
            await http.request(client, "model", "GET", "http://model/health")
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    clock[0] = 4
    assert circuit.enter() == circuit.generation
    separate = CircuitBreaker(1, 1)
    old = separate.enter()
    separate.finish(old, True)
    separate.finish(old, False)
    assert separate.is_open
