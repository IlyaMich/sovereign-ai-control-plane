"""OPA HTTP adapter. Undefined responses and schema deviations fail closed."""
from __future__ import annotations

import re
from typing import Any

import httpx

from app.domain.contracts import Effect, Obligation, PolicyContext, PolicyDecision


class PolicyEvaluationError(Exception):
    pass


_SAFE_CODE = re.compile(r"^[A-Z][A-Z0-9_]{0,79}$")


class OPAPolicyEvaluator:
    def __init__(self, client: httpx.AsyncClient, base_url: str):
        self._client = client
        self._url = base_url.rstrip("/") + "/v1/data/sovereign/authz/decision"

    async def evaluate(self, context: PolicyContext) -> PolicyDecision:
        try:
            response = await self._client.post(self._url, json={"input": context.to_dict()}, timeout=2.0)
            response.raise_for_status()
            data = response.json()
            raw = data["result"]
            return parse_decision(raw)
        except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
            raise PolicyEvaluationError("OPA unavailable or returned an invalid decision") from exc


def parse_decision(raw: Any) -> PolicyDecision:
    if not isinstance(raw, dict) or set(raw) != {"effect", "obligations", "reason_codes", "policy_revision"}:
        raise ValueError("Invalid decision fields")
    if raw["effect"] not in ("PERMIT", "DENY"):
        raise ValueError("Unknown effect")
    if not isinstance(raw["policy_revision"], str) or not (1 <= len(raw["policy_revision"]) <= 80):
        raise ValueError("Invalid policy revision")
    if not isinstance(raw["reason_codes"], list) or not raw["reason_codes"]:
        raise ValueError("Missing rationale")
    if any(not isinstance(x, str) or not _SAFE_CODE.fullmatch(x) for x in raw["reason_codes"]):
        raise ValueError("Invalid rationale")
    if not isinstance(raw["obligations"], list):
        raise ValueError("Invalid obligations")
    obligations: list[Obligation] = []
    for item in raw["obligations"]:
        if not isinstance(item, dict) or set(item) != {"type", "destination_id"}:
            raise ValueError("Invalid obligation")
        if item["type"] != "ROUTE" or not isinstance(item["destination_id"], str):
            raise ValueError("Unsupported obligation")
        obligations.append(Obligation(item["type"], item["destination_id"]))
    result = PolicyDecision(Effect(raw["effect"]), tuple(obligations), tuple(raw["reason_codes"]), raw["policy_revision"])
    if result.effect == Effect.DENY and result.obligations:
        raise ValueError("Deny cannot carry route obligations")
    return result
