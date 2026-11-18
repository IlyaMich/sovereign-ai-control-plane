"""OPA HTTP adapter. Undefined responses and schema deviations fail closed."""
from __future__ import annotations

import re
from typing import Any

import httpx

from app.domain.contracts import Effect, Obligation, PolicyContext, PolicyDecision
from app.policy.snapshots import PolicySnapshotStore, SnapshotError, DIGEST_RE


class PolicyEvaluationError(Exception):
    pass


class PolicyIntegrityError(PolicyEvaluationError):
    pass


_SAFE_CODE = re.compile(r"^[A-Z][A-Z0-9_]{0,79}$")


class OPAPolicyEvaluator:
    def __init__(self, client: httpx.AsyncClient, base_url: str, snapshots: PolicySnapshotStore | None = None):
        self._client = client
        self._url = base_url.rstrip("/") + "/v1/data/sovereign/authz/decision"
        self.snapshots = snapshots

    async def evaluate(self, context: PolicyContext) -> PolicyDecision:
        try:
            try:
                pinned = self.snapshots.verify_active() if self.snapshots else None
            except SnapshotError as exc:
                raise PolicyIntegrityError("Policy snapshot unavailable or invalid") from exc
            response = await self._client.post(self._url, json={"input": context.to_dict()}, timeout=2.0)
            response.raise_for_status()
            data = response.json()
            raw = data["result"]
            decision = parse_decision(raw)
            if pinned and (decision.policy_digest != pinned.policy_digest or
                           decision.policy_revision != pinned.policy_revision):
                raise PolicyIntegrityError("OPA policy differs from verified active snapshot")
            return decision
        except (httpx.HTTPError, ValueError, KeyError, TypeError, SnapshotError) as exc:
            raise PolicyEvaluationError("OPA unavailable or returned an invalid decision") from exc


def parse_decision(raw: Any) -> PolicyDecision:
    required = {"effect", "obligations", "reason_codes", "policy_revision"}
    if not isinstance(raw, dict) or not (set(raw) == required or set(raw) == required | {"policy_digest"}):
        raise ValueError("Invalid decision fields")
    if raw["effect"] not in ("PERMIT", "DENY"):
        raise ValueError("Unknown effect")
    if "policy_digest" in raw and (not isinstance(raw["policy_digest"], str) or
                                   not DIGEST_RE.fullmatch(raw["policy_digest"])):
        raise ValueError("Invalid policy digest")
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
        if not isinstance(item, dict):
            raise ValueError("Invalid obligation")
        if item.get("type") == "ROUTE" and set(item) == {"type", "destination_id"}:
            if not isinstance(item["destination_id"], str) or not item["destination_id"]:
                raise ValueError("Invalid route")
            obligations.append(Obligation("ROUTE", item["destination_id"]))
        elif item.get("type") == "REDACT" and set(item) == {"type", "categories"}:
            cats = item["categories"]
            if (not isinstance(cats, list) or not cats or
                any(not isinstance(c, str) or not _SAFE_CODE.fullmatch(c) for c in cats) or
                len(set(cats)) != len(cats)):
                raise ValueError("Invalid redaction categories")
            obligations.append(Obligation("REDACT", categories=tuple(cats)))
        else:
            raise ValueError("Unsupported obligation")
    result = PolicyDecision(Effect(raw["effect"]), tuple(obligations), tuple(raw["reason_codes"]),
                            raw["policy_revision"], raw.get("policy_digest", ""))
    if result.effect == Effect.DENY and result.obligations:
        raise ValueError("Deny cannot carry route obligations")
    return result
