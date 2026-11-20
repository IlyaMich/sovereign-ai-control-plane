"""OPA HTTP adapter. Undefined responses and schema deviations fail closed."""

from __future__ import annotations

import logging
import re
import time
from functools import partial
from typing import Any, Callable

import httpx

from app.domain.contracts import (
    Effect,
    Obligation,
    OutputPolicyContext,
    PolicyContext,
    PolicyDecision,
    ReleaseVerifier,
)
from app.infrastructure.config import HTTPTimeouts
from app.infrastructure.integrity_executor import (
    BoundedIntegrityExecutor,
    IntegrityCapacityExceeded,
    IntegrityExecutorClosed,
    integrity_unavailable_code,
)
from app.infrastructure.logging import event, failure_code
from app.infrastructure.resilience import ResilientHTTP
from app.policy.snapshots import DIGEST_RE, PolicySnapshotStore, SnapshotError
from app.release.approvals import ReleaseIntegrityError


class PolicyEvaluationError(Exception):
    pass


class PolicyIntegrityError(PolicyEvaluationError):
    pass


_SAFE_CODE = re.compile(r"^[A-Z][A-Z0-9_]{0,79}$")


class OPAPolicyEvaluator:
    def __init__(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        snapshots: PolicySnapshotStore | None = None,
        releases: ReleaseVerifier | None = None,
        *,
        resilient_http: ResilientHTTP | None = None,
        timeout: float = HTTPTimeouts.opa,
        integrity_executor: BoundedIntegrityExecutor | None = None,
    ):
        self._client = client
        self._http = resilient_http
        self._timeout = timeout
        self._url = base_url.rstrip("/") + "/v1/data/sovereign/authz/decision"
        self._output_url = base_url.rstrip("/") + "/v1/data/sovereign/authz/output_decision"
        self.snapshots = snapshots
        self.releases = releases
        self.integrity_executor = integrity_executor

    async def _verify(self, operation: Callable[[], Any]) -> Any:
        if self.integrity_executor is not None:
            try:
                return await self.integrity_executor.run(operation)
            except (IntegrityCapacityExceeded, IntegrityExecutorClosed) as exc:
                raise PolicyIntegrityError("Integrity verification unavailable") from exc
        # Injected legacy/test adapters remain usable.
        return operation()

    async def evaluate(self, context: PolicyContext) -> PolicyDecision:
        return await self._evaluate(context, self._url)

    async def evaluate_output(self, context: OutputPolicyContext) -> PolicyDecision:
        return await self._evaluate(context, self._output_url)

    async def _evaluate(
        self, context: PolicyContext | OutputPolicyContext, url: str
    ) -> PolicyDecision:
        started = time.perf_counter()
        try:
            try:
                pinned = await self._verify(
                    lambda: self.snapshots.verify_active() if self.snapshots else None
                )
            except SnapshotError as exc:
                raise PolicyIntegrityError("Policy snapshot unavailable or invalid") from exc
            releases = self.releases
            pinned_release = (
                await self._verify(
                    partial(
                        releases.verify_active,
                        policy_digest=pinned.policy_digest if pinned else None,
                        detector_digest=context.classification.artifact_digest,
                    )
                )
                if releases is not None
                else None
            )
            if self._http is None:
                response = await self._client.post(
                    url, json={"input": context.to_dict()}, timeout=self._timeout
                )
            else:
                response = await self._http.request(
                    self._client,
                    "opa",
                    "POST",
                    url,
                    json={"input": context.to_dict()},
                    timeout=self._timeout,
                )
            response.raise_for_status()
            data = response.json()
            raw = data["result"]
            decision = parse_decision(raw)
            if pinned and (
                decision.policy_digest != pinned.policy_digest
                or decision.policy_revision != pinned.policy_revision
            ):
                raise PolicyIntegrityError("OPA policy differs from verified active snapshot")
            if pinned_release is not None and releases is not None:
                verified_after = await self._verify(
                    partial(
                        releases.verify_active,
                        policy_digest=decision.policy_digest,
                        detector_digest=context.classification.artifact_digest,
                    )
                )
                if verified_after["release_id"] != pinned_release["release_id"]:
                    raise ReleaseIntegrityError("Approved release changed during evaluation")
            return decision
        except PolicyIntegrityError as exc:
            unavailable = integrity_unavailable_code(exc)
            event(
                "policy_verification_unavailable" if unavailable else "policy_integrity_failed",
                level=logging.WARNING if unavailable else logging.ERROR,
                limited=unavailable is not None,
                stage="policy",
                error_code=unavailable or "POLICY_INTEGRITY_FAILED",
            )
            raise
        except ReleaseIntegrityError as exc:
            event(
                "policy_integrity_failed",
                level=logging.ERROR,
                stage="policy",
                error_code="RELEASE_INTEGRITY_FAILED",
            )
            raise PolicyIntegrityError("Release signature or artifact identity invalid") from exc
        except (httpx.HTTPError, ValueError, KeyError, TypeError, SnapshotError) as exc:
            event(
                "policy_evaluation_failed",
                level=logging.ERROR,
                stage="policy",
                error_code=failure_code(exc, "OPA"),
                http_status=exc.response.status_code
                if isinstance(exc, httpx.HTTPStatusError)
                else None,
                duration_ms=round((time.perf_counter() - started) * 1000, 3),
            )
            raise PolicyEvaluationError("OPA unavailable or returned an invalid decision") from exc


def parse_decision(raw: Any) -> PolicyDecision:
    required = {"effect", "obligations", "reason_codes", "policy_revision"}
    if not isinstance(raw, dict) or not (
        set(raw) == required or set(raw) == required | {"policy_digest"}
    ):
        raise ValueError("Invalid decision fields")
    if raw["effect"] not in ("PERMIT", "DENY"):
        raise ValueError("Unknown effect")
    if "policy_digest" in raw and (
        not isinstance(raw["policy_digest"], str) or not DIGEST_RE.fullmatch(raw["policy_digest"])
    ):
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
            if (
                not isinstance(cats, list)
                or not cats
                or any(not isinstance(c, str) or not _SAFE_CODE.fullmatch(c) for c in cats)
                or len(set(cats)) != len(cats)
            ):
                raise ValueError("Invalid redaction categories")
            obligations.append(Obligation("REDACT", categories=tuple(cats)))
        else:
            raise ValueError("Unsupported obligation")
    result = PolicyDecision(
        Effect(raw["effect"]),
        tuple(obligations),
        tuple(raw["reason_codes"]),
        raw["policy_revision"],
        raw.get("policy_digest", ""),
    )
    if result.effect == Effect.DENY and result.obligations:
        raise ValueError("Deny cannot carry route obligations")
    return result
