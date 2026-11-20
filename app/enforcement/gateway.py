"""Fail-closed enforcement; registry resolves identifiers to fixed trusted URLs."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass

import httpx

from app.domain.contracts import (
    DetectionResult,
    DetectionStatus,
    Effect,
    ModelResult,
    PolicyDecision,
    PromptCommand,
)
from app.enforcement.pre_egress import external_content_signals
from app.infrastructure.config import HTTPTimeouts
from app.infrastructure.logging import event, failure_code


class InvalidPlan(Exception):
    pass


class ExternalContentUnverified(InvalidPlan):
    """Independent external-boundary safety check rejected the input."""


class ModelUnavailable(Exception):
    pass


@dataclass(frozen=True)
class Destination:
    id: str
    url: str
    boundary: str  # INTERNAL or EXTERNAL_SIMULATED


class DestinationRegistry:
    def __init__(self, destinations: tuple[Destination, ...]):
        if len({d.id for d in destinations}) != len(destinations):
            raise ValueError("Duplicate destinations")
        if not destinations or any(
            d.boundary not in {"INTERNAL", "EXTERNAL_SIMULATED"}
            or not d.url.startswith("http://")
            or "/" in d.url[7:].rstrip("/")
            for d in destinations
        ):
            raise ValueError("Invalid destination configuration")
        self._destinations = {d.id: d for d in destinations}

    def get(self, destination_id: str) -> Destination | None:
        return self._destinations.get(destination_id)


class EnforcementPlanner:
    def __init__(
        self,
        allowed_destinations: frozenset[str] = frozenset({"sovereign-model"}),
        registry: DestinationRegistry | None = None,
    ):
        self.allowed_destinations = allowed_destinations
        self.registry = registry

    def validate(
        self,
        command: PromptCommand,
        decision: PolicyDecision,
        classification: DetectionResult | None = None,
    ) -> None:
        if decision.effect == Effect.DENY:
            if decision.obligations:
                raise InvalidPlan("Deny must have no obligations")
            return
        obligations = decision.obligations
        routes = [o for o in obligations if o.type == "ROUTE"]
        redactions = [o for o in obligations if o.type == "REDACT"]
        if (
            len(routes) != 1
            or len(redactions) > 1
            or len(obligations) != len(routes) + len(redactions)
            or obligations[-1].type != "ROUTE"
            or (redactions and obligations[0].type != "REDACT")
        ):
            raise InvalidPlan("Invalid obligation sequence")
        destination_id = routes[0].destination_id
        if (
            destination_id != command.destination_id
            or destination_id not in self.allowed_destinations
        ):
            raise InvalidPlan("Unapproved destination")
        destination = self.registry.get(destination_id) if self.registry else None
        if self.registry and destination is None:
            raise InvalidPlan("Destination unregistered")
        # A permissive detector/OPA result is insufficient to clear known
        # syntactic risk patterns for simulated external routing. Review the
        # ORIGINAL prompt before any redaction, so partial transformations
        # cannot erase the evidence needed for this independent guard.
        if destination is not None and destination.boundary != "INTERNAL":
            if external_content_signals(command.prompt, command.prompt):
                raise ExternalContentUnverified("External content cannot be independently cleared")
            # Until a separately validated full-span check exists, PERSON
            # redaction is not a sufficient basis for external forwarding.
            # Unrecognized names still require the independent source guard.
            if classification is not None and any(
                finding.category == "PERSON" for finding in classification.findings
            ):
                raise ExternalContentUnverified("External PERSON transformation not cleared")
        if classification is not None:
            if classification.status == DetectionStatus.UNKNOWN:
                raise InvalidPlan("Unknown classification")
            categories = {f.category for f in classification.findings}
            if redactions:
                permitted = set(redactions[0].categories)
                if not permitted or not categories or not categories.issubset(permitted):
                    raise InvalidPlan("Incomplete redaction obligations")
            if destination and destination.boundary != "INTERNAL" and categories and not redactions:
                raise InvalidPlan("External private data must be redacted")


class HTTPModelGateway:
    def __init__(
        self,
        client: httpx.AsyncClient,
        model_url: str,
        registry: DestinationRegistry | None = None,
        *,
        timeout: float = HTTPTimeouts.model,
    ):
        self._client = client
        self._timeout = timeout
        self.registry = registry or DestinationRegistry(
            (Destination("sovereign-model", model_url, "INTERNAL"),)
        )

    async def invoke(self, request_id: str, prompt: str, destination_id: str) -> ModelResult:
        destination = self.registry.get(destination_id)
        if destination is None:
            event(
                "model_destination_rejected",
                level=logging.ERROR,
                request_id=request_id,
                error_code="DESTINATION_UNREGISTERED",
            )
            raise ModelUnavailable("Destination not registered")
        # Last-mile barrier even if a caller bypasses EnforcementPlanner.
        # It cannot see the original source after redaction; the planner must
        # therefore also screen that source before transformation.
        if destination.boundary != "INTERNAL" and external_content_signals(prompt, prompt):
            event(
                "model_destination_rejected",
                level=logging.ERROR,
                request_id=request_id,
                error_code="EXTERNAL_CONTENT_UNVERIFIED",
            )
            raise ModelUnavailable("External payload failed independent safety review")
        started = time.perf_counter()
        try:
            response = await self._client.post(
                destination.url.rstrip("/") + "/generate",
                json={"request_id": request_id, "prompt": prompt},
                timeout=self._timeout,
            )
            response.raise_for_status()
            payload = response.json()
            if (
                not isinstance(payload.get("output"), str)
                or payload.get("model_id") != destination_id
            ):
                raise ValueError("Invalid model response")
            event(
                "model_invocation_completed",
                level=logging.DEBUG,
                request_id=request_id,
                destination_id=destination_id,
                http_status=response.status_code,
                duration_ms=round((time.perf_counter() - started) * 1000, 3),
            )
            return ModelResult(payload["model_id"], payload["output"])
        except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
            event(
                "model_invocation_failed",
                level=logging.ERROR,
                request_id=request_id,
                destination_id=destination_id,
                error_code=failure_code(exc, "MODEL"),
                http_status=exc.response.status_code
                if isinstance(exc, httpx.HTTPStatusError)
                else None,
                duration_ms=round((time.perf_counter() - started) * 1000, 3),
                execution_status="UNKNOWN",
            )
            raise ModelUnavailable("Model invocation failed") from exc
