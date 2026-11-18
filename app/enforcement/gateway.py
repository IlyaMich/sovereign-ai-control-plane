"""Destination is selected by approved identifiers, never caller-supplied URLs."""
import httpx

from app.domain.contracts import Effect, ModelResult, PolicyDecision, PromptCommand


class InvalidPlan(Exception):
    pass


class ModelUnavailable(Exception):
    pass


class EnforcementPlanner:
    def __init__(self, allowed_destinations: frozenset[str] = frozenset({"sovereign-model"})):
        self.allowed_destinations = allowed_destinations

    def validate(self, command: PromptCommand, decision: PolicyDecision) -> None:
        if decision.effect == Effect.DENY:
            if decision.obligations:
                raise InvalidPlan("Deny must have no obligations")
            return
        if len(decision.obligations) != 1:
            raise InvalidPlan("Permit requires exactly one routing obligation in milestone 1")
        obligation = decision.obligations[0]
        if (obligation.type != "ROUTE" or obligation.destination_id != command.destination_id
                or obligation.destination_id not in self.allowed_destinations):
            raise InvalidPlan("Unapproved destination or unsupported obligation")


class HTTPModelGateway:
    def __init__(self, client: httpx.AsyncClient, model_url: str):
        self._client = client
        self._url = model_url.rstrip("/") + "/generate"

    async def invoke(self, request_id: str, prompt: str, destination_id: str) -> ModelResult:
        if destination_id != "sovereign-model":
            raise ModelUnavailable("Destination not registered")
        try:
            response = await self._client.post(
                self._url,
                json={"request_id": request_id, "prompt": prompt},
                timeout=10.0,
            )
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload.get("output"), str) or payload.get("model_id") != "sovereign-model":
                raise ValueError("Invalid model response")
            return ModelResult(payload["model_id"], payload["output"])
        except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
            raise ModelUnavailable("Local model invocation failed") from exc
