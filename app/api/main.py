"""API ingress; no prompt echo in exceptions, logs, audit, or validation errors."""
from __future__ import annotations

from contextlib import asynccontextmanager
from dataclasses import dataclass
import hmac
import uuid

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.api.schemas import PromptInput
from app.api.body_limit import RequestBodyLimitMiddleware
from app.application.orchestrator import RequestOrchestrator
from app.audit.sqlite_store import AuditUnavailable, SQLiteAuditStore
from app.detection.presidio_detector import PresidioDetector
from app.domain.contracts import Principal, PromptCommand, RequestStatus
from app.enforcement.gateway import Destination, DestinationRegistry, EnforcementPlanner, HTTPModelGateway
from app.infrastructure.config import Settings
from app.policy.opa import OPAPolicyEvaluator


@dataclass
class Components:
    settings: Settings
    orchestrator: RequestOrchestrator
    audit: SQLiteAuditStore
    client: httpx.AsyncClient | None = None


def make_components() -> Components:
    settings = Settings.from_env()
    client = httpx.AsyncClient(trust_env=False)
    audit = SQLiteAuditStore(settings.db_path, settings.signing_key_path)
    destinations = [Destination("sovereign-model", settings.model_url, "INTERNAL")]
    if settings.enable_external_simulator:
        destinations.append(Destination("external-simulator", settings.egress_gateway_url, "EXTERNAL_SIMULATED"))
    registry = DestinationRegistry(tuple(destinations))
    orchestrator = RequestOrchestrator(
        detector=PresidioDetector.create(),
        policy=OPAPolicyEvaluator(client, settings.opa_url),
        audit=audit,
        model=HTTPModelGateway(client, settings.model_url, registry),
        planner=EnforcementPlanner(frozenset(d.id for d in destinations), registry),
    )
    return Components(settings, orchestrator, audit, client)


def create_app(components: Components | None = None) -> FastAPI:
    deps = components or make_components()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        yield
        if deps.client is not None:
            await deps.client.aclose()

    app = FastAPI(
        title="Sovereign AI Control Plane",
        version="0.3.0",
        description="Milestone 3: verified redaction, OPA obligations, and simulated egress.",
        lifespan=lifespan,
    )
    app.add_middleware(RequestBodyLimitMiddleware, max_bytes=16384)
    app.state.components = deps

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        # FastAPI's default validation errors can contain submitted field values.
        return JSONResponse(status_code=422, content={"detail": "Invalid request body"})

    @app.exception_handler(AuditUnavailable)
    async def audit_unavailable(request: Request, exc: AuditUnavailable):
        return JSONResponse(
            status_code=503,
            content={"status": "ERROR", "reason_codes": ["AUDIT_UNAVAILABLE"]},
        )

    def authenticate(api_key: str | None) -> Principal:
        if not api_key or not hmac.compare_digest(api_key, deps.settings.api_key):
            raise HTTPException(status_code=401, detail="Unauthorized")
        return Principal("local-tester", "local-tenant", ("tester",))

    @app.get("/health/live")
    async def live():
        return {"status": "UP"}

    @app.get("/health/ready")
    async def ready():
        # A policy endpoint probe is stronger than merely checking that OPA is running.
        if deps.client is None:
            return {"status": "TEST_MODE"}
        try:
            response = await deps.client.post(
                deps.settings.opa_url.rstrip("/") + "/v1/data/sovereign/authz/decision",
                json={"input": {}}, timeout=1.0,
            )
            response.raise_for_status()
            result = response.json().get("result")
            if (not isinstance(result, dict) or
                result.get("policy_revision") != deps.settings.expected_policy_revision):
                raise ValueError("Expected OPA policy revision not loaded")
            deps.audit.check_writable()
            model = await deps.client.get(deps.settings.model_url.rstrip("/") + "/health", timeout=1.0)
            model.raise_for_status()
        except (httpx.HTTPError, ValueError, AuditUnavailable):
            return JSONResponse(status_code=503, content={"status": "NOT_READY"})
        return {"status": "READY"}

    @app.post("/v1/prompts")
    async def submit(payload: PromptInput, x_api_key: str | None = Header(default=None, alias="X-API-Key")):
        principal = authenticate(x_api_key)
        request_id = str(uuid.uuid4())
        command = PromptCommand(request_id, payload.prompt, payload.destination_id, payload.purpose, principal)
        result = await deps.orchestrator.process(command)
        body = {
            "request_id": result.request_id,
            "status": result.status.value,
            "classification": result.classification.to_dict(),
            "decision": result.decision.to_dict(),
            "decision_receipt": result.decision_receipt.to_dict(),
            "outcome_receipt": result.outcome_receipt.to_dict(),
            "model_id": result.model_id,
            "output": result.output,
        }
        http_code = {RequestStatus.COMPLETED: 200, RequestStatus.BLOCKED: 403, RequestStatus.ERROR: 502}[result.status]
        return JSONResponse(status_code=http_code, content=body)

    @app.get("/v1/requests/{request_id}")
    async def get_request(request_id: uuid.UUID, x_api_key: str | None = Header(default=None, alias="X-API-Key")):
        principal = authenticate(x_api_key)
        events = deps.audit.get_events(str(request_id), principal.tenant_id)
        if not events:
            raise HTTPException(status_code=404, detail="Not found")
        return {"request_id": str(request_id), "events": events}

    return app
