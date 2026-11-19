"""API ingress; no prompt echo in exceptions, logs, audit, or validation errors."""

from __future__ import annotations

import asyncio
import hmac
import logging
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from functools import partial
from pathlib import Path

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.api.admission import InFlightAdmission
from app.api.body_limit import RequestBodyLimitMiddleware
from app.api.ingress_limit import HTTPIngressLimitMiddleware
from app.api.logging import RequestLoggingMiddleware
from app.api.schemas import PromptInput, prompt_input_model
from app.application.detector_executor import BoundedDetectorExecutor
from app.application.orchestrator import RequestOrchestrator
from app.audit.async_executor import BoundedAuditExecutor
from app.audit.idempotency import (
    ClaimState,
    IdempotencyStore,
    audit_state,
    validate_key,
)
from app.audit.sqlite_store import AuditUnavailable, SQLiteAuditStore
from app.detection.presidio_detector import PresidioDetector
from app.domain.contracts import Principal, PromptCommand, RequestStatus
from app.enforcement.gateway import (
    Destination,
    DestinationRegistry,
    EnforcementPlanner,
    HTTPModelGateway,
)
from app.infrastructure.config import Settings
from app.infrastructure.integrity_executor import BoundedIntegrityExecutor
from app.infrastructure.logging import configure_logging, context, event, logging_snapshot
from app.infrastructure.runtime_metrics import LoopLagMonitor
from app.policy.opa import OPAPolicyEvaluator
from app.policy.snapshots import PolicySnapshotStore, SnapshotError
from app.release.approvals import ReleaseIntegrityError, ReleaseStore


@dataclass
class Components:
    settings: Settings
    orchestrator: RequestOrchestrator
    audit: SQLiteAuditStore
    client: httpx.AsyncClient | None = None
    detector_executor: BoundedDetectorExecutor | None = None
    audit_executor: BoundedAuditExecutor | None = None
    idempotency: IdempotencyStore | None = None
    integrity_executor: BoundedIntegrityExecutor | None = None


def make_components() -> Components:
    event("startup_stage", stage="configuration")
    settings = Settings.from_env()
    client = httpx.AsyncClient(trust_env=False)
    event("startup_stage", stage="audit")
    audit = SQLiteAuditStore(settings.db_path, settings.signing_key_path)
    destinations = [Destination("sovereign-model", settings.model_url, "INTERNAL")]
    if settings.enable_external_simulator:
        destinations.append(
            Destination("external-simulator", settings.egress_gateway_url, "EXTERNAL_SIMULATED")
        )
    registry = DestinationRegistry(tuple(destinations))
    snapshot_store = PolicySnapshotStore(settings.active_policy_path, settings.policy_archive_path)
    # Reject an invalid or missing policy snapshot at startup.
    event("startup_stage", stage="policy")
    snapshot = snapshot_store.verify_active()
    event("policy_verified", policy_digest=snapshot.policy_digest)
    release_store = (
        ReleaseStore(
            active=Path(settings.release_active_path),
            archive=Path(settings.release_archive_path),
            trust=Path(settings.release_trust_path),
            policy_store=snapshot_store,
            detector_manifest=Path(settings.detector_manifest_path),
        )
        if settings.require_signed_release
        else None
    )
    if release_store is not None:
        event("startup_stage", stage="release")
        approval = release_store.verify_active()
        event(
            "release_verified",
            release_id=approval["release_id"],
            policy_digest=approval["payload"]["policy_digest"],
            detector_digest=approval["payload"]["detector_digest"],
        )
    event("startup_stage", stage="detector")
    detector = PresidioDetector.create(
        manifest_path=settings.detector_manifest_path,
        archive_root=settings.detector_archive_path,
    )
    executor = BoundedDetectorExecutor(
        detector,
        max_jobs=settings.detector_execution.max_jobs,
        queue_wait_seconds=settings.detector_execution.queue_wait_seconds,
        sample_window=settings.telemetry.sample_window,
    )
    idempotency = IdempotencyStore(audit)
    audit_executor = BoundedAuditExecutor(
        audit,
        max_jobs=settings.audit_execution.max_jobs,
        queue_wait_seconds=settings.audit_execution.queue_wait_seconds,
        max_waiters=settings.audit_execution.max_waiters,
        max_auxiliary_jobs=settings.audit_execution.max_auxiliary_jobs,
        sample_window=settings.telemetry.sample_window,
    )
    integrity_executor = BoundedIntegrityExecutor(
        max_jobs=settings.integrity_execution.max_jobs,
        max_waiters=settings.integrity_execution.max_waiters,
        queue_wait_seconds=settings.integrity_execution.queue_wait_seconds,
    )
    orchestrator = RequestOrchestrator(
        detector=detector,
        policy=OPAPolicyEvaluator(
            client,
            settings.opa_url,
            snapshot_store,
            release_store,
            timeout=settings.http.opa,
            integrity_executor=integrity_executor,
        ),
        audit=audit,
        model=HTTPModelGateway(client, settings.model_url, registry, timeout=settings.http.model),
        planner=EnforcementPlanner(frozenset(d.id for d in destinations), registry),
        release_store=release_store,
        detection_executor=executor,
        audit_executor=audit_executor,
        integrity_executor=integrity_executor,
    )
    return Components(
        settings,
        orchestrator,
        audit,
        client,
        executor,
        audit_executor,
        idempotency,
        integrity_executor,
    )


def create_app(components: Components | None = None) -> FastAPI:
    configure_logging()
    event("startup_started", stage="configuration")
    try:
        deps = components or make_components()
    except Exception:
        event("startup_failed", level=logging.ERROR, error_code="INITIALIZATION_FAILED")
        raise
    readiness_state = None

    def readiness(state, stage):
        nonlocal readiness_state
        identity = (state, stage)
        if identity != readiness_state:
            event(
                "readiness_changed",
                level=logging.ERROR if state == "NOT_READY" else logging.INFO,
                state=state,
                stage=stage,
            )
            readiness_state = identity

    admission = InFlightAdmission(deps.settings.admission.max_inflight_requests)
    http_admission = InFlightAdmission(deps.settings.ingress.max_active_http_requests)
    lag = LoopLagMonitor(
        interval_seconds=deps.settings.telemetry.loop_lag_interval_seconds,
        sample_window=deps.settings.telemetry.sample_window,
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        lag.start()
        event("service_started", stage="runtime")
        try:
            yield
        finally:
            event("shutdown_started", stage="runtime")
            await lag.aclose()
            try:
                if deps.integrity_executor is not None:
                    await deps.integrity_executor.aclose()
            finally:
                try:
                    if deps.detector_executor is not None:
                        await deps.detector_executor.aclose()
                finally:
                    try:
                        if deps.audit_executor is not None:
                            await deps.audit_executor.aclose()
                    finally:
                        if deps.client is not None:
                            await deps.client.aclose()
                        event("service_stopped", stage="runtime")

    app = FastAPI(
        title="Sovereign AI Control Plane",
        version="0.6.0",
        description="Milestone 6: independently signed release approvals and evidence.",
        lifespan=lifespan,
    )
    app.add_middleware(
        RequestBodyLimitMiddleware, max_bytes=deps.settings.limits.max_request_body_bytes
    )
    # Logging wraps ingress; ingress wraps body buffering and FastAPI routing.
    app.add_middleware(HTTPIngressLimitMiddleware, admission=http_admission)
    app.add_middleware(RequestLoggingMiddleware)
    app.state.components = deps
    app.state.admission = admission
    app.state.http_admission = http_admission
    app.state.loop_lag = lag

    async def idempotency_io(operation):
        """Route auxiliary DB work through M7.3's bounded SQLite lane."""
        if deps.audit_executor is not None:
            return await deps.audit_executor.run(operation)
        # Test/developer adapters may not have the production executor.
        return await asyncio.to_thread(operation)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        # FastAPI's default validation errors can contain submitted field values.
        event("validation_rejected", error_code="INVALID_BODY", limited=True)
        return JSONResponse(status_code=422, content={"detail": "Invalid request body"})

    @app.exception_handler(AuditUnavailable)
    async def audit_unavailable(request: Request, exc: AuditUnavailable):
        event("audit_unavailable", level=logging.ERROR, error_code="AUDIT_UNAVAILABLE")
        return JSONResponse(
            status_code=503,
            content={"status": "ERROR", "reason_codes": ["AUDIT_UNAVAILABLE"]},
        )

    def authenticate(api_key: str | None) -> Principal:
        if not api_key or not hmac.compare_digest(api_key, deps.settings.api_key):
            event(
                "authentication_rejected",
                level=logging.WARNING,
                limited=True,
                error_code="UNAUTHORIZED",
            )
            raise HTTPException(status_code=401, detail="Unauthorized")
        return Principal("local-tester", "local-tenant", ("tester",))

    @app.get("/v1/diagnostics/concurrency")
    async def concurrency_diagnostics(
        x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    ):
        authenticate(x_api_key)
        # No prompts, keys, request IDs, destinations or model content are exposed.
        return JSONResponse(
            headers={"Cache-Control": "no-store"},
            content={
                "scope": "process",
                "logging": logging_snapshot(),
                "http_ingress": {
                    "limit": http_admission.limit,
                    "active": http_admission.active,
                    "peak_active": http_admission.peak_active,
                    "rejected": http_admission.rejected,
                },
                "admission": {
                    "limit": admission.limit,
                    "active": admission.active,
                    "peak_active": admission.peak_active,
                    "rejected": admission.rejected,
                },
                "detector": (
                    deps.detector_executor.metrics.snapshot()
                    if deps.detector_executor is not None
                    else None
                ),
                "audit": (
                    deps.audit_executor.metrics.snapshot()
                    if deps.audit_executor is not None
                    else None
                ),
                "audit_limits": (
                    deps.audit_executor.capacity_snapshot()
                    if deps.audit_executor is not None
                    else None
                ),
                "event_loop": lag.snapshot(),
                "integrity": (
                    deps.integrity_executor.snapshot()
                    if deps.integrity_executor is not None
                    else None
                ),
            },
        )

    @app.get("/health/live")
    async def live():
        return {"status": "UP"}

    @app.get("/health/ready")
    async def ready():
        # A policy endpoint probe is stronger than merely checking that OPA is running.
        if deps.client is None:
            return {"status": "TEST_MODE"}
        stage = "policy"
        try:
            response = await deps.client.post(
                deps.settings.opa_url.rstrip("/") + "/v1/data/sovereign/authz/decision",
                json={"input": {}},
                timeout=deps.settings.http.readiness,
            )
            response.raise_for_status()
            result = response.json().get("result")
            if not isinstance(result, dict):
                raise ValueError("OPA policy result missing")
            stage = "integrity"
            # All filesystem reads, signatures, and the full installed-model
            # byte scan run off-loop. Overlapping readiness probes coalesce,
            # but each subsequent probe performs a fresh live verification.
            policy = deps.orchestrator.policy
            detector = deps.orchestrator.detector

            def check_files():
                info = (
                    policy.snapshots.verify_active()
                    if isinstance(policy, OPAPolicyEvaluator) and policy.snapshots is not None
                    else None
                )
                if hasattr(detector, "check_integrity"):
                    detector.check_integrity()
                if deps.orchestrator.release_store is not None:
                    deps.orchestrator.release_store.verify_active()
                return info

            if deps.integrity_executor is not None:
                info = await deps.integrity_executor.check_readiness(check_files)
            else:
                # Injected developer/test components also avoid blocking the loop.
                info = await asyncio.to_thread(check_files)
            if info is not None and (
                result.get("policy_digest") != info.policy_digest
                or result.get("policy_revision") != info.policy_revision
            ):
                raise ValueError("OPA policy does not match active archived snapshot")
            if result.get("policy_revision") != deps.settings.expected_policy_revision:
                raise ValueError("Expected OPA policy revision not loaded")
            stage = "audit"
            if deps.audit_executor is not None:
                await deps.audit_executor.check_writable()
            else:
                deps.audit.check_writable()
            stage = "model"
            model = await deps.client.get(
                deps.settings.model_url.rstrip("/") + "/health",
                timeout=deps.settings.http.readiness,
            )
            model.raise_for_status()
        except (
            httpx.HTTPError,
            ValueError,
            RuntimeError,
            OSError,
            AuditUnavailable,
            SnapshotError,
            ReleaseIntegrityError,
        ):
            readiness("NOT_READY", stage)
            return JSONResponse(status_code=503, content={"status": "NOT_READY"})
        readiness("READY", "runtime")
        return {"status": "READY"}

    async def submit(
        payload: PromptInput,
        x_api_key: str | None = Header(default=None, alias="X-API-Key"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ):
        principal = authenticate(x_api_key)
        if not admission.try_enter():
            event(
                "admission_rejected",
                level=logging.WARNING,
                limited=True,
                error_code="CAPACITY_EXCEEDED",
            )
            return JSONResponse(
                status_code=429,
                headers={"Retry-After": "1"},
                content={"status": "REJECTED", "reason_codes": ["CAPACITY_EXCEEDED"]},
            )
        try:
            request_id = str(uuid.uuid4())
            log_context = context.get()
            if log_context is not None:
                log_context["request_id"] = request_id
            if idempotency_key is not None:
                try:
                    validate_key(idempotency_key)
                except ValueError:
                    event(
                        "idempotency_rejected", error_code="INVALID_IDEMPOTENCY_KEY", limited=True
                    )
                    return JSONResponse(
                        status_code=400, content={"detail": "Invalid Idempotency-Key"}
                    )
                if deps.idempotency is None:
                    event(
                        "idempotency_unavailable",
                        level=logging.ERROR,
                        error_code="IDEMPOTENCY_UNAVAILABLE",
                    )
                    return JSONResponse(
                        status_code=503,
                        content={"status": "ERROR", "reason_codes": ["IDEMPOTENCY_UNAVAILABLE"]},
                    )
                claimed = await idempotency_io(
                    partial(
                        deps.idempotency.claim,
                        tenant_id=principal.tenant_id,
                        principal_id=principal.principal_id,
                        key=idempotency_key,
                        prompt=payload.prompt,
                        destination_id=payload.destination_id,
                        purpose=payload.purpose,
                        request_id=request_id,
                    )
                )
                if claimed.state == ClaimState.CONFLICT:
                    event(
                        "idempotency_conflict", error_code="IDEMPOTENCY_KEY_CONFLICT", limited=True
                    )
                    return JSONResponse(
                        status_code=409,
                        headers={"Cache-Control": "no-store"},
                        content={
                            "status": "REJECTED",
                            "reason_codes": ["IDEMPOTENCY_KEY_CONFLICT"],
                        },
                    )
                if claimed.state == ClaimState.EXISTING:
                    if log_context is not None:
                        log_context["request_id"] = claimed.request_id
                    event(
                        "idempotency_replay_prevented",
                        error_code="IDEMPOTENCY_ALREADY_ACCEPTED",
                        limited=True,
                    )
                    return JSONResponse(
                        status_code=409,
                        headers={"Cache-Control": "no-store"},
                        content={
                            "status": "REPLAY_PREVENTED",
                            "reason_codes": ["IDEMPOTENCY_ALREADY_ACCEPTED"],
                            "request_id": claimed.request_id,
                        },
                    )
            command = PromptCommand(
                request_id, payload.prompt, payload.destination_id, payload.purpose, principal
            )
            result = await deps.orchestrator.process(command)
        finally:
            admission.leave()
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
        http_code = {
            RequestStatus.COMPLETED: 200,
            RequestStatus.BLOCKED: 403,
            RequestStatus.ERROR: 502,
        }[result.status]
        return JSONResponse(status_code=http_code, content=body)

    # Bind the configured schema before FastAPI inspects the endpoint annotations.
    submit.__annotations__["payload"] = prompt_input_model(deps.settings.limits.max_prompt_bytes)
    app.post("/v1/prompts")(submit)

    @app.get("/v1/idempotency/status")
    async def idempotency_status(
        x_api_key: str | None = Header(default=None, alias="X-API-Key"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ):
        principal = authenticate(x_api_key)
        try:
            idempotency_key = validate_key(idempotency_key)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid Idempotency-Key")
        if deps.idempotency is None:
            raise HTTPException(status_code=503, detail="Idempotency unavailable")
        request_id = await idempotency_io(
            partial(
                deps.idempotency.lookup,
                tenant_id=principal.tenant_id,
                principal_id=principal.principal_id,
                key=idempotency_key,
            )
        )
        if request_id is None:
            raise HTTPException(status_code=404, detail="Not found")
        if deps.audit_executor is not None:
            events = await deps.audit_executor.get_events(request_id, principal.tenant_id)
        else:
            events = await asyncio.to_thread(deps.audit.get_events, request_id, principal.tenant_id)
        state, outcome = audit_state(events)
        return JSONResponse(
            headers={"Cache-Control": "no-store"},
            content={"request_id": request_id, "audit_state": state, "execution_status": outcome},
        )

    @app.get("/v1/requests/{request_id}")
    async def get_request(
        request_id: uuid.UUID, x_api_key: str | None = Header(default=None, alias="X-API-Key")
    ):
        principal = authenticate(x_api_key)
        if deps.audit_executor is not None:
            events = await deps.audit_executor.get_events(str(request_id), principal.tenant_id)
        else:
            events = deps.audit.get_events(str(request_id), principal.tenant_id)
        if not events:
            raise HTTPException(status_code=404, detail="Not found")
        return {"request_id": str(request_id), "events": events}

    return app
