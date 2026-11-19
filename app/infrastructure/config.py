"""Local environment-based configuration; never use implicit demo credentials."""

from __future__ import annotations

import math
import os
from dataclasses import dataclass, field
from urllib.parse import urlsplit


def positive_int(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except ValueError as exc:
        raise ValueError(f"{name} must be a positive integer") from exc
    if value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def positive_float(name: str, default: float) -> float:
    try:
        value = float(os.environ.get(name, str(default)))
    except ValueError as exc:
        raise ValueError(f"{name} must be a finite positive number") from exc
    if not math.isfinite(value) or value <= 0:
        raise ValueError(f"{name} must be a finite positive number")
    return value


@dataclass(frozen=True)
class RequestLimits:
    max_prompt_bytes: int = 8192
    max_request_body_bytes: int = 16384
    max_forwarded_prompt_bytes: int = 8192

    def __post_init__(self) -> None:
        for value in (
            self.max_prompt_bytes,
            self.max_request_body_bytes,
            self.max_forwarded_prompt_bytes,
        ):
            if type(value) is not int or value <= 0:
                raise ValueError("Request limits must be positive integers")
        if self.max_request_body_bytes <= self.max_prompt_bytes:
            raise ValueError(
                "MAX_REQUEST_BODY_BYTES must exceed MAX_PROMPT_BYTES for JSON overhead"
            )

    @classmethod
    def from_env(cls) -> RequestLimits:
        return cls(
            max_prompt_bytes=positive_int("MAX_PROMPT_BYTES", cls.max_prompt_bytes),
            max_request_body_bytes=positive_int(
                "MAX_REQUEST_BODY_BYTES", cls.max_request_body_bytes
            ),
            max_forwarded_prompt_bytes=positive_int(
                "MAX_FORWARDED_PROMPT_BYTES", cls.max_forwarded_prompt_bytes
            ),
        )


@dataclass(frozen=True)
class HTTPTimeouts:
    opa: float = 2.0
    model: float = 10.0
    readiness: float = 1.0
    simulator_egress: float = 5.0

    def __post_init__(self) -> None:
        for value in (self.opa, self.model, self.readiness, self.simulator_egress):
            if isinstance(value, bool) or not math.isfinite(value) or value <= 0:
                raise ValueError("HTTP timeouts must be finite positive numbers")

    @classmethod
    def from_env(cls) -> HTTPTimeouts:
        return cls(
            opa=positive_float("OPA_TIMEOUT_SECONDS", cls.opa),
            model=positive_float("MODEL_TIMEOUT_SECONDS", cls.model),
            readiness=positive_float("READINESS_TIMEOUT_SECONDS", cls.readiness),
            simulator_egress=positive_float(
                "SIMULATOR_EGRESS_TIMEOUT_SECONDS", cls.simulator_egress
            ),
        )


def simulator_upstream_url() -> str:
    value = os.environ.get("SIMULATOR_UPSTREAM_URL", "http://external-simulator:9000")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("SIMULATOR_UPSTREAM_URL must be an HTTP(S) origin") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise ValueError("SIMULATOR_UPSTREAM_URL must be an HTTP(S) origin")
    return value.rstrip("/")


@dataclass(frozen=True)
class AdmissionLimits:
    """Per API process, fail-fast capacity for admitted prompt requests."""

    max_inflight_requests: int = 8

    def __post_init__(self) -> None:
        value = self.max_inflight_requests
        if type(value) is not int or not 1 <= value <= 1024:
            raise ValueError("MAX_INFLIGHT_REQUESTS must be an integer from 1 to 1024")

    @classmethod
    def from_env(cls) -> AdmissionLimits:
        return cls(
            max_inflight_requests=positive_int("MAX_INFLIGHT_REQUESTS", cls.max_inflight_requests)
        )


@dataclass(frozen=True)
class DetectorExecutionLimits:
    """Per-worker bounded detector submissions (one detector thread)."""

    max_jobs: int = 8
    queue_wait_seconds: float = 1.0

    def __post_init__(self) -> None:
        if type(self.max_jobs) is not int or not 1 <= self.max_jobs <= 1024:
            raise ValueError("MAX_DETECTOR_JOBS must be an integer from 1 to 1024")
        value = self.queue_wait_seconds
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or value <= 0
        ):
            raise ValueError("DETECTOR_QUEUE_WAIT_SECONDS must be finite and positive")

    @classmethod
    def from_env(cls) -> DetectorExecutionLimits:
        return cls(
            max_jobs=positive_int("MAX_DETECTOR_JOBS", cls.max_jobs),
            queue_wait_seconds=positive_float(
                "DETECTOR_QUEUE_WAIT_SECONDS", cls.queue_wait_seconds
            ),
        )


@dataclass(frozen=True)
class AuditExecutionLimits:
    """Per-worker bounded SQLite audit operations (one thread)."""

    max_jobs: int = 16
    queue_wait_seconds: float = 1.0

    def __post_init__(self) -> None:
        if type(self.max_jobs) is not int or not 1 <= self.max_jobs <= 1024:
            raise ValueError("MAX_AUDIT_JOBS must be an integer from 1 to 1024")
        value = self.queue_wait_seconds
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or value <= 0
        ):
            raise ValueError("AUDIT_QUEUE_WAIT_SECONDS must be finite and positive")

    @classmethod
    def from_env(cls) -> AuditExecutionLimits:
        return cls(
            max_jobs=positive_int("MAX_AUDIT_JOBS", cls.max_jobs),
            queue_wait_seconds=positive_float("AUDIT_QUEUE_WAIT_SECONDS", cls.queue_wait_seconds),
        )


@dataclass(frozen=True)
class TelemetrySettings:
    """Small bounded metrics windows, kept only in process memory."""

    loop_lag_interval_seconds: float = 0.25
    sample_window: int = 512

    def __post_init__(self) -> None:
        delay = self.loop_lag_interval_seconds
        if isinstance(delay, bool) or not math.isfinite(delay) or not 0.05 <= delay <= 5:
            raise ValueError("LOOP_LAG_INTERVAL_SECONDS must be between 0.05 and 5")
        if type(self.sample_window) is not int or not 1 <= self.sample_window <= 4096:
            raise ValueError("METRICS_SAMPLE_WINDOW must be between 1 and 4096")

    @classmethod
    def from_env(cls) -> TelemetrySettings:
        return cls(
            loop_lag_interval_seconds=positive_float(
                "LOOP_LAG_INTERVAL_SECONDS", cls.loop_lag_interval_seconds
            ),
            sample_window=positive_int("METRICS_SAMPLE_WINDOW", cls.sample_window),
        )


@dataclass(frozen=True)
class Settings:
    api_key: str
    opa_url: str = "http://opa:8181"
    model_url: str = "http://sovereign-model:9000"
    db_path: str = "/var/lib/sovereign/audit.sqlite"
    signing_key_path: str = "/var/lib/sovereign/audit-key.pem"
    enable_external_simulator: bool = False
    egress_gateway_url: str = "http://egress-gateway:9010"
    expected_policy_revision: str = "redaction-baseline-v3"
    active_policy_path: str = "/policy-active"
    policy_archive_path: str = "/policy-archive"
    detector_manifest_path: str = "/service/detector-active/manifest.json"
    detector_archive_path: str = "/var/lib/sovereign/detector-archive"
    require_signed_release: bool = True
    release_active_path: str = "/release-active/release.json"
    release_archive_path: str = "/release-archive"
    release_trust_path: str = "/release-trust"
    limits: RequestLimits = field(default_factory=RequestLimits)
    http: HTTPTimeouts = field(default_factory=HTTPTimeouts)
    admission: AdmissionLimits = field(default_factory=AdmissionLimits)
    detector_execution: DetectorExecutionLimits = field(default_factory=DetectorExecutionLimits)
    audit_execution: AuditExecutionLimits = field(default_factory=AuditExecutionLimits)
    telemetry: TelemetrySettings = field(default_factory=TelemetrySettings)

    @classmethod
    def from_env(cls) -> Settings:
        key = os.environ.get("CONTROL_PLANE_API_KEY", "")
        if len(key) < 24 or key == "replace-with-a-random-key":
            raise RuntimeError(
                "Set CONTROL_PLANE_API_KEY to a random secret of at least 24 characters"
            )
        return cls(
            api_key=key,
            limits=RequestLimits.from_env(),
            http=HTTPTimeouts.from_env(),
            admission=AdmissionLimits.from_env(),
            detector_execution=DetectorExecutionLimits.from_env(),
            audit_execution=AuditExecutionLimits.from_env(),
            telemetry=TelemetrySettings.from_env(),
            opa_url=os.environ.get("OPA_URL", "http://opa:8181"),
            model_url=os.environ.get("MODEL_URL", "http://sovereign-model:9000"),
            db_path=os.environ.get("AUDIT_DB_PATH", "/var/lib/sovereign/audit.sqlite"),
            signing_key_path=os.environ.get(
                "AUDIT_SIGNING_KEY_PATH", "/var/lib/sovereign/audit-key.pem"
            ),
            enable_external_simulator=os.environ.get("ENABLE_EXTERNAL_SIMULATOR", "false").lower()
            == "true",
            egress_gateway_url=os.environ.get("EGRESS_GATEWAY_URL", "http://egress-gateway:9010"),
            expected_policy_revision=os.environ.get(
                "EXPECTED_POLICY_REVISION", "redaction-baseline-v3"
            ),
            active_policy_path=os.environ.get("ACTIVE_POLICY_PATH", "/policy-active"),
            policy_archive_path=os.environ.get("POLICY_ARCHIVE_PATH", "/policy-archive"),
            detector_manifest_path=os.environ.get(
                "DETECTOR_MANIFEST_PATH", "/service/detector-active/manifest.json"
            ),
            detector_archive_path=os.environ.get(
                "DETECTOR_ARCHIVE_PATH", "/var/lib/sovereign/detector-archive"
            ),
            require_signed_release=os.environ.get("REQUIRE_SIGNED_RELEASE", "true").lower()
            == "true",
            release_active_path=os.environ.get(
                "RELEASE_ACTIVE_PATH", "/release-active/release.json"
            ),
            release_archive_path=os.environ.get("RELEASE_ARCHIVE_PATH", "/release-archive"),
            release_trust_path=os.environ.get("RELEASE_TRUST_PATH", "/release-trust"),
        )
