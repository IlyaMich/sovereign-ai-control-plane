"""Prometheus export with a private registry and strictly bounded label values."""

from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest

ROUTES = frozenset(
    {
        "/v1/prompts",
        "/v1/requests/{request_id}",
        "/v1/idempotency/status",
        "/v1/diagnostics/concurrency",
        "/v1/diagnostics/dlp",
        "/health/live",
        "/health/ready",
        "/metrics",
    }
)
METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})


class APIMetrics:
    def __init__(self):
        self.registry = CollectorRegistry()
        self.requests = Counter(
            "sovereign_http_requests_total",
            "HTTP responses by bounded route and status class.",
            ("route", "method", "status_class"),
            registry=self.registry,
        )
        self.errors = Counter(
            "sovereign_http_errors_total",
            "HTTP client and server errors.",
            ("route", "status_class"),
            registry=self.registry,
        )
        self.latency = Histogram(
            "sovereign_http_request_duration_seconds",
            "HTTP lifetime including body reads.",
            ("route", "method"),
            registry=self.registry,
            buckets=(0.005, 0.025, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60),
        )
        self.dependency_failures = Counter(
            "sovereign_dependency_failures_total",
            "Failed outbound HTTP attempts.",
            ("dependency",),
            registry=self.registry,
        )
        self.circuit_rejections = Counter(
            "sovereign_dependency_circuit_rejections_total",
            "Calls refused by open circuits.",
            ("dependency",),
            registry=self.registry,
        )
        self.circuit_open = Gauge(
            "sovereign_dependency_circuit_open",
            "1 while open or testing recovery.",
            ("dependency",),
            registry=self.registry,
        )
        self.active = Gauge(
            "sovereign_capacity_active",
            "Active requests or submitted executor jobs.",
            ("component",),
            registry=self.registry,
        )
        self.capacity = Gauge(
            "sovereign_capacity_limit",
            "Configured process capacity.",
            ("component",),
            registry=self.registry,
        )
        self.rejections = Gauge(
            "sovereign_capacity_rejections",
            "Cumulative process capacity rejections.",
            ("component",),
            registry=self.registry,
        )
        self.unresolved = Gauge(
            "sovereign_unresolved_requests",
            "Durable claims or decisions without an OUTCOME.",
            registry=self.registry,
        )
        self.loop_lag = Gauge(
            "sovereign_event_loop_lag_p95_seconds",
            "P95 over the bounded event loop sample window.",
            registry=self.registry,
        )

        for dependency in ("opa", "model"):
            self.dependency_failures.labels(dependency).inc(0)
            self.circuit_rejections.labels(dependency).inc(0)

    def observe(self, route: str, method: str, status: int, elapsed: float) -> None:
        route = route if route in ROUTES else "UNMATCHED"
        method = method if method in METHODS else "OTHER"
        status_class = f"{status // 100}xx" if 100 <= status <= 599 else "aborted"
        self.requests.labels(route, method, status_class).inc()
        self.latency.labels(route, method).observe(elapsed)
        if status >= 400:
            self.errors.labels(route, status_class).inc()

    def render(self, admissions, executors, circuits, lag, unresolved: int) -> bytes:
        for name in ("http", "prompts", "operations"):
            admission = admissions[name]
            self.active.labels(name).set(admission.active)
            self.capacity.labels(name).set(admission.limit)
            self.rejections.labels(name).set(admission.rejected)
        for name in ("detector", "audit", "integrity"):
            snapshot = executors[name]
            if snapshot is not None:
                self.active.labels(name).set(snapshot["active_jobs"])
                self.capacity.labels(name).set(snapshot["capacity"])
                self.rejections.labels(name).set(
                    snapshot.get("capacity_rejections", snapshot.get("rejected", 0))
                )
        for name in ("opa", "model"):
            self.circuit_open.labels(name).set(int(circuits[name].is_open))
        self.loop_lag.set((lag.get("p95_ms") or 0) / 1000)
        self.unresolved.set(unresolved)
        return generate_latest(self.registry)
