"""Closed-loop, synthetic-only HTTP benchmark for Sovereign AI Control Plane.

External dependencies: httpx. Python >=3.12. Does not require repository imports.
Never records prompts, API keys, model output, or full audit evidence.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import math
import os
import re
import time
import uuid
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

HASH = re.compile(r"^[0-9a-f]{64}$")
SCENARIOS = (
    "local_permit",
    "credential_deny",
    "unsupported_input",
    "external_redaction",
    "mixed_traffic",
)
MIXED_SCENARIOS = ("local_permit", "credential_deny", "unsupported_input")


def select_scenario(configured: str, client: int, sequence: int) -> str:
    """Deterministically interleave safe synthetic workloads across concurrent clients.

    Each request retains its *actual* scenario for response and evidence assertions.
    The mixed profile does not require enabling the optional external simulator.
    """
    if configured == "mixed_traffic":
        if client < 0 or sequence < 1:
            raise ValueError("Invalid mixed-traffic request coordinates")
        return MIXED_SCENARIOS[(client + sequence - 1) % len(MIXED_SCENARIOS)]
    if configured not in SCENARIOS:
        raise ValueError("Unknown benchmark scenario")
    return configured


def synthetic_prompt(scenario: str, nonce: str) -> str:
    if scenario == "local_permit":
        return f"Explain a generic access policy using synthetic examples. Sample {nonce}."
    if scenario == "credential_deny":
        return f"Synthetic test marker -----BEGIN PRIVATE KEY----- Sample {nonce}."
    if scenario == "unsupported_input":
        return f"Synthetic unsupported character café. Sample {nonce}."
    if scenario == "external_redaction":
        return f"Synthetic email record: sample{nonce}@example.com. Summarize this test record."
    raise ValueError(f"Unknown scenario: {scenario}")


def expected(scenario: str) -> tuple[int, str, str, str | None]:
    return {
        "local_permit": (200, "COMPLETED", "PERMIT", "sovereign-model"),
        "credential_deny": (403, "BLOCKED", "DENY", None),
        "unsupported_input": (403, "BLOCKED", "DENY", None),
        "external_redaction": (200, "COMPLETED", "PERMIT", "external-simulator"),
    }[scenario]


def destination(scenario: str) -> str:
    return "external-simulator" if scenario == "external_redaction" else "sovereign-model"


def quantile(values: list[float], q: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    pos = (len(ordered) - 1) * q
    lo = int(math.floor(pos))
    hi = int(math.ceil(pos))
    return round(ordered[lo] + (ordered[hi] - ordered[lo]) * (pos - lo), 2)


def check_receipt(receipt: Any) -> bool:
    if not isinstance(receipt, dict) or type(receipt.get("sequence")) is not int:
        return False
    if receipt["sequence"] < 1 or not isinstance(receipt.get("event_hash"), str):
        return False
    if not HASH.fullmatch(receipt["event_hash"]):
        return False
    try:
        signature = base64.b64decode(receipt["signature"], validate=True)
        return len(signature) == 64
    except (KeyError, TypeError, ValueError):
        return False


def validate_result(
    scenario: str, http_status: int, body: Any, *, allow_overload: bool = False
) -> list[str]:
    errors: list[str] = []
    if allow_overload and http_status == 429:
        if (
            isinstance(body, dict)
            and body.get("status") == "REJECTED"
            and "CAPACITY_EXCEEDED" in body.get("reason_codes", [])
            and "request_id" not in body
            and "decision_receipt" not in body
            and "outcome_receipt" not in body
        ):
            return []  # Explicit pre-admission rejection: no audit event required.
        return ["unexpected_overload_contract"]
    status, state, effect, model = expected(scenario)
    if http_status != status:
        errors.append("unexpected_http_status")
    if not isinstance(body, dict):
        return errors + ["invalid_json_body"]
    if body.get("status") != state:
        errors.append("unexpected_request_status")
    decision = body.get("decision") or {}
    if not isinstance(decision, dict) or decision.get("effect") != effect:
        errors.append("unexpected_policy_effect")
    if body.get("model_id") != model:
        errors.append("unexpected_model_id")
    if scenario == "credential_deny" and "CREDENTIAL_BLOCKED" not in decision.get(
        "reason_codes", []
    ):
        errors.append("missing_credential_denial_reason")
    classification = body.get("classification")
    if scenario == "unsupported_input" and (
        "DETECTION_UNKNOWN" not in decision.get("reason_codes", [])
        or not isinstance(classification, dict)
        or classification.get("status") != "UNKNOWN"
    ):
        errors.append("missing_unknown_detection_reason")
    if scenario == "external_redaction" and "REDACT" not in [
        x.get("type") for x in decision.get("obligations", []) if isinstance(x, dict)
    ]:
        errors.append("missing_redaction_obligation")
    request_id = body.get("request_id")
    try:
        uuid.UUID(request_id)
    except (TypeError, ValueError, AttributeError):
        errors.append("invalid_request_id")
    first = body.get("decision_receipt")
    second = body.get("outcome_receipt")
    if not check_receipt(first) or not check_receipt(second):
        errors.append("missing_or_invalid_receipt")
    elif first["sequence"] >= second["sequence"]:
        errors.append("receipt_order_invalid")
    return errors


def check_event_evidence(scenario: str, result: dict[str, Any], events: Any) -> list[str]:
    issues: list[str] = []
    if not isinstance(events, list) or len(events) != 2:
        return ["expected_exactly_two_events"]
    (dec, out) = events
    if not all(isinstance(x, dict) for x in (dec, out)):
        return ["event_not_object"]
    for item, event_type, receipt_field in (
        (dec, "DECISION", "decision_receipt"),
        (out, "OUTCOME", "outcome_receipt"),
    ):
        event = item.get("event")
        if not isinstance(event, dict) or event.get("event_type") != event_type:
            issues.append(f"wrong_{event_type.lower()}_event_type")
            continue
        if event.get("request_id") != result.get("request_id"):
            issues.append("event_request_mismatch")
        if event.get("tenant_id") != "local-tenant":
            issues.append("unexpected_tenant")
        if item.get("receipt") != result.get(receipt_field):
            issues.append(f"{event_type.lower()}_receipt_mismatch")
    if issues:
        return issues
    decision_payload = dec["event"].get("payload", {})
    outcome_payload = out["event"].get("payload", {})
    if decision_payload.get("decision", {}).get("effect") != expected(scenario)[2]:
        issues.append("audited_effect_mismatch")
    actual_execution = outcome_payload.get("execution_status")
    if actual_execution != ("BLOCKED" if expected(scenario)[1] == "BLOCKED" else "COMPLETED"):
        issues.append("audited_outcome_mismatch")
    if outcome_payload.get("model_invoked") is not (expected(scenario)[1] == "COMPLETED"):
        issues.append("audited_model_invoked_mismatch")
    first_seq = dec["receipt"]["sequence"]
    second_seq = out["receipt"]["sequence"]
    if first_seq >= second_seq:
        issues.append("audited_sequence_order")
    return issues


async def verify_audited_response(
    client: httpx.AsyncClient,
    *,
    key: str,
    scenario: str,
    row: dict[str, Any],
    max_attempts: int = 8,
) -> tuple[list[str], int]:
    """Verify evidence by exact receipt match; retry only known audit-unavailable 503.

    Returns (errors, transient_503_count). A valid signed-chain snapshot is
    checked independently by suite.py; this helper never substitutes for it.
    """
    if not 1 <= max_attempts <= 20:
        raise ValueError("Invalid evidence lookup retry count")
    if (
        row.get("request_id") is None
        or row.get("decision_receipt") is None
        or row.get("outcome_receipt") is None
    ):
        return ["no_audited_response_receipt"], 0
    retries = 0
    for attempt in range(max_attempts):
        try:
            response = await client.get(
                f"/v1/requests/{row['request_id']}",
                headers={"X-API-Key": key},
            )
        except httpx.TimeoutException:
            return ["evidence_transport_timeout"], retries
        except httpx.HTTPError:
            return ["evidence_transport_error"], retries
        if response.status_code == 503:
            try:
                failure = response.json()
            except ValueError:
                return ["evidence_503_invalid_json"], retries
            if (
                not isinstance(failure, dict)
                or failure.get("status") != "ERROR"
                or not isinstance(failure.get("reason_codes"), list)
                or "AUDIT_UNAVAILABLE" not in failure["reason_codes"]
            ):
                return ["evidence_unexpected_503"], retries
            retries += 1
            if attempt == max_attempts - 1:
                return ["evidence_audit_unavailable_retries_exhausted"], retries
            # Bounded backoff for the documented fail-closed audit lookup contract.
            await asyncio.sleep(0.03 * (attempt + 1))
            continue
        if response.status_code != 200:
            # Never turn unexpected errors into success, including other 5xx.
            return ["evidence_unexpected_http_status"], retries
        try:
            document = response.json()
        except ValueError:
            return ["evidence_invalid_json"], retries
        if not isinstance(document, dict) or document.get("request_id") != row["request_id"]:
            return ["evidence_request_id_mismatch"], retries
        try:
            return check_event_evidence(scenario, row, document.get("events")), retries
        except (AttributeError, KeyError, TypeError, ValueError):
            return ["evidence_invalid_structure"], retries
    raise AssertionError("Unreachable exhausted evidence retry loop")


@dataclass
class Config:
    api_url: str
    clients: int
    duration: float
    scenario: str
    timeout: float
    key: str
    label: str
    output_dir: Path
    verify_evidence: bool = True
    allow_overload: bool = False
    arrival_rate_rps: float | None = None


async def run(config: Config) -> dict[str, Any]:
    rate = config.arrival_rate_rps
    if rate is not None and (
        type(rate) not in (int, float)
        or not math.isfinite(rate)
        or not 0.1 <= rate <= 64
        or not 1 <= config.duration <= 3600
        or math.ceil(config.duration * rate) > 50_000
    ):
        raise ValueError("Invalid open-loop rate or unsafe scheduled request budget")
    if type(config.clients) is not int or not 1 <= config.clients <= 64:
        raise ValueError("Invalid concurrent HTTP client cap")
    config.output_dir.mkdir(parents=True, exist_ok=True)
    run_id = uuid.uuid4().hex[:12]
    created = datetime.now(timezone.utc).isoformat()
    rows: list[dict[str, Any]] = []
    # Preflight is *outside* the measurement interval and does not write audit events.
    async with httpx.AsyncClient(
        base_url=config.api_url,
        timeout=httpx.Timeout(config.timeout),
        limits=httpx.Limits(
            max_connections=config.clients + 8, max_keepalive_connections=config.clients + 8
        ),
        trust_env=False,
    ) as client:
        health = await client.get("/health/ready", headers={"X-API-Key": config.key}, timeout=30.0)
        if health.status_code != 200 or health.json().get("status") != "READY":
            raise RuntimeError(f"Readiness failed: HTTP {health.status_code}")
        max_inflight = 0
        inflight = 0
        deadline = 0.0
        start = time.perf_counter()
        deadline = start + config.duration

        async def request_once(
            index: int, local_seq: int, scheduled_at: float | None = None
        ) -> None:
            nonlocal max_inflight, inflight
            actual_scenario = select_scenario(config.scenario, index, local_seq)
            nonce = f"{run_id}{index:02d}{local_seq:06d}"
            t0 = time.perf_counter()
            inflight += 1
            max_inflight = max(max_inflight, inflight)
            row: dict[str, Any] = {
                "client": index,
                "sequence": local_seq,
                "scenario": actual_scenario,
                "started_s": round(t0 - start, 4),
                "schedule_lag_ms": (
                    round(max(0.0, (t0 - scheduled_at) * 1000), 2)
                    if scheduled_at is not None
                    else None
                ),
                "request_id": None,
                "http_status": None,
                "request_status": None,
                "policy_effect": None,
                "latency_ms": None,
                "decision_receipt": None,
                "outcome_receipt": None,
                "validation_errors": [],
                "transport_error": None,
                "evidence_errors": None,
            }
            try:
                response = await client.post(
                    "/v1/prompts",
                    headers={"X-API-Key": config.key},
                    json={
                        "prompt": synthetic_prompt(actual_scenario, nonce),
                        "destination_id": destination(actual_scenario),
                        "purpose": "GENERAL",
                    },
                )
                row["http_status"] = response.status_code
                try:
                    body = response.json()
                except ValueError:
                    body = None
                if isinstance(body, dict):
                    row["request_id"] = body.get("request_id")
                    row["request_status"] = body.get("status")
                    decision = body.get("decision")
                    row["policy_effect"] = (
                        decision.get("effect") if isinstance(decision, dict) else None
                    )
                    row["decision_receipt"] = body.get("decision_receipt")
                    row["outcome_receipt"] = body.get("outcome_receipt")
                # The signature chain is independently verified via the offline reviewer.
                row["validation_errors"] = validate_result(
                    actual_scenario,
                    response.status_code,
                    body,
                    allow_overload=config.allow_overload,
                )
            except httpx.HTTPError as exc:
                row["transport_error"] = type(exc).__name__
            finally:
                end = time.perf_counter()
                row["latency_ms"] = round((end - t0) * 1000, 2)
                row["finished_s"] = round(end - start, 4)
                inflight -= 1
                rows.append(row)

        async def worker(index: int) -> None:
            sequence = 0
            while time.perf_counter() < deadline:
                sequence += 1
                await request_once(index, sequence)

        offered_requests = 0
        client_capacity_drops = 0
        if rate is None:
            await asyncio.gather(*(worker(i) for i in range(config.clients)))
        else:
            # Fixed *scheduled* arrivals, independent of server completion. Never
            # create an unbounded client queue or silently omit offered load.
            active: set[asyncio.Task[None]] = set()
            submitted: list[asyncio.Task[None]] = []
            for tick in range(math.ceil(config.duration * rate)):
                scheduled_at = start + tick / rate
                delay = scheduled_at - time.perf_counter()
                if delay > 0:
                    await asyncio.sleep(delay)
                offered_requests += 1
                if time.perf_counter() >= deadline or len(active) >= config.clients:
                    client_capacity_drops += 1
                    continue
                task = asyncio.create_task(
                    request_once(tick % config.clients, tick // config.clients + 1, scheduled_at)
                )
                active.add(task)
                submitted.append(task)
                task.add_done_callback(active.discard)
            # Drain and verify all issued requests before querying audit evidence.
            await asyncio.gather(*submitted)
        if rate is None:
            offered_requests = len(rows)
        elapsed = time.perf_counter() - start
        measured = len(rows)
        evidence_transient_audit_503 = 0
        if config.verify_evidence:
            # Evidence verification is outside the measured request interval.
            # Read the live, authenticated per-process auxiliary limit rather than
            # assuming every deployment uses MAX_AUDIT_AUXILIARY_JOBS=4.
            try:
                diagnostic_response = await client.get(
                    "/v1/diagnostics/concurrency",
                    headers={"X-API-Key": config.key},
                )
                diagnostic_response.raise_for_status()
                diagnostic = diagnostic_response.json()
                auxiliary_limit = diagnostic["audit_limits"]["maximum_auxiliary_jobs"]
            except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
                raise RuntimeError("Cannot determine audit evidence-lookup capacity") from exc
            if type(auxiliary_limit) is not int or not 1 <= auxiliary_limit <= 1024:
                raise RuntimeError("Invalid audit evidence-lookup capacity")
            semaphore = asyncio.Semaphore(min(config.clients, auxiliary_limit))

            async def inspect(row: dict[str, Any]) -> None:
                nonlocal evidence_transient_audit_503
                if config.allow_overload and row["http_status"] == 429:
                    row["evidence_errors"] = []
                    return
                async with semaphore:
                    errors, transient_503 = await verify_audited_response(
                        client,
                        key=config.key,
                        scenario=row["scenario"],
                        row=row,
                    )
                    row["evidence_errors"] = errors
                    evidence_transient_audit_503 += transient_503

            await asyncio.gather(*(inspect(r) for r in rows))
        success = [
            r
            for r in rows
            if not r["validation_errors"]
            and r["transport_error"] is None
            and r["http_status"] == expected(r["scenario"])[0]
        ]
        latencies = [
            r["latency_ms"]
            for r in rows
            if r["latency_ms"] is not None and r["transport_error"] is None
        ]
        by_status = Counter(
            str(r["http_status"] if r["http_status"] is not None else "transport") for r in rows
        )
        unknown_outcome = sum(1 for r in rows if r["request_status"] == "ERROR")
        evidence_errors = (
            sum(bool(r["evidence_errors"]) for r in rows) if config.verify_evidence else None
        )
        with (config.output_dir / "requests.jsonl").open("w", encoding="utf-8") as out:
            for row in sorted(rows, key=lambda x: (x["started_s"], x["client"])):
                out.write(json.dumps(row, separators=(",", ":"), allow_nan=False) + "\n")
        summary = {
            "schema_version": 1,
            "run_id": run_id,
            "label": config.label,
            "scenario": config.scenario,
            "timestamp_utc": created,
            "api_url": config.api_url,
            "clients": config.clients,
            "duration_configured_s": config.duration,
            "arrival_rate_rps": rate,
            "offered_requests": offered_requests,
            "dispatched_requests": measured,
            "client_capacity_drops": client_capacity_drops,
            "offered_rps": round(offered_requests / config.duration, 3),
            "dispatched_rps": round(measured / config.duration, 3),
            "elapsed_with_drain_s": round(elapsed, 3),
            "request_count": measured,
            "success_count": len(success),
            "scenario_request_counts": dict(sorted(Counter(r["scenario"] for r in rows).items())),
            "scenario_success_counts": dict(
                sorted(Counter(r["scenario"] for r in success).items())
            ),
            "overload_rejections_429": sum(r["http_status"] == 429 for r in rows),
            "expected_success_rate_pct": round(100 * len(success) / measured, 2) if measured else 0,
            "responses_within_window": sum(
                r["finished_s"] <= config.duration for r in rows if r["http_status"] is not None
            ),
            "responses_per_test_second": round(
                sum(
                    r["finished_s"] <= config.duration for r in rows if r["http_status"] is not None
                )
                / config.duration,
                3,
            ),
            "goodput_per_test_second": round(
                sum(r["finished_s"] <= config.duration for r in success) / config.duration, 3
            ),
            "total_completed_per_elapsed_second": round(measured / elapsed, 3) if elapsed else 0,
            "http_statuses": dict(sorted(by_status.items())),
            "transport_errors": sum(r["transport_error"] is not None for r in rows),
            "functional_validation_failures": sum(bool(r["validation_errors"]) for r in rows),
            "evidence_validation_failures": evidence_errors,
            "evidence_transient_audit_503": evidence_transient_audit_503,
            "audited_receipt_responses": sum(
                check_receipt(r["decision_receipt"]) and check_receipt(r["outcome_receipt"])
                for r in rows
            ),
            "duplicate_request_ids": (lambda ids: len(ids) - len(set(ids)))(
                [r["request_id"] for r in rows if r["request_id"] is not None]
            ),
            "unresolved_status_error": unknown_outcome,
            "max_inflight_client_requests": max_inflight,
            "latency_ms": {
                "p50": quantile(latencies, 0.50),
                "p95": quantile(latencies, 0.95),
                "p99": quantile(latencies, 0.99),
                "max": max(latencies) if latencies else None,
            },
            "privacy": "Synthetic prompts only; prompts, API keys, and model outputs not written",
        }
        (config.output_dir / "summary.json").write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return summary


def local_only(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "http" or parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError("Benchmark target must be local HTTP loopback (http://127.0.0.1:8000)")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=SCENARIOS, default="local_permit")
    parser.add_argument("--clients", type=int, default=8)
    parser.add_argument("--duration", type=float, default=60)
    parser.add_argument("--timeout", type=float, default=30)
    parser.add_argument("--api-url", default="http://127.0.0.1:8000")
    parser.add_argument("--label", default="baseline")
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument(
        "--arrival-rate-rps",
        type=float,
        help="Schedule open-loop arrivals at fixed RPS (default: closed-loop clients)",
    )
    parser.add_argument("--skip-evidence-check", action="store_true")
    parser.add_argument(
        "--allow-overload",
        action="store_true",
        help="Accept explicit HTTP 429 admission rejection as controlled backpressure",
    )
    args = parser.parse_args()
    if (
        not 1 <= args.clients <= 64
        or not 1 <= args.duration <= 3600
        or not 1 <= args.timeout <= 120
    ):
        parser.error("clients=1..64, duration=1..3600, timeout=1..120 required")
    local_only(args.api_url)
    if not os.environ.get("BENCH_API_KEY"):
        parser.error("Set BENCH_API_KEY in the environment (never pass it on the command line)")
    return args


def main() -> int:
    args = parse_args()
    config = Config(
        args.api_url,
        args.clients,
        args.duration,
        args.scenario,
        args.timeout,
        os.environ["BENCH_API_KEY"],
        args.label,
        args.out_dir,
        not args.skip_evidence_check,
        args.allow_overload,
        args.arrival_rate_rps,
    )
    result = asyncio.run(run(config))
    print(json.dumps(result, indent=2))
    # Return failure on security or functional regression even when HTTP transport succeeded.
    if (
        result["functional_validation_failures"]
        or result["transport_errors"]
        or (result["evidence_validation_failures"] or 0)
        or result["duplicate_request_ids"]
        or not result["request_count"]
        or result["client_capacity_drops"]
    ):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
