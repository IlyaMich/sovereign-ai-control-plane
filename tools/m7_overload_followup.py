"""M7.9 live overload and audit-lookup follow-up, on loopback only.

Uses the separately installed benchmark kit for offline signed-chain validation.
Does not persist API keys, requests, prompts, request IDs, or audit event bodies.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import subprocess
import sys
import uuid
from collections import Counter
from pathlib import Path
from typing import Any

import httpx

from tools.m7_performance import (
    benchmark_integrity,
    load_api_key,
    loopback_url,
    safe_snapshot,
    save_json,
)

SCENARIO = "local_permit"


def check_overload(run_dir: Path, *, require_429: bool = True) -> dict[str, Any]:
    """Check signed-chain assertions AND the exact 429 pre-admission contract."""
    issues = benchmark_integrity(run_dir, [SCENARIO])
    try:
        summary = json.loads((run_dir / SCENARIO / "summary.json").read_text("utf-8"))
        profile = json.loads((run_dir / "m7_9_diagnostics.json").read_text("utf-8"))
        suite = json.loads((run_dir / "suite.json").read_text("utf-8"))
    except (OSError, ValueError, TypeError):
        return {"passed": False, "issues": issues + ["missing_or_invalid_run_files"]}
    counts = summary.get("http_statuses", {})
    if not isinstance(counts, dict):
        counts = {}
        issues.append("invalid_http_status_counts")

    def count(code: str) -> int:
        value = counts.get(code, 0)
        return value if type(value) is int and value >= 0 else 0

    admitted = count("200")
    rejected = count("429")
    other = sum(
        n for k, n in counts.items() if k not in {"200", "429"} and type(n) is int and n >= 0
    )
    clients = suite.get("clients")
    if summary.get("scenario") != SCENARIO or type(clients) is not int or clients <= 8:
        issues.append("not_an_above_limit_local_permit_run")
    if admitted == 0:
        issues.append("no_successful_admitted_requests")
    if require_429 and rejected == 0:
        issues.append("overload_not_triggered")
    if other:
        issues.append("unexpected_http_response_codes")
    if summary.get("overload_rejections_429") != rejected:
        issues.append("429_count_mismatch")
    if type(summary.get("request_count")) is int and summary["request_count"] < admitted + rejected:
        issues.append("http_status_totals_exceed_requests")
    if profile.get("benchmark_exit_code") != 0 or profile.get("poll_errors") != 0:
        issues.append("benchmark_or_diagnostics_failed")
    if profile.get("process_counter_reset") is not False:
        issues.append("process_counters_reset")
    if profile.get("benchmark_integrity_issues") != []:
        issues.append("profile_integrity_failure")
    counters = profile.get("counter_changes", {})
    if not isinstance(counters, dict):
        counters = {}
    admission_rejected = counters.get("admission.rejected")
    if type(admission_rejected) is not int or admission_rejected < rejected:
        issues.append("admission_counter_below_observed_429")
    for metric_name in (
        "transport_errors",
        "functional_validation_failures",
        "evidence_validation_failures",
        "duplicate_request_ids",
        "unresolved_status_error",
    ):
        if summary.get(metric_name) != 0:
            issues.append(metric_name)
    # Counters and scenario counts only: no response IDs or payloads in the report.
    return {
        "passed": not issues,
        "issues": sorted(set(issues)),
        "clients": suite.get("clients"),
        "duration_s": suite.get("duration_s"),
        "admitted_200": admitted,
        "admission_rejected_429": rejected,
        "other_statuses": other,
        "diagnostic_admission_rejections": admission_rejected,
        "signed_audit_verification": not benchmark_integrity(run_dir, [SCENARIO]),
    }


def accepted_rows(run_dir: Path, *, limit: int = 32) -> list[dict[str, Any]]:
    """Temporarily keep verified receipt identities in memory; do not persist them."""
    rows: list[dict[str, Any]] = []
    path = run_dir / SCENARIO / "requests.jsonl"
    with path.open("r", encoding="utf-8") as stream:
        for line in stream:
            data = json.loads(line)
            if data.get("http_status") != 200 or data.get("request_status") != "COMPLETED":
                continue
            try:
                request_id = str(uuid.UUID(data["request_id"]))
            except (TypeError, ValueError, AttributeError, KeyError):
                continue
            decision = data.get("decision_receipt")
            outcome = data.get("outcome_receipt")
            if not all(isinstance(item, dict) for item in (decision, outcome)):
                continue
            if (
                type(decision.get("sequence")) is not int
                or type(outcome.get("sequence")) is not int
            ):
                continue
            if decision["sequence"] >= outcome["sequence"]:
                continue
            rows.append({"request_id": request_id, "decision": decision, "outcome": outcome})
            if len(rows) == limit:
                break
    if len(rows) < 8:
        raise ValueError("Need at least eight admitted requests with valid receipt pairs")
    return rows


def verify_lookup(body: Any, expected: dict[str, Any]) -> bool:
    if not isinstance(body, dict) or body.get("request_id") != expected["request_id"]:
        return False
    events = body.get("events")
    if not isinstance(events, list) or len(events) != 2:
        return False
    for record, event_type, receipt in zip(
        events, ("DECISION", "OUTCOME"), ("decision", "outcome"), strict=True
    ):
        if not isinstance(record, dict) or record.get("receipt") != expected[receipt]:
            return False
        event = record.get("event")
        if not isinstance(event, dict) or event.get("event_type") != event_type:
            return False
        if event.get("request_id") != expected["request_id"]:
            return False
    return True


async def diagnostic(client: httpx.AsyncClient) -> dict[str, Any]:
    response = await client.get("/v1/diagnostics/concurrency")
    response.raise_for_status()
    return safe_snapshot(response.json())


async def lookup_rounds(
    client: httpx.AsyncClient,
    rows: list[dict[str, Any]],
    *,
    concurrency: int,
    rounds: int,
    max_retries: int = 8,
) -> dict[str, Any]:
    """Run concurrent evidence reads; retry only the known audit 503 contract."""
    if concurrency < 1 or rounds < 1 or max_retries < 1:
        raise ValueError("Invalid lookup test parameters")
    before = await diagnostic(client)
    auxiliary_limit = before.get("audit_limits", {}).get("maximum_auxiliary_jobs")
    if auxiliary_limit != 4:
        raise ValueError("Expected configured MAX_AUDIT_AUXILIARY_JOBS=4 for this test")
    old = before.get("audit", {}).get("capacity_rejections")
    if type(old) is not int:
        raise ValueError("Audit rejection counter missing")
    gate = asyncio.Semaphore(concurrency)
    counts: Counter[str] = Counter()

    async def inspect(row: dict[str, Any]) -> None:
        async with gate:
            for attempt in range(max_retries):
                try:
                    response = await client.get("/v1/requests/" + row["request_id"])
                except httpx.HTTPError:
                    counts["transport_errors"] += 1
                    return
                if response.status_code == 503:
                    try:
                        document = response.json()
                    except ValueError:
                        counts["unexpected"] += 1
                        return
                    if not isinstance(document, dict) or (
                        "AUDIT_UNAVAILABLE" not in document.get("reason_codes", [])
                    ):
                        counts["unexpected"] += 1
                        return
                    counts["audit_503"] += 1
                    if attempt + 1 < max_retries:
                        await asyncio.sleep(0.03 * (attempt + 1))
                        continue
                    counts["retry_exhausted"] += 1
                    return
                if response.status_code != 200:
                    counts["unexpected"] += 1
                    return
                try:
                    valid = verify_lookup(response.json(), row)
                except ValueError:
                    valid = False
                counts["verified" if valid else "mismatched_evidence"] += 1
                return

    for index in range(rounds):
        offset = index % len(rows)
        batch = [rows[(offset + j) % len(rows)] for j in range(concurrency)]
        await asyncio.gather(*(inspect(item) for item in batch))
    after = await diagnostic(client)
    new = after.get("audit", {}).get("capacity_rejections")
    if type(new) is not int or new < old:
        raise ValueError("Audit counter reset during lookup experiment")
    target = concurrency * rounds
    issues = []
    if counts["verified"] != target:
        issues.append("not_all_evidence_queries_verified")
    if any(
        counts[name]
        for name in ("unexpected", "mismatched_evidence", "transport_errors", "retry_exhausted")
    ):
        issues.append("lookup_errors")
    if concurrency == 4 and (counts["audit_503"] or new != old):
        issues.append("four_way_lookup_unexpected_rejection")
    # A fast system might process 8-way bursts before saturation; that is
    # inconclusive, not a failure or evidence that the four-slot bound disappeared.
    return {
        "passed": not issues,
        "issues": issues,
        "concurrency": concurrency,
        "rounds": rounds,
        "successful_verified_queries": counts["verified"],
        "target_queries": target,
        "transient_audit_503": counts["audit_503"],
        "audit_capacity_rejections_delta": new - old,
        "unexpected_errors": sum(
            counts[name]
            for name in ("unexpected", "mismatched_evidence", "transport_errors", "retry_exhausted")
        ),
        "eight_way_saturation_observed": concurrency == 8 and counts["audit_503"] > 0 and new > old,
    }


async def compare_lookup_modes(
    base_url: str, key: str, rows: list[dict[str, Any]], rounds: int
) -> dict[str, Any]:
    async with httpx.AsyncClient(
        base_url=base_url,
        headers={"X-API-Key": key},
        trust_env=False,
        timeout=httpx.Timeout(10.0),
        limits=httpx.Limits(max_connections=24, max_keepalive_connections=24),
    ) as client:
        four = await lookup_rounds(client, rows, concurrency=4, rounds=rounds)
        eight = await lookup_rounds(client, rows, concurrency=8, rounds=rounds)
    return {
        "four_way": four,
        "eight_way": eight,
        "saturation_comparison": (
            "REPRODUCED" if eight["eight_way_saturation_observed"] else "NOT_REPRODUCED"
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--label-prefix", default="m7-9-overload-16")
    parser.add_argument("--clients", type=int, default=16)
    parser.add_argument("--duration", type=float, default=20.0)
    parser.add_argument("--lookup-rounds", type=int, default=12)
    parser.add_argument("--api-url", default="http://127.0.0.1:8000")
    parser.add_argument("--env-file", type=Path, default=Path(".env"))
    parser.add_argument("--results-root", type=Path, default=Path("bench-results"))
    parser.add_argument(
        "--existing-run",
        action="store_true",
        help="Analyze an existing captured overload run; do not run load again",
    )
    args = parser.parse_args(argv)
    if not 9 <= args.clients <= 32 or not 10 <= args.duration <= 60:
        parser.error("Use 9–32 clients for 10–60 seconds")
    if not 1 <= args.lookup_rounds <= 40:
        parser.error("Use 1–40 lookup rounds")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", args.label_prefix):
        parser.error("Label prefix must be 1–64 safe ASCII characters")
    base_url = loopback_url(args.api_url)
    key = load_api_key(args.env_file)
    label = args.label_prefix + "-r01"
    run_dir = args.results_root / label
    if not args.existing_run:
        if run_dir.exists():
            parser.error("Existing results directory; choose a new label prefix")
        command = [
            sys.executable,
            "-m",
            "tools.m7_performance",
            "capture",
            "--label-prefix",
            args.label_prefix,
            "--runs",
            "1",
            "--clients",
            str(args.clients),
            "--duration",
            str(args.duration),
            "--api-url",
            base_url,
            "--env-file",
            str(args.env_file),
            "--results-root",
            str(args.results_root),
            "--interval",
            "0.5",
            "--allow-overload",
            "--scenarios",
            SCENARIO,
        ]
        if subprocess.run(command, check=False).returncode != 0:
            print("FAIL: Signed-audit benchmark or diagnostics capture failed", file=sys.stderr)
            return 1
    overload = check_overload(run_dir)
    if not overload["passed"]:
        print("FAIL: overload assertions " + ",".join(overload["issues"]), file=sys.stderr)
        return 1
    rows = accepted_rows(run_dir)
    try:
        lookups = asyncio.run(compare_lookup_modes(base_url, key, rows, args.lookup_rounds))
    except (httpx.HTTPError, ValueError, OSError) as exc:
        print("FAIL: lookup comparison: " + type(exc).__name__, file=sys.stderr)
        return 1
    result = {
        "schema_version": 1,
        "overload": overload,
        "evidence_lookups": lookups,
        "passed": lookups["four_way"]["passed"] and lookups["eight_way"]["passed"],
        "note": (
            "Independent signed chain checked by benchmarks.suite; evidence GETs match its receipts"
        ),
    }
    base = args.results_root / (args.label_prefix + "-followup")
    report = base.with_suffix(".json")
    if report.exists() and args.existing_run:
        for i in range(2, 100):
            candidate = base.with_name(base.name + f"-{i:02d}").with_suffix(".json")
            if not candidate.exists():
                report = candidate
                break
        else:
            raise ValueError("Too many existing follow-up reports")
    save_json(report, result)
    print(json.dumps(result, indent=2, sort_keys=True))
    print("Saved aggregate follow-up report:", report)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
