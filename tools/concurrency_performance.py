"""M7.9: profile the existing signed-audit benchmark with safe aggregate diagnostics.

Capture does not replace benchmarks.suite or its signed-chain assertions. The
benchmark kit is intentionally a separate, locally installed and Git-ignored
operator tool. No prompts, API keys, model outputs or request IDs are recorded.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import os
import re
import statistics
import subprocess  # nosec B404 # Required for explicit operator-owned CLI commands.
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

from app.infrastructure.executables import resolve_executable

SCENARIOS = (
    "local_permit",
    "credential_deny",
    "unsupported_input",
    "external_redaction",
    "mixed_traffic",
)
START = re.compile(
    r"^\[[^\]\r\n]+\] (local_permit|credential_deny|unsupported_input|external_redaction|mixed_traffic):"
)
END = re.compile(
    r"^(local_permit|credential_deny|unsupported_input|external_redaction|mixed_traffic): .*responses/s,"
)

# Explicit allowlist: never persist arbitrary diagnostics fields from a future API.
FIELDS = {
    "logging": ("dropped_events", "output_errors"),
    "http_ingress": ("limit", "active", "peak_active", "rejected"),
    "admission": ("limit", "active", "peak_active", "rejected"),
    "detector": (
        "capacity",
        "active_jobs",
        "waiting_for_capacity",
        "peak_active_jobs",
        "submitted",
        "completed",
        "failed",
        "capacity_rejections",
    ),
    "audit": (
        "capacity",
        "active_jobs",
        "waiting_for_capacity",
        "peak_active_jobs",
        "submitted",
        "completed",
        "failed",
        "capacity_rejections",
    ),
    "audit_limits": (
        "maximum_waiters",
        "waiting_for_slot",
        "maximum_auxiliary_jobs",
        "auxiliary_inflight",
    ),
    "integrity": (
        "capacity",
        "max_waiters",
        "active_jobs",
        "waiting_for_capacity",
        "rejected",
        "completed",
        "failed",
        "readiness_running",
        "readiness_scans",
        "readiness_coalesced",
    ),
    "event_loop": ("samples", "sample_interval_seconds", "p50_ms", "p95_ms", "max_ms"),
}
ROLLING_FIELDS = ("queue_wait", "processing")
COUNTERS = (
    "http_ingress.rejected",
    "admission.rejected",
    "detector.capacity_rejections",
    "detector.submitted",
    "detector.completed",
    "audit.capacity_rejections",
    "audit.submitted",
    "audit.completed",
    "integrity.rejected",
    "integrity.completed",
    "logging.dropped_events",
    "logging.output_errors",
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def loopback_url(url: str) -> str:
    parsed = urlsplit(url)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Invalid diagnostics URL port") from exc
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Invalid diagnostics URL port")
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ValueError("Diagnostics URL must be a plain HTTP loopback origin")
    return url.rstrip("/")


def load_api_key(env_file: Path) -> str:
    """Read a secret for headers only; never use a CLI argument or saved output."""
    key = os.environ.get("BENCH_API_KEY") or os.environ.get("CONTROL_PLANE_API_KEY")
    if key is None and env_file.is_file():
        for line in env_file.read_text(encoding="utf-8-sig").splitlines():
            text = line.strip()
            if text.startswith("CONTROL_PLANE_API_KEY="):
                key = text.partition("=")[2].strip().strip('"').strip("'")
                break
    if not key or len(key) < 24 or key == "replace-with-a-random-key":
        raise ValueError("Set BENCH_API_KEY or configure CONTROL_PLANE_API_KEY in .env")
    return key


def safe_snapshot(payload: Any) -> dict[str, Any]:
    """Reject invalid types and drop all unrecognized fields recursively."""
    if not isinstance(payload, dict) or payload.get("scope") != "process":
        raise ValueError("Expected process-local diagnostics response")
    result: dict[str, Any] = {}
    for section, keys in FIELDS.items():
        source = payload.get(section)
        if source is None:
            continue
        if not isinstance(source, dict):
            raise ValueError("Invalid diagnostics section")
        clean: dict[str, Any] = {}
        for field in keys:
            value = source.get(field)
            if type(value) in {int, float, bool} and (
                type(value) is not float or math.isfinite(value)
            ):
                clean[field] = value
        if section in {"audit", "detector"}:
            for rolling in ROLLING_FIELDS:
                distribution = source.get(rolling)
                if not isinstance(distribution, dict):
                    continue
                clean[rolling] = {
                    key: value
                    for key in ("samples", "p50_ms", "p95_ms", "max_ms")
                    if type(value := distribution.get(key)) in {int, float}
                    and (type(value) is not float or math.isfinite(value))
                }
        result[section] = clean
    for required in ("http_ingress", "admission", "audit", "detector", "event_loop"):
        if required not in result:
            raise ValueError("Incomplete process-local diagnostics response")
    return result


def metric(sample: dict[str, Any], path: str) -> int | float | None:
    node: Any = sample
    for segment in path.split("."):
        if not isinstance(node, dict):
            return None
        node = node.get(segment)
    if type(node) in {int, float} and math.isfinite(node):
        return node
    return None


def counter_changes(samples: list[dict[str, Any]]) -> tuple[dict[str, int], bool]:
    """Account for process counter resets rather than reporting false negative deltas."""
    deltas: dict[str, int] = {}
    reset = False
    for name in COUNTERS:
        values = [metric(s["metrics"], name) for s in samples]
        numbers = [int(v) for v in values if v is not None]
        if len(numbers) < 2:
            continue
        changes = [b - a for a, b in zip(numbers, numbers[1:])]
        if any(x < 0 for x in changes):
            reset = True
        deltas[name] = sum(x for x in changes if x >= 0)
    return deltas, reset


def max_for_phase(samples: list[dict[str, Any]], phase: str, name: str) -> float | None:
    values = [metric(s["metrics"], name) for s in samples if s["phase"] == phase]
    numeric = [float(v) for v in values if v is not None]
    return round(max(numeric), 3) if numeric else None


async def capture_command(
    command: list[str],
    client: httpx.AsyncClient,
    *,
    interval: float,
    label: str,
    git_commit: str,
    env: dict[str, str] | None = None,
) -> tuple[dict[str, Any], int]:
    """Tee benchmark stdout to console; store only allowlisted metrics and phase."""
    if not 0.1 <= interval <= 30 or not math.isfinite(interval):
        raise ValueError("Sampling interval must be between 0.1 and 30 seconds")
    response = await client.get("/v1/diagnostics/concurrency")
    response.raise_for_status()
    before = safe_snapshot(response.json())
    t0 = time.monotonic()
    phase = "setup"
    samples = [{"t_seconds": 0.0, "phase": phase, "metrics": before}]
    poll_errors = 0
    if not command:
        raise ValueError("Benchmark command is required")
    command_proc = await asyncio.create_subprocess_exec(
        resolve_executable(command[0]),
        *command[1:],
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        env=env,
    )

    async def read_lines() -> None:
        nonlocal phase
        stream = command_proc.stdout
        if stream is None:
            raise RuntimeError("Benchmark subprocess output was not captured")
        while line := await stream.readline():
            decoded = line.decode("utf-8", errors="replace")
            beginning = START.match(decoded)
            ending = END.match(decoded)
            if beginning:
                phase = beginning.group(1)
            elif ending and phase == ending.group(1):
                phase = "verification"
            # Existing benchmark output goes to the console, never to profile files.
            sys.stdout.write(decoded)
            sys.stdout.flush()

    reader = asyncio.create_task(read_lines())
    try:
        while command_proc.returncode is None:
            try:
                await asyncio.wait_for(command_proc.wait(), timeout=interval)
            except TimeoutError:
                pass
            try:
                response = await client.get("/v1/diagnostics/concurrency")
                response.raise_for_status()
                snapshot = safe_snapshot(response.json())
                if len(samples) < 20_000:
                    samples.append(
                        {
                            "t_seconds": round(time.monotonic() - t0, 3),
                            "phase": phase,
                            "metrics": snapshot,
                        }
                    )
                else:
                    poll_errors += 1
            except (httpx.HTTPError, ValueError, TypeError):
                poll_errors += 1
        await reader
    finally:
        if command_proc.returncode is None:
            command_proc.terminate()
            try:
                await asyncio.wait_for(command_proc.wait(), timeout=5)
            except TimeoutError:
                command_proc.kill()
                await command_proc.wait()
        if not reader.done():
            reader.cancel()
            await asyncio.gather(reader, return_exceptions=True)
    deltas, restarted = counter_changes(samples)
    profile: dict[str, Any] = {
        "schema_version": 1,
        "label": label,
        "git_commit": git_commit,
        "completed_utc": utc_now(),
        "benchmark_exit_code": command_proc.returncode,
        "sampling_interval_seconds": interval,
        "poll_errors": poll_errors,
        "process_counter_reset": restarted,
        "counter_changes": deltas,
        "samples": samples,
    }
    return profile, int(command_proc.returncode or 0)


def benchmark_integrity(run_dir: Path, scenarios: list[str]) -> list[str]:
    """Gate reports on the benchmark kit's independently verified chain checks."""
    issues: list[str] = []
    try:
        suite = json.loads((run_dir / "suite.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ["missing_or_invalid_suite_report"]
    if suite.get("errors") != []:
        issues.append("suite_reported_failures")
    for scenario in scenarios:
        try:
            assertions = json.loads(
                (run_dir / scenario / "assertions.json").read_text(encoding="utf-8")
            )
            summary = json.loads((run_dir / scenario / "summary.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            issues.append(f"{scenario}_missing_report")
            continue
        if assertions.get("passed") is not True:
            issues.append(f"{scenario}_audit_integrity_failed")
        if any(
            summary.get(field) != 0
            for field in (
                "transport_errors",
                "functional_validation_failures",
                "evidence_validation_failures",
            )
        ):
            issues.append(f"{scenario}_request_correctness_failed")
    return issues


def save_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Do not overwrite earlier captures. Avoid encoding any secret in these files.
    with path.open("x", encoding="utf-8", newline="\n") as output:
        json.dump(value, output, indent=2, sort_keys=True, allow_nan=False)
        output.write("\n")


def read_summary(run_dir: Path, scenario: str) -> dict[str, Any]:
    data = json.loads((run_dir / scenario / "summary.json").read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("scenario") != scenario:
        raise ValueError("Invalid scenario summary")
    return data


def render_report(root: Path, prefix: str, runs: int, scenarios: list[str]) -> tuple[str, bool]:
    """Report medians and observed rolling metrics; never infer real capacity."""
    lines = [
        "# M7.9 repeated benchmark and diagnostics report",
        "",
        f"Label prefix: `{prefix}`; repetitions: {runs}",
        "",
        "| Scenario | Median goodput/s | Range goodput/s | Median p95 ms | Range p95 ms |",
        "|---|---:|---:|---:|---:|",
    ]
    problems: list[str] = []
    suite_settings: set[tuple[int, float]] = set()
    profile_commits: set[str] = set()
    signal_keys = (
        "detector.queue_wait.p95_ms",
        "audit.queue_wait.p95_ms",
        "audit.processing.p95_ms",
        "event_loop.p95_ms",
        "audit_limits.waiting_for_slot",
    )
    signals: dict[str, dict[str, float | None]] = {}
    for scenario in scenarios:
        rates: list[float] = []
        latencies: list[float] = []
        peaks: dict[str, float | None] = {key: None for key in signal_keys}
        for i in range(1, runs + 1):
            label = f"{prefix}-r{i:02d}"
            directory = root / label
            if not (directory / "m7_9_diagnostics.json").exists():
                problems.append(f"{label}_missing_diagnostics")
                continue
            try:
                profile = json.loads(
                    (directory / "m7_9_diagnostics.json").read_text(encoding="utf-8")
                )
                summary = read_summary(directory, scenario)
                suite = json.loads((directory / "suite.json").read_text(encoding="utf-8"))
                issues = benchmark_integrity(directory, scenarios)
                if (
                    issues
                    or profile.get("schema_version") != 1
                    or profile.get("label") != label
                    or profile.get("benchmark_exit_code") != 0
                    or profile.get("poll_errors") != 0
                    or profile.get("process_counter_reset")
                    or not profile.get("samples")
                ):
                    problems.extend(f"{label}_{issue}" for issue in issues)
                    problems.append(f"{label}_invalid_or_incomplete_profile")
                    continue
                suite_settings.add((int(suite["clients"]), float(suite["duration_s"])))
                profile_commits.add(str(profile["git_commit"]))
                if (
                    summary.get("clients") != suite["clients"]
                    or summary.get("duration_configured_s") != suite["duration_s"]
                ):
                    raise ValueError("Scenario settings differ from suite settings")
                rate = summary["goodput_per_test_second"]
                p95 = summary["latency_ms"]["p95"]
                if not (
                    type(rate) in {int, float}
                    and math.isfinite(rate)
                    and rate > 0
                    and type(p95) in {int, float}
                    and math.isfinite(p95)
                    and p95 >= 0
                ):
                    raise ValueError("Invalid performance metrics")
                rates.append(float(rate))
                latencies.append(float(p95))
                for key in signal_keys:
                    value = max_for_phase(profile["samples"], scenario, key)
                    if value is not None:
                        current = peaks[key]
                        peaks[key] = max(value, current) if current is not None else value
            except (OSError, ValueError, KeyError, TypeError):
                problems.append(f"{label}_{scenario}_invalid_report")
        if rates:
            lines.append(
                f"| {scenario} | {statistics.median(rates):.3f} | "
                f"{min(rates):.3f}–{max(rates):.3f} | "
                f"{statistics.median(latencies):.1f} | "
                f"{min(latencies):.1f}–{max(latencies):.1f} |"
            )
        else:
            lines.append(f"| {scenario} | N/A | N/A | N/A | N/A |")
        signals[scenario] = peaks
    lines.extend(
        [
            "",
            "## Maximum observed rolling p95 and queue activity",
            "",
            "| Scenario | Detector wait p95 (ms) | Audit wait p95 (ms) | "
            "Audit processing p95 (ms) | Loop lag p95 (ms) | Audit slot waiters |",
            "|---|---:|---:|---:|---:|---:|",
        ]
    )
    for scenario in scenarios:

        def shown(key: str) -> str:
            value = signals[scenario][key]
            return "N/A" if value is None else f"{value:.1f}"

        lines.append(
            f"| {scenario} | {shown(signal_keys[0])} | {shown(signal_keys[1])} | "
            f"{shown(signal_keys[2])} | {shown(signal_keys[3])} | "
            f"{shown(signal_keys[4])} |"
        )
    if len(suite_settings) > 1:
        problems.append("mismatched_clients_or_duration")
    if len(profile_commits) > 1:
        problems.append("mismatched_git_commits")
    lines.extend(
        [
            "",
            "## Diagnostic interpretation",
            "",
            "These are closed-loop, per-process measurements. A sampled rolling p95",
            "is not the distribution p95 for a complete scenario. Compare the",
            "`m7_9_diagnostics.json` sample timelines for detector/audit queue waits,",
            "integrity saturation and event-loop lag before adjusting executor limits.",
            "",
            "## Safety and completeness checks",
            "",
        ]
    )
    lines.append(
        "PASS: complete profile and integrity checks"
        if not problems
        else "FAIL: " + ", ".join(sorted(set(problems)))
    )
    return "\n".join(lines) + "\n", not problems


async def _capture_run(args: argparse.Namespace, label: str, key: str, git_sha: str) -> bool:
    run_dir: Path = args.results_root / label
    if run_dir.exists():
        raise ValueError("Refusing to overwrite an existing benchmark run directory")
    cmd = [
        sys.executable,
        "-m",
        "benchmarks.suite",
        "--label",
        label,
        "--clients",
        str(args.clients),
        "--duration",
        str(args.duration),
        "--api-url",
        args.api_url,
        "--results-root",
        str(args.results_root),
        "--env-file",
        str(args.env_file),
        "--scenarios",
        *args.scenarios,
    ]
    if args.allow_overload:
        cmd.append("--allow-overload")
    if getattr(args, "arrival_rate_rps", None) is not None:
        cmd.extend(["--arrival-rate-rps", str(args.arrival_rate_rps)])
    env = os.environ.copy()
    env["BENCH_API_KEY"] = key
    # The benchmark child receives the key only through its environment.
    async with httpx.AsyncClient(
        base_url=args.api_url,
        headers={"X-API-Key": key},
        trust_env=False,
        timeout=3.0,
    ) as client:
        profile, code = await capture_command(
            cmd,
            client,
            interval=args.interval,
            label=label,
            git_commit=git_sha,
            env=env,
        )
    issues = benchmark_integrity(run_dir, args.scenarios)
    profile["benchmark_integrity_issues"] = issues
    save_json(run_dir / "m7_9_diagnostics.json", profile)
    print(f"M7.9 profile saved: {run_dir / 'm7_9_diagnostics.json'}", flush=True)
    return (
        code == 0
        and not issues
        and profile["poll_errors"] == 0
        and not profile["process_counter_reset"]
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    capture = sub.add_parser(
        "capture", help="Run existing signed-audit suite and sample diagnostics"
    )
    capture.add_argument("--label-prefix", required=True)
    capture.add_argument("--runs", type=int, default=3)
    capture.add_argument("--clients", type=int, default=8)
    capture.add_argument("--duration", type=float, default=60.0)
    capture.add_argument("--scenarios", choices=SCENARIOS, nargs="+", default=list(SCENARIOS[:3]))
    capture.add_argument("--api-url", default="http://127.0.0.1:8000")
    capture.add_argument("--env-file", type=Path, default=Path(".env"))
    capture.add_argument("--results-root", type=Path, default=Path("bench-results"))
    capture.add_argument("--interval", type=float, default=0.75)
    capture.add_argument("--allow-overload", action="store_true")
    report = sub.add_parser("report", help="Summarize repetitions with correctness gate")
    report.add_argument("--label-prefix", required=True)
    report.add_argument("--runs", type=int, default=3)
    report.add_argument("--results-root", type=Path, default=Path("bench-results"))
    report.add_argument("--scenarios", choices=SCENARIOS, nargs="+", default=list(SCENARIOS[:3]))
    report.add_argument("--out", type=Path, default=Path("bench-results/m7_9_report.md"))
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", args.label_prefix):
        parser.error("Label prefix must be 1–64 safe ASCII filename characters")
    if not 1 <= args.runs <= 10:
        parser.error("Runs must be between 1 and 10")
    if len(set(args.scenarios)) != len(args.scenarios):
        parser.error("Specify each benchmark scenario only once")
    if args.action == "report":
        report_text, passed = render_report(
            args.results_root, args.label_prefix, args.runs, args.scenarios
        )
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(report_text, encoding="utf-8")
        print(report_text)
        return 0 if passed else 1
    if not 1 <= args.clients <= 64 or not 1 <= args.duration <= 3600:
        parser.error("Clients must be 1–64 and duration 1–3600 seconds")
    if not 0.1 <= args.interval <= 30 or not math.isfinite(args.interval):
        parser.error("Interval must be finite and between 0.1 and 30 seconds")
    try:
        args.api_url = loopback_url(args.api_url)
        key = load_api_key(args.env_file)
    except ValueError as exc:
        parser.error(str(exc))
    # Do not silently import a different benchmark implementation.
    if not (Path("benchmarks") / "suite.py").is_file():
        parser.error("Install the existing local benchmarks kit under benchmarks/ first")
    git_sha = "unavailable"
    try:
        git = resolve_executable("git")
        sha = subprocess.run(  # nosec B603 # Resolved binary and constant arguments; no shell.
            [git, "rev-parse", "HEAD"],
            shell=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if sha.returncode == 0:
            git_sha = sha.stdout.strip()
    except (OSError, ValueError, subprocess.TimeoutExpired):
        pass  # Commit metadata is optional; benchmark integrity checks still run.
    for index in range(1, args.runs + 1):
        label = f"{args.label_prefix}-r{index:02d}"
        print(f"\nM7.9 repetition {index}/{args.runs}: {label}", flush=True)
        try:
            passed = asyncio.run(_capture_run(args, label, key, git_sha))
        except (ValueError, OSError, httpx.HTTPError) as exc:
            print(f"Capture failed: {type(exc).__name__}", file=sys.stderr)
            return 1
        if not passed:
            print(
                "Benchmark integrity or diagnostic capture failed; stopping repetitions",
                file=sys.stderr,
            )
            return 1
    print("All repetitions completed; run: python -m tools.concurrency_performance report ...")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
