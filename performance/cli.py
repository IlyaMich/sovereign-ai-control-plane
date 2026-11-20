"""Repeatable benchmarks powered by the existing verified M7.9 reviewer kit."""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import platform
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from performance.config import PROFILE_DIR, load_profile
from performance.reporting import compare, write_report
from performance.resources import collect_periodically
from tools.concurrency_performance import _capture_run, load_api_key, loopback_url

DEFAULT_ROOT = Path("performance/results")


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def git_sha() -> str:
    process = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True)
    if process.returncode or not re.fullmatch(r"[a-f0-9]{40}", process.stdout.strip()):
        raise ValueError("Cannot determine repository commit; run from tracked checkout")
    return process.stdout.strip()


def explain_failed_capture(directory: Path, scenarios: tuple[str, ...]) -> str:
    """Describe only allowlisted missing artifact paths and validated status codes."""
    problems: list[str] = []
    required = ("before.json", "after.json", "assertions.json", "summary.json", "requests.jsonl")
    for scenario in scenarios:
        for filename in required:
            if not (directory / scenario / filename).is_file():
                problems.append(f"missing {scenario}/{filename}")
    path = directory / "m7_9_diagnostics.json"
    if path.is_file():
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(report, dict):
                issues = report.get("benchmark_integrity_issues")
                if isinstance(issues, list):
                    for issue in issues:
                        if isinstance(issue, str) and re.fullmatch(r"[a-z0-9_]{1,100}", issue):
                            problems.append(issue)
                if report.get("benchmark_exit_code") != 0:
                    problems.append("benchmark_nonzero_exit")
                if report.get("poll_errors"):
                    problems.append("diagnostic_poll_errors")
                if report.get("process_counter_reset"):
                    problems.append("diagnostic_counter_reset")
        except (OSError, ValueError, TypeError):
            problems.append("diagnostics_unreadable")
    else:
        problems.append("missing m7_9_diagnostics.json")
    return "; ".join(dict.fromkeys(problems)) or "see raw suite assertions and diagnostics"


async def execute(args: argparse.Namespace) -> int:
    profile = load_profile(args.profile)
    if not (Path("benchmarks") / "suite.py").is_file():
        raise ValueError(
            "Existing ignored benchmarks/suite.py kit is required; do not replace reviewer"
        )
    if args.environment_tag is None or not re.fullmatch(
        r"[A-Za-z0-9._-]{1,64}", args.environment_tag
    ):
        raise ValueError("--environment-tag must identify the fixed benchmark host/configuration")
    api_url = loopback_url(args.api_url)
    key = load_api_key(args.env_file)
    sha = git_sha()
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"{timestamp}-{sha[:8]}-{profile.name}"
    target = args.results_root / run_id
    target.mkdir(parents=True, exist_ok=False)
    (target / "raw").mkdir()
    manifest = {
        "schema_version": 1,
        "run_id": run_id,
        "status": "running",
        "profile": profile.name,
        "profile_digest": profile.digest,
        "description": profile.description,
        "levels": list(profile.levels),
        "runs": profile.runs,
        "duration_s": profile.duration_s,
        "interval_s": profile.interval_s,
        "scenarios": list(profile.scenarios),
        "allow_overload": profile.allow_overload,
        "git_commit": sha,
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "environment": {
            "tag": args.environment_tag,
            "system": platform.system(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "resource_sampling": "best_effort_podman_stats",
    }
    write_json(target / "manifest.json", manifest)
    try:
        for level in profile.levels:
            for repeat in range(1, profile.runs + 1):
                label = f"{run_id}-c{level}-r{repeat:02d}"
                print(f"Running {label}: {profile.scenarios}", flush=True)
                capture_args = argparse.Namespace(
                    results_root=target / "raw",
                    clients=level,
                    duration=profile.duration_s,
                    scenarios=list(profile.scenarios),
                    api_url=api_url,
                    env_file=args.env_file,
                    interval=profile.interval_s,
                    allow_overload=profile.allow_overload,
                )
                resource_samples: list[dict] = []
                stop = asyncio.Event()
                observer = asyncio.create_task(collect_periodically(resource_samples, stop))
                try:
                    passed = await _capture_run(capture_args, label, key, sha)
                finally:
                    stop.set()
                    await observer
                    write_json(
                        target / "raw" / label / "resources.json",
                        {
                            "schema_version": 1,
                            "samples": resource_samples,
                            "status": "observed" if resource_samples else "unavailable",
                        },
                    )
                if not passed:
                    raise ValueError(
                        f"Benchmark integrity or diagnostics failed: {label}; "
                        + explain_failed_capture(target / "raw" / label, profile.scenarios)
                    )
        manifest["status"] = "passed"
        manifest["finished_utc"] = datetime.now(timezone.utc).isoformat()
        write_json(target / "manifest.json", manifest)
        output = write_report(target)
        print(f"PASS: verified results at {target}; HTML report: {output}")
        return 0
    except Exception:
        manifest["status"] = "failed"
        manifest["finished_utc"] = datetime.now(timezone.utc).isoformat()
        write_json(target / "manifest.json", manifest)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="List installed versioned profiles")
    run = sub.add_parser("run", help="Capture and verify benchmark repetitions")
    run.add_argument("--profile", default="baseline")
    run.add_argument(
        "--environment-tag",
        required=True,
        help="User-chosen non-secret identity of host and fixed container configuration",
    )
    run.add_argument("--api-url", default="http://127.0.0.1:8000")
    run.add_argument("--env-file", type=Path, default=Path(".env"))
    run.add_argument("--results-root", type=Path, default=DEFAULT_ROOT)
    report = sub.add_parser("report", help="Re-verify all signed assertions and render reports")
    report.add_argument("--run", type=Path, required=True)
    diff = sub.add_parser("compare", help="Compare only verified, identically configured runs")
    diff.add_argument("--baseline", type=Path, required=True)
    diff.add_argument("--candidate", type=Path, required=True)
    diff.add_argument("--warning-pct", type=float, default=10.0)
    diff.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "list":
            for path in sorted(PROFILE_DIR.glob("*.json")):
                item = load_profile(path.stem)
                print(
                    f"{item.name}: clients={list(item.levels)} repetitions={item.runs} "
                    f"scenarios={list(item.scenarios)}"
                )
        elif args.command == "run":
            return asyncio.run(execute(args))
        elif args.command == "report":
            print(write_report(args.run))
        else:
            if not math.isfinite(args.warning_pct) or not 0 <= args.warning_pct <= 100:
                parser.error("--warning-pct must be finite between 0 and 100")
            results, warned = compare(args.baseline, args.candidate, args.warning_pct)
            rendered = json.dumps(results, indent=2) + "\n"
            if args.out:
                args.out.parent.mkdir(parents=True, exist_ok=True)
                if args.out.exists():
                    raise ValueError("Refusing to overwrite existing comparison file")
                args.out.write_text(rendered, encoding="utf-8")
            print(rendered)
            return 2 if warned else 0
        return 0
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as exc:
        print(f"Performance benchmark failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
