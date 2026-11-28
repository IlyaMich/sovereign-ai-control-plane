"""Run timed scenarios with independent, disconnected SQLite chain verification.

Requires Podman Compose reviewer image from the repository and httpx on host.
Run from the repository root; never deletes or resets audit-data.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from benchmarks.audit_snapshot import CREATE_SNAPSHOT_CODE, DELETE_SNAPSHOT_CODE, snapshot_paths
    from benchmarks.compose_audit import (
        AuditPaths,
        resolve_audit_paths,
        resolve_control_audit_paths,
    )
    from benchmarks.load import SCENARIOS, Config, local_only, run
    from benchmarks.resources import ResourceSampler
except ModuleNotFoundError:  # Direct execution: python benchmarks/suite.py
    from audit_snapshot import CREATE_SNAPSHOT_CODE, DELETE_SNAPSHOT_CODE, snapshot_paths
    from compose_audit import AuditPaths, resolve_audit_paths, resolve_control_audit_paths
    from load import SCENARIOS, Config, local_only, run
    from resources import ResourceSampler


def command(argv: list[str], *, cwd: Path) -> str:
    try:
        completed = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, check=True)
    except FileNotFoundError as exc:
        raise RuntimeError(f"Required executable not found: {argv[0]}") from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"Command failed (exit={exc.returncode}): {' '.join(argv[:5])}\n"
            f"stderr tail: {exc.stderr[-1500:]}\nstdout tail: {exc.stdout[-500:]}"
        ) from exc
    return completed.stdout


def compose_prefix(cli: str, compose: Path, env_file: Path) -> list[str]:
    return [
        cli,
        "compose",
        "-f",
        str(compose),
        "--env-file",
        str(env_file),
        "--profile",
        "audit-review",
    ]


def audit_head(prefix: list[str], cwd: Path, paths: AuditPaths, control_db: str) -> dict[str, Any]:
    """Online SQLite backup + isolated, read-only verification of a stable copy.

    SQLite WAL cannot reliably open with mode=ro under a read-only volume when
    the -wal/-shm sidecars are absent. We never enable `immutable=1` on a live DB
    because that can hide uncheckpointed commits. Instead create a SQLite
    online backup inside the writable control-plane volume, normalize the
    snapshot to DELETE journal mode, and verify that file using audit-reviewer.
    """
    source_snapshot, reviewer_snapshot = snapshot_paths(control_db, paths.database)
    try:
        command(
            [
                *prefix,
                "exec",
                "-T",
                "control-plane",
                "python",
                "-c",
                CREATE_SNAPSHOT_CODE,
                control_db,
                source_snapshot,
            ],
            cwd=cwd,
        )
        snapshot = AuditPaths(reviewer_snapshot, paths.public_key)
        stdout = command(
            [
                *prefix,
                "run",
                "--rm",
                "--no-deps",
                "--entrypoint",
                "python",
                "audit-reviewer",
                "-m",
                "tools.verify_audit",
                "--db",
                snapshot.database,
                "--public-key",
                snapshot.public_key,
            ],
            cwd=cwd,
        )
        match = re.search(r'\{\s*"status"\s*:\s*"VERIFIED".*?\}\s*$', stdout, re.DOTALL)
        if not match:
            raise RuntimeError("Reviewer did not produce a VERIFIED JSON report")
        result = json.loads(match.group(0))
        if result.get("status") != "VERIFIED" or type(result.get("verified_events")) is not int:
            raise RuntimeError("Invalid verifier report")
        return result
    finally:
        command(
            [
                *prefix,
                "exec",
                "-T",
                "control-plane",
                "python",
                "-c",
                DELETE_SNAPSHOT_CODE,
                control_db,
                source_snapshot,
            ],
            cwd=cwd,
        )


def probe_audit_paths(prefix: list[str], cwd: Path, paths: AuditPaths) -> None:
    # Confirm the shared volume and public key, but do not query the LIVE WAL DB
    # from a read-only mount. audit_head() verifies a consistent snapshot instead.
    snippet = """import json, os, sys
 db, pub = sys.argv[1:3]
 print(json.dumps({'db_exists': os.path.isfile(db),
                   'pub_exists': os.path.isfile(pub)}))
""".replace("\n ", "\n")
    stdout = command(
        [
            *prefix,
            "run",
            "--rm",
            "--no-deps",
            "--entrypoint",
            "python",
            "audit-reviewer",
            "-c",
            snippet,
            paths.database,
            paths.public_key,
        ],
        cwd=cwd,
    )
    info = json.loads(stdout.strip())
    if not (info.get("db_exists") and info.get("pub_exists")):
        raise RuntimeError(
            f"Audit reviewer cannot see the database and public key: {info}; "
            f"DB={paths.database}, key={paths.public_key}. Do not reset the audit volume."
        )
    print(
        "Reviewer audit files visible; using WAL-safe online snapshots for chain checks.",
        flush=True,
    )


def pin_key(prefix: list[str], cwd: Path, trusted_key: Path, paths: AuditPaths) -> None:
    observed = (
        command(
            [
                *prefix,
                "run",
                "--rm",
                "--no-deps",
                "--entrypoint",
                "cat",
                "audit-reviewer",
                paths.public_key,
            ],
            cwd=cwd,
        )
        .strip()
        .replace("\r\n", "\n")
    )
    trusted = trusted_key.read_text(encoding="utf-8").strip().replace("\r\n", "\n")
    if not observed.startswith("-----BEGIN PUBLIC KEY-----") or observed != trusted:
        raise RuntimeError("Live audit public key differs from independently pinned public key")


def save_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def compare_chain_heads(
    before: dict[str, Any], after: dict[str, Any], summary: dict[str, Any]
) -> dict[str, Any]:
    prior = before["verified_events"]
    latest = after["verified_events"]
    actual_delta = latest - prior
    expected_delta = 2 * summary["audited_receipt_responses"]
    problems: list[str] = []
    if actual_delta != expected_delta:
        problems.append("audit_delta_does_not_match_receipt_pairs")
    if latest < prior or after["latest_sequence"] < before["latest_sequence"]:
        problems.append("audit_head_sequence_regressed")
    if prior > 0 and after["latest_sequence"] != latest:
        problems.append("audit_head_not_contiguous")
    # Note: the new head may be the same only if there were no admitted requests.
    return {
        "passed": not problems,
        "problems": problems,
        "audit_head_before": before["latest_hash"],
        "audit_head_after": after["latest_hash"],
        "verified_events_before": prior,
        "verified_events_after": latest,
        "actual_new_events": actual_delta,
        "expected_new_events": expected_delta,
        "assumption": "Exclusive benchmark writer; no other requests or external audit events",
    }


def parser_config() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--label", required=True, help="baseline or improved")
    p.add_argument(
        "--scenarios",
        nargs="+",
        choices=SCENARIOS,
        default=["local_permit", "credential_deny", "unsupported_input"],
    )
    p.add_argument("--clients", type=int, default=8)
    p.add_argument(
        "--arrival-rate-rps",
        type=float,
        help="Fixed open-loop arrivals per second; absent means closed-loop clients",
    )
    p.add_argument("--duration", type=float, default=60)
    p.add_argument("--timeout", type=float, default=30)
    p.add_argument("--api-url", default="http://127.0.0.1:8000")
    p.add_argument("--results-root", type=Path, default=Path("bench-results"))
    p.add_argument("--compose-file", type=Path, default=Path("deploy/compose.yaml"))
    p.add_argument("--env-file", type=Path, default=Path(".env"))
    p.add_argument("--podman", default="podman")
    p.add_argument(
        "--trusted-audit-public-key",
        type=Path,
        help="Previously pinned public key OUTSIDE audit volume",
    )
    p.add_argument(
        "--audit-db", help="Explicit database path INSIDE audit-reviewer (advanced override)"
    )
    p.add_argument(
        "--audit-public-key",
        help="Explicit public-key path INSIDE audit-reviewer (advanced override)",
    )
    p.add_argument(
        "--audit-control-db", help="Explicit database path INSIDE control-plane (advanced override)"
    )
    p.add_argument("--settle-seconds", type=float, default=3)
    p.add_argument(
        "--stats-container", help="Optional Podman container name/ID to sample CPU and memory"
    )
    p.add_argument("--stats-interval", type=float, default=3.0)
    p.add_argument(
        "--allow-overload",
        action="store_true",
        help="Treat HTTP 429 as deliberate rejection before admission (not failure)",
    )
    args = p.parse_args()
    local_only(args.api_url)
    if not 1 <= args.clients <= 64 or not 1 <= args.duration <= 3600:
        p.error("clients=1..64 and duration=1..3600 required")
    if args.arrival_rate_rps is not None and (
        not math.isfinite(args.arrival_rate_rps)
        or not 0.1 <= args.arrival_rate_rps <= 64
        or math.ceil(args.arrival_rate_rps * args.duration) > 50_000
    ):
        p.error("arrival-rate-rps must be finite, 0.1..64, at most 50,000 scheduled arrivals")
    if not 1 <= args.timeout <= 120 or not 0 <= args.settle_seconds <= 120:
        p.error("timeout=1..120 and settle-seconds=0..120 required")
    if args.stats_interval < 2:
        p.error("stats-interval must be at least 2 seconds")
    if bool(args.audit_db) != bool(args.audit_public_key):
        p.error("Specify both --audit-db and --audit-public-key, or neither")
    if not os.getenv("BENCH_API_KEY"):
        p.error("Set BENCH_API_KEY in environment; do not pass it as a CLI argument")
    return args


def main() -> int:
    args = parser_config()
    root = Path.cwd().resolve()
    compose = (root / args.compose_file).resolve()
    env_file = (root / args.env_file).resolve()
    if not compose.is_file() or not env_file.is_file():
        raise SystemExit("Run from repository root with deploy/compose.yaml and .env present")
    prefix = compose_prefix(args.podman, compose, env_file)
    label_dir = (root / args.results_root / args.label).resolve()
    if label_dir.exists() and any(label_dir.iterdir()):
        raise SystemExit(f"Refusing to overwrite existing benchmark results: {label_dir}")
    label_dir.mkdir(parents=True, exist_ok=True)
    print(
        "Building reviewer image only (not rebuilding approved control-plane image)...", flush=True
    )
    command([*prefix, "build", "audit-reviewer"], cwd=root)
    try:
        config = json.loads(command([*prefix, "config", "--format", "json"], cwd=root))
        discovered = resolve_audit_paths(config)
        control = resolve_control_audit_paths(config)
        paths = AuditPaths(args.audit_db, args.audit_public_key) if args.audit_db else discovered
        control_db = args.audit_control_db or control.database
    except (ValueError, RuntimeError, json.JSONDecodeError) as exc:
        if not (args.audit_db and args.audit_public_key and args.audit_control_db):
            raise SystemExit(
                "Could not resolve audit paths from Compose: "
                + str(exc)
                + "\nPass all three of --audit-db, --audit-public-key and "
                "--audit-control-db if your Compose provider lacks JSON config support."
            ) from exc
        paths = AuditPaths(args.audit_db, args.audit_public_key)
        control_db = args.audit_control_db
    print(f"Reviewer audit DB: {paths.database}; public key: {paths.public_key}", flush=True)
    probe_audit_paths(prefix, root, paths)
    if args.trusted_audit_public_key:
        pin_key(prefix, root, (root / args.trusted_audit_public_key).resolve(), paths)
    failures: list[str] = []
    try:
        git_sha = command(["git", "rev-parse", "HEAD"], cwd=root).strip()
    except RuntimeError:
        git_sha = "unavailable"
    metadata = {
        "label": args.label,
        "utc_started": datetime.now(timezone.utc).isoformat(),
        "git_commit": git_sha,
        "clients": args.clients,
        "duration_s": args.duration,
        "arrival_rate_rps": args.arrival_rate_rps,
        "python": sys.version.split()[0],
        "url": args.api_url,
        "trusted_audit_public_key_pinned": args.trusted_audit_public_key is not None,
        "scenarios": args.scenarios,
        "allow_overload": args.allow_overload,
        "stats_container": args.stats_container,
        "audit_db_in_reviewer": paths.database,
        "audit_public_key_in_reviewer": paths.public_key,
        "audit_db_in_control_plane": control_db,
        "audit_verification_mode": "sqlite-online-backup-then-offline-reviewer",
    }
    save_json(label_dir / "environment.json", metadata)
    for scenario in args.scenarios:
        location = label_dir / scenario
        location.mkdir(parents=True)
        print(
            f"\n[{args.label}] {scenario}: {args.clients} clients x {args.duration}s"
            + (
                f" at scheduled {args.arrival_rate_rps:g} arrivals/s"
                if args.arrival_rate_rps is not None
                else " closed-loop"
            ),
            flush=True,
        )
        before = audit_head(prefix, root, paths, control_db)
        save_json(location / "before.json", before)
        sampler = (
            ResourceSampler(
                args.stats_container,
                location / "podman-stats.jsonl",
                podman=args.podman,
                interval=args.stats_interval,
            )
            if args.stats_container
            else None
        )
        if sampler:
            sampler.start()
        try:
            summary = asyncio.run(
                run(
                    Config(
                        args.api_url,
                        args.clients,
                        args.duration,
                        scenario,
                        args.timeout,
                        os.environ["BENCH_API_KEY"],
                        args.label,
                        location,
                        allow_overload=args.allow_overload,
                        arrival_rate_rps=args.arrival_rate_rps,
                    )
                )
            )
        except Exception as exc:
            failures.append(f"{scenario}: load failed: {type(exc).__name__} {exc}")
            # Even after a client crash, verify the persisted audit chain.
            time.sleep(args.settle_seconds)
            save_json(location / "after.json", audit_head(prefix, root, paths, control_db))
            continue
        finally:
            if sampler:
                sampler.stop()
        time.sleep(args.settle_seconds)
        after = audit_head(prefix, root, paths, control_db)
        save_json(location / "after.json", after)
        assertions = compare_chain_heads(before, after, summary)
        save_json(location / "assertions.json", assertions)
        if (
            not assertions["passed"]
            or summary["functional_validation_failures"]
            or summary["transport_errors"]
            or (summary["evidence_validation_failures"] or 0)
            or summary["request_count"] == 0
            or summary["success_count"] == 0
            or summary["duplicate_request_ids"]
            or summary["client_capacity_drops"]
        ):
            failures.append(f"{scenario}: correctness or availability assertions failed")
        print(
            f"{scenario}: {summary['responses_per_test_second']} responses/s, "
            f"p95={summary['latency_ms']['p95']}ms, "
            f"offered={summary['offered_requests']} issued={summary['dispatched_requests']} "
            f"client_drops={summary['client_capacity_drops']}, "
            f"new events={assertions['actual_new_events']} "
            f"(expected={assertions['expected_new_events']}), "
            f"pass={assertions['passed']}",
            flush=True,
        )
    save_json(
        label_dir / "suite.json",
        {**metadata, "errors": failures, "completed_utc": datetime.now(timezone.utc).isoformat()},
    )
    if failures:
        for failure in failures:
            print("FAILED: " + failure, file=sys.stderr)
        return 1
    print(f"All scenario assertions passed. Results: {label_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
