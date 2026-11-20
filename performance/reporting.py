"""Integrity-gated reporting and comparable-run analysis of M7.9 suite outputs."""
from __future__ import annotations

import csv
import html
import json
import math
import statistics
from pathlib import Path
from typing import Any

from tools.concurrency_performance import benchmark_integrity, max_for_phase

SIGNALS = (
    "detector.queue_wait.p95_ms", "detector.processing.p95_ms",
    "audit.queue_wait.p95_ms", "audit.processing.p95_ms",
    "event_loop.p95_ms", "audit_limits.waiting_for_slot",
)


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Invalid JSON object in {path.name}")
    return value


def number(value: Any, *, positive: bool = False) -> float:
    if type(value) not in (float, int) or not math.isfinite(value):
        raise ValueError("Missing or non-finite metric")
    if value < 0 or (positive and value <= 0):
        raise ValueError("Invalid negative/zero metric")
    return float(value)


def collect(folder: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    manifest = read_json(folder / "manifest.json")
    if manifest.get("schema_version") != 1 or manifest.get("status") != "passed":
        raise ValueError("Run is incomplete or failed; no performance comparison allowed")
    scenarios = manifest["scenarios"]
    rows: list[dict[str, Any]] = []
    for level in manifest["levels"]:
        for repeat in range(1, manifest["runs"] + 1):
            label = f"{manifest['run_id']}-c{level}-r{repeat:02d}"
            directory = folder / "raw" / label
            issues = benchmark_integrity(directory, scenarios)
            if issues:
                raise ValueError(f"Signed-audit integrity/correctness failed: {label}: {issues}")
            suite = read_json(directory / "suite.json")
            diag = read_json(directory / "m7_9_diagnostics.json")
            if (suite.get("clients") != level
                or number(suite.get("duration_s"), positive=True) != manifest["duration_s"]
                or diag.get("label") != label or diag.get("git_commit") != manifest["git_commit"]
                or diag.get("benchmark_exit_code") != 0 or diag.get("poll_errors") != 0
                or diag.get("process_counter_reset") is not False
                or diag.get("benchmark_integrity_issues") != []
                or not isinstance(diag.get("samples"), list) or not diag["samples"]):
                raise ValueError(f"Missing, invalid or mismatched diagnostics for {label}")
            for scenario in scenarios:
                summary = read_json(directory / scenario / "summary.json")
                if (summary.get("scenario") != scenario or summary.get("clients") != level
                    or number(summary.get("duration_configured_s"), positive=True)
                    != manifest["duration_s"]):
                    raise ValueError(f"Invalid scenario identity for {label}")
                row: dict[str, Any] = {
                    "level": level, "repetition": repeat, "scenario": scenario,
                    "goodput_rps": number(summary.get("goodput_per_test_second")),
                    "p50_ms": number(summary["latency_ms"]["p50"]),
                    "p95_ms": number(summary["latency_ms"]["p95"]),
                    "p99_ms": number(summary["latency_ms"]["p99"]),
                    "requests": int(number(summary.get("request_count"))),
                    "http_statuses": summary.get("http_statuses", {}),
                }
                if not isinstance(row["http_statuses"], dict):
                    raise ValueError("Invalid status counts")
                for signal in SIGNALS:
                    row[signal] = max_for_phase(diag["samples"], scenario, signal)
                rows.append(row)
    return manifest, rows


def aggregate(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[int, str], list[dict[str, Any]]] = {}
    for row in rows:
        groups.setdefault((row["level"], row["scenario"]), []).append(row)
    result = []
    for (level, scenario), members in sorted(groups.items()):
        item: dict[str, Any] = {"level": level, "scenario": scenario, "runs": len(members)}
        for field in ("goodput_rps", "p50_ms", "p95_ms", "p99_ms"):
            values = [r[field] for r in members]
            item[field] = round(statistics.median(values), 4)
            item[field + "_min"] = round(min(values), 4)
            item[field + "_max"] = round(max(values), 4)
        for signal in SIGNALS:
            values = [number(r[signal]) for r in members if r[signal] is not None]
            item[signal] = round(max(values), 3) if values else None
        result.append(item)
    return result


def write_report(folder: Path) -> Path:
    manifest, rows = collect(folder)
    data = aggregate(rows)
    (folder / "summary.json").write_text(json.dumps({
        "schema_version": 1, "run_id": manifest["run_id"], "integrity": "passed",
        "aggregates": data,
    }, indent=2) + "\n", encoding="utf-8")
    with (folder / "metrics.csv").open("w", newline="", encoding="utf-8") as output:
        fields = ("level", "repetition", "scenario", "requests", "goodput_rps",
                  "p50_ms", "p95_ms", "p99_ms")
        writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    table_rows = "\n".join(
        "<tr>" + "".join(f"<td>{html.escape(str(item[key]))}</td>" for key in
        ("level", "scenario", "runs", "goodput_rps", "p50_ms", "p95_ms", "p99_ms")) + "</tr>"
        for item in data
    )
    page = ("<!doctype html><html lang='en'><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<title>Control-plane benchmark</title>"
            "<style>body{font:16px system-ui;max-width:1150px;margin:3rem auto;padding:1rem}"
            "table{border-collapse:collapse;width:100%}th,td{padding:.65rem;border-bottom:1px solid #aaa;text-align:left}"
            "th{background:#eee;color:#222}td{font-variant-numeric:tabular-nums}</style>"
            f"<h1>Benchmark: {html.escape(manifest['run_id'])}</h1>"
            f"<p>Profile: {html.escape(manifest['profile'])} · Signed-audit assertions: PASS</p>"
            "<p>Closed-loop clients. Metrics are medians of repetitions; component signals "
            "are maxima of sampled rolling windows, not whole-run percentiles.</p>"
            "<table><thead><tr><th>Clients</th><th>Scenario</th><th>Runs</th>"
            "<th>Goodput/s</th><th>p50 ms</th><th>p95 ms</th><th>p99 ms</th>"
            f"</tr></thead><tbody>{table_rows}</tbody></table>"
            "<p>Raw benchmark assertions and diagnostics remain in raw/.</p></html>")
    out = folder / "report.html"
    out.write_text(page, encoding="utf-8")
    return out


def compare(baseline: Path, candidate: Path, warning_pct: float = 10.0) -> tuple[dict[str, Any], bool]:
    a, ar = collect(baseline)
    b, br = collect(candidate)
    identity_fields = ("profile", "profile_digest", "levels", "runs", "duration_s",
                       "interval_s", "scenarios", "allow_overload")
    mismatches = [field for field in identity_fields if a[field] != b[field]]
    if a["git_commit"] == b["git_commit"]:
        mismatches.append("git_commit_is_identical")
    # Environment fingerprints are operator-supplied and must be compared before interpreting changes.
    if a.get("environment") != b.get("environment"):
        mismatches.append("environment")
    if mismatches:
        raise ValueError("Runs not comparable: " + ", ".join(mismatches))
    aa = {(v["level"], v["scenario"]): v for v in aggregate(ar)}
    bb = {(v["level"], v["scenario"]): v for v in aggregate(br)}
    if aa.keys() != bb.keys():
        raise ValueError("Mismatched scenario keys")
    comparisons = []
    regressed = False
    for key in sorted(aa):
        before, after = aa[key], bb[key]
        if before["goodput_rps"] <= 0:
            raise ValueError("Baseline goodput missing")
        goodput_pct = 100 * (after["goodput_rps"] / before["goodput_rps"] - 1)
        p95_pct = (100 * (after["p95_ms"] / before["p95_ms"] - 1)
                   if before["p95_ms"] > 0 else None)
        warn = goodput_pct < -warning_pct or (p95_pct is not None and p95_pct > warning_pct)
        regressed |= warn
        comparisons.append({"clients": key[0], "scenario": key[1],
                            "baseline_goodput_rps": before["goodput_rps"],
                            "candidate_goodput_rps": after["goodput_rps"],
                            "goodput_change_pct": round(goodput_pct, 2),
                            "baseline_p95_ms": before["p95_ms"],
                            "candidate_p95_ms": after["p95_ms"],
                            "p95_change_pct": round(p95_pct, 2) if p95_pct is not None else None,
                            "regression_warning": warn})
    return {"baseline": a["run_id"], "candidate": b["run_id"],
            "warning_threshold_pct": warning_pct, "comparisons": comparisons,
            "regression_warning": regressed, "integrity": "passed"}, regressed
