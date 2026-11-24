"""Compare baseline and improved benchmark suites with matching scenarios/settings."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def percent(new: float, old: float) -> str:
    if old == 0:
        return "N/A"
    return f"{100 * (new - old) / old:+.1f}%"


def display(value: Any) -> str:
    return "N/A" if value is None else str(value)


def compare(base_dir: Path, new_dir: Path) -> str:
    base = {p.parent.name: load(p) for p in base_dir.glob("*/summary.json")}
    improved = {p.parent.name: load(p) for p in new_dir.glob("*/summary.json")}
    shared = sorted(set(base) & set(improved))
    if not shared:
        raise ValueError("No matching scenarios found")
    lines = [
        "# Sovereign AI concurrency benchmark comparison",
        "",
        f"Baseline: `{base_dir}`",
        f"Improved: `{new_dir}`",
        "",
        "| Scenario | Metric | Baseline | Improved | Change |",
        "|---|---|---:|---:|---:|",
    ]
    failures: list[str] = []
    for scenario in shared:
        a, b = base[scenario], improved[scenario]
        for field in ("clients", "duration_configured_s", "scenario"):
            if a[field] != b[field]:
                raise ValueError(f"Scenario {scenario}: mismatched comparison setting {field}")
        metrics = [
            ("All responses in window/s", "responses_per_test_second", "higher"),
            ("Goodput in window/s", "goodput_per_test_second", "higher"),
            ("Functional success (%)", "expected_success_rate_pct", "higher"),
            ("p50 latency (ms)", "latency_ms.p50", "lower"),
            ("p95 latency (ms)", "latency_ms.p95", "lower"),
            ("p99 latency (ms)", "latency_ms.p99", "lower"),
            ("Transport errors", "transport_errors", "lower"),
            ("Evidence assertion failures", "evidence_validation_failures", "lower"),
        ]
        for label, key, direction in metrics:

            def get(doc: dict[str, Any]) -> Any:
                cur: Any = doc
                for step in key.split("."):
                    cur = cur[step]
                return cur

            old = get(a)
            new = get(b)
            change = (
                percent(float(new), float(old)) if old is not None and new is not None else "N/A"
            )
            lines.append(f"| {scenario} | {label} | {display(old)} | {display(new)} | {change} |")
        for phase, path in (("baseline", base_dir), ("improved", new_dir)):
            check_path = path / scenario / "assertions.json"
            if not check_path.exists() or not load(check_path).get("passed"):
                failures.append(f"{phase}/{scenario}: audit delta assertions missing or failed")
        if (
            a.get("functional_validation_failures")
            or b.get("functional_validation_failures")
            or a.get("evidence_validation_failures")
            or b.get("evidence_validation_failures")
        ):
            failures.append(f"{scenario}: correctness failures recorded")
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "A throughput increase is not a win if integrity assertions regress.",
            "Compare CPU/RAM, resource limits, OS, Podman version, policy/detector digests, and model configuration separately.",
            "These are closed-loop client results (8 clients), not a maximum-RPS capacity claim.",
            "",
            "## Comparison checks",
            "",
        ]
    )
    lines.append(
        "**PASS**: all available integrity checks passed"
        if not failures
        else "**FAIL:** " + "; ".join(failures)
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--improved", required=True, type=Path)
    parser.add_argument("--out", type=Path, default=Path("bench-results/comparison.md"))
    args = parser.parse_args()
    report = compare(args.baseline, args.improved)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(report, encoding="utf-8")
    print(report)
    print(f"Saved: {args.out}")
    return 1 if "**FAIL:**" in report else 0


if __name__ == "__main__":
    raise SystemExit(main())
