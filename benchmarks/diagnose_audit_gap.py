"""Reconcile recorded HTTP responses with signed audit-event sequence windows.

Read-only, does not modify audit history, deploy images, or release artifacts.
Requires the existing benchmarks/compose_audit.py helper and Podman Compose.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from benchmarks.compose_audit import resolve_control_audit_paths

# Executed in the *running* control-plane service, where WAL sidecars can be read.
# Never returns prompt text, fingerprints, detector findings, secrets or output.
EVENT_QUERY = r"""import json, sqlite3, sys
from pathlib import Path
path, lo, hi = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
if hi < lo or hi - lo > 100000:
    raise SystemExit('Invalid audit sequence interval')
conn = sqlite3.connect('file:' + str(Path(path).resolve()) + '?mode=ro', uri=True, timeout=10)
try:
    conn.execute('PRAGMA query_only=ON')
    rows = conn.execute(
      'SELECT sequence, request_id, event_type, event_json FROM events '
      'WHERE sequence > ? AND sequence <= ? ORDER BY sequence', (lo,hi)
    ).fetchall()
    result = []
    for seq, request_id, kind, raw in rows:
        obj = json.loads(raw)
        payload = obj.get('payload') or {}
        reason = (payload.get('decision') or {}).get('reason_codes', [])
        result.append({'sequence': seq, 'request_id': request_id,
                       'event_type': kind, 'timestamp': obj.get('timestamp'),
                       'reason_codes': reason if kind == 'DECISION' else [],
                       'execution_status': payload.get('execution_status') if kind == 'OUTCOME' else None})
    print(json.dumps(result, separators=(',', ':')))
finally:
    conn.close()
"""


def run_command(args: list[str], cwd: Path) -> str:
    result = subprocess.run(args, cwd=cwd, capture_output=True, text=True)
    if result.returncode:
        # Do not print full Compose configuration: it contains environment secrets.
        raise RuntimeError(
            f"Command failed: {args[0]} (exit {result.returncode}); "
            f"stderr tail: {result.stderr[-900:]}"
        )
    return result.stdout


def receipt_pair(row: dict[str, Any]) -> bool:
    return (
        isinstance(row.get("request_id"), str)
        and isinstance(row.get("decision_receipt"), dict)
        and isinstance(row.get("outcome_receipt"), dict)
    )


def reconcile(rows: list[dict[str, Any]], events: list[dict[str, Any]]) -> dict[str, Any]:
    observed = {r["request_id"] for r in rows if receipt_pair(r)}
    by_id: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        by_id[event["request_id"]].append(event)
    seen_ids = set(by_id)
    unexpected = {rid: by_id[rid] for rid in sorted(seen_ids - observed)}
    missing = sorted(observed - seen_ids)
    incomplete = {
        rid: by_id[rid]
        for rid in observed & seen_ids
        if [e["event_type"] for e in by_id[rid]] != ["DECISION", "OUTCOME"]
    }
    no_receipt = [r for r in rows if not receipt_pair(r)]
    return {
        "responses_with_receipt_pairs": len(observed),
        "response_rows_without_receipt_pairs": len(no_receipt),
        "transport_errors": dict(
            Counter(str(r.get("transport_error")) for r in no_receipt if r.get("transport_error"))
        ),
        "http_statuses_without_receipts": dict(
            Counter(str(r.get("http_status")) for r in no_receipt)
        ),
        "events_in_sequence_window": len(events),
        "unmatched_audited_request_count": len(unexpected),
        "unmatched_audited_requests": [
            {
                "request_id": rid,
                "events": [
                    {
                        k: e.get(k)
                        for k in (
                            "sequence",
                            "event_type",
                            "timestamp",
                            "reason_codes",
                            "execution_status",
                        )
                    }
                    for e in hits
                ],
            }
            for rid, hits in unexpected.items()
        ],
        "responses_missing_from_audit_window": missing,
        "responses_with_nonstandard_audit_pairs": {
            rid: [e["event_type"] for e in hits] for rid, hits in incomplete.items()
        },
        "other_possible_causes": (
            "Another caller or HTTP timeout/disconnect may account "
            "for an unmatched request; the event itself does not "
            "identify which client submitted it."
        ),
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--label", required=True)
    p.add_argument("--scenario", required=True)
    p.add_argument("--results-root", type=Path, default=Path("bench-results"))
    p.add_argument("--compose-file", type=Path, default=Path("deploy/compose.yaml"))
    p.add_argument("--env-file", type=Path, default=Path(".env"))
    p.add_argument("--podman", default="podman")
    p.add_argument("--audit-control-db", help="Override DB location inside control-plane container")
    args = p.parse_args()
    root = Path.cwd().resolve()
    target = root / args.results_root / args.label / args.scenario
    before = json.loads((target / "before.json").read_text(encoding="utf-8"))
    after = json.loads((target / "after.json").read_text(encoding="utf-8"))
    rows = [
        json.loads(line)
        for line in (target / "requests.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    lo, hi = int(before["latest_sequence"]), int(after["latest_sequence"])
    if hi < lo or hi - lo > 100000:
        raise SystemExit("Audit event window is invalid or too large for diagnostic")
    prefix = [
        args.podman,
        "compose",
        "-f",
        str((root / args.compose_file).resolve()),
        "--env-file",
        str((root / args.env_file).resolve()),
        "--profile",
        "audit-review",
    ]
    if args.audit_control_db:
        db = args.audit_control_db
    else:
        # Load config only in memory; never print the secret-bearing Compose result.
        config = json.loads(run_command([*prefix, "config", "--format", "json"], root))
        db = resolve_control_audit_paths(config).database
    output = run_command(
        [*prefix, "exec", "-T", "control-plane", "python", "-c", EVENT_QUERY, db, str(lo), str(hi)],
        root,
    )
    events = json.loads(output)
    diagnosis = reconcile(rows, events)
    diagnosis["audit_sequence_range"] = {"after": lo, "through": hi}
    report = target / "audit_reconciliation.json"
    report.write_text(json.dumps(diagnosis, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(diagnosis, indent=2, sort_keys=True))
    print(f"\nSaved: {report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
