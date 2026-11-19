"""PII-free, portable CSV and HTML reports; no prompt text is exported."""
from __future__ import annotations

import csv
import html
import json
from pathlib import Path
from typing import Any

from evaluation.dataset import Case, Entity
from evaluation.scoring import Prediction, _matched


def _percent(value: float | None) -> str:
    return "N/A" if value is None else f"{value * 100:.2f}%"


def _entities(items: tuple[Entity, ...]) -> str:
    return "; ".join(f"{e.category}:{e.start}-{e.end}" for e in items)


def write_reports(path: Path, run: dict[str, Any], cases: tuple[Case, ...],
                  predictions: list[Prediction]) -> None:
    metrics = run["metrics"]
    with (path / "cases.csv").open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(("case_id", "split", "group", "expected_status", "actual_status",
                         "expected_entities", "detected_entities", "exact_tp", "exact_fp",
                         "exact_fn", "latency_ms", "reason_codes", "error_type"))
        for c, p in zip(cases, predictions):
            assert c.id == p.case_id
            matched = _matched(c.entities, p.entities, relaxed=False)
            writer.writerow((c.id, c.split, c.group, c.expected_status, p.status,
                             _entities(c.entities), _entities(p.entities), len(matched),
                             len(p.entities) - len(matched), len(c.entities) - len(matched),
                             round(p.latency_ms, 4), ";".join(p.reason_codes), p.error_type or ""))
    with (path / "categories.csv").open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(("category", "tp", "fp", "fn", "precision", "recall", "f1"))
        for category, counts in metrics["entities_exact_full"]["by_category"].items():
            writer.writerow((category, counts["tp"], counts["fp"], counts["fn"],
                             counts["precision"], counts["recall"], counts["f1"]))
    (path / "report.html").write_text(render_html(run), encoding="utf-8")


def render_html(run: dict[str, Any]) -> str:
    """Report contents come from labels/scores only. Escape all dynamic values."""
    m = run["metrics"]
    metric = m["entities_exact_full"]["overall"]

    def esc(value: Any) -> str:
        return html.escape(str(value))

    def td(value: Any) -> str:
        return f"<td>{esc(value)}</td>"

    rows = "\n".join(
        "<tr>" + td(category) + td(x["tp"]) + td(x["fp"]) + td(x["fn"]) +
        td(_percent(x["precision"])) + td(_percent(x["recall"])) +
        td(_percent(x["f1"])) + "</tr>"
        for category, x in m["entities_exact_full"]["by_category"].items()
    )
    group_rows = "\n".join(
        "<tr>" + td(group) + td(x["total"]) + td(x["correct"]) +
        td(_percent(x["accuracy"])) + "</tr>"
        for group, x in m["group_accuracy"].items()
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Detection Evaluation: {esc(run['run_id'])}</title>
<style>
body{{margin:0 auto;max-width:1100px;padding:32px;font-family:system-ui,Arial,sans-serif;color:#17253d;background:#f7f9fc}}
h1{{font-size:26px}}h2{{margin-top:34px}}.meta{{color:#526176;line-height:1.75}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}}
.card{{background:#fff;border:1px solid #e1e8f0;border-radius:10px;padding:18px}}
.kpi{{font-size:25px;font-weight:700;margin-top:9px}}.label{{color:#526176;font-size:13px}}
table{{border-collapse:collapse;width:100%;background:white}}th,td{{padding:11px;text-align:left;border-bottom:1px solid #e4e8ee}}
th{{background:#edf2f8;font-weight:650}}.note{{font-size:13px;color:#526176}}
</style></head><body>
<h1>Sovereign AI — Detection Evaluation</h1>
<div class="meta">Run: {esc(run['run_id'])}<br>Adapter: {esc(run['adapter'])}<br>
Dataset: {esc(run['dataset_name'])} · {esc(run['dataset_version'])} · split: {esc(run['split'])}<br>
Dataset SHA-256: <code>{esc(run['dataset_sha256'])}</code><br>
Git commit: <code>{esc(run.get('git_commit') or 'not available')}</code><br>
Detector artifact digest: <code>{esc(run.get('detector_artifact_digest') or 'standalone/unavailable')}</code></div>
<h2>Overview</h2><div class="cards">
<div class="card"><div class="label">Cases</div><div class="kpi">{m['total_cases']}</div></div>
<div class="card"><div class="label">Entity precision · exact</div><div class="kpi">{_percent(metric['precision'])}</div></div>
<div class="card"><div class="label">Entity recall · exact, all cases</div><div class="kpi">{_percent(metric['recall'])}</div></div>
<div class="card"><div class="label">Entity F1 · exact</div><div class="kpi">{_percent(metric['f1'])}</div></div>
<div class="card"><div class="label">Unsafe negative rate (sensitive prompts)</div><div class="kpi">{_percent(m['unsafe_negative_rate'])}</div></div>
<div class="card"><div class="label">UNKNOWN on in-scope prompts</div><div class="kpi">{m['in_scope_unknown_count']}</div></div>
<div class="card"><div class="label">Detection errors</div><div class="kpi">{m['detector_error_count']}</div></div>
<div class="card"><div class="label">p95 detector-call latency</div><div class="kpi">{esc(run['timing']['detector_call_p95_ms'])} ms</div></div>
</div>
<p class="note">UNKNOWN and ERROR do not count as successful detections in the full entity recall. Selective entity metrics are also available in run.json. Overlap matching is reported separately and is not a substitute for exact redaction coverage. This is a detector-only evaluation, not an enforcement or external-egress test.</p>
<h2>Entity metrics — exact span matching</h2>
<table><thead><tr><th>Category</th><th>TP</th><th>FP</th><th>FN</th><th>Precision</th><th>Recall</th><th>F1</th></tr></thead><tbody>{rows}</tbody></table>
<h2>Classification by scenario group</h2>
<table><thead><tr><th>Group</th><th>Cases</th><th>Correct status</th><th>Accuracy</th></tr></thead><tbody>{group_rows}</tbody></table>
<p class="note">All prompts are synthetic. This report contains case identifiers and aggregates, never original prompt strings.</p>
</body></html>"""


def rerender(path: Path) -> Path:
    run = json.loads((path / "run.json").read_text(encoding="utf-8"))
    target = path / "report.html"
    target.write_text(render_html(run), encoding="utf-8")
    return target
