"""Run a detector against immutable ground truth without changing production code."""

from __future__ import annotations

import hashlib
import json
import math
import platform
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path
from typing import Any, Protocol

from evaluation.dataset import Case, Dataset, Entity
from evaluation.scoring import Prediction, score


class DetectorAdapter(Protocol):
    name: str

    def detect(self, text: str) -> dict[str, Any]: ...


def _git_head(repo_root: Path) -> str | None:
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            timeout=3,
            check=True,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    value = proc.stdout.strip()
    return value if len(value) == 40 else None


def _file_digest(path: Path) -> str | None:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None


def _parse_prediction(cid: str, raw: Any, latency_ms: float, text: str) -> Prediction:
    if not isinstance(raw, dict):
        raise ValueError("Detector result must be a mapping")
    status = raw.get("status")
    if status not in ("PRIVATE", "NO_PRIVATE_DETECTED", "UNKNOWN"):
        raise ValueError("Invalid classification status")
    findings = raw.get("findings")
    if not isinstance(findings, list):
        raise ValueError("Invalid findings array")
    entities: list[Entity] = []
    for item in findings:
        if not isinstance(item, dict):
            raise ValueError("Invalid finding")
        cat, start, end = item.get("category"), item.get("start"), item.get("end")
        if not (
            isinstance(cat, str)
            and cat
            and type(start) is int
            and type(end) is int
            and 0 <= start < end <= len(text)
        ):
            raise ValueError("Invalid finding span")
        entities.append(Entity(cat, start, end))
    if status == "NO_PRIVATE_DETECTED" and entities or status == "PRIVATE" and not entities:
        raise ValueError("Classification and findings disagree")
    if status == "UNKNOWN" and entities:
        raise ValueError("Unknown result cannot claim definite findings")
    reasons = raw.get("reason_codes", [])
    if not isinstance(reasons, (list, tuple)) or not all(isinstance(r, str) for r in reasons):
        raise ValueError("Invalid reason codes")
    return Prediction(cid, status, tuple(entities), latency_ms, tuple(reasons))


def _percentile(values: list[float], p: float) -> float | None:
    if not values:
        return None
    sorted_values = sorted(values)
    index = (len(sorted_values) - 1) * p
    lo, hi = math.floor(index), math.ceil(index)
    if lo == hi:
        return round(sorted_values[lo], 4)
    interpolated = sorted_values[lo] * (hi - index) + sorted_values[hi] * (index - lo)
    return round(interpolated, 4)


def evaluate(
    dataset: Dataset, adapter: DetectorAdapter, *, split: str = "all", repo_root: Path | None = None
) -> tuple[dict[str, Any], list[Prediction]]:
    """Errors are counted as ERROR, never silently converted to negative/UNKNOWN."""
    cases = dataset.select(split)
    predictions: list[Prediction] = []
    verified_identity: tuple[str, str, str] | None = None
    started = time.perf_counter()
    for case in cases:
        tick = time.perf_counter()
        try:
            raw = adapter.detect(case.text)
            result = _parse_prediction(case.id, raw, (time.perf_counter() - tick) * 1000, case.text)
            if result.status != "UNKNOWN":
                identity = (
                    str(raw.get("detector_version", "")),
                    str(raw.get("config_digest", "")),
                    str(raw.get("artifact_digest", "")),
                )
                if verified_identity is not None and identity != verified_identity:
                    raise RuntimeError("Detector identity changed during evaluation")
                verified_identity = identity
        except Exception as exc:
            # Never serialize exception messages: they might contain submitted text.
            result = Prediction(
                case.id, "ERROR", (), (time.perf_counter() - tick) * 1000, (), type(exc).__name__
            )
        predictions.append(result)
    elapsed = time.perf_counter() - started
    latency = [p.latency_ms for p in predictions]
    repo_root = repo_root or Path(__file__).resolve().parent.parent
    rules = repo_root / "app" / "detection" / "rules.json"

    def package_version(name: str) -> str | None:
        try:
            return metadata.version(name)
        except metadata.PackageNotFoundError:
            return None

    run = {
        "schema_version": 1,
        "run_id": (
            datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
        ),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "adapter": adapter.name,
        "split": split,
        "dataset_name": dataset.manifest["name"],
        "dataset_version": dataset.manifest["dataset_version"],
        "dataset_sha256": dataset.manifest["cases_sha256"],
        "git_commit": _git_head(repo_root),
        "detector_version": verified_identity[0] if verified_identity else None,
        "detector_config_digest": verified_identity[1] if verified_identity else None,
        "detector_artifact_digest": verified_identity[2] if verified_identity else None,
        "detector_rules_sha256": _file_digest(rules),
        "detector_source_sha256": _file_digest(
            repo_root / "app" / "detection" / "presidio_detector.py"
        ),
        "aggregator_source_sha256": _file_digest(
            repo_root / "app" / "detection" / "aggregation.py"
        ),
        "runtime": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "presidio_analyzer": package_version("presidio-analyzer"),
            "spacy": package_version("spacy"),
            "spacy_model": package_version("en_core_web_sm"),
        },
        "scoring_spec": "strict-and-overlap-v1",
        "metrics": score(cases, predictions),
        "timing": {
            "total_seconds": round(elapsed, 4),
            "cases_per_second": round(len(cases) / elapsed, 3) if elapsed else None,
            "detector_call_p50_ms": _percentile(latency, 0.50),
            "detector_call_p95_ms": _percentile(latency, 0.95),
            "detector_call_p99_ms": _percentile(latency, 0.99),
            "note": "Sequential detection calls only; includes Python adapter overhead.",
        },
    }
    return run, predictions


def save_run(
    outdir: Path, run: dict[str, Any], cases: tuple[Case, ...], predictions: list[Prediction]
) -> None:
    from evaluation.reporting import write_reports

    outdir.mkdir(parents=True, exist_ok=False)
    (outdir / "run.json").write_text(
        json.dumps(run, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    with (outdir / "predictions.jsonl").open("w", encoding="utf-8", newline="\n") as f:
        for item in predictions:
            f.write(
                json.dumps(
                    {
                        "case_id": item.case_id,
                        "status": item.status,
                        "entities": [vars(entity) for entity in item.entities],
                        "latency_ms": round(item.latency_ms, 5),
                        "reason_codes": item.reason_codes,
                        "error_type": item.error_type,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            )
    write_reports(outdir, run, cases, predictions)
