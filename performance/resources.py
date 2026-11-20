"""Best-effort, allowlisted container statistics; no payloads or identifiers."""
from __future__ import annotations

import asyncio
import json
import re
import shutil
from typing import Any

_ALLOWED = ("control-plane", "opa", "sovereign-model")
_PERCENT = re.compile(r"^\s*([0-9]+(?:\.[0-9]+)?)%\s*$")


def _parse_one(raw: Any) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    name = str(raw.get("name", raw.get("Name", "")))
    if not any(name == service or name.endswith("_" + service + "_1")
               or name.endswith("-" + service + "-1") for service in _ALLOWED):
        return None
    # Podman's JSON output uses snake_case, unlike its Go-template field names.
    cpu = str(raw.get("cpu_percent", raw.get("CPUPerc", raw.get("CPU", ""))))
    mem = str(raw.get("mem_usage", raw.get("MemUsage", "")))
    match = _PERCENT.fullmatch(cpu)
    # Never persist arbitrary strings from a container runtime.
    if not re.fullmatch(r"[A-Za-z0-9 ./%+-]{1,80}", mem):
        mem = ""
    return {"service": next((s for s in _ALLOWED if name == s or name.endswith("_" + s + "_1")
                             or name.endswith("-" + s + "-1")), ""),
            "cpu_pct": float(match.group(1)) if match else None,
            "memory_usage": mem[:80] if len(mem) <= 80 else None}


async def sample() -> list[dict[str, Any]] | None:
    if not shutil.which("podman"):
        return None
    try:
        process = await asyncio.create_subprocess_exec(
            "podman", "stats", "--no-stream", "--format", "json",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(process.communicate(), timeout=8)
        if process.returncode != 0 or len(stdout) > 200000:
            return None
        parsed = json.loads(stdout)
        if isinstance(parsed, dict):
            parsed = [parsed]
        if not isinstance(parsed, list):
            return None
        results = [item for value in parsed if (item := _parse_one(value)) is not None]
        # Unknown/missing stats are unavailable, not valid resource measurements.
        if not any(row["cpu_pct"] is not None or row["memory_usage"] for row in results):
            return None
        return results
    except (OSError, ValueError, asyncio.TimeoutError):
        return None


async def collect_periodically(output: list[dict[str, Any]], stop: asyncio.Event) -> None:
    loop = asyncio.get_running_loop()
    start = loop.time()
    while not stop.is_set():
        data = await sample()
        if data is not None:
            output.append({"seconds": round(loop.time() - start, 2), "containers": data})
        try:
            await asyncio.wait_for(stop.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            pass
