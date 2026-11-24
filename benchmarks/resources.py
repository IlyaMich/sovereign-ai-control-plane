"""Optional, nonintrusive Podman CPU/memory sampling during the timed phase."""

from __future__ import annotations

import json
import subprocess
import threading
from datetime import datetime, timezone
from pathlib import Path


class ResourceSampler:
    def __init__(
        self, container: str, output: Path, *, podman: str = "podman", interval: float = 3.0
    ):
        self.container = container
        self.output = output
        self.podman = podman
        self.interval = interval
        self.stop_event = threading.Event()
        self.worker = threading.Thread(target=self._sample, daemon=True)

    def start(self) -> None:
        self.worker.start()

    def stop(self) -> None:
        self.stop_event.set()
        self.worker.join(timeout=15)

    def _sample(self) -> None:
        with self.output.open("w", encoding="utf-8") as handle:
            while not self.stop_event.is_set():
                try:
                    sample = subprocess.run(
                        [self.podman, "stats", "--no-stream", "--format", "json", self.container],
                        text=True,
                        capture_output=True,
                        timeout=min(10.0, self.interval + 5.0),
                        check=False,
                    )
                    data = {
                        "utc": datetime.now(timezone.utc).isoformat(),
                        "exit_code": sample.returncode,
                        "raw": sample.stdout[:10000].strip(),
                        "error": sample.stderr[:500].strip() if sample.returncode else "",
                    }
                except (OSError, subprocess.TimeoutExpired) as exc:
                    data = {
                        "utc": datetime.now(timezone.utc).isoformat(),
                        "exit_code": -1,
                        "raw": "",
                        "error": type(exc).__name__,
                    }
                handle.write(json.dumps(data, sort_keys=True) + "\n")
                handle.flush()
                self.stop_event.wait(self.interval)
