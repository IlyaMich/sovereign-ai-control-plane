"""Review or apply the M7.1 admission-only changes against GitHub main b0c328f.

Default: prints a unified diff and changes nothing.
  python m7_stage1_rebased/apply_stage1.py --root .
  python m7_stage1_rebased/apply_stage1.py --root . --patch-out m7_1.patch
  python m7_stage1_rebased/apply_stage1.py --root . --apply
"""

from __future__ import annotations

import argparse
import difflib
import subprocess
from pathlib import Path
from typing import Callable

BASE_SHA = "b0c328f1d3ed180b8720bdf456791c67ebfce083"
# GitHub blob SHAs of reviewed source files. Detects a stale patch even on an unchanged branch.
EXPECTED_BLOBS = {
    "app/api/main.py": "114c635fed9ab3774b812d7356181ae81a970cfa",
    "app/infrastructure/config.py": "2954d7afc9081e1af11a00625a6daad209cee0a6",
    "deploy/compose.yaml": "6adc4e6353d20e7e5d2d72a12b32bf11f41d37f1",
    ".env.example": "ffd9ab02ed4f26dc504fddfc9e4f0ef2c4c93cd3",
    "docs/configuration.md": "b3a0b9b291c863ea25ebf0bfc70364f263d71728",
}
NEW_FILES = ("app/api/admission.py", "tests/test_m7_admission.py")


def replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one exact anchor, found {count}; rebase required")
    return source.replace(old, new, 1)


def transform_main(s: str) -> str:
    s = replace_once(
        s,
        "from app.api.body_limit import RequestBodyLimitMiddleware\n",
        "from app.api.admission import InFlightAdmission\n"
        "from app.api.body_limit import RequestBodyLimitMiddleware\n",
        "main: import",
    )
    s = replace_once(
        s,
        "    deps = components or make_components()\n",
        "    deps = components or make_components()\n"
        "    admission = InFlightAdmission(deps.settings.admission.max_inflight_requests)\n",
        "main: init",
    )
    s = replace_once(
        s,
        "    app.state.components = deps\n",
        "    app.state.components = deps\n    app.state.admission = admission\n",
        "main: app state",
    )
    s = replace_once(
        s,
        """        principal = authenticate(x_api_key)
        request_id = str(uuid.uuid4())
        command = PromptCommand(
            request_id, payload.prompt, payload.destination_id, payload.purpose, principal
        )
        result = await deps.orchestrator.process(command)
        body = {
""",
        """        principal = authenticate(x_api_key)
        if not admission.try_enter():
            return JSONResponse(
                status_code=429,
                headers={"Retry-After": "1"},
                content={"status": "REJECTED", "reason_codes": ["CAPACITY_EXCEEDED"]},
            )
        try:
            request_id = str(uuid.uuid4())
            command = PromptCommand(
                request_id, payload.prompt, payload.destination_id, payload.purpose, principal
            )
            result = await deps.orchestrator.process(command)
        finally:
            admission.leave()
        body = {
""",
        "main: submit",
    )
    return s


def transform_config(s: str) -> str:
    s = replace_once(
        s,
        "@dataclass(frozen=True)\nclass Settings:\n",
        '''@dataclass(frozen=True)
class AdmissionLimits:
    """Per API process, fail-fast capacity for admitted prompt requests."""

    max_inflight_requests: int = 8

    def __post_init__(self) -> None:
        value = self.max_inflight_requests
        if type(value) is not int or not 1 <= value <= 1024:
            raise ValueError("MAX_INFLIGHT_REQUESTS must be an integer from 1 to 1024")

    @classmethod
    def from_env(cls) -> AdmissionLimits:
        return cls(max_inflight_requests=positive_int("MAX_INFLIGHT_REQUESTS", cls.max_inflight_requests))


@dataclass(frozen=True)
class Settings:
''',
        "config: model",
    )
    s = replace_once(
        s,
        "    http: HTTPTimeouts = field(default_factory=HTTPTimeouts)\n",
        "    http: HTTPTimeouts = field(default_factory=HTTPTimeouts)\n"
        "    admission: AdmissionLimits = field(default_factory=AdmissionLimits)\n",
        "config: field",
    )
    s = replace_once(
        s,
        "            http=HTTPTimeouts.from_env(),\n",
        "            http=HTTPTimeouts.from_env(),\n"
        "            admission=AdmissionLimits.from_env(),\n",
        "config: from env",
    )
    return s


def transform_compose(s: str) -> str:
    return replace_once(
        s,
        "      MAX_FORWARDED_PROMPT_BYTES: ${MAX_FORWARDED_PROMPT_BYTES:-8192}\n"
        "      OPA_TIMEOUT_SECONDS: ${OPA_TIMEOUT_SECONDS:-2.0}\n",
        "      MAX_FORWARDED_PROMPT_BYTES: ${MAX_FORWARDED_PROMPT_BYTES:-8192}\n"
        "      MAX_INFLIGHT_REQUESTS: ${MAX_INFLIGHT_REQUESTS:-8}\n"
        "      OPA_TIMEOUT_SECONDS: ${OPA_TIMEOUT_SECONDS:-2.0}\n",
        "compose: env",
    )


def transform_example(s: str) -> str:
    return replace_once(
        s,
        "MAX_FORWARDED_PROMPT_BYTES=8192\n",
        "MAX_FORWARDED_PROMPT_BYTES=8192\n\n"
        "# Per control-plane worker; requests above the limit receive HTTP 429.\n"
        "MAX_INFLIGHT_REQUESTS=8\n",
        ".env.example: setting",
    )


def transform_docs(s: str) -> str:
    s = replace_once(
        s,
        "| `MAX_FORWARDED_PROMPT_BYTES` | 8192 | Maximum prompt accepted by all model simulators and egress gateway |\n",
        "| `MAX_FORWARDED_PROMPT_BYTES` | 8192 | Maximum prompt accepted by all model simulators and egress gateway |\n"
        "| `MAX_INFLIGHT_REQUESTS` | 8 | Maximum admitted prompt requests per API process (1-1024), fail-fast 429 |\n",
        "docs: table",
    )
    return replace_once(
        s,
        "Limits must be positive integers. The body limit must exceed the ingress prompt limit.\n",
        "Limits must be positive integers. The body limit must exceed the ingress prompt limit.\n"
        "Admission uses a separate 1-1024 integer limit and rejects with a sanitized HTTP 429\n"
        "(`Retry-After: 1`) after authentication and request validation, but before any\n"
        "detection, audit or model work. Rejected requests have no audit receipt because\n"
        "they were never admitted; client retries must use backoff. This limit applies\n"
        "per Uvicorn worker, not globally across multiple processes. It does not cap\n"
        "HTTP body buffering, event-loop CPU work or the model server's queue.\n",
        "docs: guidance",
    )


TRANSFORMS: dict[str, Callable[[str], str]] = {
    "app/api/main.py": transform_main,
    "app/infrastructure/config.py": transform_config,
    "deploy/compose.yaml": transform_compose,
    ".env.example": transform_example,
    "docs/configuration.md": transform_docs,
}


def run_git(root: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, check=False)
    if result.returncode:
        raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def preflight(root: Path) -> None:
    head = run_git(root, "rev-parse", "HEAD")
    if head != BASE_SHA:
        raise RuntimeError(
            f"Patch targets {BASE_SHA[:12]}; local HEAD is {head[:12]}. "
            "Do not force it onto a different revision; regenerate/rebase the patch."
        )
    changed = run_git(root, "status", "--porcelain", "--", *TRANSFORMS, *NEW_FILES)
    if changed:
        raise RuntimeError(
            "Target paths have local modifications; commit/stash them first:\n" + changed
        )
    for rel, expected in EXPECTED_BLOBS.items():
        actual = run_git(root, "rev-parse", f"HEAD:{rel}")
        if actual != expected:
            raise RuntimeError(f"{rel} has unexpected committed contents: {actual}")
    for rel in NEW_FILES:
        if (root / rel).exists():
            raise RuntimeError(f"Refusing to overwrite new file: {rel}")


def generate(root: Path, assets: Path) -> tuple[str, dict[Path, str]]:
    planned: dict[Path, str] = {}
    pieces: list[str] = []
    for rel, transform in TRANSFORMS.items():
        source = (root / rel).read_text(encoding="utf-8")
        updated = transform(source)
        planned[root / rel] = updated
        pieces.append(f"diff --git a/{rel} b/{rel}\n")
        pieces.extend(
            difflib.unified_diff(
                source.splitlines(keepends=True),
                updated.splitlines(keepends=True),
                fromfile=f"a/{rel}",
                tofile=f"b/{rel}",
                n=3,
            )
        )
    for rel in NEW_FILES:
        content = (assets / rel).read_text(encoding="utf-8")
        planned[root / rel] = content
        pieces.extend(
            (
                f"diff --git a/{rel} b/{rel}\n",
                "new file mode 100644\n",
            )
        )
        pieces.extend(
            difflib.unified_diff(
                [],
                content.splitlines(keepends=True),
                fromfile="/dev/null",
                tofile=f"b/{rel}",
                n=3,
            )
        )
    return "".join(pieces), planned


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--apply", action="store_true", help="Write changed source files")
    parser.add_argument("--patch-out", type=Path, help="Save git-apply-compatible unified diff")
    args = parser.parse_args()
    root = args.root.resolve()
    preflight(root)
    patch, planned = generate(root, Path(__file__).resolve().parent / "files")
    if args.patch_out:
        args.patch_out.write_text(patch, encoding="utf-8")
        print(f"Saved {args.patch_out}")
    if args.apply:
        for target, content in planned.items():
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        print("Applied M7.1 locally. Review git diff and run tests; no GitHub changes made.")
    elif not args.patch_out:
        print(patch)
        print("DRY RUN: no files modified. Use --patch-out or --apply after review.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
