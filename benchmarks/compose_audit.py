"""Resolve audit paths from the effective Compose configuration, not fixed defaults.

Inspecting `compose config --format json` also respects .env interpolation and
AUDIT_DATA_DIR, AUDIT_DB_PATH, and AUDIT_SIGNING_KEY_PATH overrides.
Never log Compose config: it can contain CONTROL_PLANE_API_KEY.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any


@dataclass(frozen=True)
class AuditPaths:
    database: str
    public_key: str


def _environ(raw: object) -> dict[str, str]:
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items() if v is not None}
    if isinstance(raw, list):
        pairs = (str(item).partition("=") for item in raw)
        return {name: value for name, sep, value in pairs if sep}
    raise ValueError("Control-plane environment missing in Compose configuration")


def _volumes(raw: object) -> list[dict[str, str]]:
    if not isinstance(raw, list):
        raise ValueError("Compose service volumes are missing")
    volumes: list[dict[str, str]] = []
    for item in raw:
        if isinstance(item, dict):
            source = item.get("source")
            target = item.get("target")
            if isinstance(source, str) and isinstance(target, str):
                volumes.append({"source": source, "target": target})
    return volumes


def _relative(path: str, mount: str) -> PurePosixPath | None:
    p = PurePosixPath(path)
    m = PurePosixPath(mount)
    if not p.is_absolute() or not m.is_absolute():
        return None
    try:
        rel = p.relative_to(m)
    except ValueError:
        return None
    return rel if str(rel) not in ("", ".") else None


def resolve_audit_paths(compose: dict[str, Any]) -> AuditPaths:
    """Translate container paths from control-plane volume to reviewer mount.

    The paths may be different if the two services mount the same named volume
    at different targets. This function only reads public Compose metadata.
    """
    services = compose.get("services")
    if not isinstance(services, dict):
        raise ValueError("Invalid Compose config: services missing")
    control = services.get("control-plane")
    reviewer = services.get("audit-reviewer")
    if not isinstance(control, dict) or not isinstance(reviewer, dict):
        raise ValueError("Compose must define control-plane and audit-reviewer services")
    env = _environ(control.get("environment"))
    db = env.get("AUDIT_DB_PATH", "/var/lib/sovereign/audit.sqlite")
    signing_key = env.get("AUDIT_SIGNING_KEY_PATH", "/var/lib/sovereign/audit-key.pem")
    public = str(PurePosixPath(signing_key).with_suffix(".pub.pem"))
    source_mounts = _volumes(control.get("volumes"))
    reviewer_mounts = _volumes(reviewer.get("volumes"))

    def translate(path: str) -> str:
        # Match source volume and longest containing target; no implicit default
        # and no touching policy/release mounts.
        choices = []
        for source in source_mounts:
            suffix = _relative(path, source["target"])
            if suffix is None:
                continue
            for dest in reviewer_mounts:
                if dest["source"] == source["source"]:
                    choices.append(
                        (len(source["target"]), str(PurePosixPath(dest["target"]) / suffix))
                    )
        if not choices:
            raise ValueError(
                f"Audit artifact at {path} is not on a volume shared with audit-reviewer. "
                "Check AUDIT_DATA_DIR and the reviewer volume mapping."
            )
        return max(choices)[1]

    return AuditPaths(translate(db), translate(public))


def resolve_control_audit_paths(compose: dict[str, Any]) -> AuditPaths:
    """Find live container paths from effective Compose environment.

    Never dump Compose configuration; it can contain secret API keys.
    """
    services = compose.get("services")
    if not isinstance(services, dict) or not isinstance(services.get("control-plane"), dict):
        raise ValueError("Compose control-plane service missing")
    env = _environ(services["control-plane"].get("environment"))
    db = env.get("AUDIT_DB_PATH", "/var/lib/sovereign/audit.sqlite")
    signing_key = env.get("AUDIT_SIGNING_KEY_PATH", "/var/lib/sovereign/audit-key.pem")
    return AuditPaths(db, str(PurePosixPath(signing_key).with_suffix(".pub.pem")))
