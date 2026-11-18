"""Local environment-based configuration; never use implicit demo credentials."""
from __future__ import annotations

from dataclasses import dataclass
import os


@dataclass(frozen=True)
class Settings:
    api_key: str
    opa_url: str = "http://opa:8181"
    model_url: str = "http://sovereign-model:9000"
    db_path: str = "/var/lib/sovereign/audit.sqlite"
    signing_key_path: str = "/var/lib/sovereign/audit-key.pem"

    @classmethod
    def from_env(cls) -> Settings:
        key = os.environ.get("CONTROL_PLANE_API_KEY", "")
        if len(key) < 24 or key == "replace-with-a-random-key":
            raise RuntimeError("Set CONTROL_PLANE_API_KEY to a random secret of at least 24 characters")
        return cls(
            api_key=key,
            opa_url=os.environ.get("OPA_URL", "http://opa:8181"),
            model_url=os.environ.get("MODEL_URL", "http://sovereign-model:9000"),
            db_path=os.environ.get("AUDIT_DB_PATH", "/var/lib/sovereign/audit.sqlite"),
            signing_key_path=os.environ.get("AUDIT_SIGNING_KEY_PATH", "/var/lib/sovereign/audit-key.pem"),
        )
