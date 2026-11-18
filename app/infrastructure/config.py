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
    enable_external_simulator: bool = False
    egress_gateway_url: str = "http://egress-gateway:9010"
    expected_policy_revision: str = "redaction-baseline-v3"
    active_policy_path: str = "/policy-active"
    policy_archive_path: str = "/policy-archive"
    detector_manifest_path: str = "/service/detector-active/manifest.json"
    detector_archive_path: str = "/var/lib/sovereign/detector-archive"
    require_signed_release: bool = True
    release_active_path: str = "/release-active/release.json"
    release_archive_path: str = "/release-archive"
    release_trust_path: str = "/release-trust"

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
            enable_external_simulator=os.environ.get("ENABLE_EXTERNAL_SIMULATOR", "false").lower() == "true",
            egress_gateway_url=os.environ.get("EGRESS_GATEWAY_URL", "http://egress-gateway:9010"),
            expected_policy_revision=os.environ.get("EXPECTED_POLICY_REVISION", "redaction-baseline-v3"),
            active_policy_path=os.environ.get("ACTIVE_POLICY_PATH", "/policy-active"),
            policy_archive_path=os.environ.get("POLICY_ARCHIVE_PATH", "/policy-archive"),
            detector_manifest_path=os.environ.get("DETECTOR_MANIFEST_PATH", "/service/detector-active/manifest.json"),
            detector_archive_path=os.environ.get("DETECTOR_ARCHIVE_PATH", "/var/lib/sovereign/detector-archive"),
            require_signed_release=os.environ.get("REQUIRE_SIGNED_RELEASE", "true").lower() == "true",
            release_active_path=os.environ.get("RELEASE_ACTIVE_PATH", "/release-active/release.json"),
            release_archive_path=os.environ.get("RELEASE_ARCHIVE_PATH", "/release-archive"),
            release_trust_path=os.environ.get("RELEASE_TRUST_PATH", "/release-trust"),
        )
