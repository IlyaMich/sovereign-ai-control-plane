"""Explicitly separated fixture policy and locally evaluated real OPA snapshot."""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

from app.domain.contracts import DetectionStatus, Effect, Obligation, PolicyContext, PolicyDecision
from app.policy.opa import PolicyIntegrityError, parse_decision
from app.policy.snapshots import PolicySnapshotStore


class FixturePolicy:
    """Faithful baseline-policy fixture for orchestrator tests, NOT proof of OPA behavior."""

    name = "fixture-policy-not-opa"

    async def evaluate(self, context: PolicyContext) -> PolicyDecision:
        c = context.classification
        request = context.command
        categories = {f.category for f in c.findings}
        deny = PolicyDecision.deny("DEFAULT_DENY", "redaction-baseline-v3")
        if c.status == DetectionStatus.UNKNOWN:
            return deny
        if categories & {"API_CREDENTIAL", "PRIVATE_KEY"}:
            return PolicyDecision.deny("CREDENTIAL_BLOCKED", "redaction-baseline-v3")
        if request.purpose not in {"GENERAL", "SUMMARIZATION", "INTERNAL_ANALYSIS"}:
            return deny
        if request.destination_id == "sovereign-model":
            return PolicyDecision(
                Effect.PERMIT,
                (Obligation("ROUTE", "sovereign-model"),),
                ("APPROVED_INTERNAL_ROUTE",),
                "redaction-baseline-v3",
            )
        if request.destination_id == "external-simulator":
            if c.status == DetectionStatus.NO_PRIVATE_DETECTED:
                return PolicyDecision(
                    Effect.PERMIT,
                    (Obligation("ROUTE", "external-simulator"),),
                    ("APPROVED_SIMULATED_EXTERNAL_ROUTE",),
                    "redaction-baseline-v3",
                )
            if (
                c.status == DetectionStatus.PRIVATE
                and categories
                and categories <= {"EMAIL_ADDRESS", "PHONE_NUMBER", "PERSON"}
            ):
                return PolicyDecision(
                    Effect.PERMIT,
                    (
                        Obligation(
                            "REDACT", categories=("EMAIL_ADDRESS", "PHONE_NUMBER", "PERSON")
                        ),
                        Obligation("ROUTE", "external-simulator"),
                    ),
                    ("SIMULATED_EXTERNAL_REDACTION_REQUIRED",),
                    "redaction-baseline-v3",
                )
        return deny


class OPACliPolicy:
    """Runs the actual pinned local policy snapshot via an installed OPA CLI.

    This does not verify a signed release or contact the production OPA service.
    """

    name = "opa-cli-verified-snapshot"

    def __init__(self, *, opa_executable: str, active: Path, archive: Path) -> None:
        self.executable = opa_executable
        self.active = active.resolve()
        self.archive = archive.resolve()
        self.store = PolicySnapshotStore(self.active, self.archive)
        self.pinned = self.store.verify_active()
        probe = subprocess.run(
            [self.executable, "version"], capture_output=True, text=True, timeout=10, check=True
        )
        if not probe.stdout:
            raise RuntimeError("OPA executable did not return a version")

    async def evaluate(self, context: PolicyContext) -> PolicyDecision:
        # OPA requires input JSON; it contains trusted structural metadata, not prompt text.
        pinned = self.store.verify_active()
        if pinned != self.pinned:
            raise PolicyIntegrityError("Active policy changed during evaluation")
        with tempfile.TemporaryDirectory(prefix="sovereign-opa-eval-") as dirname:
            data_path = Path(dirname) / "input.json"
            data_path.write_text(json.dumps(context.to_dict()), encoding="utf-8")
            # No shell, no network calls; the local policy snapshot is evaluated directly.
            proc = subprocess.run(
                [
                    self.executable,
                    "eval",
                    "--format",
                    "json",
                    "--data",
                    str(self.active),
                    "--input",
                    str(data_path),
                    "data.sovereign.authz.decision",
                ],
                capture_output=True,
                text=True,
                timeout=15,
                check=True,
            )
        try:
            raw = json.loads(proc.stdout)["result"][0]["expressions"][0]["value"]
            decision = parse_decision(raw)
        except (ValueError, KeyError, TypeError, IndexError) as exc:
            raise PolicyIntegrityError("Invalid OPA decision output") from exc
        if (
            decision.policy_digest != self.pinned.policy_digest
            or decision.policy_revision != self.pinned.policy_revision
        ):
            raise PolicyIntegrityError("OPA decision differs from verified snapshot")
        return decision
