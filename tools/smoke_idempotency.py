"""Synthetic local M7.4 smoke check. Run inside the approved control-plane container."""

import asyncio
import os
import uuid

import httpx


async def main() -> None:
    key = os.environ["CONTROL_PLANE_API_KEY"]
    headers = {"X-API-Key": key, "Idempotency-Key": "m7-smoke-" + uuid.uuid4().hex}
    body = {
        "prompt": "Explain local policy evaluation",
        "destination_id": "sovereign-model",
        "purpose": "GENERAL",
    }
    async with httpx.AsyncClient(
        base_url="http://127.0.0.1:8000", timeout=30.0, trust_env=False
    ) as client:
        first = await client.post("/v1/prompts", json=body, headers=headers)
        if first.status_code != 200:
            raise RuntimeError(f"First request unexpected HTTP {first.status_code}")
        request_id = first.json()["request_id"]
        second = await client.post("/v1/prompts", json=body, headers=headers)
        if second.status_code != 409 or second.json().get("request_id") != request_id:
            raise RuntimeError("Idempotency claim did not prevent replay")
        status = await client.get("/v1/idempotency/status", headers=headers)
        if status.status_code != 200 or status.json().get("audit_state") != "OUTCOME_RECORDED":
            raise RuntimeError("Outcome not visible through idempotency status")
        evidence = await client.get(f"/v1/requests/{request_id}", headers=headers)
        if evidence.status_code != 200 or len(evidence.json().get("events", [])) != 2:
            raise RuntimeError("Expected signed DECISION and OUTCOME evidence")
    print("M7_4_IDEMPOTENCY_SMOKE_PASSED")


if __name__ == "__main__":
    asyncio.run(main())
