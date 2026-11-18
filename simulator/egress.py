"""Test-only boundary gateway: fixed destination; no arbitrary URLs or DNS from caller."""

import httpx
from fastapi import FastAPI, HTTPException

from app.infrastructure.config import HTTPTimeouts, simulator_upstream_url
from simulator.main import GenerateRequest

upstream_url = simulator_upstream_url()
timeouts = HTTPTimeouts.from_env()

app = FastAPI(title="Simulated Egress Gateway")


@app.post("/generate")
async def generate(request: GenerateRequest):
    async with httpx.AsyncClient(trust_env=False, timeout=timeouts.simulator_egress) as client:
        try:
            response = await client.post(upstream_url + "/generate", json=request.model_dump())
            response.raise_for_status()
            data = response.json()
            if data.get("model_id") != "external-simulator" or not isinstance(
                data.get("output"), str
            ):
                raise ValueError("Malformed simulator response")
            return data
        except (httpx.HTTPError, ValueError):
            raise HTTPException(502, "Simulated external destination unavailable")
