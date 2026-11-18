"""No real model inference: deterministic, in-boundary HTTP adapter fixture."""

import hashlib

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.api.schemas import validate_prompt_bytes
from app.infrastructure.config import RequestLimits

limits = RequestLimits.from_env()

app = FastAPI(title="Sovereign Model Simulator")


class GenerateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request_id: str
    prompt: str = Field(min_length=1, max_length=limits.max_forwarded_prompt_bytes)

    @field_validator("prompt")
    @classmethod
    def check_prompt_bytes(cls, value: str) -> str:
        return validate_prompt_bytes(value, limits.max_forwarded_prompt_bytes)


@app.get("/health")
def health():
    return {"status": "UP"}


@app.post("/generate")
def generate(request: GenerateRequest):
    # Simulator deliberately does not return or log the raw prompt.
    digest = hashlib.sha256(request.prompt.encode("utf-8")).hexdigest()[:16]
    return {
        "model_id": "sovereign-model",
        "output": f"[LOCAL SIMULATOR] Accepted prompt (SHA-256 prefix: {digest})",
    }
