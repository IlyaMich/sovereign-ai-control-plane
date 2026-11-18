"""HTTP contracts only; domain types intentionally remain Pydantic-independent."""

from pydantic import BaseModel, ConfigDict, Field, field_validator


class PromptInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    prompt: str = Field(min_length=1, max_length=8192)
    destination_id: str = Field(default="sovereign-model", pattern=r"^[a-z][a-z0-9-]{0,63}$")
    purpose: str = Field(default="GENERAL", pattern=r"^[A-Z][A-Z0-9_]{0,39}$")

    @field_validator("prompt")
    @classmethod
    def check_prompt_bytes(cls, value: str) -> str:
        if len(value.encode("utf-8")) > 8192 or not value.strip():
            raise ValueError("Invalid prompt size")
        return value
