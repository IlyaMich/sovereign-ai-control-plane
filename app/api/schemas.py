"""HTTP contracts with per-application UTF-8 prompt limits."""

from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.infrastructure.config import RequestLimits


def validate_prompt_bytes(value: str, maximum: int) -> str:
    if len(value.encode("utf-8")) > maximum or not value.strip():
        raise ValueError("Invalid prompt size")
    return value


class PromptInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    max_prompt_bytes: ClassVar[int] = RequestLimits.max_prompt_bytes

    prompt: str = Field(min_length=1, max_length=RequestLimits.max_prompt_bytes)
    destination_id: str = Field(default="sovereign-model", pattern=r"^[a-z][a-z0-9-]{0,63}$")
    purpose: str = Field(default="GENERAL", pattern=r"^[A-Z][A-Z0-9_]{0,39}$")

    @field_validator("prompt")
    @classmethod
    def check_prompt_bytes(cls, value: str) -> str:
        return validate_prompt_bytes(value, cls.max_prompt_bytes)


def prompt_input_model(maximum: int) -> type[PromptInput]:
    class ConfiguredPromptInput(PromptInput):
        max_prompt_bytes: ClassVar[int] = maximum
        prompt: str = Field(min_length=1, max_length=maximum)

    return ConfiguredPromptInput
