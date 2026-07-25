"""Public AI Pass account DTOs; no OAuth secret or client identifier fields."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class AIPassStatusOut(BaseModel):
    available: bool
    connected: bool
    active: bool
    model: str | None
    status: str


class AIPassModelOut(BaseModel):
    id: str
    name: str


class AIPassModelsOut(BaseModel):
    models: list[AIPassModelOut]


class AIPassModelSelect(BaseModel):
    model_config = ConfigDict(extra="forbid")
    model: str = Field(min_length=1, max_length=128)


class AIPassActivePatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    is_active: bool


__all__ = [
    "AIPassActivePatch",
    "AIPassModelOut",
    "AIPassModelSelect",
    "AIPassModelsOut",
    "AIPassStatusOut",
]
