from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class TaskDecision(BaseModel):
    decision: Literal["approved", "rejected"]
    notes: str | None = Field(default=None, max_length=2000)


class ScopeUpdate(BaseModel):
    monitoring_enabled: bool | None = None
    environment: str | None = Field(default=None, max_length=32)
