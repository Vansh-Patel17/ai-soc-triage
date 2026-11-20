"""Data models shared by the pipeline.

Every string field on an Alert comes from a log source and is UNTRUSTED,
attacker-controllable input (docs/threat-model.md). Never interpolate these
values into instructions.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["informational", "low", "medium", "high", "critical"]


class Alert(BaseModel):
    """A normalized alert as seen by the model. Contains no labels or provenance."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    alert_id: str
    timestamp: str
    provider: str
    channel: str
    event_id: int
    hostname: str
    user: str | None = None
    process_name: str | None = None
    command_line: str | None = None
    parent_process: str | None = None
    parent_command_line: str | None = None
    extra: dict[str, str] = Field(default_factory=dict)
