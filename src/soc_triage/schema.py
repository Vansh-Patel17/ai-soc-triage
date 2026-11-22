"""Data models shared by the pipeline.

Every string field on an Alert comes from a log source and is UNTRUSTED,
attacker-controllable input (docs/threat-model.md). Never interpolate these
values into instructions.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["informational", "low", "medium", "high", "critical"]
SEVERITY_ORDER: tuple[str, ...] = ("informational", "low", "medium", "high", "critical")


def severity_index(sev: str) -> int:
    return SEVERITY_ORDER.index(sev)


def max_severity(*sevs: str) -> str:
    return max(sevs, key=severity_index)

# ATT&CK technique or sub-technique ID, e.g. T1003 or T1003.006.
TECHNIQUE_PATTERN = r"^T\d{4}(\.\d{3})?$"


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


class TriageVerdict(BaseModel):
    """The model's verdict. Model output is untrusted: anything that doesn't
    validate exactly is rejected (no coercion, no extra keys)."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    summary: str = Field(min_length=1, max_length=2000)
    severity: Severity
    # null only makes sense for benign alerts (no technique applies)
    attack_technique: str | None = Field(pattern=TECHNIQUE_PATTERN)
    recommended_action: str = Field(min_length=1, max_length=2000)


class TriageResult(BaseModel):
    """Outcome of triaging one alert. On any failure the result fails CLOSED:
    status="failed" with an escalation verdict, never a silent low severity."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    alert_id: str
    status: Literal["ok", "failed"]
    verdict: TriageVerdict
    needs_human_review: bool
    error: str | None = None
    raw_output: str | None = None
    model: str
    # Hardened pipeline only: what the model said before rule adjustments, and why
    # the delivered verdict differs (floor raised, injection detected, output check).
    model_verdict: TriageVerdict | None = None
    flags: list[str] = Field(default_factory=list)
    pipeline: str = "baseline"
    nonce: str | None = None   # isolation delimiter token, kept so results can be replayed
