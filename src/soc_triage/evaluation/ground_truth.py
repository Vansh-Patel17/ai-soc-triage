"""Hand-labeled ground truth for eval/alerts.json (stored in eval/ground_truth.json)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from ..schema import Severity

TECHNIQUE_PATTERN = r"^T\d{4}(\.\d{3})?$"


class GroundTruth(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    alert_id: str
    is_malicious: bool
    severity: Severity
    technique: str | None = Field(default=None, pattern=TECHNIQUE_PATTERN)
    related_techniques: list[str] = Field(default_factory=list)
    difficulty: Literal["easy", "medium", "hard"]
    ambiguous: bool = False
    source_file: str
    source_record_id: int
    note: str
