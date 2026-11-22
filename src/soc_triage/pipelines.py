"""Select a triage pipeline by name.

  baseline                      - undefended control (prompt.py)
  hardened                      - all defense layers
  hardened:isolation+floor      - any '+'-joined subset of hardened.pipeline.LAYER_NAMES
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .hardened.pipeline import Layers, system_prompt_for, triage_hardened
from .prompt import build_system_prompt
from .schema import Alert, TriageResult
from .triage import ChatClient, triage_alert


@dataclass(frozen=True)
class Pipeline:
    name: str
    system_prompt: str   # static system prompt (for provenance hashing)
    run: Callable[[Alert, ChatClient], TriageResult]

    def __call__(self, alert: Alert, client: ChatClient) -> TriageResult:
        return self.run(alert, client)


def make_pipeline(spec: str = "baseline", canary: str | None = None) -> Pipeline:
    if spec == "baseline":
        system = build_system_prompt(canary)
        return Pipeline("baseline", system, lambda a, c: triage_alert(a, c, system))
    if spec == "hardened" or spec.startswith("hardened:"):
        layers = Layers.parse(spec.partition(":")[2])
        return Pipeline(layers.name, system_prompt_for(layers, canary),
                        lambda a, c: triage_hardened(a, c, layers, canary))
    raise ValueError(f"unknown pipeline {spec!r}: use 'baseline', 'hardened' or 'hardened:<layer>+<layer>'")
