"""Triage one alert: build prompt -> call model -> validate -> fail closed."""

from __future__ import annotations

from typing import Protocol

from pydantic import ValidationError

from .ollama_client import OllamaError
from .prompt import SYSTEM_PROMPT, build_user_prompt
from .schema import Alert, TriageResult, TriageVerdict

ESCALATION_VERDICT = TriageVerdict(
    summary="Automated triage failed; the model output could not be validated. Escalated for analyst review.",
    severity="high",
    attack_technique=None,
    recommended_action="Manual triage required: review the raw alert.",
)


class ChatClient(Protocol):
    model: str

    def chat(self, system: str, user: str, json_mode: bool = True) -> str: ...


def call_and_validate(client: ChatClient, system: str, user: str
                      ) -> tuple[str | None, TriageVerdict | None, str | None]:
    """Return (raw_output, verdict, error). Exactly one of verdict/error is set."""
    try:
        raw = client.chat(system, user)
    except OllamaError as ex:
        return None, None, str(ex)
    verdict, error = validate_output(raw)
    return raw, verdict, error


def validate_output(raw: str) -> tuple[TriageVerdict | None, str | None]:
    """Strictly validate raw model text. Returns (verdict, None) or (None, error)."""
    try:
        return TriageVerdict.model_validate_json(raw), None
    except ValidationError as ex:
        errors = "; ".join(f"{'.'.join(map(str, e['loc'])) or '<root>'}: {e['msg']}" for e in ex.errors())
        return None, f"invalid model output: {errors}"


def triage_alert(alert: Alert, client: ChatClient, system_prompt: str = SYSTEM_PROMPT) -> TriageResult:
    """BASELINE pipeline (no injection defense). See prompt.py."""
    raw, verdict, error = call_and_validate(client, system_prompt, build_user_prompt(alert))
    if verdict is None:
        return TriageResult(alert_id=alert.alert_id, status="failed", verdict=ESCALATION_VERDICT,
                            needs_human_review=True, error=error, raw_output=raw, model=client.model)
    return TriageResult(alert_id=alert.alert_id, status="ok", verdict=verdict,
                        needs_human_review=False, raw_output=raw, model=client.model)
