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


def _failed(alert: Alert, model: str, error: str, raw: str | None) -> TriageResult:
    return TriageResult(alert_id=alert.alert_id, status="failed", verdict=ESCALATION_VERDICT,
                        needs_human_review=True, error=error, raw_output=raw, model=model)


def triage_alert(alert: Alert, client: ChatClient) -> TriageResult:
    try:
        raw = client.chat(SYSTEM_PROMPT, build_user_prompt(alert))
    except OllamaError as ex:
        return _failed(alert, client.model, str(ex), None)

    try:
        verdict = TriageVerdict.model_validate_json(raw)
    except ValidationError as ex:
        errors = "; ".join(f"{'.'.join(map(str, e['loc'])) or '<root>'}: {e['msg']}" for e in ex.errors())
        return _failed(alert, client.model, f"invalid model output: {errors}", raw)

    return TriageResult(alert_id=alert.alert_id, status="ok", verdict=verdict,
                        needs_human_review=False, raw_output=raw, model=client.model)
