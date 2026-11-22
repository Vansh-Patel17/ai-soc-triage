"""Compose the defense layers into a triage pipeline.

Order: [isolation] build prompt -> model -> strict validation (always on; fail
closed) -> [output_checks] -> [floor] raise to rule minimum -> [detector] raise
to high if injection found. Each layer is independent so its contribution can
be measured on its own or cumulatively.

Everything after the model call is deterministic and lives in apply_layers(),
which is shared by live triage and by offline replay of stored model outputs.
"""

from __future__ import annotations

from dataclasses import dataclass, fields

from ..prompt import build_system_prompt, build_user_prompt
from ..schema import Alert, TriageResult, severity_index
from ..triage import ESCALATION_VERDICT, ChatClient, OllamaError, validate_output
from .detector import detect
from .fields import content_fields
from .floor import floor_hits, severity_floor
from .isolation import build_isolated_user_prompt, isolated_system_prompt
from .output_checks import check_output

LAYER_NAMES = ("isolation", "output_checks", "floor", "detector")
POST_MODEL_LAYERS = ("output_checks", "floor", "detector")  # replayable offline


@dataclass(frozen=True)
class Layers:
    isolation: bool = True
    output_checks: bool = True
    floor: bool = True
    detector: bool = True

    @classmethod
    def parse(cls, spec: str) -> "Layers":
        """'all' or '+'-joined layer names, e.g. 'isolation+floor'."""
        if spec in ("", "all"):
            return cls()
        if spec == "none":
            return cls(False, False, False, False)
        names = [n.strip() for n in spec.split("+") if n.strip()]
        unknown = set(names) - set(LAYER_NAMES)
        if unknown:
            raise ValueError(f"unknown layer(s) {sorted(unknown)}; choose from {LAYER_NAMES}")
        return cls(**{n: n in names for n in LAYER_NAMES})

    @property
    def name(self) -> str:
        on = [f.name for f in fields(self) if getattr(self, f.name)]
        return "hardened:" + ("+".join(on) if on else "none")


def system_prompt_for(layers: Layers, canary: str | None = None) -> str:
    return isolated_system_prompt(canary) if layers.isolation else build_system_prompt(canary)


def apply_layers(alert: Alert, raw: str | None, model_error: str | None, layers: Layers, *,
                 canary: str | None, nonce: str | None, model: str) -> TriageResult:
    """Deterministic post-model processing. raw is None iff the model call itself failed
    (then model_error carries the reason)."""
    flags: list[str] = []
    if raw is None:
        verdict, error = None, model_error
    else:
        verdict, error = validate_output(raw)
    model_verdict = verdict

    hits = detect(alert) if (layers.detector or layers.output_checks) else []
    if verdict is not None and layers.output_checks:
        fields_ = content_fields(alert)
        suspicious = {h.field: fields_[h.field] for h in hits}
        violations = check_output(raw or "", verdict, fields_, canary=canary, nonce=nonce,
                                  suspicious_fields=suspicious)
        if violations:
            flags += [f"output_check:{v}" for v in violations]
            error, verdict = "output check failed: " + ", ".join(violations), None

    status = "ok" if verdict is not None else "failed"
    delivered = verdict if verdict is not None else ESCALATION_VERDICT
    needs_review = status == "failed"

    if layers.floor:
        fh = floor_hits(alert)
        flags += [f"floor:{h.rule}={h.severity}" for h in fh]
        floor = severity_floor(fh)
        if floor and severity_index(delivered.severity) < severity_index(floor):
            flags.append(f"raised_to_floor:{delivered.severity}->{floor}")
            delivered = delivered.model_copy(update={"severity": floor})
            needs_review = True

    if layers.detector and hits:
        flags += sorted({f"injection:{h.category}@{h.field}" for h in hits})
        needs_review = True
        if severity_index(delivered.severity) < severity_index("high"):
            flags.append(f"raised_for_injection:{delivered.severity}->high")
            delivered = delivered.model_copy(update={"severity": "high"})

    return TriageResult(alert_id=alert.alert_id, status=status, verdict=delivered,
                        needs_human_review=needs_review, error=error, raw_output=raw, model=model,
                        model_verdict=model_verdict, flags=flags, pipeline=layers.name, nonce=nonce)


def triage_hardened(alert: Alert, client: ChatClient, layers: Layers = Layers(),
                    canary: str | None = None) -> TriageResult:
    system = system_prompt_for(layers, canary)
    if layers.isolation:
        user, nonce = build_isolated_user_prompt(alert)
    else:
        user, nonce = build_user_prompt(alert), None
    try:
        raw, model_error = client.chat(system, user), None
    except OllamaError as ex:
        raw, model_error = None, str(ex)
    return apply_layers(alert, raw, model_error, layers, canary=canary, nonce=nonce, model=client.model)
