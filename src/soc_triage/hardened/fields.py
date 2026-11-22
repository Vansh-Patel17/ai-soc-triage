"""Which alert fields carry log content (attacker-influenced text)."""

from __future__ import annotations

from ..schema import Alert

_CONTENT_FIELDS = ("hostname", "user", "process_name", "command_line", "parent_process", "parent_command_line")


def content_fields(alert: Alert) -> dict[str, str]:
    """All log-derived string values, keyed 'command_line', 'extra.Details', ..."""
    out = {name: getattr(alert, name) for name in _CONTENT_FIELDS if getattr(alert, name)}
    out.update({f"extra.{k}": v for k, v in alert.extra.items() if v})
    return out
