"""Map raw Windows events onto the Alert schema.

Values are copied verbatim (no stripping of suspicious strings); only empty
and "-" placeholders are dropped, and pure bookkeeping fields are omitted.
"""

from __future__ import annotations

from .evtx_parser import RawEvent
from .schema import Alert

# Bookkeeping fields with no triage value.
_DROP = {"RuleName", "UtcTime", "ProcessGuid", "ParentProcessGuid", "SourceProcessGUID",
         "TargetProcessGUID", "LogonGuid"}

# TerminalServices 1149 uses positional Param1..3.
_RENAME = {("Microsoft-Windows-TerminalServices-RemoteConnectionManager", 1149):
           {"Param1": "User", "Param2": "Domain", "Param3": "SourceAddress"}}


def _present(v: str | None) -> bool:
    return v is not None and v.strip() not in ("", "-")


def _join_user(domain: str | None, name: str | None) -> str | None:
    if not _present(name):
        return None
    return f"{domain}\\{name}" if _present(domain) else name


def to_alert(event: RawEvent, alert_id: str) -> Alert:
    data = dict(event.data)
    for old, new in _RENAME.get((event.provider, event.event_id), {}).items():
        if old in data:
            data[new] = data.pop(old)

    used: set[str] = set()

    def take(*keys: str) -> str | None:
        for k in keys:
            if _present(data.get(k)):
                used.add(k)
                return data[k]
        return None

    # The "user" is the account the activity ran as / logged on as.
    if event.event_id == 4624 and "Security" in event.provider:
        user = _join_user(data.get("TargetDomainName"), data.get("TargetUserName"))
        used |= {"TargetDomainName", "TargetUserName"}
    elif _present(data.get("User")):
        user = take("User")
        if _present(data.get("Domain")):
            user = _join_user(data["Domain"], user)
            used.add("Domain")
    else:
        user = _join_user(data.get("SubjectDomainName"), data.get("SubjectUserName"))
        if user:
            used |= {"SubjectDomainName", "SubjectUserName"}

    process_name = take("Image", "NewProcessName", "ProcessName", "SourceImage")
    command_line = take("CommandLine")
    parent_process = take("ParentImage")
    parent_command_line = take("ParentCommandLine")

    extra = {k: v for k, v in data.items()
             if k not in used and k not in _DROP and _present(v)}

    return Alert(
        alert_id=alert_id,
        timestamp=event.timestamp,
        provider=event.provider,
        channel=event.channel,
        event_id=event.event_id,
        hostname=event.computer,
        user=user,
        process_name=process_name,
        command_line=command_line,
        parent_process=parent_process,
        parent_command_line=parent_command_line,
        extra=extra,
    )
