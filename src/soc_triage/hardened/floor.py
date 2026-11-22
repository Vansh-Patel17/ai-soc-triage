"""Layer: deterministic severity floor.

Small, generic detection rules for activity that is high-signal regardless of
what any log text claims. The model may rate higher, never lower: a lower model
verdict is raised to the floor and flagged for human review. Rules look only at
event semantics (event IDs, target objects, process relationships), so appended
attacker prose cannot remove the evidence they key on.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

from ..schema import Alert, Severity, max_severity

# DS-Replication-Get-Changes, -Get-Changes-All, -Get-Changes-In-Filtered-Set
_REPLICATION_GUIDS = ("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
                      "89e95b76-444d-4c62-991a-0facbeda640c")
_PRIVILEGED_GROUPS = {"administrators", "domain admins", "enterprise admins", "schema admins",
                      "account operators", "backup operators", "server operators", "dnsadmins"}
_USER_WRITABLE = re.compile(r"\\(users\\public|temp|windows\\tasks|programdata|perflogs)\\", re.I)


@dataclass(frozen=True)
class FloorHit:
    rule: str
    severity: Severity
    reason: str


def _x(alert: Alert, key: str) -> str:
    return (alert.extra.get(key) or "").lower()


def _base(path: str | None) -> str:
    return (path or "").replace("/", "\\").rsplit("\\", 1)[-1].lower()


def _security(alert: Alert) -> bool:
    return "security-auditing" in alert.provider.lower() or "eventlog" in alert.provider.lower()


def _sysmon(alert: Alert, eid: int) -> bool:
    return "sysmon" in alert.provider.lower() and alert.event_id == eid


def _rule_replication(a: Alert):
    if a.event_id == 4662 and _security(a):
        props = _x(a, "Properties") + _x(a, "AccessList")
        if any(g in props for g in _REPLICATION_GUIDS) and not (a.user or "").endswith("$"):
            return "critical", "directory replication rights used by a non-machine account (DCSync)"


def _rule_lsass_access(a: Alert):
    if a.event_id in (4656, 4663) and _security(a) and _x(a, "ObjectName").endswith("\\lsass.exe"):
        return "high", "handle to lsass.exe requested"
    if _sysmon(a, 10) and _x(a, "TargetImage").endswith("\\lsass.exe"):
        return "high", "process access to lsass.exe"


def _rule_lsass_file_write(a: Alert):
    if _sysmon(a, 11) and _base(a.process_name) == "lsass.exe":
        return "high", "lsass.exe created a file"


def _rule_log_cleared(a: Alert):
    if (a.event_id == 1102 and _security(a)) or (a.event_id == 104 and "eventlog" in a.provider.lower()):
        return "high", "event log cleared"


def _rule_privileged_group_add(a: Alert):
    if a.event_id in (4728, 4732, 4756) and _security(a) and _x(a, "TargetUserName") in _PRIVILEGED_GROUPS:
        return "high", f"member added to privileged group {a.extra.get('TargetUserName')}"


def _rule_account_created(a: Alert):
    if a.event_id == 4720 and _security(a):
        return "medium", "user account created"


def _rule_run_key(a: Alert):
    if _sysmon(a, 13) and "\\currentversion\\run" in _x(a, "TargetObject"):
        return "medium", "autorun registry key modified"


def _rule_rdp_enabled(a: Alert):
    if _sysmon(a, 13) and _x(a, "TargetObject").endswith("\\fdenytsconnections") and "0x00000000" in _x(a, "Details"):
        return "medium", "RDP enabled via registry"


def _rule_lolbin_proxy(a: Alert):
    exe, cmd = _base(a.process_name), (a.command_line or "").lower()
    if exe == "mshta.exe" and (".hta" in cmd or "http" in cmd or "javascript:" in cmd or "vbscript:" in cmd):
        return "medium", "mshta executing script content"
    if exe == "rundll32.exe":
        m = re.search(r"rundll32(\.exe)?\"?\s+\"?([^,\"]+)", cmd)
        if m and not m.group(2).strip().endswith(".dll"):
            return "medium", "rundll32 loading a non-DLL file"


def _rule_system_child_of_user_path(a: Alert):
    if (a.user or "").upper().endswith("\\SYSTEM") and _USER_WRITABLE.search(a.parent_process or ""):
        return "high", "SYSTEM process spawned from a user-writable path (privilege escalation)"


def _rule_exec_user_writable(a: Alert):
    if _sysmon(a, 1) and _USER_WRITABLE.search(a.process_name or ""):
        return "medium", "process executed from a user-writable path"


def _rule_firewall_open(a: Alert):
    cmd = (a.command_line or "").lower()
    if _base(a.process_name) == "netsh.exe" and "firewall" in cmd and "add" in cmd and "allow" in cmd:
        return "medium", "inbound firewall allow rule added"


def _rule_system_file_acl(a: Alert):
    cmd = (a.command_line or "").lower()
    if _base(a.process_name) in ("icacls.exe", "takeown.exe") and "\\windows\\system32\\" in cmd:
        return "medium", "ownership/ACL change on a system file"


RULES: list[Callable[[Alert], tuple[str, str] | None]] = [
    _rule_replication, _rule_lsass_access, _rule_lsass_file_write, _rule_log_cleared,
    _rule_privileged_group_add, _rule_account_created, _rule_run_key, _rule_rdp_enabled,
    _rule_lolbin_proxy, _rule_system_child_of_user_path, _rule_exec_user_writable,
    _rule_firewall_open, _rule_system_file_acl,
]


def floor_hits(alert: Alert) -> list[FloorHit]:
    hits = []
    for rule in RULES:
        res = rule(alert)
        if res:
            hits.append(FloorHit(rule.__name__.removeprefix("_rule_"), res[0], res[1]))
    return hits


def severity_floor(hits: list[FloorHit]) -> Severity | None:
    return max_severity(*(h.severity for h in hits)) if hits else None
