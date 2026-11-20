"""Build eval/alerts.json (model-visible) and eval/ground_truth.json (labels) from data/*.evtx.

Source: EVTX-ATTACK-SAMPLES. Each SPEC selects exactly one event by file, event ID
and field substrings, and carries its hand label. Labels and the source filename
go ONLY into ground truth; alert field values are copied verbatim.

Usage:  python scripts/build_dataset.py [--data data] [--out eval]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

from soc_triage.evaluation.ground_truth import GroundTruth
from soc_triage.evtx_parser import RawEvent, iter_events
from soc_triage.normalize import to_alert


@dataclass(frozen=True)
class Spec:
    file: str
    event_id: int
    match: dict[str, str]          # field -> case-insensitive substring (all must match)
    severity: str
    technique: str | None
    difficulty: str
    note: str
    malicious: bool = True
    ambiguous: bool = False
    related: tuple[str, ...] = field(default=())


BENIGN = dict(severity="informational", technique=None, malicious=False)

SPECS: list[Spec] = [
    # ---------------- Credential access ----------------
    Spec("CA_DCSync_4662.evtx", 4662, {"Properties": "1131f6ad"}, "critical", "T1003.006", "hard",
         "DS-Replication-Get-Changes-All (1131f6ad) exercised by a user account, not a DC machine "
         "account. Only GUIDs visible."),
    Spec("CA_hashdump_4663_4656_lsass_access.evtx", 4656, {"ProcessName": "cscript.exe"}, "critical",
         "T1003.001", "medium", "cscript.exe requests PROCESS_ALL_ACCESS (0x1f3fff) handle to lsass."),
    Spec("CA_Mimikatz_Memssp_Default_Logs_Sysmon_11.evtx", 11, {"TargetFilename": "mimilsa.log"},
         "critical", "T1547.005", "easy",
         "lsass writes mimilsa.log: Mimikatz misc::memssp injected SSP logging cleartext creds.",
         related=("T1003.001",)),
    # ---------------- Privilege escalation ----------------
    Spec("EfsPotato_sysmon_17_18_privesc_seimpersonate_to_system.evtx", 1, {"Image": "EfsPotato.exe"},
         "critical", "T1068", "easy", "EfsPotato run from c:\\temp as NETWORK SERVICE (SeImpersonate abuse).",
         related=("T1134.001",)),
    Spec("EfsPotato_sysmon_17_18_privesc_seimpersonate_to_system.evtx", 1,
         {"Image": "whoami.exe", "ParentImage": "EfsPotato.exe"}, "high", "T1134.001", "easy",
         "whoami running as SYSTEM, spawned by EfsPotato: successful escalation."),
    Spec("Sysmon_UACME_34.evtx", 1, {"Image": "schtasks.exe", "CommandLine": "SilentCleanup"}, "high",
         "T1548.002", "medium", "UACME method 34: SilentCleanup task run after windir env hijack."),
    Spec("Sysmon_UACME_34.evtx", 13, {"TargetObject": "Environment\\windir"}, "high", "T1548.002",
         "medium", "HKCU Environment\\windir set to cmd.exe: UAC bypass setup (DiskCleanup)."),
    Spec("eop_appcontainer_il_broker_filewrite.evtx", 1, {"CommandLine": "POC.exe"}, "medium", "T1068",
         "medium", "Unsigned POC.exe from C:\\Users\\Public\\POC\\bin\\Debug: AppContainer broker EoP PoC."),
    Spec("privesc_spoolsv_spl_file_write_sysmon11.evtx", 1,
         {"ParentImage": "WerTrigger.exe", "CommandLine": "QueueReporting"}, "high", "T1068", "easy",
         "WerTrigger (CVE-2020-1337 PoC) triggers WER QueueReporting task."),
    Spec("privesc_spoolsv_spl_file_write_sysmon11.evtx", 13, {"TargetObject": "phoneinfo.dll"}, "high",
         "T1068", "hard", "spoolsv registers a printer port pointing at phoneinfo.dll (PrintDemon-style "
         "arbitrary write)."),
    # ---------------- Defense evasion / persistence ----------------
    Spec("DE_1102_security_log_cleared.evtx", 1102, {}, "high", "T1070.001", "easy",
         "Security log cleared by a regular domain user."),
    Spec("DE_Fake_ComputerAccount_4720.evtx", 4720, {"SamAccountName": "$"}, "high", "T1136.002",
         "medium", "Account named '$' created: fake computer-style account to blend in."),
    Spec("evasion_persis_hidden_run_keyvalue_sysmon_13.evtx", 13, {"TargetObject": "CurrentVersion\\Run"},
         "high", "T1547.001", "medium", "Run key with empty/hidden value name pointing at "
         "c:\\windows\\tasks\\taskhost.exe, written by a.exe from Public\\tools.", related=("T1112",)),
    Spec("maldoc_mshta_via_shellbrowserwind_rundll32.evtx", 1, {"Image": "mshta.exe"}, "high",
         "T1218.005", "medium", "mshta running an .hta from C:\\Users\\Public right after WINWORD opened "
         "stats.doc (via ShellBrowserWindow COM, so parent is explorer).", related=("T1566.001",)),
    Spec("maldoc_mshta_via_shellbrowserwind_rundll32.evtx", 1, {"CommandLine": "memViewData.jpg"},
         "high", "T1218.011", "medium", "rundll32 loading a .jpg as a DLL (PluginInit), parent mshta."),
    Spec("maldoc_mshta_via_shellbrowserwind_rundll32.evtx", 1, {"CommandLine": "KDECO.bat"}, "high",
         "T1548.002", "medium", "Batch cleans up HKCU Environment\\windir: UAC bypass trailing the maldoc."),
    Spec("sysmon_13_rdp_settings_tampering.evtx", 13, {"TargetObject": "fDenyTSConnections"}, "high",
         "T1112", "medium", "RDPWrap installer enables RDP (fDenyTSConnections=0).",
         related=("T1021.001",)),
    Spec("sysmon_13_rdp_settings_tampering.evtx", 1, {"CommandLine": "S-1-1-0"}, "high", "T1222.001",
         "medium", "icacls grants Everyone full control of termsrv.dll ahead of patching it."),
    Spec("sysmon_13_rdp_settings_tampering.evtx", 1, {"Image": "netsh.exe"}, "medium", "T1562.004",
         "medium", "Firewall rule opening 3389 inbound, spawned by RDPWInst."),
    # ---------------- Persistence / account manipulation (SID-only) ----------------
    Spec("Network_Service_Guest_added_to_admins_4732.evtx", 4732, {"MemberSid": "-501"}, "high", "T1098",
         "hard", "Built-in Guest (RID 501) added to Administrators. Only the SID is shown."),
    Spec("Network_Service_Guest_added_to_admins_4732.evtx", 4732, {"MemberSid": "S-1-5-20"}, "high",
         "T1098", "hard", "NETWORK SERVICE (S-1-5-20) added to Administrators. Only the SID is shown."),
    # ---------------- Lateral movement ----------------
    Spec("ImpersonateUser-via local Pass The Hash Sysmon and Security.evtx", 4624,
         {"TargetUserName": "user03", "LogonType": "3"}, "high", "T1550.002", "hard",
         "NTLM network logon as user03 from 127.0.0.1: local pass-the-hash impersonation."),
    Spec("ImpersonateUser-via local Pass The Hash Sysmon and Security.evtx", 1,
         {"Image": "cmd.exe", "User": "user03"}, "high", "T1550.002", "medium",
         "cmd.exe running as user03 with IEUser's PowerShell as parent: impersonated token."),
    Spec("DE_RDP_Tunneling_TerminalServices-RemoteConnectionManagerOperational_1149.evtx", 1149,
         {"Param1": "admin01", "Param3": "127.0.0.1"}, "high", "T1572", "hard",
         "RDP auth success with loopback source: RDP tunneled through a local port forward.",
         related=("T1021.001",)),
    Spec("LM_PowershellRemoting_sysmon_1_wsmprovhost.evtx", 1, {"ParentImage": "wsmprovhost.exe"},
         "medium", "T1021.006", "medium", "Command executed via PowerShell remoting (wsmprovhost) as "
         "domain Administrator on DC1."),
    Spec("LM_sysmon_remote_task_src_powershell.evtx", 3, {"DestinationPort": "135"}, "medium",
         "T1053.005", "hard", "PowerShell opening RPC (135) to another host: remote scheduled task "
         "creation (source side)."),
    # ---------------- Discovery ----------------
    Spec("discovery_bloodhound.evtx", 5145, {"SubjectUserName": "user01", "RelativeTargetName": "samr"},
         "medium", "T1087.002", "hard", "SAMR pipe access by user01 as part of BloodHound/SharpHound "
         "collection.", related=("T1069.002",)),
    # ---------------- Ambiguous (medium, see note) ----------------
    Spec("DE_RDP_Tunneling_4624.evtx", 4624, {"LogonType": "10", "IpAddress": "127.0.0.1"}, "medium",
         "T1572", "hard", "AMBIGUOUS: RemoteInteractive logon from 127.0.0.1. Part of RDP tunneling in "
         "this capture, but loopback RDP is also seen in normal local tooling. Tests over/under-flagging; "
         "low or high are defensible, critical is over-flagging.", ambiguous=True),
    Spec("DE_WinEventLogSvc_Crash_System_7036.evtx", 7036, {"param1": "Windows Event Log"}, "medium",
         "T1562.002", "hard", "AMBIGUOUS: Event Log service entering running state. In this capture it "
         "follows a deliberate crash of the service, but alone it is an ordinary restart. Tests "
         "over-flagging.", ambiguous=True),
    # ---------------- Benign ----------------
    Spec("DE_WinEventLogSvc_Crash_System_7036.evtx", 7036, {"param1": "Time Broker"}, difficulty="easy",
         note="Routine service state change.", **BENIGN),
    Spec("DE_WinEventLogSvc_Crash_System_7036.evtx", 7036, {"param1": "NetBIOS Helper"},
         difficulty="easy", note="Routine service state change.", **BENIGN),
    Spec("DE_RDP_Tunneling_4624.evtx", 4624, {"LogonType": "5", "TargetUserName": "SYSTEM"},
         difficulty="easy", note="Service logon (type 5) by services.exe.", **BENIGN),
    Spec("privesc_spoolsv_spl_file_write_sysmon11.evtx", 1, {"CommandLine": "CheckStatus.bat"},
         difficulty="medium", note="Npcap service health-check script run by SYSTEM.", **BENIGN),
    Spec("privesc_spoolsv_spl_file_write_sysmon11.evtx", 1, {"CommandLine": "reg query"},
         difficulty="medium", note="Npcap CheckStatus.bat querying its own install key.", **BENIGN),
    Spec("ImpersonateUser-via local Pass The Hash Sysmon and Security.evtx", 1,
         {"CommandLine": "-s gpsvc"}, difficulty="easy", note="Group Policy client service host start.",
         **BENIGN),
    Spec("maldoc_mshta_via_shellbrowserwind_rundll32.evtx", 1, {"CommandLine": "-s fdPHost"},
         difficulty="easy", note="Function Discovery Provider Host service start.", **BENIGN),
    Spec("EfsPotato_sysmon_17_18_privesc_seimpersonate_to_system.evtx", 1, {"Image": "FileCoAuth.exe"},
         difficulty="easy", note="OneDrive COM helper launched by DcomLaunch.", **BENIGN),
    Spec("DE_1102_security_log_cleared.evtx", 4663, {"ObjectName": "FipsAlgorithmPolicy"},
         difficulty="medium", note="LOCAL SERVICE svchost reading LSA FIPS policy key: routine audit "
                                   "noise despite the Lsa path.", **BENIGN),
    Spec("sysmon_13_rdp_settings_tampering.evtx", 1, {"CommandLine": "SHCreateLocalServerRunDll"},
         difficulty="medium", note="Standard shell32 COM local server launch via rundll32.", **BENIGN),
    Spec("discovery_bloodhound.evtx", 5145, {"ShareName": "SYSVOL"}, difficulty="medium",
         note="Machine account reading SYSVOL (Group Policy processing).", **BENIGN),
]


def _matches(ev: RawEvent, spec: Spec) -> bool:
    if ev.event_id != spec.event_id:
        return False
    return all(sub.lower() in (ev.data.get(k) or "").lower() for k, sub in spec.match.items())


def alert_id_for(source_file: str, record_id: int) -> str:
    # Opaque but reproducible; reveals neither order nor source.
    return "ALR-" + hashlib.sha256(f"{source_file}#{record_id}".encode()).hexdigest()[:10]


def build(data_dir: Path) -> tuple[list[dict], list[dict]]:
    cache: dict[str, list[RawEvent]] = {}
    alerts, truths, seen = [], [], set()
    for spec in SPECS:
        if spec.file not in cache:
            cache[spec.file] = list(iter_events(data_dir / spec.file))
        hits = [e for e in cache[spec.file] if _matches(e, spec) and (e.source_file, e.record_id) not in seen]
        if not hits:
            raise SystemExit(f"No event matched spec: {spec.file} {spec.event_id} {spec.match}")
        ev = hits[0]
        seen.add((ev.source_file, ev.record_id))
        aid = alert_id_for(ev.source_file, ev.record_id)
        alerts.append(to_alert(ev, aid).model_dump(mode="json"))
        truths.append(GroundTruth(
            alert_id=aid, is_malicious=spec.malicious, severity=spec.severity, technique=spec.technique,
            related_techniques=list(spec.related), difficulty=spec.difficulty, ambiguous=spec.ambiguous,
            source_file=ev.source_file, source_record_id=ev.record_id, note=spec.note,
        ).model_dump(mode="json"))
    alerts.sort(key=lambda a: a["alert_id"])
    truths.sort(key=lambda t: t["alert_id"])
    return alerts, truths


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--data", type=Path, default=Path("data"))
    ap.add_argument("--out", type=Path, default=Path("eval"))
    args = ap.parse_args()

    alerts, truths = build(args.data)
    args.out.mkdir(parents=True, exist_ok=True)
    for name, obj in (("alerts.json", alerts), ("ground_truth.json", truths)):
        (args.out / name).write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    mal = sum(t["is_malicious"] for t in truths)
    print(f"Wrote {len(alerts)} alerts ({mal} malicious incl. {sum(t['ambiguous'] for t in truths)} "
          f"ambiguous, {len(alerts) - mal} benign) to {args.out}/", file=sys.stderr)


if __name__ == "__main__":
    main()
