# Dataset source files

`eval/alerts.json` and `eval/ground_truth.json` are generated from **20** event-log files in
[EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) by Samir Bousseaden
(GPL-3.0). The raw `.evtx` files are not redistributed in this repository; download them as below.

- **Pinned upstream commit:** `4ceed2f4706daf601c212a8f91c113dd85349a2c` (2023-01-24, `master` at the time of writing). The paths and
  hashes below refer to that commit.
- **Verification hash:** the *git blob SHA-1* of each file, i.e. what `git hash-object <file>`
  prints. It matches the blob ID in the upstream tree.
- **Selection:** `scripts/build_dataset.py` selects one or more specific events from each file (by
  event ID and field content), 40 events in total. Other files in `data/` are ignored.

## The 20 files

| # | Path in EVTX-ATTACK-SAMPLES | Git blob SHA-1 |
|---|---|---|
| 1 | `Command and Control/DE_RDP_Tunneling_4624.evtx` | `8743adbd706e4029d214cfc2c8c224dd7b401af6` |
| 2 | `Command and Control/DE_RDP_Tunneling_TerminalServices-RemoteConnectionManagerOperational_1149.evtx` | `e58abe47bd8bfb9f0c2d0af88347fdece9bde20e` |
| 3 | `Credential Access/CA_DCSync_4662.evtx` | `b1fc4b670aa2435b6ae1bea31479954bb919f4c9` |
| 4 | `Credential Access/CA_hashdump_4663_4656_lsass_access.evtx` | `5520f1bb24231a5bef583e645a790f534ba7386b` |
| 5 | `Credential Access/CA_Mimikatz_Memssp_Default_Logs_Sysmon_11.evtx` | `f327cae927dc825ff4731a20f3a6ee84efb4eda5` |
| 6 | `Defense Evasion/DE_1102_security_log_cleared.evtx` | `78a6e19222016dc56fb43a5558eea93472c95ab8` |
| 7 | `Defense Evasion/DE_Fake_ComputerAccount_4720.evtx` | `16d8131d89c8972a355f69109ca3b165c941d770` |
| 8 | `Defense Evasion/DE_WinEventLogSvc_Crash_System_7036.evtx` | `bc8714a53c5723430517af41330a1a932f300708` |
| 9 | `Defense Evasion/sysmon_13_rdp_settings_tampering.evtx` | `14f391a02047f8e9158bdbcf61061e8fef690b43` |
| 10 | `Discovery/discovery_bloodhound.evtx` | `578d89be0780c7ce45d5984c9e97bfb4feedaeaf` |
| 11 | `Lateral Movement/ImpersonateUser-via local Pass The Hash Sysmon and Security.evtx` | `def2fad1cee704b439f58d86cea7a8f6ca25ba3d` |
| 12 | `Lateral Movement/LM_PowershellRemoting_sysmon_1_wsmprovhost.evtx` | `ec9defca52aa26499e8e2fc5c0ce1668e538c30f` |
| 13 | `Lateral Movement/LM_sysmon_remote_task_src_powershell.evtx` | `3a7c4e42184082015afec0abcea490576f8a31b7` |
| 14 | `Other/maldoc_mshta_via_shellbrowserwind_rundll32.evtx` | `e4f737adf7af751eb5c70698d6dc6865a18a77c6` |
| 15 | `Persistence/evasion_persis_hidden_run_keyvalue_sysmon_13.evtx` | `936196bca9e18b00b81ca9bdb7aa5792608666a8` |
| 16 | `Persistence/Network_Service_Guest_added_to_admins_4732.evtx` | `e04868866aca1e110588479f9562ab7f84876fbf` |
| 17 | `Privilege Escalation/EfsPotato_sysmon_17_18_privesc_seimpersonate_to_system.evtx` | `9f0192d4d9c745be465ef9601dc8da289c87a231` |
| 18 | `Privilege Escalation/eop_appcontainer_il_broker_filewrite.evtx` | `01258655b67e5dd84c55dee69f9a78a1d496930a` |
| 19 | `Privilege Escalation/privesc_spoolsv_spl_file_write_sysmon11.evtx` | `6b275277af2f17469c4dd622b5b25eed165e03ce` |
| 20 | `Privilege Escalation/Sysmon_UACME_34.evtx` | `ef0306e22792c094ccce72704864850f0a7a4f0a` |

## Download

Every file goes **flat** into `data/`, with its original file name and without the upstream
folder. Run these commands from the repository root.

**PowerShell (Windows):**
```powershell
$commit = '4ceed2f4706daf601c212a8f91c113dd85349a2c'
$paths = @(
  'Command and Control/DE_RDP_Tunneling_4624.evtx',
  'Command and Control/DE_RDP_Tunneling_TerminalServices-RemoteConnectionManagerOperational_1149.evtx',
  'Credential Access/CA_DCSync_4662.evtx',
  'Credential Access/CA_hashdump_4663_4656_lsass_access.evtx',
  'Credential Access/CA_Mimikatz_Memssp_Default_Logs_Sysmon_11.evtx',
  'Defense Evasion/DE_1102_security_log_cleared.evtx',
  'Defense Evasion/DE_Fake_ComputerAccount_4720.evtx',
  'Defense Evasion/DE_WinEventLogSvc_Crash_System_7036.evtx',
  'Defense Evasion/sysmon_13_rdp_settings_tampering.evtx',
  'Discovery/discovery_bloodhound.evtx',
  'Lateral Movement/ImpersonateUser-via local Pass The Hash Sysmon and Security.evtx',
  'Lateral Movement/LM_PowershellRemoting_sysmon_1_wsmprovhost.evtx',
  'Lateral Movement/LM_sysmon_remote_task_src_powershell.evtx',
  'Other/maldoc_mshta_via_shellbrowserwind_rundll32.evtx',
  'Persistence/evasion_persis_hidden_run_keyvalue_sysmon_13.evtx',
  'Persistence/Network_Service_Guest_added_to_admins_4732.evtx',
  'Privilege Escalation/EfsPotato_sysmon_17_18_privesc_seimpersonate_to_system.evtx',
  'Privilege Escalation/eop_appcontainer_il_broker_filewrite.evtx',
  'Privilege Escalation/privesc_spoolsv_spl_file_write_sysmon11.evtx',
  'Privilege Escalation/Sysmon_UACME_34.evtx'
)
New-Item -ItemType Directory -Force data | Out-Null
foreach ($p in $paths) {
  $url = "https://raw.githubusercontent.com/sbousseaden/EVTX-ATTACK-SAMPLES/$commit/" + [uri]::EscapeUriString($p)
  Invoke-WebRequest -Uri $url -OutFile (Join-Path data (Split-Path $p -Leaf))
}
```

**bash (Linux/macOS/Git Bash):**
```bash
commit=4ceed2f4706daf601c212a8f91c113dd85349a2c
mkdir -p data
while IFS= read -r p; do
  curl -fsSL "https://raw.githubusercontent.com/sbousseaden/EVTX-ATTACK-SAMPLES/$commit/${p// /%20}" -o "data/${p##*/}"
done <<'LIST'
Command and Control/DE_RDP_Tunneling_4624.evtx
Command and Control/DE_RDP_Tunneling_TerminalServices-RemoteConnectionManagerOperational_1149.evtx
Credential Access/CA_DCSync_4662.evtx
Credential Access/CA_hashdump_4663_4656_lsass_access.evtx
Credential Access/CA_Mimikatz_Memssp_Default_Logs_Sysmon_11.evtx
Defense Evasion/DE_1102_security_log_cleared.evtx
Defense Evasion/DE_Fake_ComputerAccount_4720.evtx
Defense Evasion/DE_WinEventLogSvc_Crash_System_7036.evtx
Defense Evasion/sysmon_13_rdp_settings_tampering.evtx
Discovery/discovery_bloodhound.evtx
Lateral Movement/ImpersonateUser-via local Pass The Hash Sysmon and Security.evtx
Lateral Movement/LM_PowershellRemoting_sysmon_1_wsmprovhost.evtx
Lateral Movement/LM_sysmon_remote_task_src_powershell.evtx
Other/maldoc_mshta_via_shellbrowserwind_rundll32.evtx
Persistence/evasion_persis_hidden_run_keyvalue_sysmon_13.evtx
Persistence/Network_Service_Guest_added_to_admins_4732.evtx
Privilege Escalation/EfsPotato_sysmon_17_18_privesc_seimpersonate_to_system.evtx
Privilege Escalation/eop_appcontainer_il_broker_filewrite.evtx
Privilege Escalation/privesc_spoolsv_spl_file_write_sysmon11.evtx
Privilege Escalation/Sysmon_UACME_34.evtx
LIST
```

Alternatively, `git clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES`, run
`git checkout 4ceed2f4706daf601c212a8f91c113dd85349a2c`, and copy the 20 files above into `data/`.

**Verify the downloads** (optional): `git hash-object data/*.evtx`, then compare the output with
the table.

## Regenerate the dataset

```
.venv\Scripts\python.exe scripts/build_dataset.py        # Windows
.venv/bin/python scripts/build_dataset.py                  # Linux/macOS
```

This rewrites `eval/alerts.json` and `eval/ground_truth.json`. The build is deterministic, and
regenerating from these 20 files gives the committed content exactly, so `git status` should show
**no changes**:

```
git diff --exit-code eval/alerts.json eval/ground_truth.json && echo identical
```

The script writes files with the platform's line endings. On Windows that means CRLF, which git
normalizes, so compare through git rather than byte by byte. The committed files use LF. With LF
line endings, their SHA-256 values are:

```
1a04b105707afd30657684c2b0975dad99a3d36371222349f83ad0cfdbf47c88  eval/alerts.json
31c512a4e8d7c81e12e746fb63de3b19f1a68bd573376defb8ebeaa6cf17c5db  eval/ground_truth.json
```
