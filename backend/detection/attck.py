"""The MITRE ATT&CK half of the detection-footprint knowledge: technique -> tactic + telemetry.

SOURCE. Every row here is transcribed from the **MITRE ATT&CK Enterprise** knowledge base
(``mitre-attack/attack-stix-data``, Enterprise ATT&CK **v19.1**), which is public and free to
use with attribution:

    © 2015–2026 The MITRE Corporation. This work is reproduced and distributed with the
    permission of The MITRE Corporation. https://attack.mitre.org/

WHAT EACH ROW HOLDS, and where ATT&CK puts it:

* ``name`` / ``tactics`` — the technique's name and its ``kill_chain_phases``.
* ``data_components`` — ATT&CK's own data-source taxonomy: the ``x-mitre-data-component``
  objects its detection strategy references (e.g. "Process Creation", "Active Directory Object
  Access", "Network Traffic Flow"). This is the DEFENDER's answer to "what kind of telemetry
  would show this?".
* ``log_sources`` — the concrete channels named by ATT&CK's detection analytics
  (``x-mitre-analytic.x_mitre_log_source_references``), e.g. ``WinEventLog:Security
  EventCode=4662``. This is the answer to "which log, which event id?".
* ``detection_strategy`` — the ``DET…`` id of the ATT&CK detection strategy the rows came from,
  so a reader can go read ATT&CK's own detection guidance.

TRIMMING. ``log_sources`` keeps the Windows / Linux / network entries — the platforms HackPit
actually touches — and drops the macOS / ESXi / cloud / container ones. It is therefore a SUBSET
of what ATT&CK lists, never a superset; ``pipeline/detection_sources.py --verify`` enforces
exactly that (every row here must exist upstream) so this table cannot silently drift or invent.

A NOTE ON TA0005. In ATT&CK v19 the tactic historically called **Defense Evasion** is named
**Stealth** (TA0005), and a new **Defense Impairment** (TA0112) tactic carries the "turn the
defenses off" techniques. Both are surfaced by the panel; :data:`TACTIC_ALIASES` keeps the old
name visible so the mapping is obvious to anyone who learned the old matrix.

This module is DATA ONLY. It executes nothing.
"""

from __future__ import annotations

from dataclasses import dataclass

ATTACK_VERSION = "19.1"
ATTACK_SOURCE = "MITRE ATT&CK Enterprise (mitre-attack/attack-stix-data)"
ATTACK_ATTRIBUTION = (
    "© 2015–2026 The MITRE Corporation. Reproduced with permission. https://attack.mitre.org/"
)

# ATT&CK tactic id -> display name (v19.1 names).
TACTICS: dict[str, str] = {
    "TA0043": "Reconnaissance",
    "TA0042": "Resource Development",
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Stealth",
    "TA0112": "Defense Impairment",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0011": "Command and Control",
    "TA0010": "Exfiltration",
    "TA0040": "Impact",
}

# Names the same tactic used to carry, kept so an operator who learned the old matrix still
# recognises it. Purely a display aid.
TACTIC_ALIASES: dict[str, str] = {
    "TA0005": "Defense Evasion",       # renamed to "Stealth" in ATT&CK v19
    "TA0112": "Defense Evasion",       # the "impair the defenses" half, split out in v19
}


@dataclass(frozen=True)
class Technique:
    """One ATT&CK technique, as the footprint panel needs it."""

    id: str
    name: str
    tactics: tuple[str, ...]
    data_components: tuple[str, ...] = ()
    log_sources: tuple[str, ...] = ()
    detection_strategy: str = ""

    @property
    def url(self) -> str:
        return "https://attack.mitre.org/techniques/" + self.id.replace(".", "/")

    def tactic_names(self) -> list[str]:
        return [TACTICS.get(t, t) for t in self.tactics]

    def is_stealth(self) -> bool:
        """True when this technique sits under Stealth (TA0005) or Defense Impairment (TA0112)
        — i.e. what the old matrix called Defense Evasion. The panel SURFACES this; it never
        advises using it."""
        return any(t in ("TA0005", "TA0112") for t in self.tactics)


def _t(id_: str, name: str, tactics: str, components: str, logs: str, det: str = "") -> Technique:
    return Technique(
        id=id_,
        name=name,
        tactics=tuple(tactics.split()),
        data_components=tuple(x.strip() for x in components.split(";") if x.strip()),
        log_sources=tuple(x.strip() for x in logs.split(";") if x.strip()),
        detection_strategy=det,
    )


TECHNIQUES: dict[str, Technique] = {t.id: t for t in [
    # --- reconnaissance / discovery -------------------------------------------------------- #
    _t("T1595.002", "Vulnerability Scanning", "TA0043",
       "Network Traffic Content; Network Traffic Flow",
       "Network Traffic"),
    _t("T1595.003", "Wordlist Scanning", "TA0043",
       "Network Traffic Content",
       "Network Traffic"),
    _t("T1590.002", "DNS", "TA0043", "", ""),
    _t("T1596", "Search Open Technical Databases", "TA0043", "", ""),
    _t("T1046", "Network Service Discovery", "TA0007",
       "Network Connection Creation; Network Traffic Content; Network Traffic Flow; Process Creation",
       "WinEventLog:Sysmon EventCode=1; WinEventLog:Sysmon EventCode=3, 22; auditd:SYSCALL execve; "
       "NSM:Flow Outbound TCP SYN or UDP to multiple ports/hosts"),
    _t("T1018", "Remote System Discovery", "TA0007",
       "Command Execution; File Access; Network Connection Creation; Process Creation",
       "WinEventLog:Sysmon EventCode=1; WinEventLog:Sysmon EventCode=3, 22; auditd:EXECVE execve"),
    _t("T1087.002", "Account Discovery: Domain Account", "TA0007",
       "Command Execution; Network Traffic Content; Process Creation",
       "WinEventLog:Sysmon EventCode=1; WinEventLog:PowerShell EventCode=4103, 4104, 4105, 4106; "
       "NSM:Flow LDAP Bind/Search; NSM:Flow LDAP Query; auditd:SYSCALL execve"),
    _t("T1069.002", "Permission Groups Discovery: Domain Groups", "TA0007",
       "Command Execution; Network Traffic Content; Process Creation",
       "WinEventLog:Security EventCode=4688; WinEventLog:PowerShell EventCode=4103, 4104, 4105, 4106; "
       "NSM:Flow ldap.log; auditd:SYSCALL execve"),
    _t("T1482", "Domain Trust Discovery", "TA0007",
       "Active Directory Object Access; Command Execution; Module Load; Process Access; Process Creation",
       "WinEventLog:Security EventCode=4662; WinEventLog:Sysmon EventCode=1; "
       "WinEventLog:PowerShell Get-ADTrust|GetAllTrustRelationships"),
    _t("T1135", "Network Share Discovery", "TA0007",
       "Command Execution; Named Pipe Metadata; Network Connection Creation; Network Traffic Flow; "
       "OS API Execution; Process Creation",
       "WinEventLog:Security EventCode=4688; WinEventLog:Sysmon EventCode=3, 22; "
       "WinEventLog:Sysmon EventCode=17; "
       "etw:Microsoft-Windows-RPC rpc_call: srvsvc.NetShareEnum / NetShareEnumAll from non-admin "
       "or unusual processes; "
       "NSM:Flow connection: TCP connections to ports 139/445 to multiple hosts"),
    _t("T1201", "Password Policy Discovery", "TA0007",
       "Active Directory Object Access; Command Execution; Process Creation; User Account Metadata",
       "WinEventLog:Sysmon EventCode=1; WinEventLog:Security EventCode=4662; auditd:SYSCALL execve"),

    # --- initial access / exploitation ----------------------------------------------------- #
    _t("T1190", "Exploit Public-Facing Application", "TA0001",
       "Application Log Content; Module Load; Network Connection Creation; Network Traffic Content; "
       "Network Traffic Flow; Process Creation",
       "ApplicationLog:WebServer /var/log/httpd/access_log, /var/log/apache2/access.log, "
       "/var/log/nginx/access.log with exploit indicators and burst errors; "
       "ApplicationLog:IIS IIS W3C logs in C:\\inetpub\\logs\\LogFiles\\W3SVC* (spikes in 5xx, "
       "RCE/SQLi/path traversal/JNDI patterns); "
       "NSM:Flow HTTP payloads with SQLi/LFI/JNDI/deserialization indicators; "
       "WinEventLog:Sysmon EventCode=1; auditd:SYSCALL execve"),
    _t("T1210", "Exploitation of Remote Services", "TA0008",
       "Application Log Content; File Creation; Module Load; Network Connection Creation; "
       "Network Traffic Content; Process Access; Process Creation",
       "WinEventLog:System EventCode=1000; WinEventLog:Sysmon EventCode=1; "
       "NSM:Flow Inbound connections to 445, 3389, 5985-5986 with high error/connection-reset rate, "
       "followed by new outbound sessions from the same host to internal assets within short interval."),

    # --- credential access ----------------------------------------------------------------- #
    _t("T1110", "Brute Force", "TA0006",
       "User Account Authentication",
       "WinEventLog:Security EventCode=4776, 4625; auditd:USER_LOGIN USER_AUTH"),
    _t("T1110.003", "Brute Force: Password Spraying", "TA0006",
       "User Account Authentication",
       "WinEventLog:Security EventCode=4625, 4771, 4648; "
       "linux:syslog Failed password for invalid user"),
    _t("T1003.002", "OS Credential Dumping: Security Account Manager", "TA0006",
       "File Creation; File Modification; Process Creation; Windows Registry Key Modification",
       "WinEventLog:Security EventCode=4688; WinEventLog:Sysmon EventCode=13, 14; "
       "WinEventLog:Sysmon EventCode=11"),
    _t("T1003.003", "OS Credential Dumping: NTDS", "TA0006",
       "File Creation; File Modification; Process Creation; Volume Creation",
       "WinEventLog:Security EventCode=4688; WinEventLog:Sysmon EventCode=11; "
       "WinEventLog:Microsoft-Windows-VSS Volume Shadow Copy Creation"),
    _t("T1003.004", "OS Credential Dumping: LSA Secrets", "TA0006",
       "File Modification; Module Load; Process Access; Process Creation",
       "WinEventLog:Security EventCode=4663, 4670, 4656; WinEventLog:Sysmon EventCode=1; "
       "WinEventLog:Sysmon EventCode=10"),
    _t("T1003.006", "OS Credential Dumping: DCSync", "TA0006",
       "Active Directory Object Access; Active Directory Object Deletion; Network Traffic Content",
       "WinEventLog:Security EventCode=4662; WinEventLog:Security EventCode=4929; "
       "NSM:Content Traffic on RPC DRSUAPI"),
    _t("T1558.003", "Steal or Forge Kerberos Tickets: Kerberoasting", "TA0006",
       "Active Directory Credential Request; Logon Session Creation; Logon Session Metadata; "
       "Process Access",
       "WinEventLog:Security EventCode=4769; WinEventLog:Security EventCode=4624, 4648; "
       "WinEventLog:Security EventCode=4672; WinEventLog:Sysmon EventCode=10"),
    _t("T1558.004", "Steal or Forge Kerberos Tickets: AS-REP Roasting", "TA0006",
       "Active Directory Credential Request; Process Creation",
       "WinEventLog:Security EventCode=4768; WinEventLog:Sysmon EventCode=1"),
    _t("T1649", "Steal or Forge Authentication Certificates", "TA0006",
       "Active Directory Credential Request; Active Directory Object Modification; "
       "Application Log Content; Command Execution; File Access; Windows Registry Key Access",
       "WinEventLog:Security EventCode=4768; WinEventLog:Security EventCode=4657"),
    _t("T1552.006", "Unsecured Credentials: Group Policy Preferences", "TA0006",
       "File Creation; Network Share Access; Process Creation; Script Execution",
       "WinEventLog:Sysmon EventCode=11; WinEventLog:Sysmon EventCode=1; "
       "WinEventLog:Security EventCode=5145"),
    _t("T1557.001", "Adversary-in-the-Middle: Name Resolution Poisoning and SMB Relay",
       "TA0006 TA0009",
       "Network Traffic Content; Network Traffic Flow; Service Creation; "
       "Windows Registry Key Modification",
       "NSM:Flow Unusual responses to LLMNR (UDP 5355) or NBT-NS (UDP 137) queries from "
       "unauthorized hosts; "
       "NSM:Flow Abnormal SMB authentication attempts correlated with poisoned LLMNR/NBT-NS "
       "sessions; WinEventLog:Security EventCode=4697"),

    # --- lateral movement / execution ------------------------------------------------------ #
    _t("T1021.001", "Remote Services: Remote Desktop Protocol", "TA0008",
       "Logon Session Creation; Logon Session Metadata; Network Connection Creation; Process Creation",
       "WinEventLog:Security EventCode=4624, 4648; "
       "WinEventLog:Security EventCode=4778, EventCode=4779; WinEventLog:Sysmon EventCode=3, 22"),
    _t("T1021.002", "Remote Services: SMB/Windows Admin Shares", "TA0008",
       "Logon Session Creation; Network Connection Creation; Process Creation",
       "WinEventLog:Security EventCode=4624, 4648; WinEventLog:Sysmon EventCode=3, 22; "
       "WinEventLog:Sysmon EventCode=1"),
    _t("T1021.003", "Remote Services: Distributed Component Object Model", "TA0008",
       "Logon Session Creation; Module Load; Network Connection Creation; Process Creation",
       "WinEventLog:Security EventCode=4624, 4648; WinEventLog:Sysmon EventCode=3, 22; "
       "WinEventLog:Sysmon EventCode=1; WinEventLog:Sysmon EventCode=7"),
    _t("T1021.006", "Remote Services: Windows Remote Management", "TA0008",
       "Logon Session Creation; Network Traffic Flow; Process Creation; Service Metadata",
       "WinEventLog:Security EventCode=4624, 4648; WinEventLog:WinRM EventCode=6; "
       "NSM:Connections Inbound on ports 5985/5986; WinEventLog:Sysmon EventCode=1"),
    _t("T1550.002", "Use Alternate Authentication Material: Pass the Hash", "TA0008",
       "Active Directory Credential Request; Logon Session Creation; Network Connection Creation; "
       "Process Creation",
       "WinEventLog:Security EventCode=4624, 4648; WinEventLog:Security EventCode=4768; "
       "WinEventLog:Sysmon EventCode=3, 22"),
    _t("T1550.003", "Use Alternate Authentication Material: Pass the Ticket", "TA0008",
       "Active Directory Credential Request; Logon Session Creation; Module Load; Process Access; "
       "User Account Authentication",
       "WinEventLog:Security EventCode=4769; WinEventLog:Security EventCode=4768; "
       "WinEventLog:Security EventCode=4624, 4648; WinEventLog:Sysmon EventCode=10"),
    _t("T1569.002", "System Services: Service Execution", "TA0002",
       "Network Connection Creation; Process Creation; Service Creation; "
       "Windows Registry Key Modification",
       "WinEventLog:Security EventCode=4697; WinEventLog:Sysmon EventCode=1; "
       "WinEventLog:Sysmon EventCode=13, 14"),
    _t("T1047", "Windows Management Instrumentation", "TA0002",
       "Network Connection Creation; Process Creation; WMI Creation",
       "WinEventLog:Sysmon EventCode=1; WinEventLog:Sysmon EventCode=3, 22; "
       "WinEventLog:WMI EventCode=5857, 5858, 5860, 5861"),
    _t("T1053.005", "Scheduled Task/Job: Scheduled Task", "TA0002 TA0003 TA0004",
       "File Creation; Process Creation; Scheduled Job Creation; Scheduled Job Modification; "
       "Windows Registry Key Modification",
       "WinEventLog:Security EventCode=4698; WinEventLog:Security EventCode=4702; "
       "WinEventLog:Sysmon EventCode=1"),
    _t("T1059.001", "Command and Scripting Interpreter: PowerShell", "TA0002",
       "Command Execution; Module Load; Process Creation; Process Metadata",
       "WinEventLog:PowerShell EventCode=4103, 4104, 4105, 4106; "
       "WinEventLog:PowerShell EventCode=400, 403; WinEventLog:Sysmon EventCode=1"),
    _t("T1059.003", "Command and Scripting Interpreter: Windows Command Shell", "TA0002",
       "Module Load; Process Creation; Script Execution",
       "WinEventLog:Security EventCode=4688; WinEventLog:Sysmon EventCode=7; "
       "EDR:scriptblock Process Tree + Script Block Logging"),
    _t("T1059.004", "Command and Scripting Interpreter: Unix Shell", "TA0002",
       "Command Execution; Logon Session Creation; Network Connection Creation; "
       "Network Traffic Flow; Process Creation; Script Execution",
       "auditd:SYSCALL execve; linux:osquery socket_events; linux:syslog auth.log / secure.log; "
       "NSM:Flow remote access"),
    _t("T1059.006", "Command and Scripting Interpreter: Python", "TA0002",
       "Command Execution; Network Traffic Content; Process Creation; Script Execution",
       "WinEventLog:Sysmon EventCode=1; auditd:SYSCALL execve; linux:syslog /var/log/syslog; "
       "EDR:hunting Advanced Hunting: DeviceProcessEvents + DeviceNetworkEvents"),

    # --- persistence / privilege ----------------------------------------------------------- #
    _t("T1098", "Account Manipulation", "TA0003 TA0004",
       "Active Directory Object Modification; File Modification; Process Creation; "
       "User Account Modification",
       "WinEventLog:Security EventCode=4738, 4728, 4670; WinEventLog:Sysmon EventCode=1; "
       "auditd:SYSCALL usermod, groupmod, passwd"),
    _t("T1556", "Modify Authentication Process", "TA0112 TA0003 TA0006",
       "Cloud Service Modification; File Modification; Module Load; Process Access; "
       "Process Creation; User Account Modification; Windows Registry Key Modification",
       "WinEventLog:Security EventCode=4657; WinEventLog:Sysmon EventCode=10; "
       "WinEventLog:Sysmon EventCode=7; auditd:SYSCALL open, write"),

    # --- command and control --------------------------------------------------------------- #
    _t("T1071.001", "Application Layer Protocol: Web Protocols", "TA0011",
       "Command Execution; Network Connection Creation; Network Traffic Content; "
       "Network Traffic Flow; Process Creation",
       "NSM:Flow http.log, ssl.log; NSM:Flow http.log, conn.log; "
       "WinEventLog:Sysmon EventCode=3, 22; auditd:SYSCALL execve"),
    _t("T1105", "Ingress Tool Transfer", "TA0011",
       "Command Execution; File Creation; Network Connection Creation; Network Traffic Flow; "
       "Process Creation",
       "WinEventLog:Sysmon EventCode=3, 22; WinEventLog:Sysmon EventCode=11; "
       "auditd:SYSCALL connect, execve, write; iptables:LOG TCP connections"),

    # --- stealth / defense impairment (SURFACED, never prescribed) -------------------------- #
    _t("T1027", "Obfuscated Files or Information", "TA0005",
       "Command Execution; File Creation; File Metadata; File Modification; "
       "Network Traffic Content; OS API Execution; Process Creation",
       "WinEventLog:Security EventCode=4688; WinEventLog:Sysmon EventCode=1; "
       "auditd:SYSCALL execve; networkdevice:IDS content inspection / PCAP / HTTP body"),
    _t("T1027.010", "Obfuscated Files or Information: Command Obfuscation", "TA0005",
       "Command Execution; Process Creation",
       "WinEventLog:Security EventCode=4688; auditd:SYSCALL execve; "
       "linux:osquery process_events.command_line"),
    _t("T1036", "Masquerading", "TA0005",
       "Command Execution; File Metadata; File Modification; Image Metadata; Process Creation; "
       "Process Metadata; Service Creation; Service Metadata",
       "WinEventLog:Sysmon EventCode=1; WinEventLog:System EventCode=7045; auditd:SYSCALL execve"),
    _t("T1222", "File and Directory Permissions Modification", "TA0112",
       "Active Directory Object Modification; Command Execution; File Creation; File Metadata; "
       "Process Creation",
       "WinEventLog:Security EventCode=4688; WinEventLog:Security EventCode=4663, 4670, 4656; "
       "auditd:SYSCALL syscall in (chmod, fchmod, fchmodat, chown, fchown, fchownat, setxattr, "
       "lsetxattr, fsetxattr)"),
    _t("T1685", "Disable or Modify Tools", "TA0112",
       "Cloud Service Modification; Command Execution; Host Status; Process Creation; "
       "Process Termination; Service Creation; Service Metadata; Service Modification; "
       "Windows Registry Key Modification",
       "WinEventLog:System EventCode=7045; WinEventLog:Sysmon EventCode=5; "
       "WinEventLog:Sysmon EventCode=13, 14; "
       "auditd:SYSCALL execve: systemctl stop, service stop, or kill -9 on security daemons "
       "(e.g., falcon-sensor, auditd)"),
    _t("T1690", "Prevent Command History Logging", "TA0112",
       "Command Execution; Process Creation",
       "auditd:SYSCALL execve calls modifying HISTFILE or HISTCONTROL via unset/export; "
       "WinEventLog:PowerShell EventCode=4103, 4104, 4105, 4106; WinEventLog:Sysmon EventCode=1"),
    _t("T1112", "Modify Registry", "TA0112 TA0003",
       "Process Creation; Windows Registry Key Modification",
       "WinEventLog:Sysmon EventCode=13, 14; WinEventLog:Sysmon EventCode=1"),

    # --- resource development -------------------------------------------------------------- #
    _t("T1588.002", "Obtain Capabilities: Tool", "TA0042",
       "Malware Metadata", "Malware Repository"),
]}


def technique(tid: str) -> Technique | None:
    """The ATT&CK technique row for an id (``T1046``, ``T1003.006``), or None if unmapped."""
    return TECHNIQUES.get(tid)


def describe(tid: str) -> dict:
    """One technique as a plain dict for the API/UI, with tactics resolved to names."""
    t = TECHNIQUES.get(tid)
    if t is None:
        return {"id": tid, "name": tid, "url": "https://attack.mitre.org/techniques/"
                + tid.replace(".", "/"), "tactics": [], "known": False}
    return {
        "id": t.id,
        "name": t.name,
        "url": t.url,
        "tactics": [
            {
                "id": tac,
                "name": TACTICS.get(tac, tac),
                "also_known_as": TACTIC_ALIASES.get(tac),
                "url": f"https://attack.mitre.org/tactics/{tac}",
            }
            for tac in t.tactics
        ],
        "data_components": list(t.data_components),
        "log_sources": list(t.log_sources),
        "stealth": t.is_stealth(),
        "known": True,
    }


__all__ = [
    "ATTACK_VERSION", "ATTACK_SOURCE", "ATTACK_ATTRIBUTION",
    "TACTICS", "TACTIC_ALIASES", "TECHNIQUES", "Technique",
    "technique", "describe",
]
