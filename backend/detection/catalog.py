"""The curated tool/command -> detection-footprint mapping (the SigmaHQ half + the loudness rating).

Together with :mod:`detection.attck` this is the knowledge the purple-team panel runs on:

    command  ->  ATT&CK technique(s)  ->  telemetry / data sources  ->  Sigma rule(s)  ->  loudness

SOURCES.

* The **ATT&CK technique ids** in every spec resolve through :mod:`detection.attck` (Enterprise
  ATT&CK v19.1) — that module carries the tactic, the data components and the concrete log
  channels, straight from ATT&CK's own detection strategies.
* The **Sigma rules** in :data:`SIGMA` are real rules from the **SigmaHQ** open ruleset
  (https://github.com/SigmaHQ/sigma, Detection Rule License) — id (the rule's UUID), title,
  repo path and severity, exactly as upstream has them. Nothing here is invented: run
  ``python pipeline/detection_sources.py --verify`` and every technique id, technique name,
  tactic, log source, Sigma UUID, Sigma title and Sigma path in this package is re-checked
  against live ATT&CK + SigmaHQ, and drift is reported.

THE LINE. Every string in this file DESCRIBES what a defender would see. None of it tells an
operator how to be seen less. ``loudness`` is an awareness rating — and, read from the blue
side, a COVERAGE rating: a "quiet" action is one whose detection depends on logging that is
frequently not turned on, which is a gap for the defender to close, not a lane for the operator
to drive through. ``why_rating`` is written that way on purpose.

This module is DATA + PURE MATCHING. It executes nothing.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

SIGMA_REPO = "https://github.com/SigmaHQ/sigma"
SIGMA_BLOB = SIGMA_REPO + "/blob/master/"
SIGMA_LICENSE = "Detection Rule License (DRL) 1.1 — SigmaHQ"

# The loud-vs-quiet scale. Higher = more likely to raise a high-confidence alert.
LOUDNESS_SCALE: dict[str, int] = {"quiet": 1, "moderate": 2, "notable": 3, "loud": 4}
LOUDNESS_MEANING: dict[str, str] = {
    "quiet": "Little or no telemetry on the target by default — a defender only sees this if "
             "the relevant logging (LDAP/NSM/auditd) is switched on and retained.",
    "moderate": "Logged, but the events look like ordinary administration until they are "
                "correlated with volume, source or timing.",
    "notable": "Throws distinctive events that mature detection stacks alert on directly.",
    "loud": "High-volume and/or high-fidelity — public detection rules match this shape, and a "
            "monitored environment should raise it.",
}


# --------------------------------------------------------------------------- #
# SigmaHQ rules cited by the specs below (verified against the live ruleset)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class SigmaRule:
    """One real SigmaHQ rule — the detection that would fire."""

    id: str        # the rule's UUID (its stable identity upstream)
    title: str
    path: str      # path inside the SigmaHQ repo
    level: str     # informational | low | medium | high | critical

    @property
    def url(self) -> str:
        return SIGMA_BLOB + self.path


def _s(id_: str, title: str, path: str, level: str) -> SigmaRule:
    return SigmaRule(id=id_, title=title, path=path, level=level)


SIGMA: dict[str, SigmaRule] = {
    # --- scanning / web ---
    "nmap_pua": _s("f6ecd1cf-19b8-4488-97f6-00f0924991a3", "PUA - Nmap/Zenmap Execution",
                   "rules/windows/process_creation/proc_creation_win_pua_nmap_zenmap.yml", "medium"),
    "netscan_auditd": _s("3761e026-f259-44e6-8826-719ed8079408",
                         "Linux Network Service Scanning - Auditd",
                         "rules/linux/auditd/syscall/lnx_auditd_network_service_scanning.yml", "low"),
    "portscan_syn": _s("974be8d2-283e-4033-ab08-7505b84204d0",
                       "OpenCanary - Host Port Scan (SYN Scan)",
                       "rules/application/opencanary/opencanary_portscan_syn_scan.yml", "high"),
    "recon_ua": _s("19aa4f58-94ca-45ff-bc34-92e533c0994a",
                   "Suspicious User-Agents Related To Recon Tools",
                   "rules/web/webserver_generic/web_susp_useragents.yml", "medium"),
    "src_enum": _s("953d460b-f810-420a-97a2-cfca4c98e602",
                   "Source Code Enumeration Detection by Keyword",
                   "rules/web/webserver_generic/web_source_code_enumeration.yml", "medium"),
    "iis_shortname": _s("7cb02516-6d95-4ffc-8eee-162075e111ac", "Successful IIS Shortname Fuzzing Scan",
                        "rules/web/webserver_generic/web_iis_tilt_shortname_scan.yml", "medium"),
    "sqli_uri": _s("5513deaf-f49a-46c2-a6c8-3f111b5cb453", "SQL Injection Strings In URI",
                   "rules/web/webserver_generic/web_sql_injection_in_access_logs.yml", "high"),
    # --- credential attack ---
    "hydra": _s("aaafa146-074c-11eb-adc1-0242ac120002",
                "HackTool - Hydra Password Bruteforce Execution",
                "rules/windows/process_creation/proc_creation_win_hktl_hydra.yml", "high"),
    "failed_logon_public": _s("f88e112a-21aa-44bd-9b01-6ee2a2bbbed1", "Failed Logon From Public IP",
                              "rules/windows/builtin/security/account_management/"
                              "win_security_susp_failed_logon_source.yml", "medium"),
    "mssql_failed_logon": _s("218d2855-2bba-4f61-9c85-81d0ea63ac71", "MSSQL Server Failed Logon",
                             "rules/windows/builtin/application/mssqlserver/"
                             "win_mssql_failed_logon.yml", "low"),
    # --- AD enumeration ---
    "ldap_recon": _s("31d68132-4038-47c7-8f8e-635a39a7c174",
                     "Potential Active Directory Reconnaissance/Enumeration Via LDAP",
                     "rules/windows/builtin/ldap/win_ldap_recon.yml", "medium"),
    "bloodhound_files": _s("02773bed-83bf-469f-b7ff-e676e7d78bab", "BloodHound Collection Files",
                           "rules/windows/file/file_event/file_event_win_bloodhound_collection.yml",
                           "high"),
    "sharphound_rpc": _s("65f77b1e-8e79-45bf-bb67-5988a8ce45a5", "SharpHound Recon Account Discovery",
                         "rules/application/rpc_firewall/rpc_firewall_sharphound_recon_account.yml",
                         "high"),
    "adws_uncommon": _s("b3ad3c0f-c949-47a1-a30e-b0491ccae876",
                        "Uncommon Connection to Active Directory Web Services",
                        "rules/windows/network_connection/net_connection_win_adws_unusual_connection.yml",
                        "medium"),
    "net_recon": _s("968eef52-9cff-4454-8992-1e74b9cbad6c", "Reconnaissance Activity",
                    "rules/windows/builtin/security/win_security_susp_net_recon_activity.yml", "high"),
    "net_exe": _s("183e7ea8-ac4b-4c23-9aec-b3dac4e401ac", "Net.EXE Execution",
                  "rules-threat-hunting/windows/process_creation/"
                  "proc_creation_win_net_execution.yml", "low"),
    # --- SMB / shares ---
    "admin_share": _s("098d7118-55bc-4912-a836-dc6483a8d150", "Access To ADMIN$ Network Share",
                      "rules/windows/builtin/security/win_security_admin_share_access.yml", "low"),
    "named_pipe_first": _s("021310d9-30a6-480a-84b7-eaa69aeb92bb",
                           "First Time Seen Remote Named Pipe - Zeek",
                           "rules/network/zeek/zeek_smb_converted_win_lm_namedpipe.yml", "high"),
    "smb_admin_write": _s("b210394c-ba12-4f89-9117-44a2464b9511", "SMB Create Remote File Admin Share",
                          "rules/windows/builtin/security/"
                          "win_security_smb_file_creation_admin_shares.yml", "high"),
    # --- credential dumping ---
    "secretsdump": _s("252902e3-5830-4cf6-bf21-c22083dfd5cf",
                      "Possible Impacket SecretDump Remote Activity",
                      "rules/windows/builtin/security/win_security_impacket_secretdump.yml", "high"),
    "secretsdump_zeek": _s("92dae1ed-1c9d-4eff-a567-33acbd95b00e",
                           "Possible Impacket SecretDump Remote Activity - Zeek",
                           "rules/network/zeek/zeek_smb_converted_win_impacket_secretdump.yml", "high"),
    "dcsync": _s("611eab06-a145-4dfa-a295-3ccc5c20f59a", "Mimikatz DC Sync",
                 "rules/windows/builtin/security/win_security_dcsync.yml", "high"),
    "dcsync_rpc": _s("56fda488-113e-4ce9-8076-afc2457922c3", "Possible DCSync Attack",
                     "rules/application/rpc_firewall/rpc_firewall_dcsync_attack.yml", "high"),
    # --- kerberos ---
    "kerberoast": _s("d04ae2b8-ad54-4de0-bd87-4bc1da66aa59", "Kerberoasting Activity - Initial Query",
                     "rules/windows/builtin/security/win_security_kerberoasting_activity.yml", "medium"),
    "kerb_rc4": _s("503fe26e-b5f2-4944-a126-eab405cc06e5",
                   "Kerberos Network Traffic RC4 Ticket Encryption",
                   "rules/network/zeek/zeek_susp_kerberos_rc4.yml", "medium"),
    "spn_enum": _s("1eeed653-dbc8-4187-ad0c-eeebb20e6599", "Potential SPN Enumeration Via Setspn.EXE",
                   "rules/windows/process_creation/proc_creation_win_setspn_spn_enumeration.yml",
                   "medium"),
    "asrep": _s("3e2f1b2c-4d5e-11ee-be56-0242ac120002",
                "Potential AS-REP Roasting via Kerberos TGT Requests",
                "rules/windows/builtin/security/win_security_kerberos_asrep_roasting.yml", "medium"),
    # --- remote execution / lateral movement ---
    "impacket_psexec": _s("32d56ea1-417f-44ff-822b-882873f5f43b", "Impacket PsExec Execution",
                          "rules/windows/builtin/security/win_security_impacket_psexec.yml", "high"),
    "psexec_pipe": _s("f3f3a972-f982-40ad-b63c-bca6afdfad7c", "PsExec Default Named Pipe",
                      "rules-threat-hunting/windows/pipe_created/"
                      "pipe_created_sysinternals_psexec_default_pipe.yml", "low"),
    "psexec_service": _s("6fb63b40-e02a-403e-9ffd-3bcc1d749442",
                         "Metasploit Or Impacket Service Installation Via SMB PsExec",
                         "rules/windows/builtin/security/"
                         "win_security_metasploit_or_impacket_smb_psexec_service_install.yml", "high"),
    "psexec_zeek": _s("f1b3a22a-45e6-4004-afb5-4291f9c21166", "Suspicious PsExec Execution - Zeek",
                      "rules/network/zeek/zeek_smb_converted_win_susp_psexec.yml", "high"),
    "dcom_wmi_rpc": _s("68050b10-e477-4377-a99b-3721b422d6ef", "Remote DCOM/WMI Lateral Movement",
                       "rules/application/rpc_firewall/rpc_firewall_remote_dcom_or_wmi.yml", "high"),
    "bzar_exec": _s("b640c0b8-87f8-4daa-aef8-95a24261dd1d", "MITRE BZAR Indicators for Execution",
                    "rules/network/zeek/zeek_dce_rpc_mitre_bzar_execution.yml", "medium"),
    "winrm_session": _s("13acf386-b8c6-4fe0-9a6e-c4756b974698",
                        "Remote PowerShell Sessions Network Connections (WinRM)",
                        "rules/windows/builtin/security/win_security_remote_powershell_session.yml",
                        "high"),
    "evil_winrm": _s("9fe55ea2-4cd6-4491-8a54-dd6871651b51",
                     "HackTool - Evil-WinRm Execution - PowerShell Module",
                     "rules/windows/powershell/powershell_module/"
                     "posh_pm_hktl_evil_winrm_execution.yml", "high"),
    "rdp_public": _s("1fc0809e-06bf-4de3-ad52-25e5263b7623", "Publicly Accessible RDP Service",
                     "rules/network/zeek/zeek_rdp_public_listener.yml", "high"),
    "rdp_denied": _s("8e5c03fa-b7f0-11ea-b242-07e0576828d9", "Denied Access To Remote Desktop",
                     "rules/windows/builtin/security/win_security_not_allowed_rdp_access.yml",
                     "medium"),
    # --- AD object abuse ---
    "shadow_creds": _s("f598ea0c-c25a-4f72-a219-50c44411c791", "Possible Shadow Credentials Added",
                       "rules/windows/builtin/security/"
                       "win_security_susp_possible_shadow_credentials_added.yml", "high"),
    "adcs_denied": _s("994bfd6d-0a2e-481e-a861-934069fcf5f5",
                      "Active Directory Certificate Services Denied Certificate Enrollment Request",
                      "rules/windows/builtin/system/microsoft_windows_certification_authority/"
                      "win_system_adcs_enrollment_request_denied.yml", "low"),
    "dcsync_rights": _s("2c99737c-585d-4431-b61a-c911d86ff32f",
                        "Powerview Add-DomainObjectAcl DCSync AD Extend Right",
                        "rules/windows/builtin/security/"
                        "win_security_account_backdoor_dcsync_rights.yml", "high"),
    "ad_user_control": _s("311b6ce2-7890-4383-a8c2-663a9f6b43cd",
                          "Enabled User Right in AD to Control User Objects",
                          "rules/windows/builtin/security/"
                          "win_security_alert_active_directory_user_control.yml", "high"),
    "priv_group_add": _s("10fb649c-3600-4d37-b1e6-56ea90bb7e09", "User Added To Highly Privileged Group",
                         "rules/windows/process_creation/"
                         "proc_creation_win_susp_add_user_privileged_group.yml", "high"),
    # --- mssql ---
    "xp_cmdshell": _s("7f103213-a04e-4d59-8261-213dddf22314", "MSSQL XPCmdshell Suspicious Execution",
                      "rules/windows/builtin/application/mssqlserver/"
                      "win_mssql_xp_cmdshell_audit_log.yml", "high"),
    "xp_cmdshell_change": _s("d08dd86f-681e-4a00-a92c-1db218754417", "MSSQL XPCmdshell Option Change",
                             "rules/windows/builtin/application/mssqlserver/"
                             "win_mssql_xp_cmdshell_change.yml", "high"),
    # --- shells ---
    "rev_shell_cmdline": _s("738d9bcf-6999-4fdb-b4ac-3033037db8ab",
                            "Suspicious Reverse Shell Command Line",
                            "rules/linux/builtin/lnx_shell_susp_rev_shells.yml", "high"),
    "rev_shell_net": _s("83dcd9f6-9ca8-4af7-a16e-a1c7a6b51871", "Linux Reverse Shell Indicator",
                        "rules/linux/network_connection/"
                        "net_connection_lnx_back_connect_shell_dev.yml", "critical"),
    "netcat_rev": _s("7f734ed0-4f47-46c0-837f-6ee62505abd9", "Potential Netcat Reverse Shell Execution",
                     "rules/linux/process_creation/proc_creation_lnx_netcat_reverse_shell.yml", "high"),
    "perl_rev": _s("259df6bc-003f-4306-9f54-4ff1a08fa38e", "Potential Perl Reverse Shell Execution",
                   "rules/linux/process_creation/proc_creation_lnx_perl_reverse_shell.yml", "high"),
    # --- obfuscation (surfaced, never prescribed) ---
    "posh_token_obf": _s("f3a98ce4-6164-4dd4-867c-4d83de7eca51", "Powershell Token Obfuscation - Powershell",
                         "rules-threat-hunting/windows/powershell/powershell_script/"
                         "posh_ps_token_obfuscation.yml", "medium"),
}


# --------------------------------------------------------------------------- #
# the specs: one per activity family
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class FootprintSpec:
    """What a defender sees when this family of command runs."""

    key: str
    label: str                       # the activity, in defender language
    techniques: tuple[str, ...]      # ATT&CK ids (resolve through detection.attck)
    sigma: tuple[str, ...]           # keys into SIGMA
    telemetry: tuple[str, ...]       # concrete observations beyond ATT&CK's generic list
    loudness: str                    # quiet | moderate | notable | loud
    blue_view: str                   # one line: what shows up on the defender's screen
    why_rating: str                  # why that rating — awareness + where the coverage gap is


def _f(key, label, techniques, sigma, telemetry, loudness, blue_view, why_rating):
    return FootprintSpec(
        key=key, label=label,
        techniques=tuple(techniques.split()),
        sigma=tuple(x for x in sigma.split() if x),
        telemetry=tuple(x.strip() for x in telemetry.split(";") if x.strip()),
        loudness=loudness, blue_view=blue_view, why_rating=why_rating,
    )


# --------------------------------------------------------------------------- #
# THE OFFENSIVE HALF (D10) — OPSEC notes, the mirror of the blue-team view above
# --------------------------------------------------------------------------- #
# The blue-team view above answers "what does the defender see?". This answers the
# authorized red-team question CRTP examines: "given that this is loud, what is the
# quieter way, and what STILL records it?" It is a SECOND, SEPARATE channel:
#
#   * The detection copy above is never touched, and still passes the never-prescribe
#     guard in resolver.py — the blue view cannot be diluted by adding this.
#   * These notes are keyed by the same spec key, so an OPSEC note only ever exists
#     alongside a grounded footprint, never on its own.
#   * `still_recorded` is load-bearing and mandatory. Every quieter approach names
#     the telemetry it does NOT escape. That is what keeps this honest rather than a
#     how-to-disappear guide: there is no "and now you're invisible" here, because
#     against logging that is actually on, there isn't one.
#
# Legitimate inside authorized testing (an engagement scoped to test detection, a
# CRTP-style assessment). HackPit only ever describes; a human still approves and
# runs every command through the four gates.
@dataclass(frozen=True)
class OpsecNote:
    """The operator-side counterpart to a FootprintSpec: quieter tradecraft + its limits."""

    key: str                          # same key as the FootprintSpec it annotates
    loud_because: str                 # the specific thing that generates the signal
    quieter: tuple[str, ...]          # concrete quieter approaches / knobs
    still_recorded: str               # what logs it anyway — mandatory, keeps it honest
    tradeoff: str                     # what the quieter path costs (time, reliability, coverage)


def _o(key, loud_because, quieter, still_recorded, tradeoff):
    return OpsecNote(
        key=key, loud_because=loud_because,
        quieter=tuple(x.strip() for x in quieter.split(";") if x.strip()),
        still_recorded=still_recorded, tradeoff=tradeoff,
    )


OPSEC: dict[str, OpsecNote] = {n.key: n for n in [
    _o("portscan",
       "The scan SHAPE — one source touching many ports/hosts fast — is what NSM and IDS are "
       "built to alert on, and it survives payload encryption.",
       "Scan far fewer ports (a top-20 / known-service list, not -p-); "
       "slow the rate hard (nmap -T2/-T1, --max-rate, --scan-delay) so it falls under burst "
       "thresholds; "
       "space work across time rather than one sweep; "
       "prefer a -sT connect scan from a host that is expected to talk to the target over a raw "
       "-sS from an unexpected source",
       "Every port that answers still logs the connection at the service, and NetFlow/Zeek still "
       "records the flows — slowing down changes WHEN it is noticed, not WHETHER the artefacts "
       "exist. A patient defender reviewing conn.log still sees it.",
       "A slow, narrow scan can take hours instead of seconds and will miss services on ports you "
       "chose not to probe."),
    _o("web_vuln_scan",
       "Default scanner user-agents (Nikto/Nuclei/WPScan announce themselves) and request VOLUME "
       "matched directly by rules like SigmaHQ's recon user-agent rule.",
       "Set a browser-realistic User-Agent instead of the tool default; "
       "throttle concurrency and add jitter (nuclei -rate-limit / -c low); "
       "scope templates to the stack you fingerprinted rather than firing everything; "
       "run authenticated so requests look like a session, not a crawl",
       "The request COUNT is the primary signal and no user-agent change removes it — a WAF and "
       "the access log still see one IP make far more requests than a human would. The 404 wall "
       "from probing paths that do not exist is still there.",
       "Rate-limiting a scan multiplies its wall-clock time; a tightly-scoped template set trades "
       "coverage for quiet and can miss a finding outside the guessed stack."),
    _o("dir_brute",
       "High request volume by construction, plus requests for paths (.git, .env, backups) no real "
       "user asks for, in a wordlist's ordered shape.",
       "Use a small, targeted wordlist over a mega-list; "
       "rate-limit and add delay (ffuf -rate / -p, feroxbuster --rate-limit); "
       "filter to interesting responses so you can stop early rather than exhaust the list; "
       "seed guesses from crawled/observed paths so the traffic looks like navigation",
       "The request count is the signal and it is irreducible below the number of guesses — the "
       "access log and any rate-limit/bot-score control still register the run.",
       "A smaller wordlist and a rate cap directly trade discovery odds and speed for a smaller "
       "footprint."),
    _o("sqli",
       "Injection strings sit in URIs/bodies in the clear, matched by WAF signatures and rules "
       "like SigmaHQ's 'SQL Injection Strings In URI', and sqlmap fires hundreds of requests.",
       "Hand-craft a few targeted payloads over an automated tool sweep; "
       "reduce sqlmap's noise (--technique to one class, --level/--risk low, --delay, "
       "--threads 1) once you know the vector; "
       "prefer a single confirming request per hypothesis over blind enumeration",
       "A WAF inspects request bodies regardless of volume, and the DB/app error and query logs "
       "still record the injected input — a quieter payload is still the same anomalous input in "
       "the log.",
       "Manual, low-and-slow SQLi is far slower and needs you to already understand the injection "
       "point; automated tooling is loud precisely because it is exhaustive."),
    _o("brute_force",
       "A burst of failed logons from one source — the most-alerted-on auth pattern; public-IP "
       "failed-logon and account-lockout rules fire, and lockouts announce the attack outright.",
       "Password-SPRAY (one/few passwords across many accounts) instead of many passwords per "
       "account, staying under the lockout threshold; "
       "add long delays between attempts and spread across the observation window; "
       "target one well-chosen credential from OSINT/breach data over blind volume",
       "Every attempt is still an auth event on the identity provider; spraying trades a per-"
       "account spike for a broad low rate that volume-over-many-accounts detections and impossible-"
       "travel logic still surface. Lockout policy still counts.",
       "Spraying with delays turns minutes into hours or days and a single spray round tests only "
       "one password guess across the org."),
    _o("ad_collect",
       "Domain-wide collection is a huge fan-out of LDAP/SAMR/RPC queries in a short window; "
       "SharpHound/BloodHound have named collection artefacts and dedicated rules.",
       "Collect in targeted passes (one collection method at a time, specific OUs) rather than "
       "an --all sweep; "
       "throttle (SharpHound --Throttle/--Jitter, LoopDelay); "
       "run from a host that already makes directory queries, using existing credentials over a "
       "fresh tool drop; "
       "gather offline from a single replicated copy where possible",
       "LDAP query logging (if on) and ADWS/RPC connection telemetry still record the queries; "
       "collection touches thousands of objects and that read pattern is inherently anomalous — "
       "throttling changes its timing, not its existence.",
       "Targeted, throttled collection is slower and can miss edges an --all run would have mapped, "
       "which is exactly the completeness BloodHound is used for."),
    _o("kerberoast",
       "Requesting many service tickets at once, often with RC4 (etype 0x17) downgrade, is the "
       "classic roast shape — TGS 4769 events cluster and encryption-downgrade rules fire.",
       "Request tickets for ONE targeted SPN you already know is worth cracking, not every SPN; "
       "let the ticket use the account's default (AES) encryption rather than forcing RC4; "
       "space requests out instead of enumerating and roasting in one pass",
       "Each ticket request is still a Kerberos TGS event (4769) on the DC; a single request is "
       "quieter than a sweep but is still logged, and crack success depends on a weak password "
       "regardless of how the ticket was obtained.",
       "Roasting one SPN at a time needs prior target selection and forgoes the broad harvest; "
       "AES tickets are slower to crack than RC4."),
    _o("secretsdump",
       "Remote SAM/LSA/NTDS dumping touches high-signal surfaces — service creation, remote "
       "registry, DRSUAPI replication — that mature stacks alert on directly.",
       "Prefer the least-privileged path that works (targeted SAM/LSA over a full NTDS pull when "
       "you only need one host's creds); "
       "reuse an existing admin session/protocol the host expects over dropping a new service; "
       "pull a single account rather than the whole store",
       "The replication/registry access and any service creation are still logged server-side; "
       "reading secrets is an inherently privileged, audited operation — a smaller pull is quieter "
       "but not invisible.",
       "The quieter, least-privilege paths gather far less; a full secretsdump is loud because it "
       "takes everything in one shot."),
    _o("psexec",
       "Service creation over SMB (7045 / 4697) plus a named-pipe pattern is the textbook PsExec "
       "signature that endpoint and Windows-log rules match immediately.",
       "Prefer an execution method that does not create a service (WMI, WinRM, DCOM) when it fits; "
       "use a non-default service/pipe name over the tool default; "
       "run in a maintenance window when admin tooling is expected",
       "SMB session setup, the 4624 type-3 logon and any service/pipe creation are still recorded; "
       "changing the method moves WHICH events fire, not whether remote-exec telemetry exists.",
       "The service-based path is the most reliable; the quieter methods each have their own "
       "prerequisites and their own (different) detections."),
    _o("reverse_shell",
       "A well-known shell command line (bash -i, nc -e, /dev/tcp) plus an outbound connection to "
       "an unusual host/port — matched by process-creation and network rules, some rated critical.",
       "Use an interpreter/protocol the host already uses for egress (HTTPS C2 over raw TCP, DNS "
       "where HTTP is filtered); "
       "avoid the literal signature strings where a live-off-the-land binary works; "
       "beacon on a jittered interval rather than holding an interactive socket open",
       "The outbound connection to attacker infrastructure is still a network flow that NSM and "
       "egress logging record, and process-creation telemetry still captures the launching "
       "process — encryption hides content, not the existence of the channel.",
       "Protocol-matched, jittered C2 is far more work to set up than a one-line reverse shell and "
       "trades interactivity for stealth."),
]}


def opsec_for(key: str) -> OpsecNote | None:
    """The OPSEC note for a spec key, or None when the family has no curated note."""
    return OPSEC.get(key)


SPECS: dict[str, FootprintSpec] = {s.key: s for s in [
    # --- scanning ---------------------------------------------------------------------- #
    _f("portscan", "Port / service scan", "T1046 T1018", "nmap_pua netscan_auditd portscan_syn",
       "Firewall + NetFlow: one source touching many ports across many hosts in a short window; "
       "Zeek conn.log: a burst of short-lived, rejected (REJ/S0) connections; "
       "Service logs on every port that answered — each probe is a connection somebody logged; "
       "IDS signature hits for scan-shaped traffic (Snort/Suricata scan preprocessors)",
       "loud",
       "A fan-out of connection attempts from one source — the single most-alerted-on pattern "
       "in any monitored network.",
       "Loud: the shape (one source, many ports/hosts, fast) is what perimeter and NSM tooling is "
       "built to spot, and it survives even when payloads are encrypted."),
    _f("web_vuln_scan", "Web vulnerability scan", "T1595.002", "recon_ua src_enum iis_shortname",
       "Web access log: hundreds/thousands of requests from one IP in minutes; "
       "A tool-shaped User-Agent (Nikto/Nuclei/WPScan announce themselves by default); "
       "A 404 wall plus probes for paths that do not exist in this app; "
       "WAF logs: rule hits clustered by source IP",
       "loud",
       "A request flood with a scanner fingerprint sitting in the web logs and the WAF.",
       "Loud: volume alone is anomalous, and default scanner user-agents are matched directly by "
       "public rules such as SigmaHQ's recon user-agent rule."),
    _f("dir_brute", "Directory / content brute force", "T1595.003",
       "recon_ua src_enum iis_shortname",
       "Web access log: a long run of 404s with a wordlist's alphabetical/ordered shape; "
       "Sudden spike in requests-per-second from one source; "
       "Requests for backup/config paths (.git, .env, web.config) that no real user asks for; "
       "WAF/CDN rate-limit and bot-score events",
       "loud",
       "A wall of 404s in the access log, ordered like a wordlist.",
       "Loud: it is high-volume by construction — the defender's signal is the request count, "
       "which no amount of request shaping removes."),
    _f("dns_enum", "DNS / subdomain enumeration", "T1590.002 T1018", "",
       "Authoritative DNS query logs (only if the target runs and keeps them); "
       "Passive-DNS and certificate-transparency lookups leave NO trace on the target at all; "
       "Resolver logs on the operator's own side, not the target's",
       "quiet",
       "Usually nothing — unless the target logs its authoritative DNS or watches CT feeds.",
       "Quiet: ATT&CK lists no target-side detection strategy for this. That is a defender "
       "coverage gap, not an operator advantage — external attack-surface monitoring and CT-log "
       "watching are how blue teams close it."),
    _f("passive_recon", "Passive / open-source reconnaissance", "T1596 T1590.002", "",
       "Nothing on the target — the queries go to third parties (WHOIS, Shodan, CT logs, search "
       "engines), never to the asset; "
       "Only the operator's own egress logs record it",
       "quiet",
       "Nothing. The target is never contacted.",
       "Quiet by definition: no packet reaches the asset. The blue-team answer is not detection "
       "but attack-surface reduction — knowing what is publicly indexed before an attacker does."),

    # --- web exploitation --------------------------------------------------------------- #
    _f("sqli", "SQL-injection probing / exploitation", "T1190", "sqli_uri recon_ua",
       "Web access log: URIs carrying UNION/SELECT/sleep()/quote-tampering payloads; "
       "Database error strings returned in 500 responses and echoed into app logs; "
       "DB slow-query / audit log: malformed or time-delayed queries from the app account; "
       "WAF: SQLi ruleset hits, usually many per second",
       "loud",
       "Injection payloads sitting in plain text in the web access log, plus DB errors behind them.",
       "Loud: SigmaHQ ships a rule that matches injection strings in access-log URIs, and a "
       "successful test usually produces a distinctive database error trail as well."),
    _f("web_fetch", "Direct HTTP request / file fetch", "T1071.001 T1105", "recon_ua",
       "Web access log: one line per request, with the User-Agent and source IP; "
       "Proxy/egress log on the client side; "
       "Sysmon EID 3 / auditd connect if the fetch happened on a monitored host",
       "moderate",
       "An ordinary-looking request line — visible, but indistinguishable from real traffic "
       "until it is correlated.",
       "Moderate: a single request blends into normal volume. It becomes visible through "
       "correlation (odd user-agent, odd path, odd source), which is why baselining matters."),

    # --- credential attack --------------------------------------------------------------- #
    _f("brute_force", "Credential brute force / spraying",
       "T1110 T1110.003", "hydra failed_logon_public mssql_failed_logon",
       "Windows Security 4625 (failed logon) and 4771/4776 in volume; "
       "Linux /var/log/auth.log: repeated 'Failed password' lines from one source; "
       "Account lockout events (4740) — the loudest possible outcome; "
       "Application auth logs and any IdP/SSO failure metrics",
       "loud",
       "A pile of authentication failures from one source, and possibly locked-out accounts.",
       "Loud: failed-authentication volume is the classic detection, and lockouts escalate it to "
       "a helpdesk ticket. Spraying spreads the failures across accounts, which is exactly what "
       "spray-specific rules and per-source correlation are written to catch."),

    # --- AD enumeration ------------------------------------------------------------------ #
    _f("ad_collect", "Domain-wide AD collection (BloodHound-style)",
       "T1087.002 T1069.002 T1482 T1018",
       "ldap_recon bloodhound_files sharphound_rpc adws_uncommon net_recon",
       "Windows LDAP client / DC LDAP diagnostics: one principal issuing a huge, broad LDAP "
       "search set in minutes; "
       "Security 4662 on directory objects if object auditing is enabled; "
       "SMB sessions to every host when session/loggedon collection runs; "
       "The collector's own output files (.zip / *_computers.json) landing on disk",
       "loud",
       "One account enumerating the entire directory at once — a query pattern no normal user or "
       "app produces.",
       "Loud: the volume and breadth are the signal. SigmaHQ carries rules for the LDAP query "
       "pattern, for the collector's output filenames and for the ADWS connection shape."),
    _f("ldap_query", "Targeted LDAP / directory query", "T1087.002 T1069.002 T1201",
       "ldap_recon net_exe",
       "DC LDAP diagnostic channel (Event 1644) when expensive-search logging is on; "
       "Security 4662 for object access, if SACLs are configured; "
       "NSM: LDAP bind + search visible in Zeek ldap.log on port 389/636",
       "moderate",
       "An LDAP search that looks like administration — until you notice who ran it and how "
       "broad the filter was.",
       "Moderate: single targeted queries resemble legitimate directory use. Detection depends on "
       "LDAP diagnostic logging or SACLs being enabled — a common coverage gap worth closing."),
    _f("smb_enum", "SMB share / host enumeration", "T1135 T1021.002 T1018",
       "admin_share named_pipe_first net_recon net_exe",
       "Security 5140/5145 (share access) on every host touched; "
       "Security 4624 type 3 network logons, one per host, from the same account; "
       "Zeek smb_files / dce_rpc: srvsvc NetShareEnum calls fanned out across the subnet; "
       "Sysmon EID 3 outbound 445 to many hosts",
       "notable",
       "The same account network-logging on to host after host and listing shares.",
       "Notable: individually the events are routine, but the fan-out across hosts is a strong, "
       "well-covered correlation signal."),

    # --- credential dumping -------------------------------------------------------------- #
    _f("secretsdump", "Remote secret dumping (SAM / LSA / NTDS)",
       "T1003.002 T1003.003 T1003.004 T1021.002",
       "secretsdump secretsdump_zeek admin_share smb_admin_write",
       "Security 5145 for ADMIN$ / IPC$ access with a remote-registry or service handle; "
       "A service created and deleted within seconds (7045 / 4697); "
       "Zeek smb_files: the tell-tale temporary output file written and read back; "
       "Registry save operations against SAM/SECURITY/SYSTEM hives",
       "loud",
       "Admin-share access plus a short-lived service — the exact pattern SigmaHQ's Impacket "
       "secretsdump rules match.",
       "Loud: the technique has a distinctive, well-documented artefact chain that both host and "
       "network rules key on."),
    _f("dcsync", "DCSync — directory replication of secrets", "T1003.006",
       "dcsync dcsync_rpc",
       "Security 4662 with the DS-Replication-Get-Changes / -All GUIDs, from a principal that is "
       "not a domain controller; "
       "Security 4929 (replica source removal) in some flows; "
       "NSM: DRSUAPI GetNCChanges RPC traffic from a non-DC address",
       "loud",
       "A replication request from something that is not a domain controller — one of the "
       "highest-fidelity alerts in Active Directory.",
       "Loud: near-zero false positives, so any mature stack alerts on the first attempt. "
       "Detection needs directory-object auditing on; where it is off, that is the gap."),

    # --- kerberos ------------------------------------------------------------------------ #
    _f("kerberoast", "Kerberoasting (service-ticket harvest)", "T1558.003",
       "kerberoast kerb_rc4 spn_enum",
       "Security 4769 service-ticket requests in a burst from one account, many distinct SPNs; "
       "Encryption type 0x17 (RC4) requested where the domain otherwise uses AES; "
       "Zeek kerberos.log showing the same RC4 pattern on the wire",
       "notable",
       "One account asking for service tickets for many services at once, often with downgraded "
       "encryption.",
       "Notable: 4769 is high-volume in normal use, so detection relies on the burst + RC4 "
       "correlation — which SigmaHQ ships rules for on both host and network."),
    _f("asrep_roast", "AS-REP roasting", "T1558.004", "asrep",
       "Security 4768 TGT requests for accounts with pre-authentication disabled; "
       "Requests for several such accounts from one source in quick succession",
       "notable",
       "TGT requests for pre-auth-disabled accounts — rare enough to stand out.",
       "Notable: the account population is small, so the request pattern is distinctive whenever "
       "4768 is being collected."),
    _f("ticket_use", "Kerberos ticket request / reuse", "T1550.003 T1558.003", "kerb_rc4",
       "Security 4768/4769 from an unexpected source address for the account; "
       "Ticket lifetimes or encryption types that do not match the account's usual pattern; "
       "Logon (4624) with no matching preceding authentication on that host",
       "moderate",
       "Authentication that works but does not line up with where the account normally logs in "
       "from.",
       "Moderate: individual ticket operations look normal; the signal is in the mismatch between "
       "ticket source and the account's baseline, which requires that baseline to exist."),

    # --- lateral movement / remote execution --------------------------------------------- #
    _f("psexec", "Remote execution via SMB service (PsExec-style)",
       "T1021.002 T1569.002 T1550.002",
       "impacket_psexec psexec_pipe psexec_service psexec_zeek smb_admin_write",
       "Security 7045 / 4697: a new service installed with a random-looking name; "
       "Sysmon EID 17/18: a named pipe created for the remote shell; "
       "Security 5145 write to ADMIN$ (the service binary being dropped); "
       "Security 4624 type 3 followed immediately by SYSTEM-level process creation",
       "loud",
       "A service appearing on the target for a few seconds — with the binary written over "
       "ADMIN$ just before it.",
       "Loud: four independent artefacts (share write, service install, named pipe, network "
       "logon) land within seconds, and SigmaHQ has rules for each of them."),
    _f("wmiexec", "Remote execution via WMI / scheduled task", "T1047 T1021.002 T1053.005",
       "dcom_wmi_rpc bzar_exec admin_share",
       "WMI-Activity/Operational 5857/5860/5861 on the target; "
       "Sysmon EID 1 with WmiPrvSE.exe as the parent of the launched process; "
       "Security 4624 type 3 from the operator's host; "
       "Security 4698/4702 when the variant works through a scheduled task (atexec); "
       "Zeek dce_rpc: IWbemServices calls (BZAR execution indicators)",
       "loud",
       "Processes spawning under WmiPrvSE — a parent no normal application uses.",
       "Loud: the WmiPrvSE parent-child relationship is a well-known, low-noise detection that "
       "both Sysmon-based and network (BZAR) rules cover. The scheduled-task variant adds a "
       "second, separately-audited artefact."),
    _f("remote_exploit", "Exploitation of a remote service", "T1210 T1190",
       "psexec_service recon_ua",
       "Service crash / restart entries (Windows System 1000, Linux syslog 'segmentation fault'); "
       "IDS signatures for the specific exploit's payload shape; "
       "A shell or unexpected child process spawned by the service account right after inbound "
       "traffic; "
       "Sysmon EID 1 + EID 3 correlation on the target host",
       "loud",
       "The service either crashes or gives birth to something it never should — both are logged.",
       "Loud: exploitation attempts leave crash artefacts even when they fail, and successful ones "
       "produce an anomalous child process that behavioural rules key on."),
    _f("sysvol_creds", "Harvesting credentials from SYSVOL / Group Policy Preferences",
       "T1552.006 T1135", "admin_share net_recon",
       "Security 5145 read access to the SYSVOL share and the Policies path; "
       "File-access auditing on Groups.xml / Services.xml / ScheduledTasks.xml; "
       "The read comes from an account with no administrative reason to browse policy files",
       "moderate",
       "A SYSVOL policy file being read by somebody with no reason to read it.",
       "Moderate: every domain user can read SYSVOL, so the access is authorized and blends in. "
       "Detection depends on detailed file-share auditing being enabled on the DC — a gap most "
       "environments have, and the reason removing GPP passwords matters more than detecting the "
       "read."),
    _f("dcomexec", "Remote execution via DCOM", "T1021.003 T1047", "dcom_wmi_rpc bzar_exec",
       "Sysmon EID 1: process spawned by mmc.exe / an Office or Explorer COM host; "
       "DCE/RPC activity to the target's endpoint mapper (135) then a high port; "
       "Security 4624 type 3 for the account used",
       "loud",
       "A COM server on the target giving birth to a shell — an obviously wrong parent process.",
       "Loud: the parent-process anomaly is distinctive, and the RPC path is visible to network "
       "monitoring even without endpoint coverage."),
    _f("winrm", "Remote PowerShell / WinRM session", "T1021.006 T1059.001",
       "winrm_session evil_winrm",
       "Security 4624 logon type 3 with the WinRM service; "
       "WinRM/Operational Event 6 (client creating a session) and 91/168 on the server; "
       "PowerShell 4103/4104 script-block logs for everything typed in the session; "
       "Sysmon EID 1: wsmprovhost.exe as parent of the commands",
       "notable",
       "A remote PowerShell session — and, where script-block logging is on, a transcript of "
       "every command run in it.",
       "Notable: WinRM is legitimate administration, so the session itself is normal; what makes "
       "it visible is script-block logging, which is precisely the control worth enabling."),
    _f("rdp", "Interactive logon over RDP", "T1021.001", "rdp_public rdp_denied",
       "Security 4624 logon type 10 (RemoteInteractive) with source address; "
       "Security 4778/4779 session connect/disconnect; "
       "TerminalServices-LocalSessionManager 21/25 with the client name and IP; "
       "Zeek rdp.log: the client's cookie/keyboard-layout fingerprint",
       "notable",
       "An interactive desktop session with the source IP, client hostname and account all "
       "recorded.",
       "Notable: RDP logons are individually normal but exhaustively logged — source, account and "
       "timing are all attributable after the fact."),
    _f("mssql_exec", "Command execution through MSSQL (xp_cmdshell)",
       "T1059.003 T1190", "xp_cmdshell xp_cmdshell_change mssql_failed_logon",
       "SQL Server error/audit log: the xp_cmdshell configuration change (sp_configure); "
       "Sysmon EID 1: cmd.exe spawned with sqlservr.exe as the parent; "
       "Security 4688 with the SQL service account as the actor",
       "loud",
       "The SQL Server process spawning a command shell — a parent-child pair that is almost "
       "never legitimate.",
       "Loud: both the configuration change and the child-process anomaly are separately alerted "
       "on by SigmaHQ rules."),

    # --- AD object abuse ----------------------------------------------------------------- #
    _f("acl_abuse", "Directory ACL / ownership modification",
       "T1222 T1098", "dcsync_rights ad_user_control",
       "Security 5136 (directory object modified) showing the nTSecurityDescriptor change; "
       "Security 4670 (permissions on an object were changed); "
       "The new ACE naming the operator's principal — durable, attributable evidence; "
       "Security 4662 for the write itself where SACLs cover the object",
       "notable",
       "A permission change on a directory object, with the granting account named in the event.",
       "Notable: these are rare, high-value events — but only recorded when Directory Service "
       "Changes auditing is enabled, which is the gap most environments still have."),
    _f("group_add", "Adding a member to a privileged group", "T1098",
       "priv_group_add ad_user_control net_exe",
       "Security 4728/4732/4756 (member added to a security group) naming who added whom; "
       "Sysmon EID 1 / Security 4688 for the `net group … /add` process; "
       "Any PAM/IdM or SIEM watchlist on privileged-group membership",
       "loud",
       "A privileged-group membership change — one of the most closely watched events in any "
       "directory.",
       "Loud: 4728/4732 are collected almost everywhere and usually sit on a watchlist; the event "
       "names the actor, so it is also strong evidence for the report."),
    _f("shadow_credentials", "Shadow credentials / certificate-based authentication abuse",
       "T1556 T1649 T1098", "shadow_creds adcs_denied",
       "Security 5136 modification of msDS-KeyCredentialLink on the target object; "
       "Security 4768 TGT request using PKINIT for that account shortly afterwards; "
       "ADCS issuance logs (4886/4887) when a certificate is actually requested",
       "notable",
       "A key-credential appearing on an account, then that account authenticating with a "
       "certificate it never had before.",
       "Notable: the attribute write is a specific, rule-covered event — where Directory Service "
       "Changes auditing is on. The PKINIT logon that follows is a second, independent signal."),
    _f("password_reset", "Forcing a password change on another account", "T1098",
       "ad_user_control priv_group_add net_exe",
       "Security 4724 (password reset attempt by another account) naming both parties; "
       "Security 4738 (user account changed); "
       "The account owner noticing they can no longer log in — a human detection channel",
       "loud",
       "A reset event naming exactly who reset whose password, plus a locked-out real user.",
       "Loud, and disruptive: 4724 is unambiguous and the affected user is likely to report the "
       "problem, so this is detected socially as well as technically."),
    _f("delegation_abuse", "Delegation modification (RBCD / constrained)", "T1098 T1550.003",
       "ad_user_control dcsync_rights",
       "Security 5136 writing msDS-AllowedToActOnBehalfOfOtherIdentity or "
       "msDS-AllowedToDelegateTo; "
       "Security 4769 S4U2Self / S4U2Proxy ticket requests immediately after; "
       "A computer account appearing where one was not before (4741)",
       "notable",
       "A delegation attribute changing, followed by tickets requested on behalf of another user.",
       "Notable: the attribute write plus the S4U pattern is a two-step signal — detectable "
       "wherever directory-change auditing and 4769 collection are both in place."),
    _f("relay_poison", "Name-resolution poisoning / SMB relay", "T1557.001",
       "",
       "Unexpected LLMNR (UDP 5355) / NBT-NS (UDP 137) responses from a host that is not the "
       "name owner; "
       "SMB authentication attempts arriving at an unusual host; "
       "Security 4624/4625 with a source that has no business authenticating there; "
       "A honey-credential or canary account being used at all",
       "notable",
       "A machine answering name queries it should not own, and collecting authentications "
       "because of it.",
       "Notable on the network, invisible on the endpoint. ATT&CK lists NSM flow monitoring of "
       "LLMNR/NBT-NS as the detection; where broadcast-protocol monitoring is absent (common), "
       "the coverage gap is the point — disabling LLMNR/NBT-NS is the standard hardening answer."),

    # --- shells / execution --------------------------------------------------------------- #
    _f("reverse_shell", "Reverse shell / interactive callback",
       "T1059.004 T1071.001 T1105", "rev_shell_cmdline rev_shell_net netcat_rev perl_rev",
       "auditd execve of a shell with a socket redirect (/dev/tcp, mkfifo, -e /bin/sh); "
       "Sysmon EID 1 + EID 3: a shell process opening an outbound connection; "
       "Firewall/NetFlow: a long-lived outbound session to an unusual port and destination; "
       "EDR behavioural detection on the shell-with-socket pattern",
       "loud",
       "A shell process holding an outbound socket open — the shape every EDR is tuned for.",
       "Loud: it is one of the most heavily signatured behaviours in existence; SigmaHQ alone "
       "ships several rules matching the command line and the connection."),
    _f("interpreter", "Inline interpreter execution", "T1059.004 T1059.006 T1059.003",
       "rev_shell_cmdline perl_rev",
       "Security 4688 / auditd execve with the full command line, including the inline code; "
       "Sysmon EID 1 with an interpreter spawned by a non-developer parent; "
       "Script-block logging (PowerShell 4104) capturing the code verbatim",
       "notable",
       "The code itself, recorded in the process-creation event.",
       "Notable: the command line is captured in full where process-creation auditing is on, so "
       "the payload becomes durable evidence rather than a transient action."),
    _f("payload_gen", "Payload generation / tooling", "T1588.002 T1027", "",
       "Nothing on the target — generation happens on the operator's machine; "
       "The artefact becomes visible only when it is delivered or executed; "
       "AV/EDR static detection at the moment of transfer or write",
       "quiet",
       "Nothing yet — this step happens off-target.",
       "Quiet only because the target is not involved. The generated artefact carries its own "
       "footprint the moment it lands, which is where file-write and AV telemetry take over."),
]}


# Binary / subcommand -> spec key. Longest, most specific match wins (see :func:`lookup`).
ALIASES: dict[str, str] = {
    # scanning
    "nmap": "portscan", "masscan": "portscan", "rustscan": "portscan", "zmap": "portscan",
    "unicornscan": "portscan", "naabu": "portscan", "netdiscover": "portscan", "arp-scan": "portscan",
    "fping": "portscan", "hping3": "portscan",
    # web
    "nikto": "web_vuln_scan", "nuclei": "web_vuln_scan", "wpscan": "web_vuln_scan",
    "whatweb": "web_vuln_scan", "httpx": "web_vuln_scan", "zap": "web_vuln_scan",
    "zaproxy": "web_vuln_scan", "wapiti": "web_vuln_scan", "joomscan": "web_vuln_scan",
    "gobuster": "dir_brute", "ffuf": "dir_brute", "feroxbuster": "dir_brute",
    "dirsearch": "dir_brute", "dirb": "dir_brute", "wfuzz": "dir_brute", "dirbuster": "dir_brute",
    "sqlmap": "sqli", "ghauri": "sqli",
    "curl": "web_fetch", "wget": "web_fetch", "httpie": "web_fetch",
    # dns / passive
    "dig": "dns_enum", "nslookup": "dns_enum", "host": "dns_enum", "dnsrecon": "dns_enum",
    "dnsenum": "dns_enum", "dnsx": "dns_enum", "fierce": "dns_enum",
    "amass": "passive_recon", "subfinder": "passive_recon", "assetfinder": "passive_recon",
    "whois": "passive_recon", "theharvester": "passive_recon", "shodan": "passive_recon",
    "waybackurls": "passive_recon", "gau": "passive_recon",
    # credential attack
    "hydra": "brute_force", "medusa": "brute_force", "ncrack": "brute_force",
    "patator": "brute_force", "kerbrute": "brute_force",
    # AD collection / enumeration
    "bloodhound-python": "ad_collect", "bloodhound": "ad_collect", "sharphound": "ad_collect",
    "sharphound.exe": "ad_collect", "azurehound": "ad_collect", "rusthound": "ad_collect",
    "ldapsearch": "ldap_query", "windapsearch": "ldap_query", "ldapdomaindump": "ldap_query",
    "bloodyad": "ldap_query", "rpcclient": "ldap_query", "adidnsdump": "ldap_query",
    "smbmap": "smb_enum", "smbclient": "smb_enum", "enum4linux": "smb_enum",
    "enum4linux-ng": "smb_enum", "nbtscan": "smb_enum", "smbcacls": "smb_enum",
    # credential dumping
    "secretsdump": "secretsdump", "secretsdump.py": "secretsdump",
    "impacket-secretsdump": "secretsdump", "gmsadumper": "secretsdump", "lsassy": "secretsdump",
    "mimikatz": "secretsdump", "pypykatz": "secretsdump",
    # kerberos
    "getuserspns": "kerberoast", "getuserspns.py": "kerberoast",
    "impacket-getuserspns": "kerberoast", "targetedkerberoast": "kerberoast",
    "targetedkerberoast.py": "kerberoast", "setspn": "kerberoast",
    "getnpusers": "asrep_roast", "getnpusers.py": "asrep_roast",
    "impacket-getnpusers": "asrep_roast",
    "getst": "ticket_use", "impacket-getst": "ticket_use", "gettgt": "ticket_use",
    "impacket-gettgt": "ticket_use", "ticketer": "ticket_use", "impacket-ticketer": "ticket_use",
    "rubeus": "ticket_use", "rubeus.exe": "ticket_use",
    # remote execution
    "psexec": "psexec", "psexec.py": "psexec", "impacket-psexec": "psexec",
    "smbexec": "psexec", "impacket-smbexec": "psexec", "psexec.exe": "psexec",
    "wmiexec": "wmiexec", "impacket-wmiexec": "wmiexec", "atexec": "wmiexec",
    "impacket-atexec": "wmiexec", "wmic": "wmiexec",
    "dcomexec": "dcomexec", "impacket-dcomexec": "dcomexec",
    "evil-winrm": "winrm", "winrs": "winrm",
    "xfreerdp": "rdp", "rdesktop": "rdp", "mstsc": "rdp", "freerdp": "rdp",
    "mssqlclient": "mssql_exec", "impacket-mssqlclient": "mssql_exec", "sqsh": "mssql_exec",
    # AD object abuse
    "dacledit": "acl_abuse", "impacket-dacledit": "acl_abuse",
    "owneredit": "acl_abuse", "impacket-owneredit": "acl_abuse",
    "certipy": "shadow_credentials", "pywhisker": "shadow_credentials",
    "whisker": "shadow_credentials", "certipy-ad": "shadow_credentials",
    "rbcd": "delegation_abuse", "impacket-rbcd": "delegation_abuse", "rbcd.py": "delegation_abuse",
    "responder": "relay_poison", "ntlmrelayx": "relay_poison",
    "impacket-ntlmrelayx": "relay_poison", "mitm6": "relay_poison", "inveigh": "relay_poison",
    # shells / interpreters
    "nc": "reverse_shell", "ncat": "reverse_shell", "netcat": "reverse_shell",
    "socat": "reverse_shell", "rlwrap": "reverse_shell",
    "python": "interpreter", "python3": "interpreter", "perl": "interpreter",
    "ruby": "interpreter", "php": "interpreter", "bash": "interpreter", "sh": "interpreter",
    "powershell": "interpreter", "pwsh": "interpreter", "node": "interpreter",
    "msfvenom": "payload_gen",
    "msfconsole": "remote_exploit", "msfcli": "remote_exploit", "searchsploit": "payload_gen",
    "gpp-decrypt": "sysvol_creds", "gpp_decrypt": "sysvol_creds",
}

# Tools whose meaning depends on the FIRST argument (a protocol / subcommand).
SUBCOMMAND_TOOLS: dict[str, dict[str, str]] = {
    "nxc": {"smb": "smb_enum", "ldap": "ldap_query", "winrm": "winrm", "mssql": "mssql_exec",
            "rdp": "rdp", "ssh": "brute_force", "ftp": "brute_force", "wmi": "wmiexec"},
    "crackmapexec": {"smb": "smb_enum", "ldap": "ldap_query", "winrm": "winrm",
                     "mssql": "mssql_exec", "rdp": "rdp", "ssh": "brute_force"},
    "cme": {"smb": "smb_enum", "ldap": "ldap_query", "winrm": "winrm", "mssql": "mssql_exec"},
    # NB: no "rpc" key — `net rpc …` is a transport, not the action. The real verb that
    # follows it (password / group / addmem / user / share) is what the defender sees.
    "net": {"password": "password_reset", "addmem": "group_add", "delmem": "group_add",
            "group": "group_add", "localgroup": "group_add", "user": "ldap_query",
            "view": "smb_enum", "use": "smb_enum", "share": "smb_enum",
            "accounts": "ldap_query", "rights": "acl_abuse"},
    "certipy": {"shadow": "shadow_credentials", "auth": "shadow_credentials",
                "req": "shadow_credentials", "find": "ldap_query", "relay": "relay_poison"},
    "bloodyad": {"add": "acl_abuse", "set": "acl_abuse", "get": "ldap_query",
                 "remove": "acl_abuse"},
}


# --------------------------------------------------------------------------- #
# argument-level signals: things that CHANGE the footprint of a command
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ArgSignal:
    """An argument pattern that adds techniques / telemetry to the base footprint.

    Two kinds live here and both are DESCRIPTIVE:

    * escalations — ``-just-dc`` turns a secretsdump into a DCSync, which is a different (and
      much louder) event on the defender's side;
    * stealth-shaped arguments — flags whose PURPOSE is to be less visible. The panel names the
      ATT&CK Stealth/Defense-Impairment technique they map to and the telemetry that still
      records them. It does not suggest using them, and the ``note`` is always written from the
      defender's chair.
    """

    id: str
    label: str
    pattern: str                      # regex, matched against the joined argv (case-insensitive)
    techniques: tuple[str, ...] = ()
    sigma: tuple[str, ...] = ()
    telemetry: tuple[str, ...] = ()
    note: str = ""
    stealth: bool = False             # True = an ATT&CK Stealth / Defense-Impairment mapping
    louder: bool = False              # True = bumps the loudness rating up one step
    case_sensitive: bool = False      # True for flag-shaped patterns where -D != -d (nmap)
    # Spec keys this signal may fire on. Empty = any command. Short flags are reused across
    # tools with entirely different meanings (nmap's -S is a spoofed source; net's -S is the
    # server), so a flag-shaped signal must say which activity it belongs to or it will
    # mislabel unrelated commands.
    applies_to: tuple[str, ...] = ()


ARG_SIGNALS: tuple[ArgSignal, ...] = (
    ArgSignal(
        id="dcsync",
        label="Replication of directory secrets (DCSync)",
        pattern=r"(?:^|\s)-(?:just-dc|just-dc-ntlm|just-dc-user)\b",
        techniques=("T1003.006",),
        sigma=("dcsync", "dcsync_rpc"),
        telemetry=("Security 4662 with the DS-Replication-Get-Changes GUIDs from a non-DC source;"
                   " NSM: DRSUAPI GetNCChanges from an address that is not a domain controller",),
        note="This argument turns the dump into a replication request — a near-zero-false-positive "
             "event on the defender's side.",
        louder=True,
    ),
    ArgSignal(
        id="os_shell",
        label="Interactive OS shell through the exploited service",
        pattern=r"--os-shell|--os-pwn|--os-cmd|xp_cmdshell|--sql-shell",
        techniques=("T1059.003", "T1059.004"),
        sigma=("xp_cmdshell", "rev_shell_cmdline"),
        telemetry=("Process creation with the service account as the actor and the database or web "
                   "process as the parent — an anomalous parent-child pair",),
        note="Command execution through the service leaves a process-creation event whose parent "
             "is the service itself, which is what child-process rules key on.",
        louder=True,
    ),
    ArgSignal(
        id="decoy_scan",
        label="Decoy / spoofed-source scanning",
        pattern=r"(?:^|\s)-D\s|(?:^|\s)-S\s|--spoof-mac|(?:^|\s)-sI\s",
        techniques=("T1036",),
        sigma=("portscan_syn",),
        telemetry=("IDS/NSM still records every probe; decoy traffic multiplies the number of "
                   "events, and the real source remains in the flow record of whichever packets "
                   "carried a real return path",),
        note="ATT&CK classifies source spoofing as Masquerading (Stealth, TA0005). It is itself a "
             "tracked technique: NSM tooling fingerprints decoy patterns, so this typically "
             "produces MORE alertable traffic, not less.",
        stealth=True,
        louder=True,
        case_sensitive=True,      # -D (decoys) is not -d (debug)
        applies_to=("portscan",),  # nmap's -S/-D; `net ... -S <server>` is a different flag
    ),
    ArgSignal(
        id="fragmented_scan",
        label="Fragmented / evasion-shaped probe packets",
        pattern=r"(?:^|\s)-f(?:\s|$)|--mtu\s|--data-length\s|--scan-delay\s|(?:^|\s)-T0(?:\s|$)|"
                r"(?:^|\s)-T1(?:\s|$)",
        techniques=("T1027",),
        sigma=("portscan_syn", "netscan_auditd"),
        telemetry=("IDS preprocessors specifically log fragmented and oddly-timed probes; "
                   "fragmentation is itself an anomaly that many NSM rules alert on directly",),
        note="ATT&CK tracks packet-level obfuscation under Obfuscated Files or Information "
             "(Stealth, TA0005). Fragmented or heavily-delayed probes are anomalous in their own "
             "right — IDS fragmentation handling is a standard, long-standing detection.",
        stealth=True,
        case_sensitive=True,      # -f (fragment) is not -F (fast scan)
        applies_to=("portscan",)
    ),
    ArgSignal(
        id="payload_tamper",
        label="Payload encoding / WAF-tamper scripts",
        pattern=r"--tamper|--random-agent|--hex\b|--no-cast\b",
        techniques=("T1027", "T1036"),
        sigma=("sqli_uri", "recon_ua"),
        telemetry=("WAF logs record the tampered payload verbatim, plus the rule it did or did not "
                   "match; the request volume is unchanged",),
        note="ATT&CK maps payload encoding to Obfuscated Files or Information and spoofed agents "
             "to Masquerading (both Stealth, TA0005). The request still reaches the log — encoding "
             "changes what the log line looks like, not whether there is one.",
        stealth=True,
    ),
    ArgSignal(
        id="encoded_command",
        label="Base64 / encoded command line",
        pattern=r"-enc(?:odedcommand)?\b|base64\s+-d|frombase64string|\becho\s+[A-Za-z0-9+/]{40,}={0,2}",
        techniques=("T1027.010",),
        sigma=("posh_token_obf",),
        telemetry=("The encoded string is captured verbatim in the process-creation event "
                   "(4688 / Sysmon 1) and in PowerShell script-block logs, where it is decoded by "
                   "the analyst — or by the rule",),
        note="ATT&CK calls this Command Obfuscation (Stealth, TA0005). Detection rules match the "
             "ENCODING ITSELF, so an encoded command line is frequently a stronger signal than the "
             "plain one would have been.",
        stealth=True,
        louder=True,
    ),
    ArgSignal(
        id="log_tamper",
        label="Log / history tampering",
        pattern=r"wevtutil\s+cl|clear-eventlog|auditpol\s+/set|unset\s+HISTFILE|export\s+HISTSIZE=0|"
                r"history\s+-c|rm\s+.*(?:\.bash_history|auth\.log|wtmp)",
        techniques=("T1685", "T1690", "T1222", "T1112"),
        sigma=(),
        telemetry=("Security 1102 (audit log cleared) is itself an event and is generated BEFORE "
                   "the log is emptied; forwarded logs already left the host; auditd records the "
                   "execve that did it",),
        note="ATT&CK tracks this under Defense Impairment (TA0112). It is recorded as its own "
             "high-severity event — clearing a log announces that a log was cleared. Flagged here "
             "so the operator knows the action is destructive to evidence and out of keeping with "
             "an authorized test.",
        stealth=True,
        louder=True,
    ),
    ArgSignal(
        id="pass_the_hash",
        label="Authentication with a hash rather than a password",
        pattern=r"-hashes\s|--hashes\s|(?:^|\s)-H\s+[0-9a-f]{32}|(?:^|\s)--pw-nt-hash",
        techniques=("T1550.002",),
        sigma=("impacket_psexec",),
        telemetry=("Security 4624/4776 showing NTLM where the environment normally uses Kerberos; "
                   "logon events for an account from a host it has never authenticated from",),
        note="NTLM-with-hash authentication is visible as a protocol mismatch in the logon events, "
             "which is what pass-the-hash analytics look for.",
    ),
)


# --------------------------------------------------------------------------- #
# matching (pure functions — no execution, no I/O)
# --------------------------------------------------------------------------- #
def _basename(command: str) -> str:
    """'/usr/bin/impacket-psexec' -> 'impacket-psexec'; 'C:\\tools\\Rubeus.exe' -> 'rubeus.exe'."""
    raw = str(command or "").strip().strip('"').strip("'")
    raw = raw.replace("\\", "/")
    return os.path.basename(raw).lower()


def normalize_tool(command: str) -> str:
    """The comparable tool identity for a command name.

    Strips a path, lowercases, and unwraps the common wrappers so that
    ``impacket-secretsdump``, ``secretsdump.py`` and ``/opt/impacket/examples/secretsdump.py``
    all land on the same identity.
    """
    name = _basename(command)
    if not name:
        return ""
    for prefix in ("impacket-", "python-"):
        if name.startswith(prefix) and name[len(prefix):] in ALIASES:
            return name
    return name


def _script_identity(args: list[str]) -> str | None:
    """`python3 targetedKerberoast.py …` -> 'targetedkerberoast.py' (the real actor)."""
    for a in args:
        low = str(a).lower()
        if low.endswith(".py") or low.endswith(".exe") or low.endswith(".ps1"):
            return _basename(low)
    return None


@dataclass(frozen=True)
class Match:
    """The catalog's answer for one command: the base spec plus any argument signals."""

    spec: FootprintSpec | None
    signals: tuple[ArgSignal, ...]
    matched_on: str            # what produced the spec ('tool', 'subcommand', 'script', '')

    @property
    def grounded(self) -> bool:
        return self.spec is not None


def lookup(command: str, args: list[str] | None = None) -> Match:
    """Resolve a command + argv to its curated footprint spec and argument signals.

    Pure lookup. Returns ``Match(spec=None, …)`` when the command is not in the curated map —
    the resolver then falls back to the LLM and marks the footprint ``ai_suggested``.
    """
    argv = [str(a) for a in (args or [])]
    tool = normalize_tool(command)
    joined = " ".join([tool, *argv])

    spec: FootprintSpec | None = None
    matched_on = ""

    # 1. subcommand-aware tools (nxc smb …, net rpc …, certipy shadow …)
    subs = SUBCOMMAND_TOOLS.get(tool)
    if subs:
        for a in argv:
            key = subs.get(str(a).lower())
            if key:
                spec, matched_on = SPECS.get(key), "subcommand"
                break
        if spec is None:
            # a known multi-protocol tool used without a recognised subcommand
            spec, matched_on = SPECS.get(next(iter(subs.values()))), "tool"

    # 2. an interpreter running a known script — the SCRIPT is the real actor
    if spec is None and tool in ("python", "python3", "perl", "ruby", "pwsh", "powershell"):
        ident = _script_identity(argv)
        if ident and ident in ALIASES:
            spec, matched_on = SPECS.get(ALIASES[ident]), "script"

    # 3. plain tool alias
    if spec is None:
        key = ALIASES.get(tool)
        if key:
            spec, matched_on = SPECS.get(key), "tool"

    # Argument signals last, so a signal scoped to a spec (applies_to) knows what it matched.
    signals = tuple(
        sig for sig in ARG_SIGNALS
        if (not sig.applies_to or (spec is not None and spec.key in sig.applies_to))
        and re.search(sig.pattern, joined, 0 if sig.case_sensitive else re.IGNORECASE)
    )

    return Match(spec=spec, signals=signals, matched_on=matched_on if spec else "")


def loudness_score(loudness: str) -> int:
    return LOUDNESS_SCALE.get(loudness, 0)


def bump(loudness: str, steps: int = 1) -> str:
    """Raise a loudness rating by ``steps`` (never past 'loud')."""
    order = ["quiet", "moderate", "notable", "loud"]
    try:
        i = order.index(loudness)
    except ValueError:
        return loudness
    return order[min(i + steps, len(order) - 1)]


def sigma_rules(keys) -> list[SigmaRule]:
    """SigmaRule objects for a sequence of SIGMA keys (unknown keys are skipped)."""
    out, seen = [], set()
    for k in keys:
        r = SIGMA.get(k)
        if r and r.id not in seen:
            seen.add(r.id)
            out.append(r)
    return out


__all__ = [
    "SIGMA_REPO", "SIGMA_BLOB", "SIGMA_LICENSE", "LOUDNESS_SCALE", "LOUDNESS_MEANING",
    "SigmaRule", "SIGMA", "FootprintSpec", "SPECS", "ALIASES", "SUBCOMMAND_TOOLS",
    "ArgSignal", "ARG_SIGNALS", "Match",
    "normalize_tool", "lookup", "loudness_score", "bump", "sigma_rules",
]
