"""Command parsing, the dangerous-command heuristic, and best-effort target helpers.

THE ALLOWLIST GATE WAS REMOVED (Zaid's decision, 2026-07-24). The cockpit no longer
restricts WHICH binary may run: the human-approved agent may run ANY single command
(one binary + args) against the isolated lab. This module therefore no longer holds a
command allowlist or a per-tool flag schema. What survives:

* the flag PARSER (:func:`_is_flag_token`, :func:`flags_in_args`) — spots a flag in any
  form (bare, combined short, ``=``-joined); reused by the heuristic to detect an eval
  flag (``-c``/``-e``);
* :func:`dangerous_command_heuristic` — an OVER-INCLUSIVE, best-effort detector that
  drives the red-confirm (interpreters, reverse-shell/exec tools, frameworks). It is an
  ASSIST, not a guarantee: a false positive costs one extra confirm; a false negative is a
  missed warning. The HUMAN approval is the real gate, so gaps are expected by design;
* :func:`extract_hostish` — for the best-effort target-lock (host-shaped tokens must be
  the lab); note it CANNOT see hosts hidden inside arbitrary commands (e.g.
  ``python -c "...connect..."``) — isolation is the real bound on the lab;
* :data:`SUGGESTED_COMMANDS` — purely informational hints for the UI (not enforced).

The real safety bounds on the lab are ISOLATION (egress-less sandbox) + HUMAN APPROVAL,
plus this heuristic red-confirm. Execution stays argv-style (never a shell), so what is
approved is exactly what runs.
"""

from __future__ import annotations

import os

# Informational only — example commands the UI may surface. NOT an allowlist; anything
# may run. Kept so the manual cockpit surface has something to suggest.
SUGGESTED_COMMANDS: list[tuple[str, str]] = [
    ("nmap", "Port/service scan of the lab target."),
    ("curl", "Fetch a URL from the lab target."),
    ("whatweb", "Fingerprint the lab target's web stack."),
    ("sqlmap", "SQL-injection exploitation against the lab."),
    ("ffuf", "Web fuzzer against the lab."),
    ("nuclei", "Template scanner against the lab."),
    ("gobuster", "Directory/DNS brute-forcer."),
    ("nikto", "Web server scanner."),
]


def _is_flag_token(token: str) -> bool:
    """True if a token is flag-shaped (a leading '-' plus at least one more char).

    A lone ``-`` (stdin) is an operand, not a flag. Only used now by the heuristic to
    spot an eval flag — there is no flag rejection anymore.
    """
    return len(token) >= 2 and token[0] == "-"


def flags_in_args(args: list[str]) -> set[str]:
    """Best-effort set of flag identities present in ``args`` — whole single-dash/long
    tokens plus each letter of a short cluster, ``=``-joined names split on ``=``.

    Over-inclusive on purpose: the heuristic only needs to spot an eval flag like ``-c``
    (in ``-c``, ``-abc``, ``-c=…``) or ``--command``. Reuses the flag parser so the
    forms stay consistent with how the tools actually parse them.
    """
    found: set[str] = set()
    for tok in args:
        if not _is_flag_token(tok):
            continue
        base = tok.split("=", 1)[0]
        found.add(base)
        if not base.startswith("--"):  # short cluster: each letter is a flag
            for ch in base[1:]:
                found.add("-" + ch)
    return found


# --------------------------------------------------------------------------- #
# The dangerous-command heuristic (drives the red-confirm). OVER-INCLUSIVE by
# design — an ASSIST, not a guarantee. A false positive costs one extra confirm;
# a false negative is a missed warning (the HUMAN approval is the real gate).
# --------------------------------------------------------------------------- #

# Language interpreters — the binary itself is the tell (it can run arbitrary code).
_INTERPRETERS = frozenset({
    "python", "python2", "python3", "bash", "sh", "dash", "zsh", "ksh", "fish",
    "perl", "ruby", "php", "node", "nodejs", "lua", "tclsh", "expect",
    "pwsh", "powershell", "osascript", "groovy", "gawk", "awk",
})
# Raw network / exec tools commonly used for shells + exec.
_EXEC_TOOLS = frozenset({"nc", "ncat", "netcat", "socat", "telnet", "rlwrap"})
# Exploitation frameworks / payload generators.
_FRAMEWORKS = frozenset({
    "msfconsole", "msfvenom", "msfcli", "meterpreter", "empire", "sliver",
    # The Sliver binaries as they are actually invoked. `sliver` alone never matched
    # `sliver-client generate ...`, so an implant build would not have tripped the
    # red-confirm — the one gate that stops a beacon being built on a plain approval.
    # Purely additive: this can only ever ADD reasons, never remove one.
    "sliver-client", "sliver-server",
    # The build-#4 evasion generators. Same reasoning as the Sliver binaries above: neither
    # name matched anything here, so an artifact build would have passed the danger gate on a
    # plain approval with no red-confirm. They generate a runnable payload, which is exactly
    # what this set exists to flag. `scarecrow` is matched lowercased, as every entry is.
    "donut", "scarecrow",
    "covenant", "cobaltstrike", "beacon", "chisel", "ligolo",
})
# Flags that mean "run this inline code / command".
_EVAL_FLAGS = frozenset({"-c", "-e", "--command", "--eval", "--exec", "-code"})
# Substrings anywhere in the args that signal a reverse shell / code exec shape.
_SHELL_MARKERS = (
    "/dev/tcp/", "/dev/udp/", "bash -i", "sh -i", "mkfifo", "/inet/tcp/",
    "pty.spawn", "os.system", "subprocess", "runtime.exec", "0>&1", ">&/dev/tcp",
    "exec 5<>", "socket(", "fsockopen", "sh >&", "cmd.exe", "-nlvp", "-e /bin",
    "curl | sh", "wget | sh", "| bash", "| sh", "base64 -d",
)


# --------------------------------------------------------------------------- #
# AD ABUSE SHAPES
#
# Added because the AD agent DRAFTS these steps, which makes the red confirm the last thing
# standing between a proposal and a domain. Measured against the AD technique catalog, 10 of
# its 12 destructive abuses — DCSync and ForceChangePassword among them — resolved to commands
# nothing above flagged: they are not interpreters, not netcat, not msfvenom, so they sailed
# through on approval alone.
#
# Flagged by SHAPE, not by binary. `nxc --shares` (read-only) must stay clean while
# `nxc --sam` (credential dump) trips, because a confirm that fires on everything is a confirm
# the operator learns to click through — confirm fatigue is its own safety failure.
# --------------------------------------------------------------------------- #
def _ad_tool(command: str) -> str:
    """Normalise an AD tool name. impacket ships the same script three ways
    (``secretsdump.py``, ``impacket-secretsdump``, ``secretsdump``)."""
    base = os.path.basename(str(command)).lower()
    for suffix in (".py", ".exe", ".ps1"):
        base = base.removesuffix(suffix)
    return base.removeprefix("impacket-")


# Always credential theft — replicating, dumping or parsing secrets.
_AD_CRED_DUMP = frozenset({
    "secretsdump", "mimikatz", "invoke-mimikatz", "lsassy", "nanodump", "procdump", "pwdump",
    "gsecdump", "safetykatz", "sharpdump", "dumpert", "handlekatz", "krbrelayx",
})
# Native Windows (PowerView / .NET) cmdlets that WRITE the directory or reset a credential.
# These run ON the Windows box over WinRM and are as destructive as their impacket cousins, so
# they must trip the same red confirm. Matched on the command name (no suffix to strip).
_AD_PS_WRITE = frozenset({
    "set-domainuserpassword", "add-domainobjectacl", "set-domainobjectowner",
    "add-domaingroupmember", "set-domainrbcd", "set-domainobject", "add-domainobject",
    "set-domainobjectowner.ps1",
})
# Always remote code execution on a domain host — drops a service/process on a real machine.
_AD_REMOTE_EXEC = frozenset({
    "psexec", "wmiexec", "smbexec", "atexec", "dcomexec", "evil-winrm", "winrs",
    "smbclient-ng", "wmipersist",
})
# Always mutates the directory, mints credentials, or coerces/relays authentication.
_AD_DIR_WRITE = frozenset({
    "dacledit", "owneredit", "rbcd", "addcomputer", "pywhisker", "whisker",
    "targetedkerberoast", "ticketer", "goldenpac", "raisechild", "ntlmrelayx",
    "mitm6", "responder", "petitpotam", "coercer", "printerbug", "dfscoerce",
    "shadowcoerce", "certipy-relay",
})
# Argument shapes that turn an otherwise-general tool into a credential dump.
_AD_DUMP_MARKERS = (
    "-just-dc", "--ntds", "--sam", "--lsa", "-use-vss", "dcsync", "lsadump",
    "sekurlsa", "-m lsassy", "-m nanodump", "-m procdump", "--gmsa", "--laps",
    "--dpapi", "-just-dc-ntlm", "-just-dc-user",
)
# Per-tool subcommands that mutate the directory or mint credentials.
_AD_WRITE_SUBCOMMANDS: dict[str, tuple[str, ...]] = {
    "bloodyad": ("set ", "add ", "remove "),
    "certipy": ("req", "shadow", "relay", "forge", "ca", "template", "cert", "auth"),
    "net": ("password", "/add", "/delete", "/active:"),
    "rubeus": ("ptt", "golden", "silver", "s4u", "asktgt", "changepw", "tgtdeleg", "dump"),
    "bloodhound-ce": (),
}


def _ad_abuse_reasons(command: str, args: list[str]) -> list[str]:
    """Reasons an AD-abuse command must demand the explicit confirm (empty if it need not)."""
    base = _ad_tool(command)
    blob = " ".join(str(a) for a in args).lower()
    reasons: list[str] = []

    if base in _AD_CRED_DUMP:
        reasons.append(f"{base}: dumps/replicates domain credentials")
    if base in _AD_REMOTE_EXEC:
        reasons.append(f"{base}: remote code execution on a domain host")
    if base in _AD_DIR_WRITE:
        reasons.append(f"{base}: modifies the directory / coerces or relays authentication")
    if base in _AD_PS_WRITE:
        reasons.append(f"{base}: writes the directory / resets a credential (PowerView/.NET)")

    for marker in _AD_DUMP_MARKERS:
        if marker in blob:
            reasons.append(f"credential-dump flag: {marker!r}")
            break

    verbs = _AD_WRITE_SUBCOMMANDS.get(base, ())
    for verb in verbs:
        if verb in blob:
            reasons.append(f"{base} {verb.strip()}: writes to the directory / mints credentials")
            break
    return reasons


def dangerous_command_heuristic(command: str, args: list[str]) -> list[str]:
    """Return human-readable reasons this command looks dangerous (empty if it doesn't).

    Drives the red-confirm: when non-empty the executor's danger gate requires an explicit
    ``dangerous_ack`` before running (it NEVER blocks outright). Over-inclusive best-effort
    — the human approval is the real gate, so gaps are expected. Flags: language interpreters
    (esp. with an eval flag), reverse-shell/exec tools (esp. nc/ncat/socat -e/-c), exploitation
    frameworks, and reverse-shell/code-exec shapes anywhere in the args.
    """
    reasons: list[str] = []
    cmd = os.path.basename(str(command)).lower()  # handles /usr/bin/python3, ./x
    flags = flags_in_args(args)
    eval_flags = sorted(flags & _EVAL_FLAGS)

    if cmd in _INTERPRETERS:
        note = f" with {', '.join(eval_flags)} (inline code)" if eval_flags else ""
        reasons.append(f"{cmd}: language interpreter — runs arbitrary code{note}")
    if cmd in _EXEC_TOOLS:
        if flags & {"-e", "-c"}:
            reasons.append(f"{cmd} -e/-c: command execution / reverse shell")
        else:
            reasons.append(f"{cmd}: raw network tool — can carry a reverse shell")
    if cmd in _FRAMEWORKS:
        reasons.append(f"{cmd}: exploitation framework / payload generator")

    # AD ABUSE — credential replication, remote exec on a domain host, directory writes.
    # Additive: it can only ever ADD reasons, so every command flagged before is still flagged.
    reasons.extend(_ad_abuse_reasons(command, args))

    # scan the whole arg vector for reverse-shell / code-exec shapes (payloads, one-liners)
    blob = " ".join(str(a) for a in args).lower()
    for marker in _SHELL_MARKERS:
        if marker in blob:
            reasons.append(f"reverse-shell / code-exec pattern: {marker!r}")

    # de-dup, preserve order
    seen: set[str] = set()
    out: list[str] = []
    for r in reasons:
        if r not in seen:
            seen.add(r)
            out.append(r)
    return out


def extract_hostish(args: list[str]) -> list[str]:
    """Return arg tokens that look like a host/URL operand (not flags).

    Used by the executor's best-effort target-lock: every hostish token must be the lab.
    Pure heuristic — flags (starting with '-') are skipped. It CANNOT see a host embedded
    inside an arbitrary command's payload; isolation is the real bound on the lab.
    """
    return [a for a in args if not a.startswith("-")]
