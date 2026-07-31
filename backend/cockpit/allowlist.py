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

import base64
import binascii
import os
import re

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

def _tool_name(command: str) -> str:
    """The normalised binary name every set below is matched against.

    ONE normaliser for the whole heuristic. It used to be two: the AD sets stripped
    ``.py``/``.exe``/``.ps1`` and the ``impacket-`` prefix, while the interpreter/exec/framework
    sets matched a raw ``basename().lower()``. That asymmetry meant ``powershell.exe``,
    ``python.exe``, ``nc.exe``, ``msfvenom.exe`` and even ``sliver-client.exe`` produced NO
    reason at all — and ``.exe`` is the ordinary spelling on the WinRM transport, where the
    same heuristic is the red-confirm. Normalising once, here, is the fix.

    impacket ships the same script three ways (``secretsdump.py``, ``impacket-secretsdump``,
    ``secretsdump``); all three collapse to the same name.
    """
    base = os.path.basename(str(command)).lower()
    for suffix in (".py", ".exe", ".ps1"):
        base = base.removesuffix(suffix)
    return base.removeprefix("impacket-")


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
    # The aliases the catalog lists for msfconsole. An alias is a name the operator plausibly
    # types as argv[0], so it has to carry the same verdict as the binary — an alias that does
    # not match is precisely how `sliver` missed `sliver-client`.
    "msf", "metasploit",
    # The Sliver binaries as they are actually invoked. `sliver` alone never matched
    # `sliver-client generate ...`, so an implant build would not have tripped the
    # red-confirm — the one gate that stops a beacon being built on a plain approval.
    # Purely additive: this can only ever ADD reasons, never remove one.
    "sliver-client", "sliver-server",
    # Empire's actual binary on the sandbox image is `powershell-empire`; the bare `empire`
    # above never matched it under exact-basename matching, so an Empire launch — a full C2 /
    # persistence framework that runs agents on remote hosts — would have passed the danger gate
    # on a plain approval. Same class as the Sliver binaries; purely additive.
    "powershell-empire",
    # The build-#4 evasion generators. Same reasoning as the Sliver binaries above: neither
    # name matched anything here, so an artifact build would have passed the danger gate on a
    # plain approval with no red-confirm. They generate a runnable payload, which is exactly
    # what this set exists to flag. `scarecrow` is matched lowercased, as every entry is.
    "donut", "scarecrow",
    # Same class again: Invoke-Obfuscation takes a script and emits a runnable, obfuscated
    # payload. It sat in the catalog (evasion) producing zero reasons while donut and ScareCrow
    # — which do the identical job — both tripped the confirm.
    "invoke-obfuscation",
    "covenant", "cobaltstrike", "beacon",
})
# Covert channels and pivots — a tunnel is a C2 path and an exfil path in one, and it moves
# arbitrary traffic to somewhere the operator has NOT been gated against. `chisel` and the
# ligolo binaries used to live in _FRAMEWORKS with a "payload generator" label that was simply
# untrue of them; the honest reason matters because the operator reads it.
#
# NOTE the ligolo entry: the set said `ligolo`, but the binary this repo actually runs is
# `ligolo-proxy` (cockpit/tunnels.py builds `["ligolo-proxy", "-selfcert", ...]`). Exact-basename
# matching meant the entry could never fire — the `sliver` vs `sliver-client` bug, repeated in a
# set entry added after that bug was fixed. A name that can never match is worse than no entry:
# it reads as coverage.
_TUNNEL_TOOLS = frozenset({
    "chisel", "ligolo-proxy", "ligolo-agent", "ligolo-ng",
    # DNS tunnels — a full C2/exfil channel that survives egress filtering.
    "dnscat2", "dnscat2-client", "dnscat2-server", "iodine", "iodined",
    "ptunnel", "icmpsh", "gost",
    # sshuttle needs no agent and no listener — just SSH credentials — which makes it the
    # QUIETEST way to put a whole subnet inside reach, not a lesser one. It belongs here on
    # what it DOES (moves arbitrary traffic into a network the operator has not been gated
    # against), which is the same test chisel and ligolo are held to.
    "sshuttle",
})
# Wrappers that execute ANOTHER program: the danger is the program, not the wrapper. Left
# unhandled, `proxychains -q weevely ...` produced ZERO reasons while bare `weevely` produced
# one — routing a command through a tunnel silently stripped its red-confirm, and
# cockpit/tunnels.py's wrap_command builds exactly that argv (`proxychains -q <cmd> <args>`) for
# the human to approve. The fix is in the PREDICATE: unwrap, then classify the inner command.
_PROXY_WRAPPERS = frozenset({"proxychains", "proxychains4", "proxychains-ng"})
# Wrapper flags to step over while looking for the inner command. `-f` takes a config path, so
# its VALUE must be skipped too or the config file would be read as the command.
_WRAPPER_VALUE_FLAGS = frozenset({"-f", "--config"})


def _unwrap_wrapper(cmd: str, args: list[str]) -> tuple[str, list[str]] | None:
    """(inner_command, inner_args) if ``cmd`` is a wrapper that runs another program.

    Returns None when it is not a wrapper, or when no inner command follows (a bare
    ``proxychains`` runs nothing and is correctly clean).
    """
    if cmd not in _PROXY_WRAPPERS:
        return None
    i = 0
    while i < len(args):
        a = str(args[i])
        if a in _WRAPPER_VALUE_FLAGS:
            i += 2
            continue
        if a.startswith("-"):
            i += 1
            continue
        return a, [str(x) for x in args[i + 1:]]
    return None


# Tools whose entire purpose is turning a vulnerability into command execution or an interactive
# shell ON the target. `weevely` also GENERATES the webshell it then drives, so it is a payload
# generator and a shell client in one binary.
_RCE_TOOLS = frozenset({
    "commix", "sstimap", "tplmap", "weevely", "weevely3",
})
# Installs something that will execute a payload later, without the operator present.
_PERSISTENCE_TOOLS = frozenset({"sharpersist"})
# Flags that mean "run this inline code / command".
_EVAL_FLAGS = frozenset({"-c", "-e", "--command", "--eval", "--exec", "-code"})
# Argument shapes that turn an otherwise-clean tool into OS command execution or a file write
# on the TARGET. Deliberately specific: `sqlmap --dbs` must stay clean (it is the ordinary
# enumeration path and is regression-locked in test_cockpit.py) while `sqlmap --os-shell` — the
# same binary, dropping to a shell on the database host — must not.
_RCE_ARG_MARKERS = (
    "--os-shell", "--os-cmd", "--os-pwn", "--os-bof", "--os-smbrelay",
    "--file-write", "--file-dest", "xp_cmdshell",
)
# Per-tool flags that mean "run this command on the remote host". Keyed by tool because the
# flag letters are not distinctive on their own: `ldapsearch -x` is simple authentication and
# must stay clean (regression-locked in test_adorch_safety.py), while `netexec -x` is remote
# command execution. Matched case-sensitively — netexec's -x (cmd) and -X (powershell) are
# different flags.
_TOOL_EXEC_FLAGS: dict[str, frozenset[str]] = {
    "netexec": frozenset({"-x", "-X", "--exec-method"}),
    "nxc": frozenset({"-x", "-X", "--exec-method"}),
    "crackmapexec": frozenset({"-x", "-X", "--exec-method"}),
    "cme": frozenset({"-x", "-X", "--exec-method"}),
}
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
# (the name normaliser these sets are matched against is :func:`_tool_name`, defined above —
# it is now shared with the interpreter/exec/framework sets rather than being AD-only.)

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
    # impacket's MSSQL client is the sibling of the four above: it authenticates to a database
    # host and its catalogued path from there is `enable_xp_cmdshell`, i.e. OS command execution
    # on that host. It produced no reason at all while psexec/wmiexec/smbexec all did.
    "mssqlclient", "enable_xp_cmdshell",
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
    base = _tool_name(command)
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
    frameworks and payload generators, covert tunnels, vulnerability-to-shell tools,
    persistence installers, AD abuse shapes, per-tool remote-exec flags, and
    reverse-shell/code-exec shapes anywhere in the args.

    The binary name is normalised ONCE, by :func:`_tool_name`, so a path prefix, a case
    difference and a ``.py``/``.exe``/``.ps1`` suffix all resolve to the same entry. Every set
    here is matched against that normalised name. The expected verdict for every tool in the
    catalog is pinned by the catalog's own safety tests — a tool added there without an explicit
    classification fails the suite, which is what stops this drifting again.

    A proxychains-style WRAPPER is unwrapped first and the inner command is classified in its
    place, because the wrapper is not what runs. The signature stays ``(command, args)`` —
    test_winrm_safety pins it, so the unwrap is a bounded loop, not a recursion parameter.
    """
    reasons: list[str] = []
    # /usr/bin/python3, ./x, powershell.exe, secretsdump.py — one normaliser for every set.
    cmd = _tool_name(command)

    # A wrapper carries no payload of its own; the command it RUNS does. Peel the wrappers off
    # and classify what is actually executed, keeping the wrapper visible in the reason so the
    # operator reads "through proxychains: weevely: turns a vulnerability into ..." rather than
    # nothing at all. Bounded, because `proxychains proxychains ...` is a legal argv.
    prefix: list[str] = []
    for _ in range(3):
        inner = _unwrap_wrapper(cmd, args)
        if inner is None:
            break
        prefix.append(cmd)
        # `command` moves too: _ad_abuse_reasons does its own normalising and must see the
        # command that actually RUNS, or `proxychains secretsdump.py` loses its AD verdict.
        command, args = inner
        cmd = _tool_name(command)
    lead = "".join(f"through {p}: " for p in prefix)

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
    if cmd in _TUNNEL_TOOLS:
        reasons.append(f"{cmd}: covert tunnel / C2 channel — carries arbitrary traffic")
    if cmd in _RCE_TOOLS:
        reasons.append(f"{cmd}: turns a vulnerability into command execution / a shell")
    if cmd in _PERSISTENCE_TOOLS:
        reasons.append(f"{cmd}: installs persistence that executes a payload")

    # Argument shapes that turn an otherwise-clean tool into remote command execution.
    exec_flags = sorted(flags & _TOOL_EXEC_FLAGS.get(cmd, frozenset()))
    if exec_flags:
        reasons.append(f"{cmd} {'/'.join(exec_flags)}: remote command execution on the target")

    # AD ABUSE — credential replication, remote exec on a domain host, directory writes.
    # Additive: it can only ever ADD reasons, so every command flagged before is still flagged.
    reasons.extend(_ad_abuse_reasons(command, args))

    # scan the whole arg vector for reverse-shell / code-exec shapes (payloads, one-liners)
    blob = " ".join(str(a) for a in args).lower()
    for marker in _SHELL_MARKERS:
        if marker in blob:
            reasons.append(f"reverse-shell / code-exec pattern: {marker!r}")
    for marker in _RCE_ARG_MARKERS:
        if marker in blob:
            reasons.append(f"argument requests OS command execution / file write: {marker!r}")

    # de-dup, preserve order. `lead` names any wrapper that was peeled off, so the reason the
    # operator reads matches the argv they are approving.
    seen: set[str] = set()
    out: list[str] = []
    for r in reasons:
        if r not in seen:
            seen.add(r)
            out.append(lead + r)
    return out


# --------------------------------------------------------------------------- #
# THE WHOLE-SCRIPT HEURISTIC (the WinRM transport)
#
# WHY THIS EXISTS, SEPARATELY FROM THE ONE ABOVE. On the docker path the executor passes an
# ARGV LIST to `docker exec` — no shell, so `;` and `|` are literal tokens nothing interprets,
# and classifying argv[0] is a fair model of what runs. On the WinRM path it is not: the
# executor JOINS command + args into one string and the Windows transport hands the whole thing
# to PowerShell, where `;`, `|` and newlines are live statement separators. Classifying
# only the first token meant `Write-Host go ; Invoke-Mimikatz` ran on a real domain-joined host,
# under real credentials, with no red-confirm. You defeated the gate by moving a cmdlet one
# token to the right.
#
# WHY THIS DOES NOT PARSE POWERSHELL. The obvious fix — split into statements, classify each
# statement's first token — needs a correct PowerShell tokeniser: quoting, `$( )`
# subexpressions, the `&` call operator, backtick escapes, line continuations. Any parser
# written here becomes a NEW bypass surface, which is precisely the bug being fixed: the
# classifier's model of the input was narrower than the input. So every marker is looked for
# EVERYWHERE in the joined string. There is no "position" to exploit, and that is the property
# the argv version lacks.
#
# THE COST IS ALERT FATIGUE, AND IT IS MANAGED, NOT IGNORED. Whole-string scanning over-flags
# by design (a path containing `nc`, a comment naming a cmdlet). That is acceptable ONLY because
# this gate raises a red-confirm, never a block: a false positive costs one click, a false
# negative runs Mimikatz on a domain controller. But an operator who sees a generic red banner
# on everything learns to click through it, at which point a silent bypass has merely been
# traded for a decorative one. So EVERY reason names the marker it matched and the offset it
# matched at — a reason the operator can evaluate is a gate; a banner they cannot is theatre.
# --------------------------------------------------------------------------- #

# PowerShell-native code execution, download cradles and evasion shapes. A NAME-based scan
# alone is defeated by a download cradle: `IEX (New-Object Net.WebClient).DownloadString(...)`
# never spells the payload's name anywhere, so the CRADLE has to be the marker.
_PS_SHAPE_MARKERS: tuple[tuple[str, str], ...] = (
    ("invoke-expression", "executes a string as code (download cradle)"),
    ("iex", "Invoke-Expression alias — executes a string as code"),
    ("downloadstring", "fetches remote code into memory (download cradle)"),
    ("downloadfile", "fetches a remote file to disk"),
    ("downloaddata", "fetches remote bytes into memory"),
    ("net.webclient", "web client — the classic download-cradle object"),
    ("invoke-webrequest", "fetches remote content (cradle half)"),
    ("invoke-restmethod", "fetches remote content (cradle half)"),
    ("frombase64string", "decodes an embedded blob — a payload carrier"),
    ("add-type", "compiles and loads arbitrary C# in-process"),
    ("reflection.assembly", "loads an assembly reflectively — fileless execution"),
    ("start-process", "starts another program on the host"),
    ("invoke-command", "runs a script block on a (possibly remote) host"),
    ("invoke-wmimethod", "remote method invocation via WMI"),
    ("invoke-cimmethod", "remote method invocation via CIM"),
    # Both of these were found by MEASURING the classifier against the real AD corpus
    # (Task 1 Step 6) rather than by reading the sets: `Invoke-SQLOSCmd` is OS command
    # execution on a SQL host, and `Enter-PSSession`/`New-PSSession` is a SECOND hop to
    # another box from inside an existing WinRM session — lateral movement. Both were
    # catalogued, both were silent.
    ("invoke-sqloscmd", "OS command execution on a SQL host"),
    ("enter-pssession", "opens an interactive remote session — a further hop"),
    ("new-pssession", "opens a remote session — a further hop"),
    ("new-service", "installs a service — persistence that executes a payload"),
    ("register-scheduledtask", "installs a scheduled task — persistence"),
    ("schtasks", "schedules a task — persistence"),
    ("set-mppreference", "changes Defender's configuration — AV tampering"),
    ("add-mppreference", "adds a Defender exclusion — AV tampering"),
    ("amsiinitfailed", "AMSI bypass"),
    ("amsiutils", "AMSI internals — bypass shape"),
    # mimikatz MODULE SYNTAX. `sekurlsa` and `lsadump` were already reachable through
    # _AD_DUMP_MARKERS, but `kerberos::list /export` — which writes every TGT/TGS in the
    # session to disk, i.e. the input to a pass-the-ticket — matched nothing at all. The
    # `module::` spelling is unmistakable and appears in no legitimate PowerShell, so this
    # costs nothing in confirm fatigue.
    ("kerberos::", "mimikatz Kerberos module — exports/injects tickets"),
    ("crypto::", "mimikatz crypto module — exports keys and certificates"),
    ("vault::", "mimikatz vault module — reads stored credentials"),
    ("token::", "mimikatz token module — impersonates another user"),
    ("privilege::debug", "acquires SeDebugPrivilege — the mimikatz prelude"),
    ("-windowstyle hidden", "hides the window — delivery shape"),
    ("bypass -", "execution-policy bypass"),
    ("executionpolicy bypass", "execution-policy bypass"),
)

# PowerShell accepts any unambiguous PREFIX of a parameter name, so `-e`, `-en`, `-enc`,
# `-encodedcommand` are all the same flag. Matching only the spellings a human would type is
# how a text scan gets walked around, so every prefix is matched — and the flag must END there
# (`-ErrorAction` is not `-e`).
_ENCODED_FLAG_RE = re.compile(
    r"(?<![\w-])-e(?:n(?:c(?:o(?:d(?:e(?:d(?:c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?)?)?)?)?)?)?)?"
    r"(?![\w-])\s+(\S+)",
    re.I,
)
# NOTE the `\S+` capture. It used to be `[A-Za-z0-9+/=]+`, i.e. "capture it only if it already
# looks like base64" — which quietly skipped any payload that did not, so a blob the classifier
# could not read was not reported at all. That is the same defect this whole module is fixing:
# a condition narrower than the input. Capture whatever follows the flag, then let
# :func:`_decode_encoded_command` judge it, and report the ones that will not decode.


def _script_name_markers() -> tuple[tuple[str, str], ...]:
    """``(binary-or-cmdlet name, why it is dangerous)`` for every set the argv heuristic uses.

    Built from the SAME sets rather than a hand-copied list, so a name added for the docker
    path is automatically looked for in a PowerShell script too. That shared derivation is the
    point: two lists would drift, and drift is what produced this bug.

    ``_AD_WRITE_SUBCOMMANDS`` is deliberately NOT included: its verbs are 2-4 character
    fragments (``ca``, ``req``, ``cert``) that are meaningless outside their tool's argv and
    would match half of every ordinary script. A confirm that fires on everything is one the
    operator learns to click through.
    """
    groups: tuple[tuple[frozenset[str], str], ...] = (
        (_INTERPRETERS, "language interpreter — runs arbitrary code"),
        (_EXEC_TOOLS, "raw network tool — can carry a reverse shell"),
        (_FRAMEWORKS, "exploitation framework / payload generator"),
        (_TUNNEL_TOOLS, "covert tunnel / C2 channel — carries arbitrary traffic"),
        (_RCE_TOOLS, "turns a vulnerability into command execution / a shell"),
        (_PERSISTENCE_TOOLS, "installs persistence that executes a payload"),
        (_AD_CRED_DUMP, "dumps/replicates domain credentials"),
        (_AD_REMOTE_EXEC, "remote code execution on a domain host"),
        (_AD_DIR_WRITE, "modifies the directory / coerces or relays authentication"),
        (_AD_PS_WRITE, "writes the directory / resets a credential (PowerView/.NET)"),
    )
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for names, why in groups:
        for name in sorted(names):
            if name not in seen:
                seen.add(name)
                out.append((name, why))
    return tuple(out)


_SCRIPT_NAME_MARKERS = _script_name_markers()
# One compiled word-boundary pattern per name. Word-boundary rather than bare substring so
# `nc` does not match every `Get-Content`; whole-string rather than first-token so position
# cannot be exploited.
_SCRIPT_NAME_RES: tuple[tuple[re.Pattern[str], str, str], ...] = tuple(
    (re.compile(rf"(?<![\w.-]){re.escape(name)}(?![\w-])"), name, why)
    for name, why in _SCRIPT_NAME_MARKERS
)
# Shape markers are matched as plain substrings — they are already distinctive
# (`/dev/tcp/`, `downloadstring`, `--os-shell`) and several contain spaces or punctuation
# that a word-boundary pattern would fight with.
_SCRIPT_SHAPE_MARKERS: tuple[tuple[str, str], ...] = (
    _PS_SHAPE_MARKERS
    + tuple((m, "reverse-shell / code-exec pattern") for m in _SHELL_MARKERS)
    + tuple((m, "requests OS command execution / a file write") for m in _RCE_ARG_MARKERS)
    + tuple((m, "credential-dump flag") for m in _AD_DUMP_MARKERS)
)

_MAX_DECODE_DEPTH = 2


def _decode_encoded_command(payload: str) -> str | None:
    """The plaintext behind a ``-EncodedCommand`` blob, or ``None`` if it will not decode.

    PowerShell encodes UTF-16LE; UTF-8 is tried as a fallback because operators and tooling
    produce both. ``None`` is a FINDING, not a pass — see :func:`dangerous_script_heuristic`.
    """
    if len(payload) < 8:
        return None
    try:
        raw = base64.b64decode(payload, validate=True)
    except (ValueError, binascii.Error):
        return None
    for encoding in ("utf-16-le", "utf-8"):
        try:
            text = raw.decode(encoding)
        except UnicodeDecodeError:
            continue
        # A wrong guess decodes to mojibake; require it to look like text before trusting it.
        printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in text)
        if text and printable / len(text) > 0.9:
            return text
    return None


def dangerous_script_heuristic(script: str, _depth: int = 0) -> list[str]:
    """Reasons this WHOLE PowerShell script looks dangerous (empty if it does not).

    Scans the entire joined string for every marker, everywhere — see the block comment above
    for why this deliberately does not parse PowerShell. Every reason names the matched marker
    and the offset it matched at, so the red-confirm states a specific claim the operator can
    evaluate rather than a generic warning they learn to click through.

    ``-EncodedCommand`` payloads are decoded and re-scanned: base64 defeats every text scan by
    construction. A payload that will NOT decode is itself reported — an opaque blob that the
    classifier cannot read must never pass as clean.
    """
    text = str(script or "")
    low = text.lower()
    reasons: list[str] = []

    for pattern, name, why in _SCRIPT_NAME_RES:
        m = pattern.search(low)
        if m:
            reasons.append(f"powershell script: {name!r} at offset {m.start()} — {why}")
    for marker, why in _SCRIPT_SHAPE_MARKERS:
        idx = low.find(marker)
        if idx >= 0:
            reasons.append(f"powershell script: {marker!r} at offset {idx} — {why}")

    # ENCODED COMMANDS. Decode and re-scan; an undecodable blob IS the finding.
    if _depth < _MAX_DECODE_DEPTH:
        for m in _ENCODED_FLAG_RE.finditer(text):
            payload = m.group(1)
            decoded = _decode_encoded_command(payload)
            if decoded is None:
                reasons.append(
                    f"powershell script: encoded payload at offset {m.start(1)} COULD NOT BE "
                    "DECODED — an opaque -EncodedCommand blob cannot be classified, so it is "
                    "reported rather than passed"
                )
                continue
            for inner in dangerous_script_heuristic(decoded, _depth + 1):
                reasons.append(
                    f"powershell script: -EncodedCommand at offset {m.start(1)} decodes to a "
                    f"script that trips — {inner}"
                )

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
