"""Redact credential VALUES out of an argv before the run is PERSISTED.

WHY THIS EXISTS (found by build #9's live fire, not by the hermetic suite)
--------------------------------------------------------------------------
The WinRM path never puts a secret on a command line: ``windows_profile_id`` names a profile
and the executor resolves the credential server-side, so the password exists only inside the
transport (see cockpit/winprofiles.py). Every LINUX credentialed tool works the opposite way —
``bloodhound-python -u admin -d corp.local -p <password>`` carries the secret as an argv token,
because that is the only interface the tool has.

That token used to be stored verbatim in the RunRecord. The AD collector's own PREVIEW endpoint
already masked it (``adgraph/router.py::ad_collect_preview``), which shows the sensitivity was
understood — but the preview is not where it persisted. Running a real collection against a real
domain put the domain administrator's cleartext password into:

  * the durable run record (``GET /cockpit/runs/{id}``, and the gitignored sessions.db),
  * every report rendered from that run (report.py reads ``run["args"]``),
  * and — the one that actually matters — the run HISTORY that is fed to the LLM as proposer
    context (orchestrator.py / reasoning/ledger.py both join ``run["args"]`` into the prompt).

So an operator who collected a domain shipped their DA password to the model. Redacting at the
record boundary closes all three at once, because all three read the stored record.

WHAT IT DOES NOT DO. It does not touch the argv that is EXECUTED — the tool still receives the
real credential, or nothing would work. It does not touch the live event stream either: those
events go only to the human who just typed the password, and rewriting them risks breaking a
caller that echoes them. The durable artefacts are the leak; those are what this fixes.

PER-TOOL BY CONSTRUCTION, NEVER A BLANKET FLAG LIST. ``-p`` means *password* to netexec and
*ports* to nmap. A global "-p takes a secret" rule would rewrite every ``nmap -p 445`` record
into ``nmap -p <redacted>`` and quietly destroy the audit trail it is supposed to protect. So a
flag is only ever consulted for a tool KNOWN to take a credential there.
"""

from __future__ import annotations

import re

REDACTED = "<redacted>"

# Flags whose FOLLOWING token is a credential, per tool. Case-sensitive on purpose: `-H` is a
# hash for netexec while `-h` is help, and redacting the token after `-h` would corrupt a record
# for no reason. Keys are matched after :func:`_normalize` (basename, `.exe`/`.py` stripped).
_SECRET_FLAGS: dict[str, frozenset[str]] = {
    "bloodhound-python": frozenset({"-p", "--password", "--hashes", "-aesKey"}),
    "bloodhound-ce-python": frozenset({"-p", "--password", "--hashes", "-aesKey"}),
    "netexec": frozenset({"-p", "--password", "-H", "--hash", "--hashes"}),
    "nxc": frozenset({"-p", "--password", "-H", "--hash", "--hashes"}),
    "crackmapexec": frozenset({"-p", "--password", "-H", "--hash", "--hashes"}),
    "cme": frozenset({"-p", "--password", "-H", "--hash", "--hashes"}),
    "evil-winrm": frozenset({"-p", "--password", "-H", "--hash"}),
    "smbmap": frozenset({"-p", "--password", "-H"}),
    "ldapsearch": frozenset({"-w"}),
    "kerbrute": frozenset({"-p", "--password"}),
    "smbclient": frozenset({"--password"}),
    "certipy": frozenset({"-p", "-password", "-hashes"}),
    "certipy-ad": frozenset({"-p", "-password", "-hashes"}),
}

# Every impacket example script takes the same credential flags, and Kali installs them both as
# `impacket-secretsdump` and `secretsdump.py`. One rule covers the whole family.
_IMPACKET_FLAGS = frozenset({"-p", "-password", "-hashes", "-aesKey", "-pwd"})
_IMPACKET_NAMES = frozenset({
    "secretsdump", "wmiexec", "psexec", "smbexec", "atexec", "dcomexec", "getuserspns",
    "getnpusers", "getadusers", "gettgt", "getst", "ntlmrelayx", "mssqlclient", "smbclient",
    "rpcdump", "samrdump", "lookupsid", "reg", "services", "addcomputer", "changepasswd",
    "dpapi", "findelevatedservices", "goldenpac", "karmasmb", "mimikatz", "netview",
    "ticketer", "raisechild", "rbcd", "describeticket", "owneredit", "dacledit",
})

# The impacket/`evil-winrm`-style positional: `DOMAIN/user:password@host` (domain optional).
# Anchored and deliberately narrow — a URL (`http://…`) has no `:` before an `@`, and a bare
# `user@host` has no password to mask, so neither matches.
# THE SECRET SPAN IS GREEDY, AND THAT IS THE WHOLE SUBTLETY. Passwords contain `@`. A
# non-greedy `[^@]+` span splits on the FIRST `@`, which leaves the rest of the password in the
# "host" tail and writes it to the record in the clear — build #9's live DCSync run stored
# `Administrator:<redacted>@2005@dc.corp.local`, publishing `2005` out of an 8-character
# password. A hostname cannot contain `@`, so the LAST `@` is always the real separator: pin the
# tail to `[^@\s]+` and let the secret take everything before it.
_CRED_POSITIONAL = re.compile(
    r"^(?P<head>(?:[^/@:\s]+/)?[^/@:\s]+:)(?P<secret>.+)(?P<tail>@[^@\s]+)$"
)


def _normalize(command: str) -> str:
    """The bare tool name: no directory, no `.exe`/`.py` suffix, lowercased."""
    name = (command or "").strip().replace("\\", "/").rsplit("/", 1)[-1].lower()
    for suffix in (".exe", ".py"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
    return name


def secret_flags_for(command: str) -> frozenset[str]:
    """The flags that carry a credential FOR THIS TOOL — empty for anything unknown.

    Empty is the safe default: an unknown tool's argv is stored verbatim, exactly as before.
    This function is the whole reason `nmap -p 445` survives untouched.
    """
    name = _normalize(command)
    if name in _SECRET_FLAGS:
        return _SECRET_FLAGS[name]
    impacket = name[len("impacket-"):] if name.startswith("impacket-") else name
    if impacket in _IMPACKET_NAMES:
        return _IMPACKET_FLAGS
    return frozenset()


def redact_argv(command: str, args: list[str]) -> list[str]:
    """``args`` with credential values replaced by ``<redacted>``. Never raises.

    Three shapes are covered: ``-p secret`` (value in the next token), ``--password=secret``
    (value after ``=``), and the impacket positional ``DOMAIN/user:secret@host`` (only the
    password span is masked, so the record still shows WHO ran against WHAT).
    """
    flags = secret_flags_for(command)
    out: list[str] = []
    expect_secret = False
    for raw in args or []:
        token = str(raw)
        if expect_secret:
            out.append(REDACTED)
            expect_secret = False
            continue
        if flags and token in flags:
            out.append(token)
            expect_secret = True
            continue
        if flags and "=" in token:
            head = token.split("=", 1)[0]
            if head in flags:
                out.append(f"{head}={REDACTED}")
                continue
        match = _CRED_POSITIONAL.match(token)
        if match and flags:
            out.append(f"{match.group('head')}{REDACTED}{match.group('tail')}")
            continue
        out.append(token)
    return out


__all__ = ["REDACTED", "redact_argv", "secret_flags_for"]
