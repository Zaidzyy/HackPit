"""The hardcoded safe command set + pure validation.

This module contains **no execution** — only the allowlist data and pure functions
that decide whether a (command, args) pair is permitted. It is safe to import and
unit-test before any sandbox exists, and it is one of the three independent safety
layers (see docs/cockpit-plan.md §c, Layer 3).

Two command MODES (this is the load-bearing distinction):

* RECON tools (``nmap``/``curl``/``whatweb``) — ``active=False`` (STRICT). Every flag must
  be on that command's ``allowed_flags`` or the request is rejected at the allowlist gate,
  naming the offending flag; args must be metachar-free. ``allowed_flags`` is authoritative,
  not advisory. Recon stays locked down — nothing here loosens it.
* ACTIVE web-exploitation tools (``sqlmap``/``ffuf``/``nuclei``) — ``active=True``. Full
  capability: ALL flags are permitted (no flag-allowlist rejection), because these tools
  legitimately need dangerous flags and metacharacter payloads to exploit the lab. The
  safety promise here is NOT "block the dangerous flag" but "you can't approve it by
  ACCIDENT": each command's ``dangerous_flags`` are DETECTED (never blocked) in every form
  by the hardened parser, shown RED, and require an explicit second confirmation to run
  (see :func:`dangerous_flags_present`; enforced by the executor's danger gate).

The load-bearing defenses for active tools (the risk turn): argv exec (no shell → metachars
can't inject); per-tool target-lock (each tool bound to the lab via its ``target_flags``);
isolation (no egress); human approval + RED-CONFIRM on dangerous flags; and the hardened
parser reliably DETECTING every dangerous flag (a missed form = a silent dangerous approval).

Extending the set — commands, a recon command's ``allowed_flags``, or a ``dangerous_flags``
set — is a deliberate, reviewed code change (a frozen-schema test trips on any change).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

# Characters that must never appear in an argument. We exec argv-style (no shell),
# so these cannot cause injection here — this is belt-and-suspenders and also keeps
# the audit log clean/greppable.
_FORBIDDEN_CHARS = set(";|&$`\n\r<>\\!*")


@dataclass(frozen=True)
class CommandSpec:
    """One allowlisted command and how its args are permitted."""

    name: str
    description: str
    # RECON (active=False): the STRICT flag allowlist — any flag not resolvable to this set
    # is rejected. Entries are canonical flag tokens: short (``-s``), atomic multi-char
    # (``-sV``, ``-T4``, ``-p-``), long (``--color``), or a pinned long=value form
    # (``--color=never``, allowing only that exact value).
    # ACTIVE (active=True): NOT used for rejection — all flags are permitted. Still used by
    # the parser to recognize atomic multi-char short flags so they aren't mis-decomposed.
    allowed_flags: frozenset[str] = field(default_factory=frozenset)
    # Flags that consume the FOLLOWING token as their value (recon: nmap ``-p 3000``, curl
    # ``-X GET``; active: sqlmap ``-u <url>``/``--data <payload>``, ffuf ``-u``/``-w``…).
    # Needed so a value — even one that looks like a flag, a negative number, or a
    # metachar-laden payload — is treated as a value, not misread as a flag.
    value_flags: frozenset[str] = field(default_factory=frozenset)
    # ACTIVE tools only: all flags permitted (no strict flag-allowlist rejection), and
    # metachars are allowed in VALUE args (payloads) — never in flag names, never for recon.
    active: bool = False
    # ACTIVE tools only: the escalation flags to DETECT (never block) and surface RED —
    # anything that runs code, touches the target's OS/filesystem, or loads arbitrary
    # code/config. Detected in EVERY form by the hardened parser; a match requires an
    # explicit confirm before the command can run.
    dangerous_flags: frozenset[str] = field(default_factory=frozenset)
    # ACTIVE tools only: the flag(s) whose VALUE is the target (sqlmap ``-u``/``--url``,
    # ffuf ``-u``, nuclei ``-u``/``-target``, nikto ``-h``). The target-lock binds each of
    # these to the lab. A subset of ``value_flags``.
    target_flags: frozenset[str] = field(default_factory=frozenset)
    # Max number of args (flags + operands) accepted, a rough DoS/typo guard.
    max_args: int = 24
    # Optional extra per-command validator: (args) -> (ok, reason).
    extra: Callable[[list[str]], tuple[bool, str]] | None = None


def _nmap_extra(args: list[str]) -> tuple[bool, str]:
    # Disallow nmap's script engine + output-to-file in M1 (broadens surface).
    # These also fall outside ``allowed_flags`` (so the strict flag gate would reject
    # them too), but this runs first to give the precise, recon-scope reason the
    # regression tests assert ("scripting" / "file output").
    for a in args:
        low = a.lower()
        if low.startswith("--script") or low == "-sc" or low == "-a":
            return False, "nmap scripting (--script/-sC/-A) is out of M1 scope"
        if low in ("-on", "-ox", "-og", "-oa"):
            return False, "nmap file output is out of M1 scope"
    return True, ""


# The M1 safe set. Recon-only, web-module first, lab-target only.
ALLOWLIST: dict[str, CommandSpec] = {
    "nmap": CommandSpec(
        name="nmap",
        description="Port/service scan of the lab target.",
        allowed_flags=frozenset(
            {"-sV", "-sT", "-sS", "-p", "-p-", "-T4", "-T3", "-Pn", "-n", "-oN-"}
        ),
        value_flags=frozenset({"-p"}),  # -p 80,443  (note: -p- = all-ports, atomic)
        extra=_nmap_extra,
    ),
    "curl": CommandSpec(
        name="curl",
        description="Fetch a URL from the lab target.",
        allowed_flags=frozenset({"-s", "-S", "-i", "-I", "-L", "-v", "-X"}),
        value_flags=frozenset({"-X"}),  # -X GET  (method is a value, not a flag)
        max_args=12,
    ),
    "whatweb": CommandSpec(
        name="whatweb",
        description="Fingerprint the lab target's web stack.",
        allowed_flags=frozenset({"-a", "--color=never", "-v"}),
        max_args=8,
    ),
    # --- ACTIVE web-exploitation tools (all-flags; dangerous flags detected + red-confirm) ---
    "sqlmap": CommandSpec(
        name="sqlmap",
        description="SQL-injection exploitation against the lab (all flags; dangerous flags need confirm).",
        active=True,
        # target is -u/--url; other value-flags listed so payloads/values aren't misread as flags.
        target_flags=frozenset({"-u", "--url"}),
        value_flags=frozenset(
            {
                "-u", "--url", "-p", "--data", "-r", "--cookie", "-H", "--header", "--headers",
                "--method", "-D", "-T", "-C", "-U", "--dbms", "--level", "--risk", "--technique",
                "--tamper", "--proxy", "--user-agent", "-A", "--threads", "--time-sec",
                "--os-cmd", "-e", "--eval", "--file-read", "--file-write", "--file-dest",
                "--sql-query", "--dbms-cred", "--config", "-c",
            }
        ),
        # Runs code / touches the target OS or filesystem / loads arbitrary scripts.
        dangerous_flags=frozenset(
            {
                "--os-shell", "--os-cmd", "--os-pwn", "--os-bof", "--os-smbrelay",
                "--sql-shell", "-e", "--eval",
                "--file-read", "--file-write", "--file-dest",
                "--tamper",  # loads arbitrary tamper (Python) scripts
            }
        ),
        max_args=40,
    ),
    "ffuf": CommandSpec(
        name="ffuf",
        description="Web fuzzer against the lab (all flags; dangerous flags need confirm).",
        active=True,
        target_flags=frozenset({"-u"}),
        value_flags=frozenset(
            {
                "-u", "-w", "-H", "-X", "-d", "-b", "-t", "-p", "-rate", "-timeout",
                "-o", "-of", "-mc", "-ms", "-mr", "-ml", "-fc", "-fs", "-fw", "-fl", "-fr",
                "-recursion-depth", "-replay-proxy", "-config", "-x", "-maxtime",
            }
        ),
        # -config loads an arbitrary ffuf config (can carry any option, incl. a proxy/replay).
        dangerous_flags=frozenset({"-config"}),
        max_args=40,
    ),
    "nuclei": CommandSpec(
        name="nuclei",
        description="Template scanner against the lab (all flags; dangerous flags need confirm).",
        active=True,
        target_flags=frozenset({"-u", "-target"}),
        value_flags=frozenset(
            {
                "-u", "-target", "-l", "-t", "-templates", "-w", "-tags", "-etags", "-itags",
                "-severity", "-H", "-o", "-c", "-rl", "-rate-limit", "-timeout", "-retries",
                "-proxy", "-interactsh-server", "-mc", "-ec",
            }
        ),
        # -code enables code-protocol templates (arbitrary code exec); -headless drives a browser.
        dangerous_flags=frozenset({"-code", "-headless"}),
        max_args=40,
    ),
}


def is_allowed_command(command: str) -> bool:
    """True iff ``command`` is in the hardcoded allowlist."""
    return command in ALLOWLIST


def is_active(command: str) -> bool:
    """True iff ``command`` is an ACTIVE (all-flags, dangerous-flag-detected) tool."""
    spec = ALLOWLIST.get(command)
    return spec is not None and spec.active


def has_forbidden_chars(token: str) -> bool:
    """True iff a token contains any shell-metachar we refuse to pass along."""
    return any(c in _FORBIDDEN_CHARS for c in token)


def _is_flag_token(token: str) -> bool:
    """True if a token is flag-shaped (a leading '-' plus at least one more char).

    A lone ``-`` (stdin) is an operand, not a flag; so are bare words and negative
    numbers/flag-like strings when they are the VALUE of a preceding value-flag (the
    walk consumes those before they reach here). Only flag-shaped tokens that are NOT
    such a value are checked against the per-command ``allowed_flags``.

    Note ``--`` (POSIX end-of-options) IS flag-shaped and is deliberately NOT honored
    as an operand marker — honoring it would switch off flag enforcement (and, via
    :func:`extract_hostish`, the target-lock) for every token after it, a fail-open
    hole. It is instead treated as an un-listed flag and rejected. No recon command
    needs it.
    """
    return len(token) >= 2 and token[0] == "-"


def _check_long_flag(
    token: str, allowed: frozenset[str], value_flags: frozenset[str]
) -> tuple[str | None, bool]:
    """Resolve a ``--long`` token. Returns (offending_token_or_None, takes_next_value).

    Forms: ``--flag`` (bool), ``--flag=value`` (=-joined). A pinned ``--flag=value``
    entry (e.g. ``--color=never``) permits only that exact value; a ``--flag`` that is a
    value-flag permits any ``--flag=value``.
    """
    if "=" in token:
        if token in allowed:  # pinned exact form, e.g. --color=never
            return None, False
        name = token.split("=", 1)[0]
        if name in allowed and name in value_flags:  # arbitrary value permitted
            return None, False
        return token, False
    if token in allowed:
        return None, token in value_flags
    return token, False


def _check_short_flag(
    token: str, allowed: frozenset[str], value_flags: frozenset[str]
) -> tuple[str | None, bool]:
    """Resolve a ``-short`` token. Returns (offending_flag_or_None, takes_next_value).

    An atomic multi-char flag (``-sV``, ``-T4``, ``-p-``) is matched whole first; else
    the token is treated getopt-style as a cluster where each letter is its own short
    flag (``-sI`` = ``-s`` + ``-I``). Every resolved flag must be in ``allowed``.

    A value-flag stops the cluster: its value is either the REMAINDER of this token
    (inline getopt form, ``-XGET`` = ``-X`` value ``GET``; ``-p3000``) or, if it is the
    last letter, the NEXT token (``takes_next_value=True``). Either way the value is
    never re-scanned as a flag — so a flag-like or negative-number value cannot be
    misread as an un-listed flag.
    """
    if token in allowed:  # atomic multi-char flag (-sV, -T4, -p-)
        return None, token in value_flags
    cluster = token[1:]  # getopt cluster: each letter is a short flag
    for idx, ch in enumerate(cluster):
        flag = "-" + ch
        if flag not in allowed:
            return flag, False
        if flag in value_flags:
            has_inline_value = idx + 1 < len(cluster)
            # inline value → consume within this token; else the value is the next one
            return None, not has_inline_value
    return None, False  # all boolean flags, no value follows


def _first_disallowed_flag(spec: CommandSpec, args: list[str]) -> str | None:
    """Return the first flag token not permitted for ``spec``, else None.

    Walks args left to right. Operands (non-flag tokens) and the value consumed by a
    declared value-flag are skipped — a value is never misread as a flag.
    """
    allowed = spec.allowed_flags
    value_flags = spec.value_flags
    i = 0
    n = len(args)
    while i < n:
        token = args[i]
        if not _is_flag_token(token):
            i += 1
            continue
        if token.startswith("--"):
            bad, takes_value = _check_long_flag(token, allowed, value_flags)
        else:
            bad, takes_value = _check_short_flag(token, allowed, value_flags)
        if bad is not None:
            return bad
        # a value-flag in space-separated form consumes the following token
        i += 2 if (takes_value and i + 1 < n) else 1
    return None


def extract_hostish(args: list[str]) -> list[str]:
    """Return arg tokens that look like a host/URL operand (not flags).

    Used by the executor's target-lock: every hostish token must be the lab.
    Pure heuristic — flags (starting with '-') and flag-values are skipped.
    """
    hostish: list[str] = []
    for a in args:
        if a.startswith("-"):
            continue
        hostish.append(a)
    return hostish


def validate(command: str, args: list[str]) -> tuple[bool, str]:
    """Pure validation of a (command, args) pair. Returns (ok, reason).

    Does NOT check the target lock (that needs config + belongs with the executor) nor the
    danger-confirm gate (dangerous flags are DETECTED, not blocked — see
    :func:`dangerous_flags_present`). This is purely: allowlisted command + sane args +
    per-command flag policy.

    RECON (strict): metachar-free args + every flag on ``allowed_flags``.
    ACTIVE (all-flags): every flag permitted; no flag-allowlist rejection. (E3 relaxes the
    metachar rule for VALUE args so payloads can carry metacharacters.)
    """
    if not is_allowed_command(command):
        return False, f"command '{command}' is not on the allowlist"
    spec = ALLOWLIST[command]

    if len(args) > spec.max_args:
        return False, f"too many args for '{command}' (max {spec.max_args})"

    if spec.active:
        # ACTIVE: all flags allowed (full capability). No flag-allowlist rejection. The
        # metachar check still runs here (belt) — E3 relaxes it to VALUE args only so
        # payloads can carry metacharacters (argv exec makes that safe).
        for a in args:
            if has_forbidden_chars(a):
                return False, f"argument contains a forbidden character: {a!r}"
        return True, ""

    # RECON (strict): metachar-free + strict per-command flag allowlist.
    for a in args:
        if has_forbidden_chars(a):
            return False, f"argument contains a forbidden character: {a!r}"

    # Per-command semantic rules (e.g. nmap scripting/output) run first so their precise
    # recon-scope reason wins; the strict flag gate below catches everything else.
    if spec.extra is not None:
        ok, reason = spec.extra(args)
        if not ok:
            return False, reason

    bad = _first_disallowed_flag(spec, args)
    if bad is not None:
        return False, f"flag '{bad}' is not permitted for '{command}'"

    return True, ""
