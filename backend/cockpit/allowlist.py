"""The hardcoded safe command set + pure validation.

This module contains **no execution** — only the allowlist data and pure functions
that decide whether a (command, args) pair is permitted. It is safe to import and
unit-test before any sandbox exists, and it is one of the three independent safety
layers (see docs/cockpit-plan.md §c, Layer 3).

Design:
* Only commands in ``ALLOWLIST`` may ever run.
* Args are validated conservatively: no shell metacharacters (defense in depth even
  though we exec argv-style, never through a shell); each command's own arg rule; and
  a STRICT per-command flag allowlist — every flag/option a command receives must be on
  that command's ``allowed_flags``, or the request is rejected at the allowlist gate,
  naming the offending flag. ``allowed_flags`` is authoritative, not advisory.
* The target-lock (a host arg must be the lab) is enforced together with this by the
  executor, using :func:`extract_hostish` + ``config.LAB_TARGET_ALIASES``.

Why strict flags matter: when active tools land later (sqlmap, ffuf, nuclei…) they
carry genuinely dangerous flags (``--os-shell``, ``--file-write``, ``-e``, intrusive
``--script``…) AND legitimately need metacharacters in payload args, so the metachar
filter can no longer blanket-apply. The load-bearing defense then becomes target-lock +
isolation + this strict per-command flag schema. Hardening it now, while the allowlist
is still recon-only, keeps any mistake low-stakes.

M1 web-module scope: recon-only, read-mostly tools. No weaponized payloads, no
arbitrary binaries. Extending the set — commands OR a command's ``allowed_flags`` — is a
deliberate, reviewed code change (a frozen-schema test trips on any widening).
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
    # Flags/options that are explicitly permitted. STRICT: any flag token a command
    # receives that is not resolvable to this set is rejected at the allowlist gate.
    # Entries are canonical flag tokens: short (``-s``), atomic multi-char (``-sV``,
    # ``-T4``, ``-p-``), long (``--color``), or a pinned long=value form
    # (``--color=never``, allowing only that exact value).
    allowed_flags: frozenset[str] = field(default_factory=frozenset)
    # Flags that consume the FOLLOWING token as their value (e.g. nmap ``-p 3000``,
    # curl ``-X GET``). Needed so a value — even one that looks like a flag or a
    # negative number — is treated as a value, not misread as an (un-listed) flag.
    # Each entry must also appear in ``allowed_flags``.
    value_flags: frozenset[str] = field(default_factory=frozenset)
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
}


def is_allowed_command(command: str) -> bool:
    """True iff ``command`` is in the hardcoded allowlist."""
    return command in ALLOWLIST


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

    Does NOT check the target lock (that needs config + belongs with the executor);
    this is purely: allowlisted command + sane, metachar-free args + STRICT per-command
    flags (every flag must be on the command's ``allowed_flags``).
    """
    if not is_allowed_command(command):
        return False, f"command '{command}' is not on the allowlist"
    spec = ALLOWLIST[command]

    if len(args) > spec.max_args:
        return False, f"too many args for '{command}' (max {spec.max_args})"

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
