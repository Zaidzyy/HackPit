"""The hardcoded safe command set + pure validation.

This module contains **no execution** — only the allowlist data and pure functions
that decide whether a (command, args) pair is permitted. It is safe to import and
unit-test before any sandbox exists, and it is one of the three independent safety
layers (see docs/cockpit-plan.md §c, Layer 3).

Design:
* Only commands in ``ALLOWLIST`` may ever run.
* Args are validated conservatively: no shell metacharacters (defense in depth even
  though we exec argv-style, never through a shell), and each command's own arg rule.
* The target-lock (a host arg must be the lab) is enforced together with this by the
  executor, using :func:`extract_hostish` + ``config.LAB_TARGET_ALIASES``.

M1 web-module scope: recon-only, read-mostly tools. No weaponized payloads, no
arbitrary binaries. Extending the set is a deliberate code review.
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
    # Flags/options that are explicitly permitted (bare tokens starting with '-').
    allowed_flags: frozenset[str] = field(default_factory=frozenset)
    # Max number of args (flags + operands) accepted, a rough DoS/typo guard.
    max_args: int = 24
    # Optional extra per-command validator: (args) -> (ok, reason).
    extra: Callable[[list[str]], tuple[bool, str]] | None = None


def _nmap_extra(args: list[str]) -> tuple[bool, str]:
    # Disallow nmap's script engine + output-to-file in M1 (broadens surface).
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
        extra=_nmap_extra,
    ),
    "curl": CommandSpec(
        name="curl",
        description="Fetch a URL from the lab target.",
        allowed_flags=frozenset({"-s", "-S", "-i", "-I", "-L", "-v", "-X", "GET", "HEAD"}),
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
    this is purely: allowlisted command + sane, metachar-free args.
    """
    if not is_allowed_command(command):
        return False, f"command '{command}' is not on the allowlist"
    spec = ALLOWLIST[command]

    if len(args) > spec.max_args:
        return False, f"too many args for '{command}' (max {spec.max_args})"

    for a in args:
        if has_forbidden_chars(a):
            return False, f"argument contains a forbidden character: {a!r}"

    if spec.extra is not None:
        ok, reason = spec.extra(args)
        if not ok:
            return False, reason

    return True, ""
