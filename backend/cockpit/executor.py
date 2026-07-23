"""The exec layer — INTERFACE ONLY (M1.1).

This is where a validated, approved, target-locked command is actually run inside
the sandbox via ``docker exec``. It is intentionally unimplemented until M1.3, and
M1.3 itself is gated on the M1.2 isolation proof.

The public shape below is the contract the router (M1.3) and UI (M1.4) build against.
"""

from __future__ import annotations

from . import allowlist, config
from .models import ExecRequest


def check_target_lock(args: list[str]) -> tuple[bool, str]:
    """Pure check: every hostish operand must be the lab target. Returns (ok, reason).

    Safe to implement now (no execution) — it is the target-lock safety layer and is
    unit-testable before any sandbox exists.
    """
    hostish = allowlist.extract_hostish(args)
    for token in hostish:
        host = _host_of(token)
        if host is None:
            # Non-host operand (e.g. an nmap flag value that isn't a host) — allow;
            # the allowlist already vetted its shape.
            continue
        if host not in config.LAB_TARGET_ALIASES:
            return False, f"target '{host}' is not the lab — only the lab is allowed"
    return True, ""


def _host_of(token: str) -> str | None:
    """Extract a bare host from a token that may be a URL or host[:port].

    Returns None if the token doesn't look host-like at all.
    """
    t = token.strip()
    if not t or t.startswith("-"):
        return None
    # strip scheme
    if "://" in t:
        t = t.split("://", 1)[1]
    # strip path / query
    for sep in ("/", "?", "#"):
        if sep in t:
            t = t.split(sep, 1)[0]
    # strip userinfo
    if "@" in t:
        t = t.split("@", 1)[1]
    # strip port
    if ":" in t:
        t = t.split(":", 1)[0]
    return t or None


def run_command(request: ExecRequest):  # -> RunRecord (M1.3)
    """Run one approved, allowlisted, target-locked command in the sandbox.

    Order of gates (all must pass): allowlist → target lock → approval → sandbox
    isolation proven. Implemented in M1.3 after M1.2 proves isolation.
    """
    raise NotImplementedError(
        "cockpit execution is wired in M1.3, AFTER the M1.2 isolation proof passes"
    )
