"""Sandbox lifecycle — INTERFACE ONLY (M1.1).

Implemented in M1.2 (bring-up / isolation proof) and M1.3 (exec). Every function
here raises until then so nothing can accidentally touch Docker before the isolated
stack and its proof exist.
"""

from __future__ import annotations


class SandboxError(RuntimeError):
    """Raised for sandbox lifecycle / availability problems."""


def is_sandbox_up() -> bool:
    """Return True iff the Kali sandbox container is running and reachable.

    Implemented in M1.3 (docker inspect on config.SANDBOX_CONTAINER).
    """
    raise NotImplementedError("sandbox status check is wired in M1.3")


def assert_isolation_proven() -> None:
    """Raise unless the M1.2 isolation proof has passed for the current stack.

    The Cockpit executor calls this before its FIRST exec of a session. It is the
    code-level expression of the hard gate: no execution without a passing proof
    (see docs/cockpit-plan.md §c Layer 1). Implemented in M1.2/M1.3.
    """
    raise NotImplementedError("isolation gate is wired in M1.2/M1.3")
