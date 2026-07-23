"""HackPit Cockpit — live, human-approved command execution against an isolated lab.

This package is the *engine* side of the Cockpit (the Companion is the rest of the
backend). It is deliberately split into small, single-responsibility modules so the
safety mechanisms are easy to audit:

* ``config``    — constants: sandbox container, lab target, what "the lab" means.
* ``allowlist`` — the hardcoded safe command set + pure validation (no execution).
* ``models``    — Pydantic request/response/run-record contracts.
* ``sandbox``   — sandbox lifecycle (interface; implemented in M1.2/M1.3).
* ``executor``  — the exec layer (interface; wired in M1.3 AFTER isolation is proven).
* ``router``    — FastAPI routes (mounted into main.py in M1.3, not before).

SAFETY (see docs/cockpit-plan.md §c): execution is gated on three independent layers
— network isolation, a target lock (lab only), and a per-command human approval flag —
and no code here runs a command until the isolation proof (M1.2) passes.
"""

__all__ = ["config", "allowlist", "models"]
