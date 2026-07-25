"""Detection footprint — the PURPLE-TEAM view of what an operator's command leaves behind.

This package is a READ-ONLY ANNOTATION LAYER. It answers one question: *if a defender were
watching, what would they see?* — the ATT&CK technique + tactic the action maps to, the
telemetry/data sources it generates, the public detection (Sigma) rule that would fire, and how
loud the action is.

THE LINE THIS PACKAGE HOLDS
---------------------------
It DESCRIBES detection from the defender's side. It does NOT perform, recommend, or teach
EVASION. "This action is loud / here is the event it throws / here is the rule that catches it"
is in scope. "Here is how to make it quieter / evade that rule / blind that sensor" is NOT —
that is an evasion engine and it does not exist here. The loud-vs-quiet rating is an AWARENESS
indicator (and, for the blue side, a *coverage* indicator: a quiet action is one whose detection
depends on logging that is often not enabled). It is never a how-to-be-quiet guide.

Nothing in this package executes anything — no subprocess, no docker, no shell, no executor
call. Same structural lock the AD graph has (see test_detection_safety.py).
"""

from __future__ import annotations

__all__ = ["attck", "catalog", "resolver"]
