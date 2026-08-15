"""Tier classification for the auto-runner — is a proposed action SAFE to fire without a human?

The auto-runner (modes 2/3) needs to know, for every proposal the orchestrator returns, which of
three tiers it falls in:

  * ``passive``      — read-only / enumeration. Safe to fire autonomously in assisted AND full.
  * ``exploitation`` — writes, confirms a vuln, sprays, or is otherwise active. Fired only in
                       FULL mode (bounded by RoE); in assisted it goes to the human decision queue.
  * ``human_only``   — never fired autonomously in ANY mode. The repeater (its send is human-only
                       by construction) and any 'ask' (a value only a human can supply).

THE PASSIVE SET IS A CLOSED ALLOWLIST. Anything not explicitly named passive — an unknown or new
surface, a command carrying a dangerous flag, active recon, a detect→confirm surface at its
confirm stage — classifies as ``exploitation``. This is the load-bearing invariant: a surface
added next month cannot silently become auto-fireable; it defaults to needing a human until
someone deliberately adds it here and a test locks it. Pure, no I/O — locked by
test_autotier_safety.py.
"""

from __future__ import annotations

from typing import Any

#: Surfaces that are read-only / enumeration and safe to fire without a human. CLOSED — extend
#: only with a matching test. recon and the detect/confirm surfaces are handled specially below
#: (they are passive only in one mode/stage), so they are NOT in this bare set.
_PASSIVE_SURFACES = frozenset({"discover", "jsrecon", "nuclei"})

#: Never fired autonomously, in any mode. The repeater send is human-only by construction
#: (test_repeater_is_human_only) and _run_surface raises on it; listing it here means the
#: auto-runner queues it for a human rather than trying to fire it and hitting that raise.
_HUMAN_ONLY_SURFACES = frozenset({"repeater"})

PASSIVE = "passive"
EXPLOITATION = "exploitation"
HUMAN_ONLY = "human_only"


def classify(proposal: dict[str, Any]) -> str:
    """One of ``passive`` / ``exploitation`` / ``human_only`` for a LoopProposal-shaped dict.

    Fails SAFE: any shape it does not positively recognise as passive is ``exploitation``.
    """
    if not isinstance(proposal, dict):
        return EXPLOITATION
    kind = str(proposal.get("kind", "command")).lower()

    if kind == "ask":
        return HUMAN_ONLY  # a value only a human can supply — never auto-answered

    if kind == "surface":
        name = str(proposal.get("surface", "")).strip().lower()
        params = proposal.get("surface_params") or {}
        if not isinstance(params, dict):
            params = {}
        if name in _HUMAN_ONLY_SURFACES:
            return HUMAN_ONLY
        if name == "recon":
            # passive only when explicitly the passive sweep; a bare/active recon is exploitation
            return PASSIVE if str(params.get("mode", "")).lower() == "passive" else EXPLOITATION
        if name in ("smuggle", "cache"):
            # the DETECT stage is read-only; the CONFIRM stage plants/poisons and is exploitation.
            # Passive requires an EXPLICIT stage=="detect": an absent/empty/unknown stage is NOT
            # assumed to be detect. The surface's own default is detect, but for an AUTONOMOUS fire
            # we make the proposer say so — so a future change to that default can never silently
            # turn a bare proposal into an auto-fired poison-plant.
            return PASSIVE if str(params.get("stage", "")).lower() == "detect" else EXPLOITATION
        if name in _PASSIVE_SURFACES:
            return PASSIVE
        # intruder, race, credentials, tokens, c2, tunnels, capture, AND any unknown surface
        return EXPLOITATION

    # kind == "command": the only auto-fire signal we have is the danger heuristic the proposal
    # already carries. A flagged command is exploitation; an unflagged REAL command is passive
    # (read-only-ish). A 'command' with no command string — an empty or kind-less dict — is not a
    # recognisable action and fails safe to exploitation, never passive.
    if kind == "command":
        if proposal.get("dangerous_flags"):
            return EXPLOITATION
        if proposal.get("command"):
            return PASSIVE
        return EXPLOITATION
    return EXPLOITATION
