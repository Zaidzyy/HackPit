"""The auto-runner — the engine behind autonomy modes 2 (assisted) and 3 (full).

It does two separable things, kept separate so the dangerous half is trivial to audit:

  * :func:`decide` — PURE policy. Given a proposal and the engagement's ``autonomy_mode``, it
    returns whether that action should be FIRED, QUEUED for a human, or SKIPPED. This is where the
    modes differ, and it touches nothing.
  * :func:`fire` — THE HANDS. Executes an already-decided ``fire`` proposal server-side (reusing
    ``mcp_tools._run_surface`` for surfaces, the executor for raw commands — the same self-approving
    path ``hackpit_surface`` uses) and appends the append-only audit line. Never call it for a
    decision that was not ``fire``.

The policy, restated (the wall in each mode):
  * manual   → the human drives; the auto-runner does nothing.
  * assisted → passive fires; exploitation → human decision queue; human_only → queue.
  * full     → passive AND exploitation fire (bounded by RoE/scope/budget/kill-switch, added with
               the scheduler); human_only STILL queues — repeater and 'ask' never auto-fire.

Locked by test_autorun_safety.py. The load-bearing invariant: **assisted never fires an
exploitation-class action**, and **human_only never fires in any mode**.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from . import autoaudit, autotier

MODES = ("manual", "assisted", "full")


@dataclass
class Decision:
    action: str  # "fire" | "queue" | "skip"
    tier: str    # passive | exploitation | human_only | none
    reason: str


def normalize_mode(mode: str | None) -> str:
    """Fail safe: anything not exactly assisted/full is manual (the human-driven default)."""
    m = (mode or "manual").strip().lower()
    return m if m in MODES else "manual"


def decide(proposal: dict[str, Any] | None, mode: str | None) -> Decision:
    """FIRE / QUEUE / SKIP for one proposal under one mode. PURE — no I/O, no execution."""
    m = normalize_mode(mode)
    if not isinstance(proposal, dict) or not proposal:
        return Decision("skip", "none", "no proposal to act on")
    if m == "manual":
        return Decision("skip", "none", "manual mode — the human drives every step")

    tier = autotier.classify(proposal)
    if tier == autotier.HUMAN_ONLY:
        return Decision("queue", tier, "human-only action — queued for the operator, never auto-fired")
    if tier == autotier.PASSIVE:
        return Decision("fire", tier, f"passive action — auto-fired in {m} mode")
    # exploitation
    if m == "full":
        return Decision("fire", tier,
                        "exploitation — auto-fired in full mode (bounded by RoE / scope / budget)")
    return Decision("queue", tier, "exploitation — queued for the operator in assisted mode")


def fire(proposal: dict[str, Any], sid: str, eid: str, *, mode: str = "", tier: str = "") -> dict[str, Any]:
    """Execute an already-decided ``fire`` proposal server-side; append the audit line. Raises on an
    unknown or human-only surface (the same guard ``_run_surface`` has). Callers MUST NOT pass a
    proposal whose Decision was queue/skip — that is the whole point of deciding first."""
    kind = str(proposal.get("kind", "command")).lower()
    run_id = ""
    try:
        if kind == "surface":
            import mcp_tools  # backend-root module; not env-gated (only its TOOL registration is)

            name = str(proposal.get("surface", ""))
            params = proposal.get("surface_params") or {}
            result = mcp_tools._run_surface(name, params if isinstance(params, dict) else {}, sid, eid)
        else:
            from . import executor
            from .models import ExecRequest

            req = ExecRequest(
                command=str(proposal.get("command", "")),
                args=list(proposal.get("args", []) or []),
                approved=True,
                dangerous_ack=True,
                session_id=sid or None,
                engagement_id=eid or None,
            )
            record = executor.run_command(req)
            result = record if isinstance(record, dict) else record.model_dump()
        run_id = str((result or {}).get("run_id", "") or (result or {}).get("job_id", ""))
    except Exception as exc:  # noqa: BLE001 — audit the failure, then re-raise for the caller
        autoaudit.record(engagement_id=eid, session_id=sid, mode=mode, tier=tier, action="fire",
                         proposal=proposal, outcome="error", error=str(exc))
        raise
    autoaudit.record(engagement_id=eid, session_id=sid, mode=mode, tier=tier, action="fire",
                     proposal=proposal, outcome="started", run_id=run_id)
    return result if isinstance(result, dict) else {"run_id": run_id}


def note_non_fire(decision: Decision, proposal: dict[str, Any], sid: str, eid: str, mode: str) -> None:
    """Append an audit line for a queued/skipped decision, so the trail shows what the runner chose
    NOT to fire — a queue that leaves no record reads as 'nothing happened'."""
    autoaudit.record(engagement_id=eid, session_id=sid, mode=mode, tier=decision.tier,
                     action=decision.action, proposal=proposal,
                     outcome="queued" if decision.action == "queue" else "skipped")


# --------------------------------------------------------------------------- #
# THE UNIT OF WORK — propose -> decide -> fire-or-queue -> audit.
# Shared by the /sessions/{id}/autorun/step endpoint AND the scheduler daemon, so the policy lives
# in exactly one place. main registers its scope resolver here (the same set_*_resolver pattern the
# ad/cloud graphs use) so the daemon can resolve an engagement's scope WITHOUT importing the app.
# --------------------------------------------------------------------------- #
_scope_resolver: Any = None


def set_scope_resolver(fn: Any) -> None:
    """main calls this with `_loop_scope_context` so a step run off the daemon resolves the same
    program scope the endpoint would. Absent (never registered) → no scope context (lab-like)."""
    global _scope_resolver
    _scope_resolver = fn


def _resolve_scope(engagement_id: str) -> Any:
    if _scope_resolver is None or not engagement_id:
        return None
    try:
        return _scope_resolver(engagement_id)
    except Exception:  # noqa: BLE001 — a resolver hiccup must not fire an UNSCOPED step
        raise


def step_session(session_id: str, engagement_id: str) -> dict[str, Any]:
    """One autonomous step: propose the next action and FIRE / QUEUE / SKIP it per the engagement's
    autonomy_mode. Returns a summary dict; NEVER fires in manual mode. A propose/LLM error degrades
    to a skip (so the daemon keeps its cadence); a FIRE error propagates (the caller logs/500s).

    Lazy imports keep this module free of the app + heavy deps at import time and avoid cycles."""
    import llm
    import orchestrator
    import sessions as sessions_db

    from . import engagement as engagement_mod
    from . import runstore

    session = sessions_db.get_session(session_id)
    if session is None:
        return {"mode": "manual", "action": "skip", "reason": "session not found", "not_found": True}
    mode = engagement_mod.autonomy_mode(engagement_id) if engagement_id else "manual"
    if mode == "manual":
        return {"mode": "manual", "action": "skip",
                "reason": "manual mode — the human drives every step"}

    plan = session.get("path") or {}
    runs = [r.model_dump() for r in runstore.list_runs_for_session(session_id)]
    scope_ctx = _resolve_scope(engagement_id)
    try:
        result = orchestrator.propose_next(plan, runs, llm.load_config(), [], scope_ctx, session_id)
    except Exception as exc:  # noqa: BLE001 — LLM/propose failure: skip this cycle, don't crash
        return {"mode": mode, "action": "skip", "reason": f"propose failed: {exc}"}
    if not isinstance(result, dict) or result.get("done"):
        return {"mode": mode, "action": "skip", "done": True,
                "reason": (result or {}).get("reason", "nothing left to propose")}

    proposal = result.get("proposal")
    decision = decide(proposal, mode)
    out: dict[str, Any] = {"mode": mode, "action": decision.action, "tier": decision.tier,
                           "reason": decision.reason, "proposal": proposal}
    if decision.action == "fire":
        out["result"] = fire(proposal, session_id, engagement_id, mode=mode, tier=decision.tier)
    else:
        note_non_fire(decision, proposal, session_id, engagement_id, mode)
    return out
