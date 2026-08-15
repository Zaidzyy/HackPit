"""SAFETY invariants for the MODE-3 RoE WALL + the autonomous fire BUDGET.

In full mode the wall is not a human — it is the DECLARED RoE plus a fire budget. This locks that:

  1. governance.permits() ANSWERS from the RoE, blocking nothing itself: an empty RoE permits
     everything; excluded_actions forbids the named action; time_windows makes everything outside
     the window a blackout (a malformed window fails closed).
  2. autorun.permitted_to_fire() is the gate the auto-runner consults before EVERY autonomous fire:
     the budget caps total fires; the RoE forbids excluded actions; an unreadable RoE fails CLOSED
     (refuse to auto-fire).
  3. THE TEETH: step_session downgrades a mode-allowed fire that the RoE forbids to a QUEUE — the
     exploitation is never fired, and the operator sees it.

Hermetic (governance.get_doc + the audit path are stubbed). Run:  python test_roe_wall_safety.py
"""

from __future__ import annotations

import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cockpit import autoaudit, autorun  # noqa: E402
from state import governance  # noqa: E402


class _Doc:
    def __init__(self, payload: dict) -> None:
        self.payload = payload


def _stub_roe(payload: dict):
    governance.get_doc = lambda sid, dt=None: _Doc(payload)  # type: ignore[assignment]


def _at(hh: int, mm: int = 0) -> datetime:
    return datetime(2026, 8, 15, hh, mm, tzinfo=timezone.utc)


# --------------------------------------------------------------------------- #
# 1. governance.permits — the RoE answer
# --------------------------------------------------------------------------- #
def test_permits_reads_excluded_actions_and_time_windows() -> None:
    orig = governance.get_doc
    try:
        _stub_roe({})  # empty RoE permits everything
        assert governance.permits("s", "credentials") == (True, "")

        _stub_roe({"excluded_actions": ["credentials", "c2"]})
        assert governance.permits("s", "credentials")[0] is False
        assert governance.permits("s", "C2")[0] is False, "match must be case-insensitive"
        assert governance.permits("s", "nuclei")[0] is True

        _stub_roe({"time_windows": [{"start": "09:00", "end": "17:00"}]})
        assert governance.permits("s", "nuclei", _at(10))[0] is True, "inside the window"
        assert governance.permits("s", "nuclei", _at(20))[0] is False, "outside → blackout"

        _stub_roe({"time_windows": [{"start": "22:00", "end": "06:00"}]})  # overnight, wraps midnight
        assert governance.permits("s", "nuclei", _at(23))[0] is True
        assert governance.permits("s", "nuclei", _at(12))[0] is False

        _stub_roe({"time_windows": [{"start": "not-a-time"}]})  # malformed → nothing is inside
        assert governance.permits("s", "nuclei", _at(12))[0] is False, "a malformed window must fail closed"
    finally:
        governance.get_doc = orig  # type: ignore[assignment]
    print("  permits reads excluded_actions (case-insensitive) + time_windows (incl. overnight/malformed): PASS")


# --------------------------------------------------------------------------- #
# 2. autorun.permitted_to_fire — the gate (budget + RoE + fail-closed)
# --------------------------------------------------------------------------- #
def test_the_fire_gate_enforces_budget_roe_and_fails_closed() -> None:
    orig_doc, orig_audit = governance.get_doc, autoaudit._AUDIT_PATH
    surf = {"kind": "surface", "surface": "nuclei", "surface_params": {}}
    try:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
            autoaudit._AUDIT_PATH = str(Path(td) / "audit.jsonl")

            _stub_roe({})  # clean RoE, budget default, no fires yet → allowed
            assert autorun.permitted_to_fire(surf, "s", "e")[0] is True

            # budget: RoE caps at 2; write 2 'started' fires → the 3rd is refused
            _stub_roe({"max_autonomous_fires": 2})
            for _ in range(2):
                autoaudit.record(engagement_id="e", session_id="s", mode="full", tier="passive",
                                 action="fire", proposal=surf, outcome="started", run_id="r")
            ok, why = autorun.permitted_to_fire(surf, "s", "e")
            assert ok is False and "budget" in why, (ok, why)

            # RoE excludes the action (fresh engagement so budget is clear)
            _stub_roe({"excluded_actions": ["nuclei"]})
            ok2, why2 = autorun.permitted_to_fire(surf, "s", "e2")
            assert ok2 is False and "excluded" in why2.lower(), (ok2, why2)

        # fail-closed: an unreadable RoE refuses the fire
        def _boom(sid, ac, now=None):
            raise RuntimeError("db down")

        governance.permits = _boom  # type: ignore[assignment]
        _stub_roe({})
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
            autoaudit._AUDIT_PATH = str(Path(td) / "audit.jsonl")
            okf, whyf = autorun.permitted_to_fire(surf, "s", "e3")
            assert okf is False and "fail closed" in whyf.lower(), (okf, whyf)
    finally:
        governance.get_doc, autoaudit._AUDIT_PATH = orig_doc, orig_audit
        # restore permits (reimport binding)
        import importlib
        importlib.reload(governance)
    print("  the fire gate enforces the budget, the RoE deny list, and fails closed on an unreadable RoE: PASS")


# --------------------------------------------------------------------------- #
# 3. THE TEETH — step_session downgrades a policy-blocked fire to a queue
# --------------------------------------------------------------------------- #
def test_step_session_downgrades_a_policy_blocked_exploitation_to_queue() -> None:
    import orchestrator
    import sessions as sessions_db
    from cockpit import engagement as eng, runstore

    fired: list = []
    saved = {
        "gs": sessions_db.get_session, "pn": orchestrator.propose_next,
        "am": eng.autonomy_mode, "lr": runstore.list_runs_for_session,
        "pf": autorun.permitted_to_fire, "fire": autorun.fire,
    }
    try:
        import llm
        saved["lc"] = llm.load_config
        llm.load_config = lambda: {}  # type: ignore[assignment]
        sessions_db.get_session = lambda sid: {"path": {}}  # type: ignore[assignment]
        eng.autonomy_mode = lambda eid: "full"  # type: ignore[assignment]
        runstore.list_runs_for_session = lambda sid: []  # type: ignore[assignment]
        orchestrator.propose_next = lambda *a, **k: {  # type: ignore[assignment]
            "done": False,
            "proposal": {"kind": "surface", "surface": "credentials",
                         "surface_params": {"mode": "spray"}},
        }
        autorun.permitted_to_fire = lambda *a, **k: (  # type: ignore[assignment]
            False, "RoE excluded_actions forbids 'credentials'")
        autorun.fire = lambda *a, **k: (fired.append(a) or {"run_id": "x"})  # type: ignore[assignment]

        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
            autoaudit._AUDIT_PATH = str(Path(td) / "audit.jsonl")
            out = autorun.step_session("s1", "e1")
        assert out["action"] == "queue", f"a policy-blocked fire was not downgraded: {out}"
        assert out.get("policy_blocked") is True
        assert not fired, "a RoE-forbidden exploitation was FIRED autonomously"
    finally:
        sessions_db.get_session = saved["gs"]  # type: ignore[assignment]
        orchestrator.propose_next = saved["pn"]  # type: ignore[assignment]
        eng.autonomy_mode = saved["am"]  # type: ignore[assignment]
        runstore.list_runs_for_session = saved["lr"]  # type: ignore[assignment]
        autorun.permitted_to_fire = saved["pf"]  # type: ignore[assignment]
        autorun.fire = saved["fire"]  # type: ignore[assignment]
        if "lc" in saved:
            llm.load_config = saved["lc"]  # type: ignore[assignment]
    print("  step_session downgrades a mode-allowed but RoE-forbidden exploitation to a queue: PASS")


if __name__ == "__main__":
    test_permits_reads_excluded_actions_and_time_windows()
    test_the_fire_gate_enforces_budget_roe_and_fails_closed()
    test_step_session_downgrades_a_policy_blocked_exploitation_to_queue()
    print("ALL RoE-wall + budget safety invariants hold")
