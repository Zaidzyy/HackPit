"""SAFETY invariants for the AUTO-RUNNER SCHEDULER (the daemon that drives modes 2/3).

The daemon has hands, so its guarantees are:

  1. DEFAULT OFF. Nothing steps autonomously until the operator deliberately enables the daemon
     AND sets an engagement to assisted/full — two independent switches.
  2. MANUAL ENGAGEMENTS ARE NEVER STEPPED, even while the daemon runs. The mode filter is the
     first switch.
  3. THE KILL-SWITCH HALTS MID-TICK. Disabling the daemon stops it before the next engagement's
     step, without a restart.
  4. BOUNDED + CONTAINED. At most MAX_STEPS_PER_TICK step per engagement per cycle, and a step
     that raises is contained to its own engagement — the others still run.

Hermetic (list_active / step_session / settings are stubbed — nothing real runs).
Run:  python test_autoloop_safety.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cockpit import autoloop  # noqa: E402


def _rec(eid: str, mode: str, sid: str | None = "s") -> SimpleNamespace:
    return SimpleNamespace(engagement_id=eid, autonomy_mode=mode, session_id=sid)


class _Stub:
    """Swap list_active + step_session + get_settings on the autoloop module. Restores on exit."""

    def __init__(self, records: list, enabled: bool = True) -> None:
        self.records, self.enabled, self.calls = records, enabled, []

    def __enter__(self) -> "_Stub":
        self._la = autoloop.engagement_mod.list_active
        self._ss = autoloop.autorun.step_session
        self._gs = autoloop.get_settings
        autoloop.engagement_mod.list_active = lambda: self.records  # type: ignore[assignment]

        def _spy(sid, eid):
            self.calls.append(eid)
            return {"action": "fire", "tier": "passive", "reason": "stub"}

        autoloop.autorun.step_session = _spy  # type: ignore[assignment]
        autoloop.get_settings = lambda: {"enabled": self.enabled, "interval": 60}  # type: ignore[assignment]
        return self

    def __exit__(self, *exc: object) -> None:
        autoloop.engagement_mod.list_active = self._la  # type: ignore[assignment]
        autoloop.autorun.step_session = self._ss  # type: ignore[assignment]
        autoloop.get_settings = self._gs  # type: ignore[assignment]


# --------------------------------------------------------------------------- #
# 1. default OFF (real settings, temp DB)
# --------------------------------------------------------------------------- #
def test_the_scheduler_is_off_by_default() -> None:
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
        orig = autoloop.DB_PATH
        autoloop.DB_PATH = str(Path(td) / "sessions.db")
        try:
            autoloop.init_db()
            assert autoloop.get_settings()["enabled"] is False, "the scheduler defaulted ON"
            # enabling is a deliberate, floored write
            after = autoloop.set_settings(True, 5)
            assert after["enabled"] is True and after["interval"] == autoloop.MIN_INTERVAL
        finally:
            autoloop.DB_PATH = orig
    print("  the scheduler is OFF by default; enabling is deliberate and floored: PASS")


# --------------------------------------------------------------------------- #
# 2. only assisted/full are stepped; manual never
# --------------------------------------------------------------------------- #
def test_only_assisted_and_full_engagements_are_stepped() -> None:
    recs = [_rec("e-man", "manual"), _rec("e-ass", "assisted"), _rec("e-full", "full"),
            _rec("e-nosess", "full", sid=None)]
    with _Stub(recs, enabled=True) as s:
        autoloop.tick()
        assert set(s.calls) == {"e-ass", "e-full"}, f"stepped the wrong set: {s.calls}"
        assert "e-man" not in s.calls, "a MANUAL engagement was stepped"
        assert "e-nosess" not in s.calls, "an engagement with no session was stepped"
    print("  only assisted/full engagements with a session are stepped; manual never: PASS")


# --------------------------------------------------------------------------- #
# 3. the kill-switch halts mid-tick
# --------------------------------------------------------------------------- #
def test_disabling_halts_the_tick_immediately() -> None:
    recs = [_rec("e1", "full"), _rec("e2", "full"), _rec("e3", "full")]
    with _Stub(recs, enabled=True):
        # disabled outright → nothing steps
        autoloop.get_settings = lambda: {"enabled": False, "interval": 60}  # type: ignore[assignment]
        out = autoloop.tick()
        assert out["stepped"] == {}, f"a disabled scheduler stepped: {out}"
    # flips off after the first engagement → the rest are skipped mid-tick
    recs2 = [_rec("a", "full"), _rec("b", "full"), _rec("c", "full")]
    with _Stub(recs2, enabled=True) as s:
        state = {"n": 0}

        def _flipping():
            state["n"] += 1
            return {"enabled": state["n"] <= 1, "interval": 60}  # on for the first check only

        autoloop.get_settings = _flipping  # type: ignore[assignment]
        autoloop.tick()
        assert s.calls == ["a"], f"the kill-switch did not halt mid-tick: {s.calls}"
    print("  disabling the scheduler halts the tick immediately (mid-tick kill-switch): PASS")


# --------------------------------------------------------------------------- #
# 4. one step per engagement per tick; an error is contained
# --------------------------------------------------------------------------- #
def test_bounded_and_a_step_error_is_contained() -> None:
    recs = [_rec("e1", "full"), _rec("e2", "assisted")]
    with _Stub(recs, enabled=True) as s:
        autoloop.tick()
        # MAX_STEPS_PER_TICK == 1 → exactly one step per engagement per tick
        assert s.calls == ["e1", "e2"], f"stepped more than the per-tick budget: {s.calls}"

    with _Stub(recs, enabled=True):
        def _boom(sid, eid):
            if eid == "e1":
                raise RuntimeError("fire blew up")
            return {"action": "fire"}

        autoloop.autorun.step_session = _boom  # type: ignore[assignment]
        out = autoloop.tick()
        assert out["stepped"]["e1"]["action"] == "error", "a step error was not contained/reported"
        assert "e2" in out["stepped"], "one engagement's error aborted the others"
    print("  one step per engagement per tick; a step error is contained to its engagement: PASS")


if __name__ == "__main__":
    test_the_scheduler_is_off_by_default()
    test_only_assisted_and_full_engagements_are_stepped()
    test_disabling_halts_the_tick_immediately()
    test_bounded_and_a_step_error_is_contained()
    print("ALL auto-loop scheduler safety invariants hold")
