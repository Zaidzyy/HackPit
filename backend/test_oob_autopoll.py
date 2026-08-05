"""OOB auto-poll settings + tick (spec 2026-08-06 §4.4).

Standalone (the safety runner executes ``python test_x.py``, not pytest). Auto-poll is read-only
automation — these tests prove the setting round-trips with a floored interval, and that a tick
sweeps both backends through poll_all and touches no execution surface.

Run: python test_oob_autopoll.py
"""

from __future__ import annotations

import ast
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from oob import autopoll, settings as st  # noqa: E402

BACKEND = Path(__file__).resolve().parent
AUTOPOLL_PATH = BACKEND / "oob" / "autopoll.py"


def test_settings_default_and_floor() -> None:
    d = tempfile.mkdtemp()
    saved = st.DB_PATH
    st.DB_PATH = Path(d) / "s.db"
    try:
        st.init_db()
        assert st.get() == {"enabled": True, "interval": 60}
        assert st.set(enabled=False, interval=5)["interval"] == 30  # floored at MIN_INTERVAL
        got = st.get()
        assert got["enabled"] is False and got["interval"] == 30
    finally:
        st.DB_PATH = saved
        shutil.rmtree(d, ignore_errors=True)
    print("  settings default + floor: OK")


def test_tick_calls_poll_all_with_all_sessions() -> None:
    saved_poll = autopoll.poll_mod.poll_all
    saved_sess = autopoll.engagement_mod.session_ids
    seen = {}
    autopoll.poll_mod.poll_all = lambda sessions, after=None: seen.update(sessions=sessions) or {
        "filed": 0, "hits": [], "unfiled": [], "errors": [], "self_hosted": None, "interactsh": None,
    }
    autopoll.engagement_mod.session_ids = lambda: {"e1": "s1"}
    try:
        out = autopoll.tick()
        assert seen["sessions"] == {"e1": "s1"}
        assert out["filed"] == 0
    finally:
        autopoll.poll_mod.poll_all = saved_poll
        autopoll.engagement_mod.session_ids = saved_sess
    print("  tick sweeps via poll_all with all sessions: OK")


def test_autopoll_reaches_no_execution_surface() -> None:
    """A read-only sweep must never touch an execution or delivery surface."""
    src = AUTOPOLL_PATH.read_text(encoding="utf-8")
    for banned in ("subprocess", "run_kali", "executor", "repeater", "eval(", "exec("):
        assert banned not in src, f"autopoll.py must not reference {banned}"
    # it must parse (no syntax landmine hiding the above behind a string, either)
    ast.parse(src)
    print("  autopoll reaches no execution surface: OK")


if __name__ == "__main__":
    print("== OOB auto-poll (spec 2026-08-06 §4.4) ==")
    test_settings_default_and_floor()
    test_tick_calls_poll_all_with_all_sessions()
    test_autopoll_reaches_no_execution_surface()
    print("ALL OOB auto-poll tests pass")
