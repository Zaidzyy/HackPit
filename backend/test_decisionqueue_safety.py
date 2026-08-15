"""Invariants for the DECISION QUEUE — the held exploitation actions assisted mode collects.

  1. A queued action round-trips WITH its full proposal (so it can be re-fired), and the same held
     action queued repeatedly (the daemon re-proposes it every tick) is ONE row, not one per tick.
  2. pending_action_classes reflects what is waiting (fed to the proposer as `avoid`).
  3. APPROVE fires the held proposal through autorun.fire; SKIP dismisses it WITHOUT firing.
  4. Approving/deciding an unknown or already-decided item is refused (404 / 409).

Hermetic (temp DB; autorun.fire stubbed). Run:  python test_decisionqueue_safety.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cockpit import decisionqueue as dq  # noqa: E402


def _surf(name: str, **params) -> dict:
    return {"kind": "surface", "surface": name, "surface_params": params}


def test_enqueue_roundtrip_and_dedup() -> None:
    orig = dq.DB_PATH
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
        dq.DB_PATH = str(Path(td) / "sessions.db")
        try:
            dq.init_db()
            p = _surf("intruder", mode="sniper", targets=["https://x/FUZZ"])
            id1 = dq.enqueue("E1", "s1", p, "exploitation")
            id2 = dq.enqueue("E1", "s1", p, "exploitation")  # same held action, next tick
            assert id1 == id2, "the same held action queued twice made two rows (no dedup)"
            pend = dq.pending("E1")
            assert len(pend) == 1, f"expected 1 pending, got {len(pend)}"
            # the FULL proposal survives — this is what makes re-firing possible
            assert pend[0]["proposal"]["surface"] == "intruder"
            assert pend[0]["proposal"]["surface_params"]["targets"] == ["https://x/FUZZ"]

            # a DIFFERENT action is its own row
            dq.enqueue("E1", "s1", _surf("race", count=20), "exploitation")
            assert len(dq.pending("E1")) == 2

            # avoid list reflects both
            assert set(dq.pending_action_classes("E1")) == {"intruder", "race"}
        finally:
            dq.DB_PATH = orig
    print("  enqueue round-trips the full proposal; the same held action dedups to one row: PASS")


def test_mark_lifecycle_and_reenqueue() -> None:
    orig = dq.DB_PATH
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
        dq.DB_PATH = str(Path(td) / "sessions.db")
        try:
            dq.init_db()
            p = _surf("credentials", mode="spray")
            qid = dq.enqueue("E1", "s1", p, "exploitation")
            assert dq.get(qid)["status"] == dq.PENDING
            dq.mark(qid, dq.SKIPPED)
            assert dq.get(qid)["status"] == dq.SKIPPED
            assert dq.pending("E1") == [], "a skipped item still shows as pending"
            # once the pending one is gone, the same action can be queued afresh
            qid2 = dq.enqueue("E1", "s1", p, "exploitation")
            assert qid2 != qid and len(dq.pending("E1")) == 1
        finally:
            dq.DB_PATH = orig
    print("  mark moves an item out of pending; the same action can then re-queue: PASS")


def test_approve_fires_and_skip_does_not() -> None:
    from cockpit import autorun, router

    orig_db, orig_fire = dq.DB_PATH, autorun.fire
    fired: list = []
    autorun.fire = lambda proposal, sid, eid, **kw: (fired.append(proposal.get("surface")) or {"run_id": "r1"})  # type: ignore[assignment]
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
        dq.DB_PATH = str(Path(td) / "sessions.db")
        try:
            dq.init_db()
            # APPROVE -> fires + marks approved
            qid = dq.enqueue("E1", "s1", _surf("intruder", mode="sniper"), "exploitation")
            out = router.approve_decision(qid)
            assert out["status"] == "approved" and fired == ["intruder"], (out, fired)
            assert dq.get(qid)["status"] == dq.APPROVED
            # a second approve on the SAME id is refused (409) — no double fire
            try:
                router.approve_decision(qid)
                raise AssertionError("re-approving an already-decided item was allowed")
            except router.HTTPException as e:  # type: ignore[attr-defined]
                assert e.status_code == 409

            # SKIP -> does NOT fire
            fired.clear()
            qid2 = dq.enqueue("E1", "s1", _surf("race", count=10), "exploitation")
            out2 = router.skip_decision(qid2)
            assert out2["status"] == "skipped" and fired == [], (out2, fired)
            assert dq.get(qid2)["status"] == dq.SKIPPED

            # unknown id -> 404
            try:
                router.approve_decision("dq-nope")
                raise AssertionError("approving an unknown id was allowed")
            except router.HTTPException as e:  # type: ignore[attr-defined]
                assert e.status_code == 404
        finally:
            dq.DB_PATH, autorun.fire = orig_db, orig_fire
    print("  approve fires the held proposal; skip dismisses without firing; 404/409 hold: PASS")


if __name__ == "__main__":
    test_enqueue_roundtrip_and_dedup()
    test_mark_lifecycle_and_reenqueue()
    test_approve_fires_and_skip_does_not()
    print("ALL decision-queue safety invariants hold")
