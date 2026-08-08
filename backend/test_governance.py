"""Engagement-governance tests — the OPPLAN state machine, versioned documents, objective
CRUD, ATT&CK coverage, and the advisory (never machine-blocking) RoE-vs-scope check.

Run:  python test_governance.py
"""

from __future__ import annotations

import sys

from state import governance as gov

_S = "test-governance-session"


def _reset() -> None:
    gov.init_db()
    gov.clear(_S)


# --------------------------------------------------------------------------- #
# the OPPLAN status state machine
# --------------------------------------------------------------------------- #
def test_state_machine_rejects_illegal_transitions() -> None:
    _reset()
    o = gov.add_objective(_S, "Gain a foothold", phase="initial-access", technique_ids=["T1190"])
    assert o.status == gov.STATUS_PENDING, "a new objective starts pending"

    # legal path pending -> in-progress -> completed
    gov.update_objective(_S, o.obj_id, status="in-progress")
    gov.update_objective(_S, o.obj_id, status="completed")
    assert gov.get_objective(_S, o.obj_id).status == gov.STATUS_COMPLETED

    # completed is TERMINAL — no transition out
    for target in ("in-progress", "pending", "blocked", "cancelled"):
        try:
            gov.update_objective(_S, o.obj_id, status=target)
            raise AssertionError(f"completed -> {target} should be rejected (terminal)")
        except gov.TransitionError:
            pass
    assert gov.get_objective(_S, o.obj_id).status == gov.STATUS_COMPLETED, "state unchanged after a rejected transition"

    # a skip (pending -> completed) is rejected; and pending -> blocked is NOT a Decepticon edge
    # (a pending objective has not been attempted, so it cannot be blocked)
    o2 = gov.add_objective(_S, "Escalate", phase="post-exploit")
    for bad in ("completed", "blocked"):
        try:
            gov.update_objective(_S, o2.obj_id, status=bad)
            raise AssertionError(f"pending -> {bad} should be rejected")
        except gov.TransitionError:
            pass
    gov.update_objective(_S, o2.obj_id, status="cancelled")
    try:
        gov.update_objective(_S, o2.obj_id, status="in-progress")
        raise AssertionError("cancelled -> in-progress should be rejected (terminal)")
    except gov.TransitionError:
        pass

    # blocked -> completed IS legal (abandon-but-good-enough) — the Decepticon edge I first missed
    o3 = gov.add_objective(_S, "Kerberoast", phase="post-exploit")
    gov.update_objective(_S, o3.obj_id, status="in-progress")
    gov.update_objective(_S, o3.obj_id, status="blocked")
    gov.update_objective(_S, o3.obj_id, status="completed")
    assert gov.get_objective(_S, o3.obj_id).status == gov.STATUS_COMPLETED
    print("  state machine: legal path + terminal exits + pending->blocked/skip rejected + blocked->completed allowed: PASS")


def test_can_transition_table() -> None:
    assert gov.can_transition("pending", "in-progress")
    assert gov.can_transition("in-progress", "completed")
    assert gov.can_transition("blocked", "in-progress")
    assert gov.can_transition("blocked", "completed"), "blocked -> completed (abandon) is legal (Decepticon)"
    assert gov.can_transition("pending", "pending"), "a no-op re-save is always legal"
    assert not gov.can_transition("pending", "blocked"), "pending -> blocked is NOT a Decepticon edge"
    assert not gov.can_transition("completed", "in-progress")
    assert not gov.can_transition("cancelled", "pending")
    assert not gov.can_transition("pending", "bogus-status")
    print("  can_transition matches Decepticon's table (blocked->completed legal, pending->blocked not): PASS")


def test_illegal_transition_writes_nothing() -> None:
    """An illegal transition must not mutate the OPPLAN version either — nothing is written."""
    _reset()
    o = gov.add_objective(_S, "x", technique_ids=["T1595"])
    gov.update_objective(_S, o.obj_id, status="in-progress")
    gov.update_objective(_S, o.obj_id, status="completed")
    v_before = gov.opplan_version(_S)
    try:
        gov.update_objective(_S, o.obj_id, status="pending")
    except gov.TransitionError:
        pass
    assert gov.opplan_version(_S) == v_before, "a rejected transition bumped the version"
    print("  a rejected transition writes nothing and does not bump the OPPLAN version: PASS")


# --------------------------------------------------------------------------- #
# versioned documents
# --------------------------------------------------------------------------- #
def test_documents_are_versioned_and_round_trip() -> None:
    _reset()
    for dt in gov.DOC_TYPES:
        empty = gov.get_doc(_S, dt)
        assert empty.version == 0 and not empty.approved, f"{dt} starts at v0, unapproved"
        assert empty.payload == gov.default_payload(dt), f"{dt} default payload is the shaped form"

    d1 = gov.save_doc(_S, "roe", {"scope_spec": "*.example.com", "opsec_level": "careful"})
    assert d1.version == 1 and not d1.approved
    d2 = gov.save_doc(_S, "roe", {"scope_spec": "*.example.com", "opsec_level": "ghost"})
    assert d2.version == 2, "each save bumps the version"
    back = gov.get_doc(_S, "roe")
    assert back.payload["opsec_level"] == "ghost", "the last write round-trips"
    print("  documents version on every save and round-trip their JSON payload: PASS")


def test_approval_records_a_human_and_edit_resets_it() -> None:
    _reset()
    gov.save_doc(_S, "conops", {"approach": "phased"})
    approved = gov.approve_doc(_S, "conops", "zaid")
    assert approved.approved and approved.approved_by == "zaid" and approved.approved_at
    # editing an approved document RESETS approval — the signed-off frame changed
    edited = gov.save_doc(_S, "conops", {"approach": "phased, careful"})
    assert not edited.approved, "an edit must reset approval so the new version is re-approved"
    # an empty document cannot be approved
    try:
        gov.approve_doc(_S, "deconfliction", "zaid")
        raise AssertionError("approving a v0 document should be refused")
    except ValueError:
        pass
    print("  approval records the human; an edit resets it; a v0 doc cannot be approved: PASS")


# --------------------------------------------------------------------------- #
# objective CRUD + expand/collapse
# --------------------------------------------------------------------------- #
def test_objective_crud_and_expand_collapse() -> None:
    _reset()
    root = gov.add_objective(_S, "Compromise the domain", phase="post-exploit")
    kids = gov.expand_objective(_S, root.obj_id, ["Kerberoast a service account", "DCSync"])
    assert [k.obj_id for k in kids] == [f"{root.obj_id}.1", f"{root.obj_id}.2"], "expand makes dotted children"
    assert len(gov.load_objectives(_S)) == 3

    removed = gov.collapse_objective(_S, root.obj_id)
    assert removed == 2, "collapse deletes the children but keeps the parent"
    assert len(gov.load_objectives(_S)) == 1 and gov.get_objective(_S, root.obj_id) is not None

    # delete removes an objective AND its descendants
    gov.expand_objective(_S, root.obj_id, ["child"])
    assert gov.delete_objective(_S, root.obj_id) == 2
    assert gov.load_objectives(_S) == []
    print("  objective add / expand (dotted children) / collapse / delete-with-descendants: PASS")


def test_technique_ids_are_cleaned_not_invented() -> None:
    _reset()
    o = gov.add_objective(_S, "x", technique_ids=["t1190", "T1078", "junk", "T1190", "T1548.002"])
    assert o.technique_ids == ["T1190", "T1078", "T1548.002"], o.technique_ids
    o2 = gov.add_objective(_S, "y", technique_ids="T1595, T1590")
    assert o2.technique_ids == ["T1595", "T1590"], "a comma/space string is accepted and split"
    print("  technique ids are upper-cased, de-duplicated and validated (junk dropped): PASS")


# --------------------------------------------------------------------------- #
# ATT&CK coverage
# --------------------------------------------------------------------------- #
def test_attack_coverage_renders_from_objectives() -> None:
    _reset()
    gov.add_objective(_S, "recon", phase="recon", technique_ids=["T1595"])
    gov.add_objective(_S, "access", phase="initial-access", technique_ids=["T1190", "T9999"])  # T9999 unmapped
    cov = gov.attack_coverage(_S)
    counts = cov["counts"]
    assert counts["techniques_covered"] == 2, counts  # T1595 + T1190 are in the reference
    assert counts["tactics_touched"] == 2, counts
    assert "T9999" in counts["unmapped"], "an id not in the reference is counted as unmapped, never dropped"
    # the grid marks the covered cells
    recon = next(t for t in cov["grid"] if t["tactic_id"] == "TA0043")
    assert recon["covered"] and any(c["covered"] and c["id"] == "T1595" for c in recon["techniques"])
    print("  ATT&CK coverage renders a per-tactic grid; unmapped ids counted, never dropped: PASS")


def test_opplan_payload_summary_and_version() -> None:
    _reset()
    a = gov.add_objective(_S, "a", technique_ids=["T1595"])
    gov.add_objective(_S, "b")
    gov.update_objective(_S, a.obj_id, status="in-progress")
    p = gov.opplan_payload(_S)
    assert p["summary"] == {
        "total": 2, "pending": 1, "in_progress": 1, "completed": 0, "blocked": 0, "cancelled": 0,
    }, p["summary"]
    assert p["version"] >= 1 and len(p["objectives"]) == 2
    assert p["attack_coverage"]["counts"]["techniques_covered"] == 1
    print("  opplan_payload carries versioned objectives + summary + coverage: PASS")


# --------------------------------------------------------------------------- #
# the RoE is a FRAME, not a veto — advisory only, wired in the app layer
# --------------------------------------------------------------------------- #
def test_roe_scope_advisory_flags_but_never_blocks() -> None:
    """The RoE-vs-scope check flags a mismatch/invalid scope; it NEVER blocks an objective or a
    command. Objectives keep mutating regardless — human approval stays the bound. This exercises
    the app-layer wiring (main._roe_scope_advisory) against a live TestClient engagement."""
    import main
    from fastapi.testclient import TestClient

    # This test drives a live TestClient, which does NOT run the app lifespan (deliberate — the
    # suite stays hermetic; lifespan also spins up the OOB auto-poll daemon). Lifespan is where
    # sessions_db.init_db() normally fires, so on a clean CI checkout (no sessions.db on disk) the
    # `sessions` table is absent and POST /sessions raises `no such table: sessions`. Create just
    # the one table this test needs — gov's table is already initialised at module import (line 17).
    main.sessions_db.init_db()

    c = TestClient(main.app)
    path = {"phases": [{"phase": "recon", "label": "Recon",
                        "steps": [{"id": "recon-1", "title": "x", "why": "", "commands": [], "entry_id": "e"}]}]}
    sid = c.post("/sessions", json={"goal": "demo.example.com", "target_type": "web", "path": path}).json()["id"]
    try:
        # an invalid RoE scope is FLAGGED, not rejected — the doc still saves and the objective still adds
        gov.save_doc(sid, "roe", {"scope_spec": "!only-an-exclusion"})
        view = c.get(f"/engagement/{sid}/governance").json()
        assert view["scope_check"]["status"] == "invalid", view["scope_check"]
        assert view["scope_check"]["advisory"] is True
        # despite the invalid RoE, adding + advancing an objective is unaffected (no machine veto)
        add = c.post(f"/engagement/{sid}/objectives", json={"title": "still works", "technique_ids": ["T1190"]})
        assert add.status_code == 200, add.text
        oid = add.json()["objective"]["obj_id"]
        assert c.patch(f"/engagement/{sid}/objectives/{oid}", json={"status": "in-progress"}).status_code == 200
        # an undeclared scope is a soft note, not an error
        gov.save_doc(sid, "roe", {"scope_spec": ""})
        assert c.get(f"/engagement/{sid}/governance").json()["scope_check"]["status"] == "undeclared"
    finally:
        c.delete(f"/sessions/{sid}")
        gov.clear(sid)
    print("  RoE-vs-scope is advisory: invalid/undeclared scope is FLAGGED, objectives unaffected: PASS")


def _run_all() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
    _reset()
    print(f"\nAll governance tests passed ({len(tests)} tests).")
    return 0


if __name__ == "__main__":
    sys.exit(_run_all())
