"""Functional tests for the cloud IAM privilege-escalation graph.

Covers the four things the spec names:
  * the PARSER turns a ScoutSuite enumeration + Prowler findings into a typed IAM graph;
  * BFS ROUTING finds the shortest abusable path to an admin/owner principal;
  * the ORCHESTRATOR proposes an EDGE INDEX (and refuses a pick outside the frontier);
  * ``advance`` moves the walk ONLY on an approved, exit-0 run.

Hermetic: no Docker, no live LLM, no network. Run:  python test_cloudgraph.py
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import cloudgraph.orchestrator as O
from cloudgraph import sample_data as S
from cloudgraph import store as CS
from cloudgraph.parser import ParseError, parse_collection, parse_prowler_findings
from cloudgraph.paths import default_high_value_target, paths_to_target


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #
def test_parser_builds_a_privesc_graph() -> None:
    g = parse_collection(S.sample_collection())
    assert g.provider == "aws" and g.account == S.ACCOUNT
    kinds = {(g.node(e.source).label, e.kind, g.node(e.target).label) for e in g.edges if e.abusable}
    assert ("dev-alice", "MemberOf", "developers") in kinds
    assert ("developers", "AssumeRole", "ci-deployer") in kinds
    assert ("ci-deployer", "AttachRolePolicy", "break-glass-admin") in kinds
    # the Lambda branch reaches the execution ROLE, not the function
    assert ("ci-deployer", "UpdateFunctionCode", "break-glass-admin") in kinds
    hv = {n.label for n in g.high_value_nodes()}
    assert "break-glass-admin" in hv, hv
    print("  parser: ScoutSuite IAM tree -> typed privesc graph, admin detected: PASS")


def test_parser_reads_prowler_findings() -> None:
    rows = parse_prowler_findings(S.sample_collection())
    titles = {r["title"] for r in rows}
    sevs = {r["severity"] for r in rows}
    assert any("publicly accessible" in t for t in titles), titles
    assert "critical" in sevs and "high" in sevs, sevs
    # PASS rows are dropped
    assert all("minimum length" not in r["title"] for r in rows)
    print(f"  parser: {len(rows)} Prowler FAIL findings parsed (PASS rows dropped): PASS")


def test_parser_rejects_junk() -> None:
    for junk in ({}, {"services": {"iam": {}}}, [1, 2, 3]):
        try:
            parse_collection(junk)
            assert False, f"{junk!r} should not parse"
        except ParseError:
            pass
    print("  parser: an enumeration with no IAM objects is a clean ParseError: PASS")


# --------------------------------------------------------------------------- #
# routing
# --------------------------------------------------------------------------- #
def test_bfs_routes_to_an_admin_principal() -> None:
    g = parse_collection(S.sample_collection())
    goal = default_high_value_target(g)
    assert g.node(goal).label == "break-glass-admin", goal
    res = paths_to_target(g, S.OWNED_START, goal)
    assert res["found"], res
    hops = [h["kind"] for h in res["path"]["edges"]]
    assert hops == ["MemberOf", "AssumeRole", "AttachRolePolicy"], hops
    # a start with no route says so cleanly
    dead = parse_collection(S.sample_collection())
    res2 = paths_to_target(dead, S.BUILD_BOT, goal)
    assert not res2["found"] and res2["reason"], res2
    print("  routing: shortest abusable path dev-alice -> break-glass-admin (3 hops); "
          "a routeless start reports cleanly: PASS")


# --------------------------------------------------------------------------- #
# orchestrator — the edge-index proposal
# --------------------------------------------------------------------------- #
def _stub_llm(monkey_json: str):
    """Replace the orchestrator's llm.chat with a canned JSON; keep the real extract_json."""
    orig = O.llm.chat
    O.llm.chat = lambda *a, **k: monkey_json  # type: ignore[assignment]
    return orig


def test_orchestrator_proposes_an_edge_index() -> None:
    g = parse_collection(S.sample_collection())
    # own the first three principals so the frontier holds the runnable admin-granting edges
    state = O.CloudState(owned=(S.ALICE, S.DEVELOPERS, S.CI_DEPLOYER))
    cands = O.frontier(g, state)
    idx = next(i for i, e in enumerate(cands) if e.kind == "AttachRolePolicy")
    orig = _stub_llm(f'{{"done": false, "pick": {idx}, "rationale": "grants admin"}}')
    try:
        out = O.propose_next(g, state, S.HIGH_VALUE_TARGET, {})
    finally:
        O.llm.chat = orig
    assert out["proposal"] is not None and out["done"] is False, out
    prop = out["proposal"]
    assert prop["edge"]["kind"] == "AttachRolePolicy", prop["edge"]
    assert prop["runnable"] and prop["command"] == "aws", prop
    assert prop["destructive_technique"] is True
    print("  orchestrator: model returns an INDEX, resolved to the real edge's KB-grounded "
          "command (never authored by the model): PASS")


def test_orchestrator_refuses_a_pick_outside_the_frontier() -> None:
    g = parse_collection(S.sample_collection())
    state = O.CloudState(owned=(S.ALICE,))
    orig = _stub_llm('{"done": false, "pick": 99, "rationale": "out of range"}')
    try:
        out = O.propose_next(g, state, S.HIGH_VALUE_TARGET, {})
    finally:
        O.llm.chat = orig
    assert out["proposal"] is None and "invalid edge selection" in (out["reason"] or ""), out
    print("  orchestrator: a pick outside the candidate list is REFUSED, not repaired: PASS")


# --------------------------------------------------------------------------- #
# advance — evidence-gated
# --------------------------------------------------------------------------- #
class _Run:
    def __init__(self, approved: bool, exit_code: int) -> None:
        self.approved = approved
        self.exit_code = exit_code


def test_advance_requires_an_approved_exit0_run() -> None:
    from fastapi import HTTPException

    from cloudgraph import router as R
    from cockpit import runstore

    tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
    db = Path(tmp.name) / "sessions.db"
    db_orig, R_db_orig = CS.DB_PATH, R.store.DB_PATH
    CS.DB_PATH = R.store.DB_PATH = db
    run_orig = runstore.get_run
    try:
        CS.init_db()
        g = parse_collection(S.sample_collection())
        graph_id = CS.save_graph(g.to_dict(), session_id="sess-clg", source="sample")

        base = dict(graph_id=graph_id, owned=[S.CI_DEPLOYER], traversed=[],
                    source=S.CI_DEPLOYER, target=S.BREAK_GLASS, kind="AttachRolePolicy")

        # runnable edge, no run_id -> 422
        try:
            R.cloud_orchestrate_advance(R.AdvanceIn(**base))
            assert False, "a runnable edge with no run_id must be refused"
        except HTTPException as e:
            assert e.status_code == 422, e.status_code

        # an UNAPPROVED run -> 409
        runstore.get_run = lambda rid: _Run(approved=False, exit_code=0)
        try:
            R.cloud_orchestrate_advance(R.AdvanceIn(run_id="r1", **base))
            assert False, "an unapproved run must not advance the walk"
        except HTTPException as e:
            assert e.status_code == 409 and "not approved" in str(e.detail), e.detail

        # approved but EXIT 1 -> 409
        runstore.get_run = lambda rid: _Run(approved=True, exit_code=1)
        try:
            R.cloud_orchestrate_advance(R.AdvanceIn(run_id="r2", **base))
            assert False, "a failed run must not advance the walk"
        except HTTPException as e:
            assert e.status_code == 409 and "exited 1" in str(e.detail), e.detail

        # APPROVED + EXIT 0 -> advances, objective reached
        runstore.get_run = lambda rid: _Run(approved=True, exit_code=0)
        out = R.cloud_orchestrate_advance(R.AdvanceIn(run_id="r3", **base))
        assert S.BREAK_GLASS in out["state"]["owned"] and out["objective_reached"] is True, out

        # a NO-COMMAND edge (MemberOf) advances WITHOUT a run_id (inherited rights)
        out2 = R.cloud_orchestrate_advance(R.AdvanceIn(
            graph_id=graph_id, owned=[S.ALICE], traversed=[],
            source=S.ALICE, target=S.DEVELOPERS, kind="MemberOf"))
        assert S.DEVELOPERS in out2["state"]["owned"], out2
    finally:
        runstore.get_run = run_orig
        CS.DB_PATH, R.store.DB_PATH = db_orig, R_db_orig
        tmp.cleanup()
    print("  advance: moves the walk ONLY on an approved, exit-0 run; inherited-rights edges "
          "advance with no run to cite: PASS")


if __name__ == "__main__":
    test_parser_builds_a_privesc_graph()
    test_parser_reads_prowler_findings()
    test_parser_rejects_junk()
    test_bfs_routes_to_an_admin_principal()
    test_orchestrator_proposes_an_edge_index()
    test_orchestrator_refuses_a_pick_outside_the_frontier()
    test_advance_requires_an_approved_exit0_run()
    print("ALL cloud-graph functional tests pass")
