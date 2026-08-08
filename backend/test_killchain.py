"""Functional tests for the cross-domain kill-chain overlay.

Covers the four things the spec names:
  * MERGE of three synthetic lane dicts into one graph with ``domain`` tags on every node;
  * the BRIDGE catalog SYNTHESIZES the cross-domain seams from the lane seam-declarations;
  * BFS ROUTES a web foothold -> cloud -> on-prem Domain Admin ACROSS the lanes;
  * the ORCHESTRATOR proposes an EDGE INDEX (and refuses a pick outside the frontier), and
    ``advance`` moves the chain ONLY on an approved, exit-0 run for a cross-domain hop.

Hermetic: no Docker, no live LLM, no network. Run:  python test_killchain.py
"""
from __future__ import annotations

import killchain.orchestrator as O
from killchain import bridges, sample_data as S, service
from killchain.merge import merge_lanes
from killchain.paths import default_high_value_target, default_owned_start, paths_to_target
from killchain.schema import split_domain


# --------------------------------------------------------------------------- #
# merge + domain tags
# --------------------------------------------------------------------------- #
def test_merge_tags_every_node_with_its_domain() -> None:
    g = S.sample_graph()
    domains = {n.domain for n in g.nodes.values()}
    assert domains == {"web", "cloud", "onprem"}, domains
    # ids are domain-namespaced so lanes cannot collide, and the domain is recoverable from the id
    for n in g.nodes.values():
        assert split_domain(n.id)[0] == n.domain, n.id
    st = g.stats()
    assert st["domain_web"] >= 1 and st["domain_cloud"] >= 1 and st["domain_onprem"] >= 1, st
    print(f"  merge: {st['nodes']} nodes across web/cloud/onprem, each tagged + namespaced: PASS")


def test_bridges_synthesize_the_cross_domain_seams() -> None:
    g = S.sample_graph()
    seams = {e.kind for e in g.edges if e.bridge}
    # every bridge kind in the catalog is represented in the synthetic chain
    assert seams == set(bridges.BRIDGE_KINDS), (seams, bridges.BRIDGE_KINDS)
    # a bridge carries the two domains it crosses so the UI can draw the lane crossing
    ssrf = next(e for e in g.edges if e.kind == "SsrfToImds")
    assert ssrf.props["domain_from"] == "web" and ssrf.props["domain_to"] == "cloud", ssrf.props
    # a seam pointing at a missing node is skipped with a warning, never a dangling edge
    g2 = merge_lanes(web={"nodes": [{"id": "x", "type": "finding", "label": "x", "owned": True,
                                     "props": {"seams": [{"kind": "SsrfToImds", "to": "cloud::nope"}]}}],
                          "edges": []}, cloud=None, onprem=None)
    assert not any(e.bridge for e in g2.edges) and g2.warnings, g2.warnings
    print(f"  bridges: all {len(bridges.BRIDGE_KINDS)} seam kinds synthesized, a dangling seam "
          "refused with a warning: PASS")


# --------------------------------------------------------------------------- #
# routing across the lanes
# --------------------------------------------------------------------------- #
def test_bfs_routes_web_foothold_to_onprem_domain_admin() -> None:
    g = S.sample_graph()
    goal = default_high_value_target(g)
    assert goal == S.HIGH_VALUE_TARGET, goal
    assert split_domain(goal)[0] == "onprem", "the objective is the on-prem Domain Admin"
    start = default_owned_start(g)
    assert split_domain(start)[0] == "web", "the start foothold is the web lane"
    res = paths_to_target(g, S.OWNED_START, goal)
    assert res["found"], res
    kinds = [h["kind"] for h in res["path"]["edges"]]
    assert kinds == ["SsrfToImds", "ReadSecret", "CloudToOnprem", "GenericAll", "MemberOf"], kinds
    # the route crosses BOTH web→cloud and cloud→onprem seams
    assert res["path"]["crossings"] == 2, res["path"]["crossings"]
    doms = [split_domain(nid)[0] for nid in res["path"]["node_ids"]]
    assert doms[0] == "web" and doms[-1] == "onprem" and "cloud" in doms, doms
    print("  routing: web SSRF -> cloud ci-deployer -> on-prem SVC-SQL -> Domain Admins, crossing "
          "2 seams over 3 lanes: PASS")


# --------------------------------------------------------------------------- #
# orchestrator — the edge-index proposal
# --------------------------------------------------------------------------- #
def _stub_llm(monkey_json: str):
    orig = O.llm.chat
    O.llm.chat = lambda *a, **k: monkey_json  # type: ignore[assignment]
    return orig


def test_orchestrator_proposes_a_seam_edge_index() -> None:
    g = S.sample_graph()
    state = O.KillchainState(owned=(S.OWNED_START,))
    cands = O.frontier(g, state)
    idx = next(i for i, e in enumerate(cands) if e.kind == "SsrfToImds")
    orig = _stub_llm(f'{{"done": false, "pick": {idx}, "rationale": "pivot into cloud"}}')
    try:
        out = O.propose_next(g, state, S.HIGH_VALUE_TARGET, {})
    finally:
        O.llm.chat = orig
    prop = out["proposal"]
    assert prop is not None and prop["edge"]["kind"] == "SsrfToImds", prop
    assert prop["is_bridge"] and prop["runnable"] and prop["command"] == "curl", prop
    assert prop["edge"]["domain_from"] == "web" and prop["edge"]["domain_to"] == "cloud", prop
    assert prop["technique"]["attack_id"] == "T1552.005", prop["technique"]
    print("  orchestrator: model returns an INDEX -> the real seam edge, resolved to a KB/catalog "
          "crossing command (never authored by the model): PASS")


def test_within_lane_hop_defers_to_its_lane_view() -> None:
    g = S.sample_graph()
    edge = next(e for e in g.edges if e.kind == "AttachRolePolicy")
    prop = O.proposal_for_edge(g, edge, "")
    assert not prop["is_bridge"] and not prop["runnable"], prop
    assert prop["resolution"] == "lane-view" and prop["lane_view"] == "/cockpit/cloud", prop
    assert prop["command"] == "" and prop["args"] == [], prop
    print("  within-lane hop: not runnable here — it defers to the :cloud view (single source of "
          "truth for per-lane abuse): PASS")


def test_orchestrator_refuses_a_pick_outside_the_frontier() -> None:
    g = S.sample_graph()
    state = O.KillchainState(owned=(S.OWNED_START,))
    orig = _stub_llm('{"done": false, "pick": 99, "rationale": "out of range"}')
    try:
        out = O.propose_next(g, state, S.HIGH_VALUE_TARGET, {})
    finally:
        O.llm.chat = orig
    assert out["proposal"] is None and "invalid edge selection" in (out["reason"] or ""), out
    print("  orchestrator: a pick outside the candidate list is REFUSED, not repaired: PASS")


# --------------------------------------------------------------------------- #
# advance — evidence-gated for a cross-domain hop
# --------------------------------------------------------------------------- #
class _Run:
    def __init__(self, approved: bool, exit_code: int) -> None:
        self.approved = approved
        self.exit_code = exit_code


def test_advance_requires_an_approved_exit0_run_for_a_seam() -> None:
    g = S.sample_graph()
    cloud_secret = sample_data_qualify("cloud", S.APP_SECRET)
    svc_sql = sample_data_qualify("onprem", S.SVC_SQL)
    base = dict(source=cloud_secret, target=svc_sql, kind="CloudToOnprem",
                owned=[cloud_secret], traversed=[])

    # a runnable seam, no run_id -> 422
    try:
        service.advance_step(g, **base)
        assert False, "a runnable seam with no run_id must be refused"
    except service.KillchainError as e:
        assert e.status == 422, e.status

    # UNAPPROVED run -> 409
    try:
        service.advance_step(g, run_id="r1", run_lookup=lambda _r: _Run(False, 0), **base)
        assert False, "an unapproved run must not advance the chain"
    except service.KillchainError as e:
        assert e.status == 409 and "not approved" in str(e.detail), e.detail

    # approved but EXIT 1 -> 409
    try:
        service.advance_step(g, run_id="r2", run_lookup=lambda _r: _Run(True, 1), **base)
        assert False, "a failed run must not advance the chain"
    except service.KillchainError as e:
        assert e.status == 409 and "exited 1" in str(e.detail), e.detail

    # APPROVED + EXIT 0 -> advances, seam crossed
    out = service.advance_step(g, run_id="r3", run_lookup=lambda _r: _Run(True, 0), **base)
    assert svc_sql in out["state"]["owned"] and out["crossed_seam"] is True, out

    # a WITHIN-LANE hop advances with NO run_id (approved in its own lane view)
    out2 = service.advance_step(
        g, source=svc_sql, target=sample_data_qualify("onprem", S.BACKUP), kind="GenericAll",
        owned=[svc_sql], traversed=[])
    assert sample_data_qualify("onprem", S.BACKUP) in out2["state"]["owned"], out2
    print("  advance: a cross-domain hop moves the chain ONLY on an approved exit-0 run; a "
          "within-lane hop advances on the operator's word: PASS")


def sample_data_qualify(domain: str, raw: str) -> str:
    from killchain.schema import qualify
    return qualify(domain, raw)


if __name__ == "__main__":
    test_merge_tags_every_node_with_its_domain()
    test_bridges_synthesize_the_cross_domain_seams()
    test_bfs_routes_web_foothold_to_onprem_domain_admin()
    test_orchestrator_proposes_a_seam_edge_index()
    test_within_lane_hop_defers_to_its_lane_view()
    test_orchestrator_refuses_a_pick_outside_the_frontier()
    test_advance_requires_an_approved_exit0_run_for_a_seam()
    print("ALL kill-chain functional tests pass")
