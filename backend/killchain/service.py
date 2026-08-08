"""The cross-cutting service layer the app's kill-chain routes call.

``main.py`` owns the three ``/killchain/*`` routes (the cross-cutting join over adgraph's + cloud's
public output + engagement findings), but the LOGIC lives here so it stays thin and testable. This
module still imports NEITHER adgraph NOR cloudgraph: it takes each lane's PUBLIC DICT as data (the
route fetches them from the two stores and hands them in) and returns plain dicts. The evidence-gated
``advance_step`` takes an injected ``run_lookup`` so it can be tested with a stub run and mapped to an
HTTP error by the route.
"""

from __future__ import annotations

from typing import Any, Callable

from . import orchestrator as kc_orch
from . import paths as kc_paths
from . import sample_data
from .merge import merge_lanes
from .schema import Graph


class KillchainError(Exception):
    """A typed failure the route maps to an HTTPException (status + detail)."""

    def __init__(self, status: int, detail: Any) -> None:
        super().__init__(str(detail))
        self.status = status
        self.detail = detail


# Findings whose kind is a web foothold that can begin a cross-domain chain. Matched loosely on the
# title/tool/reference — a web lane node is a foothold, not a precise taxonomy.
_WEB_FOOTHOLD_HINTS = ("ssrf", "rce", "remote code", "deserial", "ssti", "upload", "lfi", "xxe",
                       "sqli", "sql injection", "leaked", "credential", "secret")


def web_lane_from_findings(findings: list[Any]) -> dict[str, Any]:
    """Build a web-lane public dict from engagement Findings — each web foothold is an owned node.

    Live findings do not yet declare cross-domain seams (those are created by the dedicated seams,
    e.g. the SSRF→IMDS /cloud/seed-imds flow, as live integration deepens); here they render as the
    web lane so the overlay shows all three lanes with whatever exists. Accepts Finding objects or
    plain dicts.
    """
    nodes: list[dict[str, Any]] = []
    seen: set[str] = set()
    for f in findings or []:
        title = str(getattr(f, "title", None) or (f.get("title") if isinstance(f, dict) else "") or "")
        tool = str(getattr(f, "tool", None) or (f.get("tool") if isinstance(f, dict) else "") or "")
        ref = str(getattr(f, "reference", None) or (f.get("reference") if isinstance(f, dict) else "") or "")
        sev = str(getattr(f, "severity", None) or (f.get("severity") if isinstance(f, dict) else "") or "")
        hay = f"{title} {tool} {ref}".lower()
        if not any(h in hay for h in _WEB_FOOTHOLD_HINTS):
            continue
        nid = f"finding:{ref or title}"[:120]
        if nid in seen:
            continue
        seen.add(nid)
        nodes.append({"id": nid, "type": "finding", "label": title or nid, "owned": True,
                      "high_value": False, "props": {"severity": sev, "tool": tool}})
    return {"nodes": nodes, "edges": [], "warnings": []}


def build_demo() -> Graph:
    """The synthetic three-lane demo graph (no live data)."""
    return sample_data.sample_graph()


def build_from_session(
    cloud_dict: dict[str, Any] | None,
    ad_dict: dict[str, Any] | None,
    findings: list[Any] | None,
) -> Graph:
    """Merge a session's live lanes: the cloud graph's public dict, the AD graph's public dict, and
    the web lane built from engagement findings. Any lane may be absent."""
    web = web_lane_from_findings(findings or [])
    return merge_lanes(web=web if web["nodes"] else None, cloud=cloud_dict, onprem=ad_dict)


def graph_payload(graph: Graph, start: str | None, goal: str | None,
                  grounder: Callable | None = None) -> dict[str, Any]:
    """The full kill-chain payload for the UI: the merged graph, the computed route to the objective,
    and the per-hop technique. Read-only — nothing runs."""
    resolved_goal = goal or kc_paths.default_high_value_target(graph)
    resolved_start = start or kc_paths.default_owned_start(graph)
    out: dict[str, Any] = {"graph": graph.to_dict(), "start": resolved_start, "goal": resolved_goal}
    if not resolved_start or not resolved_goal:
        out["route"] = {"found": False, "path": None, "alternatives": [],
                        "reason": "need at least one owned foothold and one high-value objective "
                                  "across the lanes to route a kill chain"}
        return out
    route = kc_paths.paths_to_target(graph, resolved_start, resolved_goal)
    route["target"] = resolved_goal
    tnode = graph.node(resolved_goal)
    route["target_label"] = tnode.label if tnode else resolved_goal
    snode = graph.node(resolved_start)
    route["start_label"] = snode.label if snode else resolved_start
    if route.get("found") and route.get("path"):
        for hop in route["path"]["edges"]:
            edge = next((e for e in graph.edges
                         if e.source == hop["source"] and e.target == hop["target"]
                         and e.kind == hop["kind"]), None)
            if edge is not None:
                hop["technique"] = kc_orch.proposal_for_edge(graph, edge, "", grounder)["technique"]
    out["route"] = route
    return out


def propose_payload(
    graph: Graph, owned: list[str], traversed: list[str], goal: str | None, cfg: dict,
    grounder: Callable | None = None, scope_ctx: Any | None = None, avoid: list[str] | None = None,
    engagement: bool = False,
) -> dict[str, Any]:
    """Propose the next edge to take. Executes nothing — returns a proposal the human approves."""
    resolved_goal = goal or kc_paths.default_high_value_target(graph)
    if not resolved_goal:
        raise KillchainError(422, "no high-value objective in the merged graph to route toward")
    state = kc_orch.KillchainState.from_dict({"owned": owned, "traversed": traversed})
    if not state.owned:
        raise KillchainError(422, "no owned foothold — mark the foothold you control before asking "
                                  "for a proposal; the agent reasons out from what you already have")
    out = kc_orch.propose_next(graph, state, resolved_goal, cfg, grounder, scope_ctx, avoid)
    node = graph.node(resolved_goal)
    return {
        **out,
        "goal": resolved_goal,
        "goal_label": node.label if node else resolved_goal,
        "state": state.to_dict(),
        "mode": "engagement" if engagement else "lab",
        "note": "PROPOSAL ONLY — nothing has run. A cross-domain (seam) step is approved and sent to "
                "POST /cockpit/exec, the same gated executor; a within-lane step is approved in its "
                "own :cloud / :ad-graph view.",
    }


def advance_step(
    graph: Graph, *, owned: list[str], traversed: list[str], source: str, target: str, kind: str,
    run_id: str | None = None, run_lookup: Callable[[str], Any] | None = None,
) -> dict[str, Any]:
    """Record that a hop SUCCEEDED: mark the edge traversed and the target owned. Advancement is tied
    to EVIDENCE for a runnable (cross-domain) hop — ``run_id`` must name a run the ``run_lookup``
    reports APPROVED and exit-0. A within-lane hop (approved in its own view) or an inherited-rights
    hop advances on the operator's word, exactly like the per-lane graphs. Executes nothing."""
    edge = next((e for e in graph.edges
                 if e.source == source and e.target == target and e.kind == kind), None)
    if edge is None:
        raise KillchainError(404, "that edge is not in the merged kill-chain graph")

    prop = kc_orch.proposal_for_edge(graph, edge, "")
    if prop["runnable"]:
        if not run_id:
            raise KillchainError(422, "this cross-domain hop has a command, so advancing it requires "
                                      "the run_id of the approved run that carried it out")
        run = run_lookup(run_id) if run_lookup else None
        if run is None:
            raise KillchainError(404, "no such run")
        if not getattr(run, "approved", False):
            raise KillchainError(409, "that run was not approved — the chain does not advance on an "
                                      "unapproved step")
        if getattr(run, "exit_code", 1) != 0:
            raise KillchainError(409, f"that run exited {getattr(run, 'exit_code', '?')} — the chain "
                                      "advances only on success")

    state = kc_orch.KillchainState.from_dict({"owned": owned, "traversed": traversed})
    new_state = kc_orch.advance(state, source, target, kind)
    goal = kc_paths.default_high_value_target(graph)
    tnode = graph.node(target)
    return {
        "state": new_state.to_dict(),
        "owned_label": tnode.label if tnode else target,
        "crossed_seam": bool(edge.bridge),
        "objective_reached": bool(goal and new_state.is_owned(goal)),
        "remaining_frontier": len(kc_orch.frontier(graph, new_state)),
        "proposal": prop,
    }


__all__ = [
    "KillchainError", "web_lane_from_findings", "build_demo", "build_from_session",
    "graph_payload", "propose_payload", "advance_step",
]
