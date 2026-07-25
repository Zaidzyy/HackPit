"""Attack-path computation — the route(s) from an owned principal to Domain Admin.

Given a START node (the owned low-priv principal) and a HIGH-VALUE target (a specific node,
or "the domain's Domain Admins / any high-value node"), find the shortest path(s) over the
ABUSABLE edges only. Structural edges (Contains, GpLink, TrustedBy) are not traversed.

The search is a breadth-first shortest-path over the abusable subgraph. Among equal-length
paths we prefer the one whose edges are "more direct / quieter" (lower cumulative abuse rank),
so a MemberOf→GenericAll route is preferred over one that pivots through a session-harvest. We
return the best path plus up to a few distinct alternatives, and say so cleanly when there is
no path at all.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any

from .schema import Edge, Graph, abuse_rank


@dataclass
class PathEdge:
    """One hop on a computed route (mirrors :class:`Edge` plus the resolved endpoint labels)."""

    source: str
    target: str
    kind: str
    source_label: str
    target_label: str
    props: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "kind": self.kind,
            "source_label": self.source_label,
            "target_label": self.target_label,
            "props": self.props,
        }


@dataclass
class AttackPath:
    """A computed route: the ordered node ids, the resolved hop edges, and its cost."""

    node_ids: list[str]
    edges: list[PathEdge]
    length: int
    cost: int  # cumulative abuse rank — the tie-break metric (lower = preferred)

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_ids": self.node_ids,
            "edges": [e.to_dict() for e in self.edges],
            "length": self.length,
            "cost": self.cost,
        }


def _label(g: Graph, oid: str) -> str:
    n = g.node(oid)
    return n.label if n else oid


def _reconstruct(g: Graph, came_from: dict[str, tuple[str, Edge]], start: str,
                 goal: str) -> AttackPath:
    hops: list[Edge] = []
    node_ids: list[str] = [goal]
    cur = goal
    while cur != start:
        prev, edge = came_from[cur]
        hops.append(edge)
        node_ids.append(prev)
        cur = prev
    hops.reverse()
    node_ids.reverse()
    path_edges = [
        PathEdge(source=e.source, target=e.target, kind=e.kind,
                 source_label=_label(g, e.source), target_label=_label(g, e.target),
                 props=e.props)
        for e in hops
    ]
    cost = sum(abuse_rank(e.kind) for e in hops)
    return AttackPath(node_ids=node_ids, edges=path_edges, length=len(hops), cost=cost)


def shortest_path(g: Graph, start: str, goal: str) -> AttackPath | None:
    """Shortest abusable path start -> goal (fewest hops; ties broken by lower abuse cost).

    Returns None if either endpoint is unknown or no abusable route exists.
    """
    if start not in g.nodes or goal not in g.nodes:
        return None
    if start == goal:
        return AttackPath(node_ids=[start], edges=[], length=0, cost=0)

    # BFS layer by layer; within the frontier keep, per node, the lowest-cost predecessor so
    # equal-length paths resolve to the quieter abuse. (Edge weights are ~1, so BFS gives the
    # min hop count; the cost tie-break is applied when a node is first settled at its depth.)
    came_from: dict[str, tuple[str, Edge]] = {}
    best_cost: dict[str, int] = {start: 0}
    depth: dict[str, int] = {start: 0}
    frontier: deque[str] = deque([start])

    while frontier:
        cur = frontier.popleft()
        for e in g.outgoing(cur, abusable_only=True):
            nxt = e.target
            nd = depth[cur] + 1
            nc = best_cost[cur] + abuse_rank(e.kind)
            if nxt not in depth:
                depth[nxt] = nd
                best_cost[nxt] = nc
                came_from[nxt] = (cur, e)
                frontier.append(nxt)
            elif nd == depth[nxt] and nc < best_cost[nxt]:
                # same-length route to nxt, but cheaper abuse — prefer it
                best_cost[nxt] = nc
                came_from[nxt] = (cur, e)

    if goal not in came_from:
        return None
    return _reconstruct(g, came_from, start, goal)


def _members_of_targets(g: Graph, goal: str) -> set[str]:
    """Nodes that ARE the goal for pathing purposes: the goal node itself. (Reaching the
    Domain Admins group node is the win — control OVER it, e.g. via GenericAll/AddMember, is
    an inbound abusable edge, so the group node is the correct terminus.)"""
    return {goal}


def paths_to_target(g: Graph, start: str, goal: str, max_alts: int = 3) -> dict[str, Any]:
    """Compute the route(s) from ``start`` to ``goal``.

    Returns ``{found, path, alternatives, reason}``. ``path`` is the best route;
    ``alternatives`` are up to ``max_alts`` distinct routes that avoid the best route's most
    critical single hop (so the UI can offer "another way in"). ``found`` is False with a
    human ``reason`` when no route exists / endpoints are unknown.
    """
    if start not in g.nodes:
        return {"found": False, "path": None, "alternatives": [],
                "reason": f"start principal '{start}' is not in the collection"}
    if goal not in g.nodes:
        return {"found": False, "path": None, "alternatives": [],
                "reason": f"target '{goal}' is not in the collection"}

    best = shortest_path(g, start, goal)
    if best is None:
        return {"found": False, "path": None, "alternatives": [],
                "reason": "no abusable path found from the owned principal to the target "
                          "(the collection may be partial, or there genuinely is no route)"}

    alternatives: list[AttackPath] = []
    seen_sigs = {tuple(best.node_ids)}
    # Find distinct alternatives by removing one hop of the current best route at a time and
    # re-searching (classic k-shortest-ish, bounded + cheap for these graph sizes).
    removable = list(best.edges)
    for hop in removable:
        if len(alternatives) >= max_alts:
            break
        alt = _shortest_path_excluding(g, start, goal, exclude=(hop.source, hop.target, hop.kind))
        if alt is None:
            continue
        sig = tuple(alt.node_ids)
        if sig in seen_sigs:
            continue
        seen_sigs.add(sig)
        alternatives.append(alt)

    return {
        "found": True,
        "path": best.to_dict(),
        "alternatives": [a.to_dict() for a in alternatives],
        "reason": None,
    }


def _shortest_path_excluding(g: Graph, start: str, goal: str,
                             exclude: tuple[str, str, str]) -> AttackPath | None:
    """Shortest abusable path that does NOT use the given (source,target,kind) edge."""
    if start not in g.nodes or goal not in g.nodes or start == goal:
        return None
    came_from: dict[str, tuple[str, Edge]] = {}
    depth: dict[str, int] = {start: 0}
    best_cost: dict[str, int] = {start: 0}
    frontier: deque[str] = deque([start])
    while frontier:
        cur = frontier.popleft()
        for e in g.outgoing(cur, abusable_only=True):
            if e.key() == exclude:
                continue
            nxt = e.target
            nd, nc = depth[cur] + 1, best_cost[cur] + abuse_rank(e.kind)
            if nxt not in depth:
                depth[nxt] = nd
                best_cost[nxt] = nc
                came_from[nxt] = (cur, e)
                frontier.append(nxt)
            elif nd == depth[nxt] and nc < best_cost[nxt]:
                best_cost[nxt] = nc
                came_from[nxt] = (cur, e)
    if goal not in came_from:
        return None
    return _reconstruct(g, came_from, start, goal)


def default_high_value_target(g: Graph, prefer_rid: str = "512") -> str | None:
    """Pick the canonical high-value target: Domain Admins (RID 512) if present, else any
    high-value group, else any high-value node. Used when the UI didn't name one."""
    hv = g.high_value_nodes()
    for n in hv:
        if n.id.endswith(f"-{prefer_rid}"):
            return n.id
    for n in hv:
        if n.type == "group":
            return n.id
    return hv[0].id if hv else None
