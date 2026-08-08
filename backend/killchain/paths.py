"""Attack-path computation over the MERGED kill-chain graph — the route across the three lanes.

The same breadth-first shortest-path the two per-lane graphs use (``adgraph/paths.py`` /
``cloudgraph/paths.py``), lifted onto the merged node/edge set: from an owned foothold in ANY lane
to a high-value target in ANY lane, over the ABUSABLE edges only (within-lane abuse edges + the
synthesized cross-domain bridges). Structural edges are not traversed.

Tie-break: among equal-length routes, prefer the one whose edges are "more direct". The overlay has
no per-lane abuse rank (it does not import either taxonomy), so within-lane edges share one rank and
bridges are ranked by :func:`bridges.bridge_rank` — enough to prefer a shorter/quieter crossing when
two routes are the same length.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any

from . import bridges
from .schema import Edge, Graph

# Every within-lane abusable edge shares this rank; a bridge's rank comes from the bridge catalog
# (all below this constant, so a route that crosses a seam sooner is preferred on a tie).
_LANE_RANK = 100


def edge_rank(edge: Edge) -> int:
    return bridges.bridge_rank(edge.kind) if edge.bridge else _LANE_RANK


@dataclass
class PathEdge:
    source: str
    target: str
    kind: str
    source_label: str
    target_label: str
    bridge: bool = False
    props: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "kind": self.kind,
            "source_label": self.source_label,
            "target_label": self.target_label,
            "bridge": self.bridge,
            "props": self.props,
        }


@dataclass
class AttackPath:
    node_ids: list[str]
    edges: list[PathEdge]
    length: int
    cost: int
    crossings: int  # how many cross-domain seams the route walks (the kill-chain's whole point)

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_ids": self.node_ids,
            "edges": [e.to_dict() for e in self.edges],
            "length": self.length,
            "cost": self.cost,
            "crossings": self.crossings,
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
                 bridge=e.bridge, props=e.props)
        for e in hops
    ]
    cost = sum(edge_rank(e) for e in hops)
    crossings = sum(1 for e in hops if e.bridge)
    return AttackPath(node_ids=node_ids, edges=path_edges, length=len(hops), cost=cost,
                      crossings=crossings)


def shortest_path(g: Graph, start: str, goal: str) -> AttackPath | None:
    """Shortest abusable path start -> goal (fewest hops; ties broken by lower edge cost)."""
    if start not in g.nodes or goal not in g.nodes:
        return None
    if start == goal:
        return AttackPath(node_ids=[start], edges=[], length=0, cost=0, crossings=0)

    came_from: dict[str, tuple[str, Edge]] = {}
    best_cost: dict[str, int] = {start: 0}
    depth: dict[str, int] = {start: 0}
    frontier: deque[str] = deque([start])

    while frontier:
        cur = frontier.popleft()
        for e in g.outgoing(cur, abusable_only=True):
            nxt = e.target
            nd = depth[cur] + 1
            nc = best_cost[cur] + edge_rank(e)
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


def _shortest_path_excluding(g: Graph, start: str, goal: str,
                             exclude: tuple[str, str, str]) -> AttackPath | None:
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
            nd, nc = depth[cur] + 1, best_cost[cur] + edge_rank(e)
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


def paths_to_target(g: Graph, start: str, goal: str, max_alts: int = 3) -> dict[str, Any]:
    """Compute the route(s) from ``start`` to ``goal``. Same contract as the per-lane path engines:
    ``{found, path, alternatives, reason}``."""
    if start not in g.nodes:
        return {"found": False, "path": None, "alternatives": [],
                "reason": f"start foothold '{start}' is not in the merged graph"}
    if goal not in g.nodes:
        return {"found": False, "path": None, "alternatives": [],
                "reason": f"objective '{goal}' is not in the merged graph"}

    best = shortest_path(g, start, goal)
    if best is None:
        return {"found": False, "path": None, "alternatives": [],
                "reason": "no abusable route found from the owned foothold to the objective across "
                          "the lanes (a lane or a seam may be missing)"}

    alternatives: list[AttackPath] = []
    seen_sigs = {tuple(best.node_ids)}
    for hop in list(best.edges):
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


# Priority order for the default objective: an on-prem Domain Admin is the canonical "end of the
# chain", then a cloud Owner/root, then any high-value node.
_GOAL_DOMAIN_ORDER = ("onprem", "cloud", "web")


def default_high_value_target(g: Graph) -> str | None:
    """Pick the canonical objective: the highest-value node furthest down the chain (on-prem DA,
    else cloud Owner/root, else any high-value node). Used when the UI didn't name one."""
    hv = g.high_value_nodes()
    if not hv:
        return None
    for dom in _GOAL_DOMAIN_ORDER:
        for n in hv:
            if n.domain == dom:
                return n.id
    return hv[0].id


def default_owned_start(g: Graph) -> str | None:
    """Pick the canonical starting foothold: an owned node furthest UP the chain (a web foothold,
    else cloud, else on-prem). Used when the UI didn't name one."""
    owned = g.owned_nodes()
    if not owned:
        return None
    for dom in reversed(_GOAL_DOMAIN_ORDER):  # web first
        for n in owned:
            if n.domain == dom:
                return n.id
    return owned[0].id


__all__ = [
    "PathEdge", "AttackPath", "shortest_path", "paths_to_target",
    "default_high_value_target", "default_owned_start", "edge_rank",
]
