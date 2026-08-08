"""The MERGED three-lane kill-chain graph schema — a read-and-stitch overlay's node/edge model.

This is deliberately SELF-CONTAINED: it imports nothing from ``adgraph`` or ``cloudgraph``. The
overlay consumes each of those graphs' PUBLIC DICT (``Graph.to_dict()`` — a plain nodes/edges/stats
mapping) and copies it into this merged model, tagging every node with its ``domain`` (web | cloud |
onprem). Because each source dict already carries a precomputed ``abusable`` flag on every edge, the
overlay never needs either package's edge taxonomy — it simply preserves that flag. Cross-domain
BRIDGE edges (synthesized by ``bridges.py``) are marked abusable here.

A node is a typed principal / resource / foothold; an edge is a directed relationship whose ``kind``
names the abuse (within a lane) or the SEAM (across lanes). The path engine walks ONLY abusable
edges; the UI renders all of them but lights the route over the abusable set — exactly like the two
per-lane graphs it stitches.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

# The three lanes a cross-domain kill chain crosses, web-foothold → cloud → on-prem.
DOMAINS = ("web", "cloud", "onprem")

# A stable per-domain id prefix, so two lanes can never collide on a shared id (an ARN, a SID and a
# Finding id are distinct in practice, but namespacing makes it guaranteed AND makes a node's domain
# recoverable from its id alone). ``web::<id>`` / ``cloud::<id>`` / ``onprem::<id>``.
_DOMAIN_SEP = "::"


def qualify(domain: str, raw_id: str) -> str:
    """The merged id for a lane-local id: ``<domain>::<raw_id>``."""
    return f"{domain}{_DOMAIN_SEP}{raw_id}"


def split_domain(merged_id: str) -> tuple[str, str]:
    """``(domain, raw_id)`` from a merged id; ``("", merged_id)`` if it carries no domain prefix."""
    if _DOMAIN_SEP in merged_id:
        d, rest = merged_id.split(_DOMAIN_SEP, 1)
        if d in DOMAINS:
            return d, rest
    return "", merged_id


@dataclass
class Node:
    """One merged node. ``id`` is the domain-qualified id; ``domain`` is web | cloud | onprem.
    ``type`` is the source graph's node type (kept verbatim for the icon) or a lane-native type."""

    id: str
    type: str
    label: str
    domain: str = ""
    props: dict[str, Any] = field(default_factory=dict)
    high_value: bool = False        # an objective — Domain Admin, cloud Owner/root, cluster-admin
    owned: bool = False             # a foothold / captured principal we already control

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "label": self.label,
            "domain": self.domain,
            "high_value": self.high_value,
            "owned": self.owned,
            "props": self.props,
        }


@dataclass
class Edge:
    """A directed relationship ``source -> target`` of a given ``kind``. ``abusable`` is preserved
    from the source graph's public dict (within a lane) or set True for a synthesized bridge.
    ``props`` carries ``domain_from`` / ``domain_to`` on a bridge so the UI can draw the lane
    crossing, plus any source-edge detail."""

    source: str
    target: str
    kind: str
    abusable: bool = False
    bridge: bool = False            # a CROSS-DOMAIN seam (synthesized by bridges.py)
    props: dict[str, Any] = field(default_factory=dict)

    def key(self) -> tuple[str, str, str]:
        return (self.source, self.target, self.kind)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "kind": self.kind,
            "abusable": self.abusable,
            "bridge": self.bridge,
            "props": self.props,
        }


@dataclass
class Graph:
    """The merged three-lane graph: nodes keyed by id + a de-duplicated edge list."""

    nodes: dict[str, Node] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    _edge_keys: set[tuple[str, str, str]] = field(default_factory=set, repr=False)

    # -- mutation (merge-side) -------------------------------------------- #
    def add_node(self, node: Node) -> Node:
        existing = self.nodes.get(node.id)
        if existing is None:
            self.nodes[node.id] = node
            return node
        existing.props.update({k: v for k, v in node.props.items() if v not in (None, "")})
        if node.label and (not existing.label or existing.label == existing.id):
            existing.label = node.label
        existing.domain = existing.domain or node.domain
        existing.high_value = existing.high_value or node.high_value
        existing.owned = existing.owned or node.owned
        return existing

    def add_edge(self, edge: Edge) -> bool:
        """Add an edge unless an identical (source,target,kind) exists. Self-loops dropped. The
        ``abusable`` flag is TAKEN AS GIVEN (preserved from the source dict / set by a bridge) — the
        overlay has no edge taxonomy of its own by design."""
        if edge.source == edge.target:
            return False
        k = edge.key()
        if k in self._edge_keys:
            return False
        self._edge_keys.add(k)
        self.edges.append(edge)
        return True

    # -- queries (engine + UI) -------------------------------------------- #
    def outgoing(self, node_id: str, abusable_only: bool = False) -> Iterable[Edge]:
        for e in self.edges:
            if e.source != node_id:
                continue
            if abusable_only and not e.abusable:
                continue
            yield e

    def node(self, node_id: str) -> Node | None:
        return self.nodes.get(node_id)

    def high_value_nodes(self) -> list[Node]:
        return [n for n in self.nodes.values() if n.high_value]

    def owned_nodes(self) -> list[Node]:
        return [n for n in self.nodes.values() if n.owned]

    def nodes_in(self, domain: str) -> list[Node]:
        return [n for n in self.nodes.values() if n.domain == domain]

    def stats(self) -> dict[str, int]:
        by_domain: dict[str, int] = {}
        for n in self.nodes.values():
            by_domain[n.domain] = by_domain.get(n.domain, 0) + 1
        abusable = sum(1 for e in self.edges if e.abusable)
        bridges = sum(1 for e in self.edges if e.bridge)
        return {
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "abusable_edges": abusable,
            "bridge_edges": bridges,
            **{f"domain_{d}": c for d, c in by_domain.items()},
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "domains": list(DOMAINS),
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges],
            "stats": self.stats(),
            "warnings": self.warnings,
        }
