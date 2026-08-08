"""Merge three lane graphs into one kill-chain graph — the read-and-stitch step.

Consumes each lane's PUBLIC DICT (``Graph.to_dict()`` from adgraph / cloudgraph, and a web-lane dict
built from engagement findings) and copies its nodes + edges into the merged model, tagging the
domain and namespacing ids so lanes cannot collide. Then it calls ``bridges.synthesize`` to add the
cross-domain seams. It imports NEITHER adgraph NOR cloudgraph — only this package's own schema +
bridge catalog — which is what keeps the two graph packages decoupled (the app layer hands us their
dicts; we never reach into their internals).
"""

from __future__ import annotations

from typing import Any

from . import bridges
from .schema import DOMAINS, Edge, Graph, Node, qualify


def _copy_lane(graph: Graph, domain: str, lane: dict[str, Any] | None) -> None:
    """Copy one lane's public dict into the merged graph under ``domain``. Ids are namespaced
    ``<domain>::<id>``; the ``abusable`` flag on each edge is preserved verbatim (the overlay has no
    edge taxonomy of its own — it trusts each lane's own classification)."""
    if not isinstance(lane, dict):
        return
    for n in lane.get("nodes", []):
        if not isinstance(n, dict) or not n.get("id"):
            continue
        graph.add_node(Node(
            id=qualify(domain, str(n["id"])),
            type=str(n.get("type") or "resource"),
            label=str(n.get("label") or n["id"]),
            domain=domain,
            props=dict(n.get("props") or {}),
            high_value=bool(n.get("high_value")),
            owned=bool(n.get("owned")),
        ))
    for e in lane.get("edges", []):
        if not isinstance(e, dict) or not e.get("source") or not e.get("target"):
            continue
        graph.add_edge(Edge(
            source=qualify(domain, str(e["source"])),
            target=qualify(domain, str(e["target"])),
            kind=str(e.get("kind") or "Edge"),
            abusable=bool(e.get("abusable")),
            bridge=False,
            props=dict(e.get("props") or {}),
        ))
    for w in lane.get("warnings", []) or []:
        graph.warnings.append(f"[{domain}] {w}")


def merge_lanes(
    web: dict[str, Any] | None = None,
    cloud: dict[str, Any] | None = None,
    onprem: dict[str, Any] | None = None,
) -> Graph:
    """Build the merged three-lane graph from the (optional) public dict of each lane, then stitch
    the cross-domain seams. Any lane may be absent — the overlay renders with whatever exists.

    Seams are declared on lane nodes as ``props["seams"]`` (see ``bridges.synthesize``); they are
    resolved AFTER all lanes are copied so a seam can reference a node in another lane. The merged
    node/edge ids are domain-qualified, so a seam target is a qualified id (the sample + the app
    layer build them with :func:`killchain.schema.qualify`).
    """
    g = Graph()
    _copy_lane(g, "web", web)
    _copy_lane(g, "cloud", cloud)
    _copy_lane(g, "onprem", onprem)
    bridges.synthesize(g)
    return g


__all__ = ["merge_lanes", "DOMAINS"]
