"""AD attack-path graph — parse a BloodHound collection into a typed graph, compute the
route(s) to Domain Admin over abusable edges, and ground each edge's abuse in the KB.

This package is a VISUALIZATION + a path engine. It runs NOTHING itself: the collector and
every abuse step execute ONLY through the existing gated cockpit executor (human-approve-each,
argv-only, engagement scope-lock). There is no autonomy here and no :kali path — the graph
surfaces techniques and hands their commands to the same gated exec every other cockpit command
uses. AD orchestration (an agent reasoning over the graph) is a deliberately separate later
phase and is NOT built here.
"""

from __future__ import annotations

from .schema import ABUSABLE_EDGES, Edge, Graph, Node
from .parser import ParseError, parse_collection

__all__ = [
    "ABUSABLE_EDGES",
    "Edge",
    "Graph",
    "Node",
    "ParseError",
    "parse_collection",
]
