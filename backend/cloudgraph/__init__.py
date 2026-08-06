"""Cloud attack surface & IAM privilege-escalation graph — parse a cloud enumeration
(ScoutSuite / Prowler, with pacu / cloudfox up next) into a typed IAM graph, compute the route(s)
to an admin/owner-equivalent principal over abusable IAM edges, and ground each edge's abuse in the
KB.

This package is the cloud parallel to ``adgraph/``. It is a VISUALIZATION + a path engine + a
propose-only orchestrator. It runs NOTHING itself except its enumeration, which — like recon — is a
GATED JOB (``enumerate.py``): the operator approves it and it clears the SAME executor gate every
command clears. Every abuse step the graph surfaces executes ONLY through the existing gated cockpit
executor (human-approve-each, argv-only, engagement scope-lock). The orchestrator proposes an EDGE
INDEX, never a command, and executes nothing — regression-locked by test_cloudgraph_safety.py.
"""

from __future__ import annotations

from .schema import ABUSABLE_EDGES, Edge, Graph, Node
from .parser import ParseError, parse_collection, parse_prowler_findings

__all__ = [
    "ABUSABLE_EDGES",
    "Edge",
    "Graph",
    "Node",
    "ParseError",
    "parse_collection",
    "parse_prowler_findings",
]
