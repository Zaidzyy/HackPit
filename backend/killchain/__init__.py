"""Cross-domain kill-chain overlay — the capstone that stitches the web foothold, cloud IAM and
on-prem AD graphs into ONE routed kill chain.

This package is a READ-AND-STITCH OVERLAY, not a new engine. It consumes each underlying graph's
PUBLIC DICT (``Graph.to_dict()``) — it imports NEITHER ``adgraph`` NOR ``cloudgraph`` (the two
graph packages stay decoupled; the cross-cutting join lives in ``main.py``). A merged node carries
its ``domain`` (web | cloud | onprem); a small bridge catalog (``bridges.py``) synthesizes the
cross-domain SEAMS (SSRF→IMDS, node→cloud, cloud-creds→on-prem, …) as abusable edges the SAME
edge-index orchestrator can walk end to end.

It adds NO new gate. The orchestrator PROPOSES an edge index, never a command; it executes nothing.
Cross-domain (bridge) hops resolve to a KB-grounded command the human approves through the existing
gated executor; within-lane hops defer to that lane's own :cloud / :ad-graph view (single source of
truth for per-lane abuse — no duplicated command catalog here).
"""
