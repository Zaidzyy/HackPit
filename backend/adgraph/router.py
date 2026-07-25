"""FastAPI routes for the AD attack-path graph.

All READ-ONLY: ingest a captured BloodHound collection into a graph, fetch the graph, compute
the route(s) to Domain Admin, and resolve an edge's KB-grounded abuse technique. None of this
executes anything — the abuse COMMAND a technique returns is only run later, by the human, at
``POST /cockpit/exec`` (approve-each, argv-only, engagement scope-locked), exactly like every
other cockpit command. A ``collect/preview`` endpoint returns the collector's ExecRequest so the
UI can hand it to that same gated exec.

The KB grounder is injected by the app via :func:`set_grounder`, so this package has no import
cycle with the KB/app layer.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from . import store
from .collector import CollectorParams, ParseError, build_collector_request, ingest_collection
from .parser import parse_collection
from .paths import default_high_value_target, paths_to_target
from .sample_data import sample_collection
from .techniques import Grounder, technique_for_edge

router = APIRouter(prefix="/cockpit/ad", tags=["ad-graph"])

# Injected by main.py (set_grounder) — maps a technique's KB seeds to a grounded command set.
_GROUNDER: Grounder | None = None


def set_grounder(fn: Grounder | None) -> None:
    global _GROUNDER
    _GROUNDER = fn


# --------------------------------------------------------------------------- #
# models
# --------------------------------------------------------------------------- #
class IngestIn(BaseModel):
    """Ingest a captured BloodHound collection. Provide EITHER ``collection`` (a decoded
    mapping / list of files) OR ``use_sample`` for the built-in demo domain. No live collection
    happens here — this parses captured output."""

    session_id: str | None = Field(None, description="Session to attach the graph to.")
    engagement_id: str | None = Field(None, description="Engagement the collection belongs to.")
    collection: Any | None = Field(
        None, description="Decoded BloodHound JSON: a combined mapping, a list of file objects, "
        "or a single file object ({data, meta}).",
    )
    use_sample: bool = Field(
        False, description="Ingest the built-in GOAD-style sample instead (demo without a lab).",
    )


class IngestOut(BaseModel):
    graph_id: str
    domain: str | None
    stats: dict[str, int]
    warnings: list[str]


class PathIn(BaseModel):
    graph_id: str
    start: str = Field(description="The owned start principal's node id (SID).")
    target: str | None = Field(
        None, description="High-value target node id; omit to auto-pick Domain Admins.",
    )
    with_techniques: bool = Field(
        True, description="Attach the KB-grounded abuse technique to each hop.",
    )


class TechniqueIn(BaseModel):
    graph_id: str
    source: str
    target: str
    kind: str


class CollectPreviewIn(BaseModel):
    """Build the collector ExecRequest for the UI to send to POST /cockpit/exec (approve-each).
    Nothing runs here — this only assembles + validates the argv."""

    engagement_id: str = Field(description="Active engagement (real domain); required.")
    session_id: str | None = None
    domain: str
    username: str
    dc: str
    password: str | None = None
    nthash: str | None = None
    nameserver: str | None = None
    collection_methods: str = "All"
    dns_tcp: bool = False


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _load_graph_obj(graph_id: str) -> dict[str, Any]:
    row = store.get_graph(graph_id)
    if row is None or not row.get("graph"):
        raise HTTPException(status_code=404, detail="AD graph not found")
    return row["graph"]


def _rebuild_graph(graph_dict: dict[str, Any]):
    """Reconstruct a Graph object from a stored dict (for the path engine + technique resolver).
    Reuses the parser's schema types without re-parsing raw BloodHound."""
    from .schema import Edge, Graph, Node

    g = Graph(domain=graph_dict.get("domain"))
    for n in graph_dict.get("nodes", []):
        g.add_node(Node(id=n["id"], type=n["type"], label=n["label"],
                        props=n.get("props") or {}, high_value=bool(n.get("high_value")),
                        owned=bool(n.get("owned"))))
    for e in graph_dict.get("edges", []):
        g.add_edge(Edge(source=e["source"], target=e["target"], kind=e["kind"],
                        props=e.get("props") or {}))
    return g


# --------------------------------------------------------------------------- #
# endpoints
# --------------------------------------------------------------------------- #
@router.post("/ingest", response_model=IngestOut)
def ad_ingest(req: IngestIn) -> IngestOut:
    """Parse a captured BloodHound collection (or the built-in sample) into a stored graph."""
    source = sample_collection() if req.use_sample else req.collection
    if source is None:
        raise HTTPException(status_code=422, detail="provide `collection` or set use_sample=true")
    try:
        res = ingest_collection(
            source, req.session_id, req.engagement_id,
            origin="sample" if req.use_sample else "upload",
        )
    except ParseError as exc:
        raise HTTPException(status_code=422, detail=f"could not parse collection: {exc}")
    return IngestOut(**res)


@router.get("/graph/{graph_id}")
def ad_graph(graph_id: str) -> dict[str, Any]:
    """The full stored graph (nodes + edges + stats)."""
    return _load_graph_obj(graph_id)


@router.get("/graphs")
def ad_graphs(session_id: str = Query(..., description="Session to list graphs for.")):
    """Metadata for every graph on a session (no payload)."""
    return store.list_for_session(session_id)


@router.get("/latest")
def ad_latest(session_id: str = Query(...)) -> dict[str, Any]:
    """The most-recent graph on a session (full payload), or 404 if none."""
    row = store.latest_for_session(session_id)
    if row is None:
        raise HTTPException(status_code=404, detail="no AD graph for this session yet")
    return row


@router.post("/path")
def ad_path(req: PathIn) -> dict[str, Any]:
    """Compute the route(s) from the owned start principal to a high-value target."""
    graph_dict = _load_graph_obj(req.graph_id)
    g = _rebuild_graph(graph_dict)
    target = req.target or default_high_value_target(g)
    if not target:
        raise HTTPException(status_code=422, detail="no high-value target in this graph")
    result = paths_to_target(g, req.start, target)
    result["target"] = target
    result["target_label"] = g.node(target).label if g.node(target) else target
    # attach the KB-grounded technique to each hop of the best path
    if req.with_techniques and result.get("found") and result.get("path"):
        for hop in result["path"]["edges"]:
            hop["technique"] = technique_for_edge(hop, g, _GROUNDER)
    return result


@router.post("/technique")
def ad_technique(req: TechniqueIn) -> dict[str, Any]:
    """The KB-grounded abuse technique + command for one edge (for the node/edge drawer)."""
    graph_dict = _load_graph_obj(req.graph_id)
    g = _rebuild_graph(graph_dict)
    edge = {"source": req.source, "target": req.target, "kind": req.kind, "props": {}}
    return technique_for_edge(edge, g, _GROUNDER)


@router.post("/collect/preview")
def ad_collect_preview(req: CollectPreviewIn) -> dict[str, Any]:
    """Build (do NOT run) the collector ExecRequest. The UI sends the returned ``request`` to
    POST /cockpit/exec, where the human approves it and the scope-lock covers the DC.

    Nothing runs here. The request comes back UNAPPROVED; the secret is never echoed in the
    preview argv (it is present in the request the UI forwards, but the preview redacts it)."""
    try:
        params = CollectorParams(
            domain=req.domain, username=req.username, dc=req.dc,
            password=req.password, nthash=req.nthash, nameserver=req.nameserver,
            collection_methods=req.collection_methods, dns_tcp=req.dns_tcp,
        )
        exec_req = build_collector_request(params, req.engagement_id, req.session_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    # redacted preview argv (mask the password/hash value)
    preview = [exec_req.command]
    args = list(exec_req.args)
    for i, a in enumerate(args):
        if i > 0 and args[i - 1] in ("-p", "--hashes"):
            preview.append("<redacted>")
        else:
            preview.append(a)
    return {
        "request": exec_req.model_dump(),
        "preview_argv": preview,
        "params": params.redacted(),
        "note": "unapproved — send `request` to POST /cockpit/exec; the human approves it there "
                "and the engagement scope-lock covers the DC host.",
    }


# expose the reconstructor for tests
__all__ = ["router", "set_grounder"]
