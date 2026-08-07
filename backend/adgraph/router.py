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

from . import orchestrator as ad_orch
from . import persistence as ad_persistence
from . import store
from .collector import (
    CollectorParams,
    ParseError,
    build_certipy_find_request,
    build_collector_request,
    ingest_collection,
)
from .parser import parse_collection
from .paths import default_high_value_target, paths_to_target
from .sample_data import sample_certipy, sample_collection
from .techniques import Grounder, technique_for_edge

router = APIRouter(prefix="/cockpit/ad", tags=["ad-graph"])

# Injected by main.py (set_grounder) — maps a technique's KB seeds to a grounded command set.
_GROUNDER: Grounder | None = None

# Injected by main.py (set_scope_resolver) — maps an engagement id to an INERT, read-only
# description of what the orchestrator may target. Deliberately injected rather than looked up
# here: like the cockpit loop's proposer, this package must have no capability to enter or
# resolve an engagement, only to be handed one. The resolver also fails CLOSED (409) on an id
# that is set but not active, so AD orchestration is never silently downgraded to lab mode
# against a real-target id.
_SCOPE_RESOLVER: Any | None = None


def set_grounder(fn: Grounder | None) -> None:
    global _GROUNDER
    _GROUNDER = fn


def set_scope_resolver(fn: Any | None) -> None:
    global _SCOPE_RESOLVER
    _SCOPE_RESOLVER = fn


def _scope_ctx(engagement_id: str | None):
    if not engagement_id or _SCOPE_RESOLVER is None:
        return None
    return _SCOPE_RESOLVER(engagement_id)


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
    certipy: Any | None = Field(
        None, description="Decoded `certipy find -json` output (AD CS). Folded into the same "
        "graph as certtemplate/certauthority nodes + synthesized ESC1-8 abuse edges.",
    )
    use_sample: bool = Field(
        False, description="Ingest the built-in GOAD-style sample instead (demo without a lab).",
    )
    use_adcs_sample: bool = Field(
        True, description="When use_sample is set, also fold in the synthetic vulnerable-CA "
        "certipy sample so the graph renders an ESC route. Ignored for a real collection.",
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
    if req.use_sample:
        certipy = sample_certipy() if req.use_adcs_sample else None
    else:
        certipy = req.certipy
    try:
        res = ingest_collection(
            source, req.session_id, req.engagement_id,
            origin="sample" if req.use_sample else "upload",
            certipy=certipy,
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


class CertipyFindIn(BaseModel):
    """Build the ``certipy find`` ExecRequest for the UI to send to POST /cockpit/exec
    (approve-each). Read-only AD CS enumeration; nothing runs here — this assembles the argv.
    NOTE: certipy's ``-dc-ip`` wants the DC's IP (not its FQDN)."""

    engagement_id: str = Field(description="Active engagement (real domain); required.")
    session_id: str | None = None
    domain: str
    username: str
    dc: str = Field(description="The DC's IP address (certipy -dc-ip).")
    password: str | None = None
    nthash: str | None = None
    nameserver: str | None = None


@router.post("/certipy/preview")
def ad_certipy_preview(req: CertipyFindIn) -> dict[str, Any]:
    """Build (do NOT run) the ``certipy find`` ExecRequest. The UI sends the returned ``request``
    to POST /cockpit/exec, where the human approves it and the scope-lock covers the DC. certipy
    find is read-only (no red-confirm), but it is still a command against a real DC, so it runs
    through the same gated executor. Its JSON output is then folded in via POST /cockpit/ad/ingest
    with the `certipy` field. Nothing runs here; the secret is redacted from the preview argv."""
    try:
        params = CollectorParams(
            domain=req.domain, username=req.username, dc=req.dc,
            password=req.password, nthash=req.nthash, nameserver=req.nameserver,
        )
        exec_req = build_certipy_find_request(params, req.engagement_id, req.session_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    preview = [exec_req.command]
    args = list(exec_req.args)
    for i, a in enumerate(args):
        if i > 0 and args[i - 1] in ("-p", "-hashes"):
            preview.append("<redacted>")
        else:
            preview.append(a)
    return {
        "request": exec_req.model_dump(),
        "preview_argv": preview,
        "params": params.redacted(),
        "note": "unapproved — send `request` to POST /cockpit/exec (read-only enum, scope-locked "
                "to the DC), then POST the JSON output to /cockpit/ad/ingest with `certipy`.",
    }


# --------------------------------------------------------------------------- #
# AD ORCHESTRATION — the agent proposes the next edge; the human approves each one
#
# There is NO run endpoint here, deliberately. An approved proposal is sent to the SAME
# gated executor every other cockpit command uses (POST /cockpit/exec), which re-checks
# approval, scope/target and the danger confirm. Adding a run path here would be a second
# execution path, which is exactly what must not exist.
# --------------------------------------------------------------------------- #
class OrchestrateIn(BaseModel):
    graph_id: str
    owned: list[str] = Field(
        default_factory=list, description="Node ids of principals the operator controls."
    )
    traversed: list[str] = Field(
        default_factory=list, description="Edge keys ('source|target|kind') already walked."
    )
    target: str | None = Field(
        None, description="Objective node id; omit to auto-pick Domain Admins."
    )
    dc: str | None = Field(None, description="Domain controller host, for command templating.")
    engagement_id: str | None = Field(
        None, description="Engagement to scope the proposal's pre-check to. Omit for lab."
    )
    avoid: list[str] = Field(
        default_factory=list, description="Edge keys the operator skipped — do not re-propose."
    )


class AdvanceIn(BaseModel):
    """Advance the walk AFTER a step actually succeeded. Never auto-called."""

    graph_id: str
    owned: list[str] = Field(default_factory=list)
    traversed: list[str] = Field(default_factory=list)
    source: str
    target: str
    kind: str
    run_id: str | None = Field(
        None, description="The recorded run that carried out this abuse. Required unless the "
        "edge resolves to no command (inherited rights, e.g. MemberOf).",
    )


@router.post("/orchestrate/propose")
def ad_orchestrate_propose(req: OrchestrateIn) -> dict[str, Any]:
    """Propose the NEXT edge to abuse. Executes NOTHING.

    Returns a proposal the human reviews and explicitly approves. Approval sends it to
    ``POST /cockpit/exec`` — the same gated executor as every other command. Nothing here
    runs, batches, or approves, and there is no way to ask this endpoint to.
    """
    import llm  # local import: the reasoning layer is optional, the graph works without it

    graph = _rebuild_graph(_load_graph_obj(req.graph_id))
    goal = req.target or default_high_value_target(graph)
    if not goal:
        raise HTTPException(status_code=422, detail="no high-value objective in this collection")
    state = ad_orch.AdState.from_dict({"owned": req.owned, "traversed": req.traversed})
    if not state.owned:
        raise HTTPException(
            status_code=422,
            detail="no owned principal — mark the principal you control before asking for a "
                   "proposal; the agent reasons out from what you already have",
        )
    try:
        out = ad_orch.propose_next(
            graph, state, goal, llm.load_config(), _GROUNDER, req.dc,
            _scope_ctx(req.engagement_id), req.avoid,
        )
    except llm.LLMError as exc:
        # the manual walk the operator already had is unaffected
        raise HTTPException(status_code=503, detail=str(exc))
    return {
        **out,
        "goal": goal,
        "goal_label": (graph.node(goal).label if graph.node(goal) else goal),
        "state": state.to_dict(),
        "mode": "engagement" if req.engagement_id else "lab",
        "note": "PROPOSAL ONLY — nothing has run. Approve it to send it to POST /cockpit/exec, "
                "which re-checks approval, scope and the danger confirm.",
    }


@router.post("/orchestrate/advance")
def ad_orchestrate_advance(req: AdvanceIn) -> dict[str, Any]:
    """Record that an abuse step SUCCEEDED: mark the edge traversed, the target owned.

    Advancement is tied to evidence, not to a claim. ``run_id`` must name a recorded run that
    was APPROVED and exited 0 — so the walk cannot move forward on a step that was refused,
    never approved, or failed. The only exception is an edge that resolves to no command at
    all (inherited rights like MemberOf): there is nothing to run, so there is no run to cite,
    and the server confirms that from the graph rather than taking the client's word.

    This endpoint executes nothing. It is called by the UI after a run the human approved.
    """
    from cockpit import runstore

    graph = _rebuild_graph(_load_graph_obj(req.graph_id))
    edge = next(
        (e for e in graph.edges
         if e.source == req.source and e.target == req.target and e.kind == req.kind),
        None,
    )
    if edge is None:
        raise HTTPException(status_code=404, detail="that edge is not in this collection")

    prop = ad_orch.proposal_for_edge(graph, edge, "", _GROUNDER)
    if prop["runnable"]:
        if not req.run_id:
            raise HTTPException(
                status_code=422,
                detail="this edge has a command, so advancing it requires the run_id of the "
                       "approved run that carried it out",
            )
        run = runstore.get_run(req.run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="no such run")
        if not getattr(run, "approved", False):
            raise HTTPException(
                status_code=409,
                detail="that run was not approved — the walk does not advance on an "
                       "unapproved step",
            )
        if run.exit_code != 0:
            raise HTTPException(
                status_code=409,
                detail=f"that run exited {run.exit_code} — the walk advances only on success",
            )

    state = ad_orch.AdState.from_dict({"owned": req.owned, "traversed": req.traversed})
    new_state = ad_orch.advance(state, req.source, req.target, req.kind)
    goal = default_high_value_target(graph)
    return {
        "state": new_state.to_dict(),
        "owned_label": (graph.node(req.target).label if graph.node(req.target) else req.target),
        "objective_reached": bool(goal and new_state.is_owned(goal)),
        "remaining_frontier": len(ad_orch.frontier(graph, new_state)),
    }


# --------------------------------------------------------------------------- #
# PERSISTENCE — golden / silver ticket forging (post-compromise, propose-only)
#
# NOT a route-to-DA edge: forging a ticket presupposes you already hold the secret (krbtgt for
# golden, a service hash for silver), so it is never part of the path search or the orchestrator
# frontier. This read-only endpoint just surfaces which forging actions are OFFERED given what
# the operator already holds. Nothing runs here — a chosen command goes to POST /cockpit/exec,
# approve-each, exactly like an abusable edge's abuse.
# --------------------------------------------------------------------------- #
class PersistenceIn(BaseModel):
    graph_id: str
    owned: list[str] = Field(
        default_factory=list, description="Node ids of principals/hosts the operator controls."
    )
    traversed: list[str] = Field(
        default_factory=list, description="Edge keys ('source|target|kind') already walked."
    )
    dc: str | None = Field(None, description="Domain controller host, for command templating.")


@router.post("/persistence")
def ad_persistence_actions(req: PersistenceIn) -> dict[str, Any]:
    """The golden / silver ticket-forging actions offered NOW, gated on the held secret.

    Golden is offered on the domain node once krbtgt is held (a DCSync / captured DC TGT); silver
    on each owned computer/service node (its account hash is held). Executes nothing — the actions
    are display data + a command the human may later approve through the gated executor. These are
    never routing edges: the path engine and the orchestrator frontier never see them.
    """
    graph = _rebuild_graph(_load_graph_obj(req.graph_id))
    state = ad_orch.AdState.from_dict({"owned": req.owned, "traversed": req.traversed})
    actions = ad_persistence.persistence_actions(graph, state, req.dc)
    return {
        "actions": actions,
        "note": "PROPOSE-ONLY persistence — nothing has run, and none of these are part of the "
                "route-to-DA search. Approve a command to send it to POST /cockpit/exec.",
    }


# expose the reconstructor for tests
__all__ = ["router", "set_grounder", "set_scope_resolver"]
