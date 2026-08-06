"""FastAPI routes for the cloud IAM privilege-escalation graph.

The cloud parallel to ``adgraph/router.py``. Two surfaces, both mirroring what already exists:

  * ENUMERATION is a GATED JOB (``enumerate.py``), the recon/nuclei shape: one human approval runs
    ScoutSuite + Prowler (+ cloudfox) and parses their JSON into a graph + engagement findings.
  * GRAPH / PATH / TECHNIQUE / ORCHESTRATE are READ-ONLY: fetch the graph, compute the route to an
    admin principal, resolve an edge's KB-grounded abuse, and PROPOSE the next edge (an index). None
    of these execute anything — an abuse COMMAND is only ever run later, by the human, at
    ``POST /cockpit/exec`` (approve-each, argv-only, engagement scope-locked), exactly like every
    other cockpit command. There is deliberately NO run endpoint here.

The KB grounder + scope resolver are injected by the app (``set_grounder`` / ``set_scope_resolver``)
so this package has no import cycle with the KB/app layer.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from state import store as state_store
from state.models import Finding

from . import enumerate as cloud_enum
from . import orchestrator as cloud_orch
from . import store
from .parser import ParseError, parse_collection, parse_prowler_findings
from .paths import default_high_value_target, paths_to_target
from .sample_data import sample_collection
from .techniques import Grounder, technique_for_edge

router = APIRouter(prefix="/cockpit/cloud", tags=["cloud-graph"])

# Injected by main.py (set_grounder) — maps a technique's KB seeds to a grounded command set.
_GROUNDER: Grounder | None = None
# Injected by main.py (set_scope_resolver) — an INERT, read-only engagement scope description.
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
# helpers
# --------------------------------------------------------------------------- #
def _load_graph_obj(graph_id: str) -> dict[str, Any]:
    row = store.get_graph(graph_id)
    if row is None or not row.get("graph"):
        raise HTTPException(status_code=404, detail="cloud graph not found")
    return row["graph"]


def _rebuild_graph(graph_dict: dict[str, Any]):
    """Reconstruct a Graph object from a stored dict (for the path engine + technique resolver)."""
    from .schema import Edge, Graph, Node

    g = Graph(provider=graph_dict.get("provider"), account=graph_dict.get("account"))
    for n in graph_dict.get("nodes", []):
        g.add_node(Node(id=n["id"], type=n["type"], label=n["label"],
                        provider=n.get("provider") or "", props=n.get("props") or {},
                        high_value=bool(n.get("high_value")), owned=bool(n.get("owned"))))
    for e in graph_dict.get("edges", []):
        g.add_edge(Edge(source=e["source"], target=e["target"], kind=e["kind"],
                        props=e.get("props") or {}))
    return g


def _enum_http_error(exc: cloud_enum.CloudEnumRefused) -> HTTPException:
    status = 409 if exc.gate in {"unavailable", "loot"} else 422 if exc.gate == "input" else 403
    return HTTPException(status_code=status,
                         detail={"gate": exc.gate, "reason": exc.reason,
                                 "dangerous_flags": exc.dangerous_flags})


# --------------------------------------------------------------------------- #
# ENUMERATION — the gated job (recon/nuclei shape)
# --------------------------------------------------------------------------- #
@router.get("/enumerate/status")
def cloud_enum_status() -> dict[str, Any]:
    """Engagement-sandbox availability + running-job count. Read-only."""
    return cloud_enum.status()


@router.post("/enumerate/preview")
def cloud_enum_preview(req: cloud_enum.CloudEnumRequest) -> dict[str, Any]:
    """The exact entry argv + the gate verdict, running NOTHING."""
    argv = cloud_enum.scoutsuite_argv(req.provider or "aws", "<loot>", req.profile, req.region)
    rej = cloud_enum.validate(req)
    return {
        "argv": argv,
        "would_run": rej is None,
        "gate": None if rej is None else getattr(rej, "gate", "unknown"),
        "reason": None if rej is None else getattr(rej, "reason", ""),
        "tools": req.tools or cloud_enum._SWEEP.get(req.provider or "aws", []),
    }


@router.post("/enumerate", response_model=cloud_enum.CloudEnumJob)
def cloud_enumerate(req: cloud_enum.CloudEnumRequest) -> cloud_enum.CloudEnumJob:
    """Run a cloud enumeration as ONE approved job. GATED (``executor.validate_request``) BEFORE
    anything spawns, then runs ScoutSuite + Prowler (+ cloudfox) and parses their JSON into a
    graph + engagement findings."""
    try:
        return cloud_enum.start(req)
    except cloud_enum.CloudEnumRefused as exc:
        raise _enum_http_error(exc)


@router.get("/enumerate/jobs", response_model=list[cloud_enum.CloudEnumJob])
def cloud_enum_jobs(session_id: str | None = Query(None)) -> list[cloud_enum.CloudEnumJob]:
    """Every enumeration job, newest first. Read-only — the results feed polls this."""
    return cloud_enum.list_jobs(session_id)


@router.get("/enumerate/jobs/{job_id}", response_model=cloud_enum.CloudEnumJob)
def cloud_enum_job(job_id: str) -> cloud_enum.CloudEnumJob:
    job = cloud_enum.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail={"reason": f"no cloud enum job {job_id!r}"})
    return job


@router.post("/enumerate/jobs/{job_id}/stop", response_model=cloud_enum.CloudEnumJob)
def cloud_enum_stop(job_id: str) -> cloud_enum.CloudEnumJob:
    """Stop an in-flight sweep. Ungated — the panic button, like recon's stop."""
    job = cloud_enum.stop(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail={"reason": f"no cloud enum job {job_id!r}"})
    return job


# --------------------------------------------------------------------------- #
# ingest / graph / path / technique
# --------------------------------------------------------------------------- #
class IngestIn(BaseModel):
    """Ingest a captured enumeration (ScoutSuite results + optional Prowler findings) or the
    built-in synthetic sample. No live collection happens here — this parses captured output."""

    session_id: str | None = Field(None, description="Session to attach the graph to.")
    engagement_id: str | None = Field(None, description="Engagement the enumeration belongs to.")
    collection: Any | None = Field(
        None, description="Decoded ScoutSuite results (or a {scoutsuite, prowler} mapping)."
    )
    use_sample: bool = Field(
        False, description="Ingest the built-in synthetic AWS sample instead (demo without creds)."
    )


class IngestOut(BaseModel):
    graph_id: str
    provider: str | None
    account: str | None
    stats: dict[str, int]
    warnings: list[str]
    findings: int = 0


@router.post("/ingest", response_model=IngestOut)
def cloud_ingest(req: IngestIn) -> IngestOut:
    """Parse a captured enumeration (or the built-in sample) into a stored graph. Prowler findings
    present in the payload are upserted into engagement state when a session is given."""
    source = sample_collection() if req.use_sample else req.collection
    if source is None:
        raise HTTPException(status_code=422, detail="provide `collection` or set use_sample=true")
    try:
        graph = parse_collection(source)
    except ParseError as exc:
        raise HTTPException(status_code=422, detail=f"could not parse enumeration: {exc}")
    graph_dict = graph.to_dict()
    graph_id = store.save_graph(graph_dict, req.session_id, req.engagement_id,
                                source="sample" if req.use_sample else "upload")
    # Prowler findings (if the payload carried any) -> engagement state.
    n = 0
    if req.session_id:
        try:
            rows = parse_prowler_findings(source)
            findings = [
                Finding(session_id=req.session_id, title=r["title"], severity=r["severity"],
                        target=r["target"], evidence=r["evidence"], tool="prowler",
                        reference=r["reference"], source_run_id=graph_id)
                for r in rows
            ]
            n = state_store.upsert_findings(findings) if findings else 0
        except Exception:  # noqa: BLE001 - findings are best-effort on ingest
            n = 0
    return IngestOut(graph_id=graph_id, provider=graph.provider, account=graph.account,
                     stats=graph.stats(), warnings=graph.warnings, findings=n)


@router.get("/graph/{graph_id}")
def cloud_graph(graph_id: str) -> dict[str, Any]:
    """The full stored graph (nodes + edges + stats)."""
    return _load_graph_obj(graph_id)


@router.get("/graphs")
def cloud_graphs(session_id: str = Query(...)):
    """Metadata for every graph on a session (no payload)."""
    return store.list_for_session(session_id)


@router.get("/latest")
def cloud_latest(session_id: str = Query(...)) -> dict[str, Any]:
    """The most-recent graph on a session (full payload), or 404 if none."""
    row = store.latest_for_session(session_id)
    if row is None:
        raise HTTPException(status_code=404, detail="no cloud graph for this session yet")
    return row


class PathIn(BaseModel):
    graph_id: str
    start: str = Field(description="The owned start principal's node id (ARN / resource id).")
    target: str | None = Field(
        None, description="High-value target node id; omit to auto-pick an admin/owner principal."
    )
    with_techniques: bool = Field(True, description="Attach the KB-grounded abuse to each hop.")


@router.post("/path")
def cloud_path(req: PathIn) -> dict[str, Any]:
    """Compute the route(s) from the owned start principal to an admin/owner-equivalent principal."""
    g = _rebuild_graph(_load_graph_obj(req.graph_id))
    target = req.target or default_high_value_target(g)
    if not target:
        raise HTTPException(status_code=422, detail="no admin/owner principal in this graph")
    result = paths_to_target(g, req.start, target)
    result["target"] = target
    result["target_label"] = g.node(target).label if g.node(target) else target
    if req.with_techniques and result.get("found") and result.get("path"):
        for hop in result["path"]["edges"]:
            hop["technique"] = technique_for_edge(hop, g, _GROUNDER, g.account)
    return result


class TechniqueIn(BaseModel):
    graph_id: str
    source: str
    target: str
    kind: str


@router.post("/technique")
def cloud_technique(req: TechniqueIn) -> dict[str, Any]:
    """The KB-grounded abuse technique + command for one edge (for the node/edge drawer)."""
    g = _rebuild_graph(_load_graph_obj(req.graph_id))
    edge = {"source": req.source, "target": req.target, "kind": req.kind, "props": {}}
    return technique_for_edge(edge, g, _GROUNDER, g.account)


# --------------------------------------------------------------------------- #
# ORCHESTRATION — the agent proposes the next edge; the human approves each one
#
# There is NO run endpoint here, deliberately. An approved proposal is sent to the SAME gated
# executor every other cockpit command uses (POST /cockpit/exec), which re-checks approval,
# scope/target and the danger confirm. Adding a run path here would be a second execution path.
# --------------------------------------------------------------------------- #
class OrchestrateIn(BaseModel):
    graph_id: str
    owned: list[str] = Field(default_factory=list, description="Node ids of controlled principals.")
    traversed: list[str] = Field(default_factory=list, description="Edge keys already walked.")
    target: str | None = Field(None, description="Objective node id; omit to auto-pick an admin.")
    engagement_id: str | None = Field(None, description="Engagement to scope the pre-check to.")
    avoid: list[str] = Field(default_factory=list, description="Edge keys the operator skipped.")


class AdvanceIn(BaseModel):
    """Advance the walk AFTER a step actually succeeded. Never auto-called."""

    graph_id: str
    owned: list[str] = Field(default_factory=list)
    traversed: list[str] = Field(default_factory=list)
    source: str
    target: str
    kind: str
    session_id: str | None = None
    run_id: str | None = Field(
        None, description="The recorded run that carried out this abuse. Required unless the edge "
        "resolves to no command (inherited rights, e.g. MemberOf).",
    )


@router.post("/orchestrate/propose")
def cloud_orchestrate_propose(req: OrchestrateIn) -> dict[str, Any]:
    """Propose the NEXT edge to abuse. Executes NOTHING. Returns a proposal the human reviews and
    explicitly approves — approval sends it to ``POST /cockpit/exec``, the same gated executor."""
    import llm  # local import: the reasoning layer is optional, the graph works without it

    graph = _rebuild_graph(_load_graph_obj(req.graph_id))
    goal = req.target or default_high_value_target(graph)
    if not goal:
        raise HTTPException(status_code=422, detail="no admin/owner objective in this enumeration")
    state = cloud_orch.CloudState.from_dict({"owned": req.owned, "traversed": req.traversed})
    if not state.owned:
        raise HTTPException(
            status_code=422,
            detail="no owned principal — mark the principal you control before asking for a "
                   "proposal; the agent reasons out from what you already have",
        )
    try:
        out = cloud_orch.propose_next(
            graph, state, goal, llm.load_config(), _GROUNDER, graph.account,
            _scope_ctx(req.engagement_id), req.avoid,
        )
    except llm.LLMError as exc:
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
def cloud_orchestrate_advance(req: AdvanceIn) -> dict[str, Any]:
    """Record that an abuse step SUCCEEDED: mark the edge traversed, the target owned, and file the
    step as a Finding. Advancement is tied to EVIDENCE, not a claim: ``run_id`` must name a recorded
    run that was APPROVED and exited 0 — so the walk cannot move forward on a step that was refused,
    never approved, or failed. The only exception is an edge that resolves to no command at all
    (inherited rights like MemberOf), which the server confirms from the graph.

    This endpoint executes nothing."""
    from cockpit import runstore

    graph = _rebuild_graph(_load_graph_obj(req.graph_id))
    edge = next(
        (e for e in graph.edges
         if e.source == req.source and e.target == req.target and e.kind == req.kind),
        None,
    )
    if edge is None:
        raise HTTPException(status_code=404, detail="that edge is not in this enumeration")

    prop = cloud_orch.proposal_for_edge(graph, edge, "", _GROUNDER, graph.account)
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
                detail="that run was not approved — the walk does not advance on an unapproved step",
            )
        if run.exit_code != 0:
            raise HTTPException(
                status_code=409,
                detail=f"that run exited {run.exit_code} — the walk advances only on success",
            )

    state = cloud_orch.CloudState.from_dict({"owned": req.owned, "traversed": req.traversed})
    new_state = cloud_orch.advance(state, req.source, req.target, req.kind)
    goal = default_high_value_target(graph)

    # The privesc STEP lands as a Finding in engagement state (the spec's requirement).
    if req.session_id:
        try:
            state_store.upsert_findings([Finding(
                session_id=req.session_id,
                title=f"IAM privilege-escalation step: {edge.kind}",
                severity="high",
                target=(graph.node(req.target).label if graph.node(req.target) else req.target),
                tool="cloudgraph", reference=req.run_id or "inherited",
                evidence=f"{prop['edge']['source_label']} --{edge.kind}--> "
                         f"{prop['edge']['target_label']} (run {req.run_id or 'n/a'})",
                source_run_id=req.run_id,
            )])
        except Exception:  # noqa: BLE001 - finding is best-effort
            pass

    return {
        "state": new_state.to_dict(),
        "owned_label": (graph.node(req.target).label if graph.node(req.target) else req.target),
        "objective_reached": bool(goal and new_state.is_owned(goal)),
        "remaining_frontier": len(cloud_orch.frontier(graph, new_state)),
    }


__all__ = ["router", "set_grounder", "set_scope_resolver"]
