"""READ-ONLY FastAPI routes for the detection-footprint (purple-team) panel.

Every route here is pure annotation: give it a command, a run id or a step and it returns what a
DEFENDER would see — ATT&CK technique + tactic, telemetry/data sources, the SigmaHQ rule that
would fire, and the loud-vs-quiet rating. Nothing in this router executes anything, changes any
gate, or writes any state. The commands it annotates still run only through
``POST /cockpit/exec``, human-approved, exactly as before.

The run lookup is injected by main.py via :func:`set_run_lookup` so this package keeps no import
cycle with the cockpit/app layer (same pattern as ``adgraph.router.set_grounder``).
"""

from __future__ import annotations

from typing import Any, Callable

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from . import attck, catalog, tagging
from .resolver import (SOURCES, footprint, footprint_for_argv, footprint_for_run,
                       footprint_for_step)

router = APIRouter(prefix="/detection", tags=["detection"])

# run_id -> RunRecord-ish dict | None. Injected by main.py.
RunLookup = Callable[[str], "dict | None"]
_RUN_LOOKUP: RunLookup | None = None
# session_id -> [RunRecord-ish dict]. Injected by main.py.
RunsLookup = Callable[[str], "list[dict]"]
_RUNS_LOOKUP: RunsLookup | None = None


def set_run_lookup(fn: RunLookup | None) -> None:
    global _RUN_LOOKUP
    _RUN_LOOKUP = fn


def set_runs_lookup(fn: RunsLookup | None) -> None:
    global _RUNS_LOOKUP
    _RUNS_LOOKUP = fn


# --------------------------------------------------------------------------- #
# models
# --------------------------------------------------------------------------- #
class FootprintIn(BaseModel):
    """Annotate one command. Nothing is executed — this only describes it."""

    command: str = Field("", description="Command name, e.g. 'nmap'. Omit if using `argv`.")
    args: list[str] = Field(default_factory=list, description="Argv tokens.")
    argv: str | None = Field(
        None, description="A whole command line instead of command+args, e.g. 'nmap -sV host'."
    )
    context: str = Field("", description="Optional free-text context for the AI-suggested path.")
    allow_llm: bool = Field(
        True,
        description="When the command is not in the curated map, ask the model for the "
        "defender's view and mark the result ai_suggested. Set false for a purely grounded "
        "answer (an uncatalogued command then returns an explicit 'unknown' footprint).",
    )


class StepFootprintIn(BaseModel):
    """Annotate an attack-path step (its first real command)."""

    step: dict[str, Any] = Field(description="An AttackStep-shaped object (id/title/commands).")
    allow_llm: bool = True


# --------------------------------------------------------------------------- #
# endpoints
# --------------------------------------------------------------------------- #
@router.get("/sources")
def detection_sources() -> dict[str, Any]:
    """Where the knowledge comes from, and the line the panel holds — for the UI's About box."""
    return {
        **SOURCES,
        "attack_version": attck.ATTACK_VERSION,
        "techniques": len(attck.TECHNIQUES),
        "specs": len(catalog.SPECS),
        "sigma_rules": len(catalog.SIGMA),
        "arg_signals": len(catalog.ARG_SIGNALS),
        "loudness_scale": [
            {"level": lvl, "score": score, "meaning": catalog.LOUDNESS_MEANING.get(lvl, "")}
            for lvl, score in sorted(catalog.LOUDNESS_SCALE.items(), key=lambda kv: kv[1])
        ],
        "tactic_aliases": attck.TACTIC_ALIASES,
        "the_line": (
            "This panel DESCRIBES detection from the defender's side: the technique, the "
            "telemetry it generates, the rule that would fire and how loud it is. It does not "
            "perform, recommend or teach evasion — there is no 'make this quieter' path here, "
            "by design. A 'quiet' rating marks a gap in the defender's coverage, not a lane for "
            "the operator."
        ),
        "read_only": True,
    }


@router.post("/footprint")
def detection_footprint(req: FootprintIn) -> dict[str, Any]:
    """The detection footprint for one command. Read-only annotation; runs nothing."""
    if req.argv:
        return footprint_for_argv(req.argv, context=req.context, allow_llm=req.allow_llm)
    if not req.command.strip():
        raise HTTPException(status_code=422, detail="provide `command` or `argv`")
    return footprint(req.command, req.args, context=req.context, allow_llm=req.allow_llm)


@router.post("/footprint/step")
def detection_footprint_step(req: StepFootprintIn) -> dict[str, Any]:
    """The detection footprint for an attack-path step (annotates its first command)."""
    return footprint_for_step(req.step, allow_llm=req.allow_llm)


@router.get("/footprint/run/{run_id}")
def detection_footprint_run(
    run_id: str,
    allow_llm: bool = Query(True, description="Allow the ai_suggested fallback."),
) -> dict[str, Any]:
    """The detection footprint for a recorded cockpit run — what blue saw when it actually ran."""
    if _RUN_LOOKUP is None:
        raise HTTPException(status_code=503, detail="run lookup not wired")
    run = _RUN_LOOKUP(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="run not found")
    out = footprint_for_run(run, allow_llm=allow_llm)
    out["run_id"] = run_id
    out["mode"] = run.get("mode") or "lab"
    return out


@router.post("/tag")
def detection_tag(req: FootprintIn) -> dict[str, Any]:
    """The COMPACT ATT&CK tag for one command — technique ids, tactics, loudness.

    Deterministic and catalog-only (never the LLM), so the UI can tag a list of steps or runs
    cheaply. ``tag`` is null when the curated map does not cover the command; ask
    ``POST /detection/footprint`` for the ai_suggested reading in that case.
    """
    tag = tagging.tag_argv(req.argv) if req.argv else tagging.tag_command(req.command, req.args)
    return {"argv": req.argv or " ".join([req.command, *req.args]).strip(), "tag": tag}


@router.get("/runs")
def detection_runs(
    session_id: str = Query(..., description="Engagement whose recorded runs to tag."),
) -> dict[str, Any]:
    """ATT&CK tags for every recorded run on an engagement, plus a coverage summary.

    READ-ONLY, and deliberately kept OUT of the cockpit: the run store and every execution path
    are untouched by this feature. The tag is a pure function of the command + argv the run
    already persisted, so it is derived here at read time rather than stored.
    """
    if _RUNS_LOOKUP is None:
        raise HTTPException(status_code=503, detail="runs lookup not wired")
    runs = _RUNS_LOOKUP(session_id) or []
    rows, tags = [], []
    for run in runs:
        tag = tagging.tag_run(run)
        tags.append(tag)
        rows.append({
            "run_id": run.get("run_id"),
            "command": run.get("command"),
            "args": run.get("args") or [],
            "target": run.get("target"),
            "mode": run.get("mode") or "lab",
            "started_at": run.get("started_at"),
            "step_id": run.get("step_id"),
            "attck": tag,
        })
    return {"session_id": session_id, "runs": rows, "summary": tagging.summarize(tags)}


@router.get("/technique/{technique_id}")
def detection_technique(technique_id: str) -> dict[str, Any]:
    """One ATT&CK technique as the panel renders it (tactic, data components, log channels)."""
    row = attck.describe(technique_id.strip().upper())
    if not row.get("known"):
        raise HTTPException(
            status_code=404,
            detail=f"{technique_id} is not in HackPit's ATT&CK table (see /detection/sources)",
        )
    row["sigma"] = [
        {"id": r.id, "title": r.title, "url": r.url, "level": r.level}
        for key, r in catalog.SIGMA.items()
        if any(key in s.sigma and row["id"] in s.techniques for s in catalog.SPECS.values())
    ]
    return row


@router.get("/catalog")
def detection_catalog() -> dict[str, Any]:
    """The whole curated map — for the UI's browsable reference view."""
    return {
        "specs": [
            {
                "key": s.key,
                "label": s.label,
                "techniques": list(s.techniques),
                "loudness": s.loudness,
                "loudness_score": catalog.loudness_score(s.loudness),
                "blue_view": s.blue_view,
                "why_rating": s.why_rating,
                "telemetry": list(s.telemetry),
                "sigma": [
                    {"id": r.id, "title": r.title, "url": r.url, "level": r.level}
                    for r in catalog.sigma_rules(s.sigma)
                ],
            }
            for s in catalog.SPECS.values()
        ],
        "signals": [
            {
                "id": g.id, "label": g.label, "note": g.note, "stealth": g.stealth,
                "louder": g.louder, "techniques": list(g.techniques),
            }
            for g in catalog.ARG_SIGNALS
        ],
        "sources": SOURCES,
    }


__all__ = ["router", "set_run_lookup", "set_runs_lookup"]
