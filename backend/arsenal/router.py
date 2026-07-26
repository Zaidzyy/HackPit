"""READ-ONLY routes for the tool arsenal.

Browsing a catalog. These routes return DATA — tool descriptions and invocation templates —
and render templates into command strings on request. They execute nothing: a rendered
invocation is a string the operator copies, and it becomes a command only by going through
``POST /cockpit/exec`` with an explicit human approval, exactly as before.

The loaded (and KB-linked) catalog is injected by main.py via :func:`set_arsenal`, the same
pattern the adgraph/detection/codescan routers use, so the package keeps no import cycle with
the app layer.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from . import loader as arsenal_loader

router = APIRouter(prefix="/arsenal", tags=["arsenal"])

_ARSENAL: arsenal_loader.Arsenal = arsenal_loader.Arsenal()


def set_arsenal(value: arsenal_loader.Arsenal | None) -> None:
    global _ARSENAL
    _ARSENAL = value or arsenal_loader.Arsenal()


def _current() -> arsenal_loader.Arsenal:
    """The injected catalog, falling back to a lazy load so the routes work standalone."""
    global _ARSENAL
    if not _ARSENAL.tools:
        try:
            _ARSENAL = arsenal_loader.load()
        except Exception:  # noqa: BLE001 - an empty catalog is a valid, browsable state
            pass
    return _ARSENAL


# --------------------------------------------------------------------------- #
# models
# --------------------------------------------------------------------------- #
class TemplateOut(BaseModel):
    label: str
    template: str = Field(description="Invocation with <placeholders> — copy and fill.")
    note: str = ""
    placeholders: list[str] = Field(default_factory=list)


class ToolOut(BaseModel):
    name: str
    aliases: list[str] = Field(default_factory=list)
    category: str
    purpose: str
    phases: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)
    docs: str = ""
    templates: list[TemplateOut] = Field(default_factory=list)
    flags: list[dict[str, str]] = Field(
        default_factory=list,
        description="Common flags, INFORMATIONAL only — the executor has no allowlist, so "
        "this is documentation, never a restriction on what may be proposed or run.",
    )
    kb_entry_id: str | None = Field(
        default=None,
        description="KB entry that documents this tool — linked only when an entry's title "
        "names it AND the entry actually invokes it. Null otherwise (never fabricated).",
    )
    kb_title: str | None = None
    # These two MUST be declared here even though Tool.to_dict() already emits them:
    # FastAPI filters the response through this model and silently DROPS any field the
    # model does not declare. Omitting them made `runs_here` arrive as undefined in the
    # UI, so `!tool.runs_here` was true for every tool and the catalog badged all 73 —
    # nmap included — as "windows only".
    platform: str = Field(
        default="",
        description="Where the tool can run. '' = the Linux sandbox; 'windows' = "
        "PowerShell/.NET tooling that cannot run there at all (D9).",
    )
    runs_here: bool = Field(
        default=True,
        description="False for tools that cannot execute on the Linux sandbox by "
        "construction. Those stay catalogued for planning and write-ups but the planner "
        "is never offered them.",
    )


class ArsenalOut(BaseModel):
    total: int
    categories: list[str]
    placeholders: dict[str, str] = Field(
        default_factory=dict, description="What each <placeholder> means."
    )
    tools: list[ToolOut]
    executes_nothing: bool = Field(
        default=True,
        description="Always true — this is a catalog. A rendered invocation is a string; it "
        "runs only via the gated cockpit executor with an explicit human approval.",
    )


class RenderOut(BaseModel):
    tool: str
    invocations: list[dict[str, Any]] = Field(
        description="Each: {tool, label, cmd, note, unfilled, ready}. An unfilled placeholder "
        "stays visible rather than being guessed."
    )


# --------------------------------------------------------------------------- #
# routes
# --------------------------------------------------------------------------- #
@router.get("", response_model=ArsenalOut)
def arsenal_index(
    category: str | None = Query(default=None, description="Filter by category."),
    phase: str | None = Query(default=None, description="Filter by engagement phase."),
    q: str | None = Query(default=None, description="Search name/purpose/technique/label."),
) -> dict[str, Any]:
    """The catalog, optionally filtered. Read-only."""
    ars = _current()
    tools = ars.tools
    if category:
        tools = [t for t in tools if t.category == category.strip().lower()]
    if phase:
        ph = phase.strip().lower()
        tools = [t for t in tools if ph in t.phases]
    if q:
        matched = {t.name for t in ars.by_technique(q)}
        tools = [t for t in tools if t.name in matched]
    return {
        "total": len(tools),
        "categories": ars.categories(),
        "placeholders": ars.placeholders,
        "tools": [t.to_dict() for t in tools],
        "executes_nothing": True,
    }


@router.get("/tool/{name}", response_model=ToolOut)
def arsenal_tool(name: str) -> dict[str, Any]:
    """One tool by name or alias."""
    tool = _current().get(name)
    if tool is None:
        raise HTTPException(status_code=404, detail=f"no tool '{name}' in the arsenal")
    return tool.to_dict()


@router.get("/render/{name}", response_model=RenderOut)
def arsenal_render(
    name: str,
    target: str | None = Query(default=None, description="Fills <target>."),
) -> dict[str, Any]:
    """Render a tool's templates against a target. Returns STRINGS — nothing is executed.

    Placeholders with no value stay visible and the invocation reports ``ready: false``, so
    the operator can always see what is still missing instead of receiving a command with a
    silently guessed value in it.
    """
    ars = _current()
    if ars.get(name) is None:
        raise HTTPException(status_code=404, detail=f"no tool '{name}' in the arsenal")
    # substitute_target is imported lazily so this package never hard-depends on the planner
    try:
        from attack_path import substitute_target
    except Exception:  # noqa: BLE001 - rendering still works without it
        substitute_target = None  # type: ignore[assignment]
    return {
        "tool": name,
        "invocations": arsenal_loader.render_tool(ars, name, target, None, substitute_target),
    }


@router.get("/suggest", response_model=ArsenalOut)
def arsenal_suggest(
    phase: str | None = Query(default=None),
    q: str | None = Query(default=None),
    limit: int = Query(default=6, ge=1, le=30),
) -> dict[str, Any]:
    """The tools worth reaching for in a phase / for a technique — the same selection the
    planner's prompt reference uses, exposed so the UI can show it."""
    ars = _current()
    picks = arsenal_loader.suggest(ars, phase, q, limit)
    return {
        "total": len(picks),
        "categories": ars.categories(),
        "placeholders": ars.placeholders,
        "tools": [t.to_dict() for t in picks],
        "executes_nothing": True,
    }
