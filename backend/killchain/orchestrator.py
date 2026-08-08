"""Kill-chain orchestration — the agent reasons over the MERGED graph and PROPOSES the next edge.

The direct parallel to ``adgraph/orchestrator.py`` / ``cloudgraph/orchestrator.py``, with the SAME
safety design, copied deliberately:

1. **The model chooses an EDGE, never a command.** It is handed a numbered list of candidate edges
   (the abusable edges out of the footholds we already own, within a lane OR across a seam) and
   returns an index. The command is then resolved deterministically — for a CROSS-DOMAIN bridge, by
   this overlay's own KB-grounded bridge catalog (``bridges.technique_for_bridge``); for a
   WITHIN-LANE edge, the proposal DEFERS to that lane's own :cloud / :ad-graph view (the overlay
   never re-implements per-lane abuse — single source of truth, no drift). A pick outside the list
   is rejected outright.

2. **This module has no way to run or approve anything.** It builds a proposal and hands it back.
   Execution happens where it already happened: the operator approves, and a bridge command goes
   through the SAME gated executor every cockpit command uses (``POST /cockpit/exec``). There is no
   second execution path and nothing here can set ``approved``. Regression-locked by a source scan
   in ``test_killchain_safety.py``.

State (owned footholds, traversed edges) is passed in and returned; this module keeps none.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass, replace
from typing import Any, Callable

import llm
from cockpit import allowlist, executor

from . import bridges
from . import paths as kc_paths
from .schema import Edge, Graph, split_domain

_MAX_CANDIDATES = 24
_MAX_PATH_HOPS = 14
_MAX_OWNED_LISTED = 20
_MAX_RATIONALE = 400

# Where a within-lane hop is resolved + approved — the dedicated per-lane view. The kill-chain
# overlay owns the SEAMS; each lane owns its own abuse (so there is exactly one command catalog per
# abuse, never a drifting copy here).
_LANE_VIEW = {"cloud": "/cockpit/cloud", "onprem": "/cockpit/ad", "web": "/cockpit/proxy"}


def _edge_key(source: str, target: str, kind: str) -> str:
    return f"{source}|{target}|{kind}"


@dataclass(frozen=True)
class KillchainState:
    """What the operator controls so far, and what has already been walked. Inert data — owning a
    foothold here means "the operator has demonstrated control", not that anything is authorized."""

    owned: tuple[str, ...] = ()
    traversed: tuple[str, ...] = ()

    def is_owned(self, node_id: str) -> bool:
        return node_id in self.owned

    def is_traversed(self, source: str, target: str, kind: str) -> bool:
        return _edge_key(source, target, kind) in self.traversed

    def to_dict(self) -> dict[str, Any]:
        return {"owned": list(self.owned), "traversed": list(self.traversed)}

    @staticmethod
    def from_dict(raw: dict[str, Any] | None) -> "KillchainState":
        raw = raw or {}
        owned = tuple(str(x) for x in (raw.get("owned") or []) if str(x).strip())
        trav = tuple(str(x) for x in (raw.get("traversed") or []) if str(x).strip())
        return KillchainState(owned=owned, traversed=trav)


def advance(state: KillchainState, source: str, target: str, kind: str) -> KillchainState:
    """The state AFTER a hop has succeeded: edge traversed, target foothold owned. A pure function —
    called only once a run has actually come back successful; nothing here executes to find out."""
    key = _edge_key(source, target, kind)
    traversed = state.traversed if key in state.traversed else (*state.traversed, key)
    owned = state.owned if target in state.owned else (*state.owned, target)
    return replace(state, owned=owned, traversed=traversed)


def frontier(graph: Graph, state: KillchainState) -> list[Edge]:
    """The abusable edges we could take NEXT: out of an owned foothold, not yet traversed."""
    out: list[Edge] = []
    for node_id in state.owned:
        for e in graph.outgoing(node_id, abusable_only=True):
            if state.is_traversed(e.source, e.target, e.kind):
                continue
            if any(x.key() == e.key() for x in out):
                continue
            out.append(e)
    return out


def _label(graph: Graph, node_id: str) -> str:
    n = graph.node(node_id)
    return n.label if n else node_id


def _route_hint(graph: Graph, state: KillchainState, goal: str) -> tuple[str, set[str]]:
    best = None
    for owner in state.owned:
        p = kc_paths.shortest_path(graph, owner, goal)
        if p is not None and (best is None or p.length < best.length):
            best = p
    if best is None or not best.edges:
        return (
            "  (no complete route from an owned foothold to the objective yet — a lane or a seam may "
            "be missing, so prefer an edge that expands what you control or crosses into a new lane)",
            set(),
        )
    lines = []
    for i, h in enumerate(best.edges[:_MAX_PATH_HOPS]):
        seam = "  ⇄ SEAM" if h.bridge else ""
        lines.append(f"  {i + 1}. {h.source_label} --{h.kind}--> {h.target_label}{seam}")
    on_route = {_edge_key(h.source, h.target, h.kind) for h in best.edges}
    return "\n".join(lines), on_route


def _candidate_lines(graph: Graph, cands: list[Edge], on_route: set[str]) -> str:
    lines = []
    for i, e in enumerate(cands):
        tnode = graph.node(e.target)
        marks = []
        if _edge_key(e.source, e.target, e.kind) in on_route:
            marks.append("ON THE SHORTEST ROUTE")
        if e.bridge:
            d_from = e.props.get("domain_from", "?")
            d_to = e.props.get("domain_to", "?")
            marks.append(f"CROSS-DOMAIN SEAM {d_from}→{d_to}")
        if tnode is not None and tnode.high_value:
            marks.append("OBJECTIVE / HIGH VALUE")
        suffix = f"  [{' · '.join(marks)}]" if marks else ""
        lines.append(
            f"  [{i}] {_label(graph, e.source)} --{e.kind}--> {_label(graph, e.target)}{suffix}"
        )
    return "\n".join(lines)


_SYSTEM = (
    "You are advising on an AUTHORIZED penetration test. You are reasoning over a MERGED kill-chain "
    "graph that stitches three lanes — a web foothold, a cloud IAM enumeration, and an on-prem "
    "Active Directory graph — into one routed chain, joined by cross-domain SEAMS (an SSRF that "
    "reaches cloud metadata, a cloud secret reused as an AD credential, a web RCE that lands on a "
    "host).\n"
    "You do NOT run anything. You choose the single next EDGE to take; a human reviews it and "
    "approves it before any command runs. Every step is approved individually.\n"
    "HARD RULES:\n"
    "- You may ONLY choose from the numbered CANDIDATE EDGES given to you. Return its index. You "
    "cannot propose a command, a resource, or an edge that is not in that list.\n"
    "- Prefer the edge that most shortens the route to the objective — edges marked ON THE SHORTEST "
    "ROUTE are the direct line, and a CROSS-DOMAIN SEAM is often the pivot that unlocks a new lane. "
    "Prefer a quieter step when two candidates advance the chain equally.\n"
    "- When an owned foothold already reaches the objective, or no candidate advances it, return "
    '{"done": true}.\n'
    "Output ONLY a JSON object, no prose, shaped exactly like:\n"
    '{"done": false, "pick": 0, "rationale": "<1-2 sentences: why this edge is the next step and '
    'what lane it advances or unlocks>"}'
)


def build_user_prompt(
    graph: Graph, state: KillchainState, goal: str, cands: list[Edge], route: str, on_route: set[str]
) -> str:
    owned = [_label(graph, n) for n in state.owned[:_MAX_OWNED_LISTED]]
    lines = [
        f"OBJECTIVE: reach {_label(graph, goal)} ({split_domain(goal)[0] or '?'} lane)",
        "",
        "FOOTHOLDS YOU ALREADY CONTROL:",
        *(f"  - {o}" for o in owned or ["  (none yet)"]),
        "",
        "CURRENT SHORTEST ROUTE TO THE OBJECTIVE:",
        route,
        "",
        f"CANDIDATE EDGES — you must pick one of these by index (0-{len(cands) - 1}):",
        _candidate_lines(graph, cands, on_route),
        "",
        "Pick the single next edge as JSON (or {\"done\": true} if the objective is already reached "
        "or nothing here advances it).",
    ]
    return "\n".join(lines)


def _argv(cmd: str) -> tuple[str, list[str]]:
    """Split the catalog's command string into argv. Parsing only — nothing is spawned."""
    line = next(
        (ln.strip() for ln in (cmd or "").splitlines()
         if ln.strip() and not ln.strip().startswith("#")),
        "",
    )
    if not line:
        return "", []
    try:
        parts = shlex.split(line)
    except ValueError:
        return "", []
    return (parts[0], parts[1:]) if parts else ("", [])


def _precheck(command: str, args: list[str], scope_ctx: Any | None) -> tuple[bool, str]:
    """Advisory: would the executor's target/scope lock refuse this bridge command? Same matcher."""
    if not command:
        return False, "this hop resolves in its own lane view — there is no cross-domain command here"
    if scope_ctx is not None:
        return executor.check_target_lock(
            args,
            command,
            allowed=frozenset(getattr(scope_ctx, "allowed_hosts", ()) or ())
            | {getattr(scope_ctx, "target", "")},
            label=getattr(scope_ctx, "scope", "") or getattr(scope_ctx, "target", ""),
            in_scope=getattr(scope_ctx, "in_scope", None),
        )
    return executor.check_target_lock(args, command)


def proposal_for_edge(
    graph: Graph,
    edge: Edge,
    rationale: str,
    grounder: Callable | None = None,
    scope_ctx: Any | None = None,
) -> dict[str, Any]:
    """Build the PROPOSAL for one chosen edge.

    A CROSS-DOMAIN bridge resolves to a KB-grounded crossing command (this overlay's bridge catalog)
    the human can approve through the gated executor. A WITHIN-LANE edge is DEFERRED to its lane's
    own view — the overlay carries the label + the lane pointer, not a duplicated command (so the
    :cloud / :ad-graph catalog stays the single source of truth for per-lane abuse). Returns data;
    nothing here is executed and ``approved`` appears nowhere.
    """
    d_from, _ = split_domain(edge.source)
    d_to, _ = split_domain(edge.target)

    if edge.bridge:
        tech = bridges.technique_for_bridge(edge, graph, grounder)
        cmds = tech.get("commands") or []
        raw_cmd = (cmds[0].get("cmd") if cmds else "") or ""
        command, args = _argv(raw_cmd)
        runnable_line = next(
            (ln for ln in (raw_cmd or "").splitlines()
             if ln.strip() and not ln.strip().startswith("#")),
            "",
        )
        resolution = "ready" if command else ("unparsable" if runnable_line else "note-only")
        destructive = bool(tech.get("destructive"))
        gate_ok, gate_reason = _precheck(command, args, scope_ctx)
        dangerous = allowlist.dangerous_command_heuristic(command, args) if command else []
        lane_view = None
        technique = {
            "title": tech.get("title"), "summary": tech.get("summary"), "tool": tech.get("tool"),
            "destructive": destructive, "grounded": bool(tech.get("grounded")),
            "ai_suggested": bool(tech.get("ai_suggested")),
            "entry_id": tech.get("entry_id"), "entry_title": tech.get("entry_title"),
            "attack_id": tech.get("attack_id"), "commands": cmds,
            "domain_from": tech.get("domain_from") or d_from,
            "domain_to": tech.get("domain_to") or d_to,
            "why": tech.get("why"),
        }
        runnable = bool(command)
    else:
        # A WITHIN-LANE hop: it belongs to a per-lane graph that already owns its abuse + its gated
        # command. The kill-chain view routes over it and hands the operator off to that view.
        raw_cmd = ""
        command, args = "", []
        resolution = "lane-view"
        destructive = False
        gate_ok, gate_reason = False, f"resolve and approve this {d_from or 'lane'} hop in its own view"
        dangerous = []
        lane_view = _LANE_VIEW.get(d_from)
        technique = {
            "title": f"{edge.kind} — within the {d_from or 'lane'} lane",
            "summary": f"A {d_from or 'lane'}-internal move. Resolve the exact command and approve it "
                       f"in the :{'cloud' if d_from == 'cloud' else 'ad-graph' if d_from == 'onprem' else d_from} "
                       "view — that lane owns this abuse (single source of truth).",
            "tool": "", "destructive": False, "grounded": False, "ai_suggested": False,
            "entry_id": None, "entry_title": None, "attack_id": edge.props.get("attack_id", ""),
            "commands": [], "domain_from": d_from, "domain_to": d_to,
            "why": "Within-lane abuse is owned by that lane's dedicated view; the kill-chain overlay "
                   "owns only the cross-domain seams.",
        }
        runnable = False

    return {
        "edge": {
            "source": edge.source,
            "target": edge.target,
            "kind": edge.kind,
            "source_label": _label(graph, edge.source),
            "target_label": _label(graph, edge.target),
            "bridge": edge.bridge,
            "domain_from": d_from,
            "domain_to": d_to,
        },
        "technique": technique,
        "command": command,
        "args": args,
        "cmd_display": raw_cmd,
        "rationale": (rationale or "").strip()[:_MAX_RATIONALE],
        "runnable": runnable,
        "is_bridge": edge.bridge,
        "lane_view": lane_view,
        "resolution": resolution,               # "ready" | "note-only" | "unparsable" | "lane-view"
        # advisory only — the executor re-checks all of this at run time
        "gate_ok": gate_ok,
        "gate_reason": gate_reason,
        "dangerous_flags": dangerous,
        "requires_confirm": bool(dangerous),
        "destructive_technique": destructive,
        "destructive_unresolved": destructive and not command,
    }


def propose_next(
    graph: Graph,
    state: KillchainState,
    goal: str,
    cfg: dict,
    grounder: Callable | None = None,
    scope_ctx: Any | None = None,
    avoid: list[str] | None = None,
) -> dict[str, Any]:
    """Ask the model which edge to take next. Returns a PROPOSAL; executes nothing.

    Returns ``{done, proposal|None, reason, candidates}``. A model pick outside the candidate list is
    refused rather than repaired. Raises ``llm.LLMError`` if the model is unreachable/unparseable."""
    if state.is_owned(goal):
        return {"done": True, "proposal": None, "candidates": 0,
                "reason": "the objective is already owned"}

    cands = frontier(graph, state)
    skip = {s.strip() for s in (avoid or []) if s.strip()}
    if skip:
        cands = [e for e in cands if _edge_key(e.source, e.target, e.kind) not in skip]
    if not cands:
        return {"done": True, "proposal": None, "candidates": 0,
                "reason": "no abusable edge remains out of the footholds you control"}
    cands = cands[:_MAX_CANDIDATES]

    route, on_route = _route_hint(graph, state, goal)
    user = build_user_prompt(graph, state, goal, cands, route, on_route)
    raw = llm.chat(_SYSTEM, user, cfg, max_tokens=500)
    parsed = llm.extract_json(raw)
    if not isinstance(parsed, dict):
        raise llm.LLMError("the model did not return a proposal object")

    if parsed.get("done") is True:
        return {"done": True, "proposal": None, "candidates": len(cands),
                "reason": "the agent judged the objective covered"}

    pick = parsed.get("pick")
    if not isinstance(pick, int) or not (0 <= pick < len(cands)):
        return {
            "done": False, "proposal": None, "candidates": len(cands),
            "reason": f"the agent returned an invalid edge selection ({pick!r}) — nothing is "
                      "proposed rather than guessing at which edge it meant",
        }

    prop = proposal_for_edge(
        graph, cands[pick], str(parsed.get("rationale") or ""), grounder, scope_ctx
    )
    return {"done": False, "proposal": prop, "candidates": len(cands), "reason": None}


__all__ = [
    "KillchainState", "advance", "frontier", "proposal_for_edge", "propose_next", "build_user_prompt",
]
