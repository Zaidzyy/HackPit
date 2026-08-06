"""Cloud IAM orchestration — the agent reasons over the graph and PROPOSES the next edge to abuse.

The cloud parallel to ``adgraph/orchestrator.py``, with the SAME safety design. Given the parsed
graph and the current state (which principals are owned, which edges are already traversed), it
asks the model for the ONE next edge to abuse and returns a PROPOSAL. It runs nothing.

WHY THIS MODULE IS SHAPED THE WAY IT IS
---------------------------------------
Cloud IAM abuse is destructive in a way passive enumeration is not: AttachRolePolicy grants a real
principal AdministratorAccess, UpdateFunctionCode overwrites production code, CreateAccessKey mints
long-lived credentials. An agent drafting those steps means "a human approves every single one" is
carrying essentially the whole safety load. Two structural choices follow:

1. **The model chooses an EDGE, never a command.** It is handed a numbered list of candidate edges
   — the abusable edges leading out of principals we already own — and returns an index. The
   command is then resolved by the deterministic, KB-grounded technique catalog
   (``techniques.technique_for_edge``). So the model cannot author an arbitrary command, invent a
   resource, or reach an edge that is not really in the enumerated graph. A pick outside the list is
   rejected outright.

2. **This module has no way to run or approve anything.** It builds a proposal and hands it back.
   Execution happens where it already happened: the operator approves, and the request goes through
   the SAME gated executor every other cockpit command uses (``POST /cockpit/exec``). There is no
   second execution path, and nothing here can set ``approved``. Regression-locked by a source scan
   in test_cloudgraph_safety.py.

State (owned principals, traversed edges) is passed in and returned; this module keeps none.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass, replace
from typing import Any, Callable

import llm
from cockpit import allowlist, executor

from . import paths as cloud_paths
from . import techniques as cloud_techniques
from .schema import Edge, Graph

# Bounds — a cloud enumeration can be enormous; the prompt must stay small and legible.
_MAX_CANDIDATES = 24
_MAX_PATH_HOPS = 12
_MAX_OWNED_LISTED = 20
_MAX_RATIONALE = 400


def _edge_key(source: str, target: str, kind: str) -> str:
    """Stable identity for one edge, used to record what has been traversed."""
    return f"{source}|{target}|{kind}"


@dataclass(frozen=True)
class CloudState:
    """What the operator controls so far, and what has already been walked.

    Inert data: node ids and edge keys. It carries no capability — owning a principal here means
    "the operator has demonstrated control", not that anything is authorized to run.
    """

    owned: tuple[str, ...] = ()
    traversed: tuple[str, ...] = ()

    def is_owned(self, node_id: str) -> bool:
        return node_id in self.owned

    def is_traversed(self, source: str, target: str, kind: str) -> bool:
        return _edge_key(source, target, kind) in self.traversed

    def to_dict(self) -> dict[str, Any]:
        return {"owned": list(self.owned), "traversed": list(self.traversed)}

    @staticmethod
    def from_dict(raw: dict[str, Any] | None) -> "CloudState":
        raw = raw or {}
        owned = tuple(str(x) for x in (raw.get("owned") or []) if str(x).strip())
        trav = tuple(str(x) for x in (raw.get("traversed") or []) if str(x).strip())
        return CloudState(owned=owned, traversed=trav)


def advance(state: CloudState, source: str, target: str, kind: str) -> CloudState:
    """The state AFTER an abuse step has succeeded: edge traversed, target principal owned.

    A pure function. It is called only once a run has actually come back successful — it is never
    how a proposal advances itself, and nothing here executes to find that out.
    """
    key = _edge_key(source, target, kind)
    traversed = state.traversed if key in state.traversed else (*state.traversed, key)
    owned = state.owned if target in state.owned else (*state.owned, target)
    return replace(state, owned=owned, traversed=traversed)


def frontier(graph: Graph, state: CloudState) -> list[Edge]:
    """The abusable edges we could take NEXT: out of an owned principal, not yet traversed.

    The entire universe the agent may choose from. Derived from the enumerated graph, so an edge
    that does not exist in the account cannot be proposed.
    """
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


def _route_hint(graph: Graph, state: CloudState, goal: str) -> tuple[str, set[str]]:
    """The current shortest route from any owned principal to the goal, as prompt grounding."""
    best = None
    for owner in state.owned:
        p = cloud_paths.shortest_path(graph, owner, goal)
        if p is not None and (best is None or p.length < best.length):
            best = p
    if best is None or not best.edges:
        return (
            "  (no complete route from an owned principal to the objective — the enumeration may "
            "be partial, so prefer an edge that expands what you control)",
            set(),
        )
    lines = [
        f"  {i + 1}. {h.source_label} --{h.kind}--> {h.target_label}"
        for i, h in enumerate(best.edges[:_MAX_PATH_HOPS])
    ]
    on_route = {_edge_key(h.source, h.target, h.kind) for h in best.edges}
    return "\n".join(lines), on_route


def _candidate_lines(graph: Graph, cands: list[Edge], on_route: set[str]) -> str:
    lines = []
    for i, e in enumerate(cands):
        tnode = graph.node(e.target)
        marks = []
        if _edge_key(e.source, e.target, e.kind) in on_route:
            marks.append("ON THE SHORTEST ROUTE")
        if tnode is not None and tnode.high_value:
            marks.append("ADMIN / HIGH VALUE")
        suffix = f"  [{' · '.join(marks)}]" if marks else ""
        lines.append(
            f"  [{i}] {_label(graph, e.source)} --{e.kind}--> {_label(graph, e.target)}{suffix}"
        )
    return "\n".join(lines)


_SYSTEM = (
    "You are advising on an AUTHORIZED cloud penetration test. You are reasoning over an IAM "
    "enumeration (ScoutSuite/Prowler/pacu/cloudfox) of an account the operator is authorized to "
    "test.\n"
    "You do NOT run anything. You choose the single next EDGE to abuse; a human reviews it and "
    "explicitly approves it before any command runs. Every step is approved individually.\n"
    "HARD RULES:\n"
    "- You may ONLY choose from the numbered CANDIDATE EDGES given to you. Return its index. You "
    "cannot propose a command, a resource, or an edge that is not in that list.\n"
    "- Prefer the edge that most shortens the route to the objective — edges marked ON THE SHORTEST "
    "ROUTE are the direct line. Prefer a quieter, less destructive abuse when two candidates advance "
    "the path equally.\n"
    "- Some abuses are DESTRUCTIVE on a real account (attaching admin policies, minting keys, "
    "overwriting function code). Choose one only when it genuinely advances the objective, and say "
    "plainly in the rationale why it is worth it.\n"
    "- When an owned principal already reaches the objective, or no candidate advances it, return "
    '{"done": true}.\n'
    "Output ONLY a JSON object, no prose, shaped exactly like:\n"
    '{"done": false, "pick": 0, "rationale": "<1-2 sentences: why this edge is the next step and '
    'what it gains>"}'
)


def build_user_prompt(
    graph: Graph, state: CloudState, goal: str, cands: list[Edge], route: str, on_route: set[str]
) -> str:
    owned = [_label(graph, n) for n in state.owned[:_MAX_OWNED_LISTED]]
    lines = [
        f"PROVIDER: {graph.provider or 'aws'}   ACCOUNT: {graph.account or '(unknown)'}",
        f"OBJECTIVE: reach {_label(graph, goal)}",
        "",
        "PRINCIPALS YOU ALREADY CONTROL:",
        *(f"  - {o}" for o in owned or ["  (none yet)"]),
        "",
        "CURRENT SHORTEST ROUTE TO THE OBJECTIVE:",
        route,
        "",
        f"CANDIDATE EDGES — you must pick one of these by index (0-{len(cands) - 1}):",
        _candidate_lines(graph, cands, on_route),
        "",
        "Pick the single next edge to abuse as JSON (or {\"done\": true} if the objective is "
        "already reached or nothing here advances it).",
    ]
    return "\n".join(lines)


def _argv(cmd: str) -> tuple[str, list[str]]:
    """Split the catalog's command string into argv. Parsing only — nothing is spawned.

    The executor runs argv-only (never a shell), so the first runnable line is tokenised the way
    the operator's shell would have, and comment lines are skipped. A command that will not tokenise
    yields ("", []) and the caller reports it rather than guessing.
    """
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
    """Advisory: would the executor's target/scope lock refuse this? Same matcher it uses."""
    if not command:
        # Not a failure — an edge like MemberOf is inherited rights, with nothing to run.
        return False, "this edge is inherited rights — there is no command to run"
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
    account: str | None = None,
    scope_ctx: Any | None = None,
) -> dict[str, Any]:
    """Build the PROPOSAL for one chosen edge — technique, command, why, and the advisories.

    The command comes from the deterministic KB-grounded technique catalog for this edge, not from
    the model. Returns data; nothing here is executed and ``approved`` appears nowhere.
    """
    tech = cloud_techniques.technique_for_edge(edge, graph, grounder, account)
    cmds = tech.get("commands") or []
    raw_cmd = (cmds[0].get("cmd") if cmds else "") or ""
    command, args = _argv(raw_cmd)
    destructive = bool(tech.get("destructive"))

    # WHY THE COMMAND IS ABSENT MATTERS, and conflating the cases is dangerous.
    #   ready       we have a program + argv to hand to the executor
    #   note-only   the technique yields prose (MemberOf — inherited rights are not something you run)
    #   unparsable  a real command line came back but would not tokenise into argv
    # A DESTRUCTIVE abuse with nothing to send to a gate must read as "this needs your attention".
    runnable_line = next(
        (ln for ln in (raw_cmd or "").splitlines()
         if ln.strip() and not ln.strip().startswith("#")),
        "",
    )
    if command:
        resolution = "ready"
    elif runnable_line:
        resolution = "unparsable"
    else:
        resolution = "note-only"

    gate_ok, gate_reason = _precheck(command, args, scope_ctx)
    dangerous = allowlist.dangerous_command_heuristic(command, args) if command else []
    return {
        "edge": {
            "source": edge.source,
            "target": edge.target,
            "kind": edge.kind,
            "source_label": _label(graph, edge.source),
            "target_label": _label(graph, edge.target),
        },
        "technique": {
            "title": tech.get("title"),
            "summary": tech.get("summary"),
            "tool": tech.get("tool"),
            "destructive": bool(tech.get("destructive")),
            "grounded": bool(tech.get("grounded")),
            "entry_id": tech.get("entry_id"),
            "entry_title": tech.get("entry_title"),
        },
        "command": command,
        "args": args,
        "cmd_display": raw_cmd,
        "rationale": (rationale or "").strip()[:_MAX_RATIONALE],
        # Some edges are RIGHTS, not actions — MemberOf resolves to no command. Flagged rather than
        # surfaced as a failed gate: there is nothing to approve because there is nothing to run.
        "runnable": bool(command),
        "resolution": resolution,               # "ready" | "note-only" | "unparsable"
        # advisory only — the executor re-checks all of this at run time
        "gate_ok": gate_ok,
        "gate_reason": gate_reason,
        "dangerous_flags": dangerous,
        # WILL THE EXECUTOR DEMAND THE RED CONFIRM? Mirrors the executor's rule exactly — a
        # non-empty danger heuristic — so the UI never promises a confirm the gate would not require.
        "requires_confirm": bool(dangerous),
        # The catalog's INDEPENDENT opinion that this abuse is destructive (cross-check for the UI).
        "destructive_technique": destructive,
        # A DESTRUCTIVE abuse with no runnable command — there is no gate to lean on because there
        # is nothing to send to it, so this warning carries the weight. Never render it as benign.
        "destructive_unresolved": destructive and not command,
    }


def propose_next(
    graph: Graph,
    state: CloudState,
    goal: str,
    cfg: dict,
    grounder: Callable | None = None,
    account: str | None = None,
    scope_ctx: Any | None = None,
    avoid: list[str] | None = None,
) -> dict[str, Any]:
    """Ask the model which edge to abuse next. Returns a PROPOSAL; executes nothing.

    Returns ``{done, proposal|None, reason, candidates}``. ``done`` is True when the objective is
    already owned, when there is no frontier left, or when the model says so. A model pick outside
    the candidate list is refused rather than repaired — a proposal we cannot tie back to a real edge
    in the enumeration is not one a human should be asked to approve.

    Raises ``llm.LLMError`` if the model is unreachable or unparseable; the API maps that to a clean
    503, and the operator is left with the manual walk they already had.
    """
    if state.is_owned(goal):
        return {"done": True, "proposal": None, "candidates": 0,
                "reason": "the objective is already owned"}

    cands = frontier(graph, state)
    skip = {s.strip() for s in (avoid or []) if s.strip()}
    if skip:
        cands = [e for e in cands
                 if _edge_key(e.source, e.target, e.kind) not in skip]
    if not cands:
        return {"done": True, "proposal": None, "candidates": 0,
                "reason": "no abusable edge remains out of the principals you control"}
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
        # STRUCTURAL GUARD: the model may only select a real edge from the list it was given.
        return {
            "done": False, "proposal": None, "candidates": len(cands),
            "reason": f"the agent returned an invalid edge selection ({pick!r}) — nothing is "
                      "proposed rather than guessing at which edge it meant",
        }

    prop = proposal_for_edge(
        graph, cands[pick], str(parsed.get("rationale") or ""), grounder, account, scope_ctx
    )
    return {"done": False, "proposal": prop, "candidates": len(cands), "reason": None}
