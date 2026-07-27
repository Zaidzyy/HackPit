"""AD orchestration — the agent reasons over the graph and PROPOSES the next edge to abuse.

This is the guided loop applied to the AD attack path. Given the parsed graph and the current
state (which principals are owned, which edges have already been traversed), it asks the model
for the ONE next edge to abuse and returns a PROPOSAL. It runs nothing.

WHY THIS MODULE IS SHAPED THE WAY IT IS
---------------------------------------
AD abuse is destructive in a way web recon is not: DCSync replicates every secret in the
domain, ForceChangePassword overwrites a real person's password, psexec/wmiexec drop a service
on a production host. An agent drafting those steps means "a human approves every single one"
is carrying essentially the whole safety load. Two structural choices follow, and they matter
more than any prompt wording:

1. **The model chooses an EDGE, never a command.** It is handed a numbered list of candidate
   edges — the abusable edges leading out of principals we already own — and returns an index.
   The command is then resolved by the existing deterministic technique catalog
   (``techniques.technique_for_edge``), which is KB-grounded. So the model cannot author an
   arbitrary command, cannot invent a host, and cannot reach an edge that is not really in the
   collected graph. A pick outside the candidate list is rejected outright.

2. **This module has no way to run or approve anything.** It builds a proposal and hands it
   back. Execution happens where it already happened before this module existed: the operator
   approves, and the request goes through the SAME gated executor the walk-the-path button
   already used (``POST /cockpit/exec``). There is no second execution path, and nothing here
   can set ``approved``. Regression-locked by source scan in test_adorch_safety.py.

The proposal carries an advisory ``gate_ok`` pre-check and the danger-heuristic reasons, so the
UI can show — before the human decides — that a step would be refused, or that it will demand
the red confirm. Enforcement is the executor's gates at run time, never this pre-check.

State (owned principals, traversed edges) is passed in and returned; this module keeps none.
Every actual run is already recorded by the run store, which is the audit trail.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass, replace
from typing import Any, Callable

import llm
from cockpit import allowlist, executor

from . import paths as ad_paths
from . import techniques as ad_techniques
from .schema import Edge, Graph

# Bounds — an AD collection can be enormous; the prompt must stay small and legible.
_MAX_CANDIDATES = 24
_MAX_PATH_HOPS = 12
_MAX_OWNED_LISTED = 20
_MAX_RATIONALE = 400


def _edge_key(source: str, target: str, kind: str) -> str:
    """Stable identity for one edge, used to record what has been traversed."""
    return f"{source}|{target}|{kind}"


@dataclass(frozen=True)
class AdState:
    """What the operator controls so far, and what has already been walked.

    Inert data: node ids and edge keys. It carries no capability — owning a principal here
    means "the operator has demonstrated control", not that anything is authorized to run.
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
    def from_dict(raw: dict[str, Any] | None) -> "AdState":
        raw = raw or {}
        owned = tuple(str(x) for x in (raw.get("owned") or []) if str(x).strip())
        trav = tuple(str(x) for x in (raw.get("traversed") or []) if str(x).strip())
        return AdState(owned=owned, traversed=trav)


def advance(state: AdState, source: str, target: str, kind: str) -> AdState:
    """The state AFTER an abuse step has succeeded: edge traversed, target principal owned.

    A pure function. It is called only once a run has actually come back successful — it is
    never how a proposal advances itself, and nothing here executes to find that out.
    """
    key = _edge_key(source, target, kind)
    traversed = state.traversed if key in state.traversed else (*state.traversed, key)
    owned = state.owned if target in state.owned else (*state.owned, target)
    return replace(state, owned=owned, traversed=traversed)


def frontier(graph: Graph, state: AdState) -> list[Edge]:
    """The abusable edges we could take NEXT: out of an owned principal, not yet traversed.

    This is the entire universe the agent may choose from. It is derived from the collected
    graph, so an edge that does not exist in the domain cannot be proposed.
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


def _route_hint(graph: Graph, state: AdState, goal: str) -> tuple[str, set[str]]:
    """The current shortest route from any owned principal to the goal, as prompt grounding.

    Also returns the set of edge keys ON that route, so the agent can be told which candidates
    actually shorten the path rather than wandering sideways. Best-effort: an empty hint just
    means the model reasons from the candidate list alone.
    """
    best = None
    for owner in state.owned:
        p = ad_paths.shortest_path(graph, owner, goal)
        if p is not None and (best is None or p.length < best.length):
            best = p
    if best is None or not best.edges:
        return (
            "  (no complete route from an owned principal to the objective — the collection "
            "may be partial, so prefer an edge that expands what you control)",
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
            marks.append("HIGH VALUE")
        suffix = f"  [{' · '.join(marks)}]" if marks else ""
        lines.append(
            f"  [{i}] {_label(graph, e.source)} --{e.kind}--> {_label(graph, e.target)}{suffix}"
        )
    return "\n".join(lines)


_SYSTEM = (
    "You are advising on an AUTHORIZED Active Directory penetration test. You are reasoning "
    "over a BloodHound collection of a domain the operator is authorized to test.\n"
    "You do NOT run anything. You choose the single next EDGE to abuse; a human reviews it and "
    "explicitly approves it before any command runs. Every step is approved individually.\n"
    "HARD RULES:\n"
    "- You may ONLY choose from the numbered CANDIDATE EDGES given to you. Return its index. "
    "You cannot propose a command, a host, or an edge that is not in that list.\n"
    "- Prefer the edge that most shortens the route to the objective — edges marked ON THE "
    "SHORTEST ROUTE are the direct line. Prefer a quieter, less destructive abuse when two "
    "candidates advance the path equally.\n"
    "- Some abuses are DESTRUCTIVE on a real domain (resetting a user's password, replicating "
    "secrets, dropping a service on a host). Choose one only when it genuinely advances the "
    "objective, and say plainly in the rationale why it is worth it.\n"
    "- When an owned principal already reaches the objective, or no candidate advances it, "
    'return {"done": true}.\n'
    "Output ONLY a JSON object, no prose, shaped exactly like:\n"
    '{"done": false, "pick": 0, "rationale": "<1-2 sentences: why this edge is the next step '
    'and what it gains>"}'
)


def build_user_prompt(
    graph: Graph, state: AdState, goal: str, cands: list[Edge], route: str, on_route: set[str]
) -> str:
    owned = [_label(graph, n) for n in state.owned[:_MAX_OWNED_LISTED]]
    lines = [
        f"DOMAIN: {graph.domain or '(unknown)'}",
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

    The executor runs argv-only (never a shell), so the first runnable line is tokenised the
    way the operator's shell would have, and comment lines are skipped. A command that will not
    tokenise yields ("", []) and the caller reports it rather than guessing.
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


def _win_argv(cmd: str) -> tuple[str, list[str]]:
    """Split a native Windows/PowerShell command into (program, args).

    Uses a NON-POSIX split so Windows paths (``DOMAIN\\krbtgt``) and PowerShell quoting
    survive — the executor rejoins command + args into one string for WinRM, so preserving
    them verbatim is what matters. Comment-only lines (inherited-rights notes) yield ("", [])."""
    line = next(
        (ln.strip() for ln in (cmd or "").splitlines()
         if ln.strip() and not ln.strip().startswith("#")),
        "",
    )
    if not line:
        return "", []
    try:
        parts = shlex.split(line, posix=False)
    except ValueError:
        return "", []
    return (parts[0], parts[1:]) if parts else ("", [])


def _precheck(
    command: str, args: list[str], scope_ctx: Any | None
) -> tuple[bool, str]:
    """Advisory: would the executor's target/scope lock refuse this? Same matcher it uses."""
    if not command:
        # Not a failure — an edge like MemberOf is inherited rights, with nothing to run.
        # The proposal reports it via ``runnable: False``.
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
    dc: str | None = None,
    scope_ctx: Any | None = None,
) -> dict[str, Any]:
    """Build the PROPOSAL for one chosen edge — technique, command, why, and the advisories.

    The command comes from the deterministic KB-grounded technique catalog for this edge, not
    from the model. Returns data; nothing here is executed and ``approved`` appears nowhere.
    """
    tech = ad_techniques.technique_for_edge(edge, graph, grounder, dc)
    cmds = tech.get("commands") or []
    raw_cmd = (cmds[0].get("cmd") if cmds else "") or ""
    command, args = _argv(raw_cmd)
    destructive = bool(tech.get("destructive"))

    # NATIVE WINDOWS variant — the CRTP command that runs ON the box over WinRM. Parsed the
    # same way (argv only, comments skipped) and given its OWN danger pre-check, so the UI can
    # show that a Windows-target run would demand the red confirm before the human decides.
    win_cmds = tech.get("windows_commands") or []
    win_raw = (win_cmds[0].get("cmd") if win_cmds else "") or ""
    win_command, win_args = _win_argv(win_raw)
    # Through the executor's OWN union, not the argv heuristic alone. A WinRM run joins
    # command + args into one PowerShell script and classifies the whole thing, so asking the
    # argv-only heuristic here would under-report exactly where the gate over-reports — the UI
    # would promise no confirm and the operator would meet one, or worse, read "safe" on a step
    # that trips. Advisory either way; the executor re-checks at run time.
    win_dangerous = (
        executor.windows_danger_reasons(win_command, list(win_args)) if win_command else []
    )

    # WHY THE COMMAND IS ABSENT MATTERS, and conflating the cases is dangerous.
    #
    #   ready       we have a program + argv to hand to the executor
    #   note-only   the technique yields prose, not a command. For MemberOf that is correct
    #               and benign — inherited rights are not something you run.
    #   unparsable  a real command line came back but would not tokenise into argv.
    #
    # Live verification against a real model caught the reason this distinction has to exist:
    # with the KB grounder wired, DCSync and ForceChangePassword came back with no usable
    # command, so the proposal reported requires_confirm=False and a domain-wide credential
    # replication rendered as though it were free. Whatever the flavour, a DESTRUCTIVE abuse
    # with nothing to send to a gate must read as "this needs your attention" — there is no
    # executor decision to lean on, because there is nothing to send.
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
        # The native Windows variant (runs on the box over WinRM), with its own danger
        # pre-check. Empty command when the edge has no native variant. The executor
        # re-checks everything at run time — this is advisory, like the Linux gate_ok.
        "windows_command": win_command,
        "windows_args": win_args,
        "windows_cmd_display": win_raw,
        "windows_runnable": bool(win_command),
        "windows_dangerous_flags": win_dangerous,
        "windows_requires_confirm": bool(win_dangerous),
        "rationale": (rationale or "").strip()[:_MAX_RATIONALE],
        # Some edges are RIGHTS, not actions — MemberOf is rights you already inherit, so it
        # resolves to no command. Flagged rather than surfaced as a failed gate: there is
        # nothing to approve because there is nothing to run. The human still advances it by
        # hand; the graph never advances itself.
        "runnable": bool(command),
        # "ready" | "note-only" (prose, correct for inherited rights) | "unparsable".
        "resolution": resolution,
        # advisory only — the executor re-checks all of this at run time
        "gate_ok": gate_ok,
        "gate_reason": gate_reason,
        "dangerous_flags": dangerous,
        # WILL THE EXECUTOR DEMAND THE RED CONFIRM? This mirrors the executor's rule exactly —
        # a non-empty danger heuristic — and nothing else, so the UI never promises a confirm
        # the gate would not actually require.
        "requires_confirm": bool(dangerous),
        # The technique catalog's INDEPENDENT opinion that this abuse is destructive. Kept
        # separate on purpose: it is not what the executor enforces, which makes it a usable
        # cross-check. Any edge the catalog calls destructive whose command does NOT trip the
        # heuristic is a hole in the heuristic — asserted in test_adorch_safety.py.
        "destructive_technique": destructive,
        # A DESTRUCTIVE abuse with no runnable command, whichever flavour. There is no
        # executor gate to lean on here BECAUSE there is nothing to send to it, so this
        # warning carries the weight: whatever the operator supplies by hand changes a real
        # domain. Never let this render as the benign "nothing to run" case.
        "destructive_unresolved": destructive and not command,
    }


def propose_next(
    graph: Graph,
    state: AdState,
    goal: str,
    cfg: dict,
    grounder: Callable | None = None,
    dc: str | None = None,
    scope_ctx: Any | None = None,
    avoid: list[str] | None = None,
) -> dict[str, Any]:
    """Ask the model which edge to abuse next. Returns a PROPOSAL; executes nothing.

    Returns ``{done, proposal|None, reason, candidates}``. ``done`` is True when the objective
    is already owned, when there is no frontier left, or when the model says so. A model pick
    outside the candidate list is refused rather than repaired — a proposal we cannot tie back
    to a real edge in the collection is not one a human should be asked to approve.

    Raises ``llm.LLMError`` if the model is unreachable or unparseable; the API maps that to a
    clean 503, and the operator is left with the manual walk they already had.
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
        graph, cands[pick], str(parsed.get("rationale") or ""), grounder, dc, scope_ctx
    )
    return {"done": False, "proposal": prop, "candidates": len(cands), "reason": None}
