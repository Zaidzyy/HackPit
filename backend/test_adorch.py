"""AD orchestration — the reasoning layer, and the synthetic end-to-end walk (AO5 + AO6).

The safety INVARIANTS live in test_adorch_safety.py. This file covers behaviour:

  * the frontier is exactly what the operator can reach next, and shrinks as edges are walked
  * state advancement is pure and idempotent
  * a proposal is well-formed, and a model pick outside the candidate list is REFUSED
  * skipping an edge takes it out of the next proposal
  * SYNTHETIC E2E (AO6): driven by a stubbed model, the agent proposes a sensible edge-by-edge
    sequence that actually reaches Domain Admin over the sample domain — and EVERY runnable
    step in that sequence is still refused by the executor when submitted unapproved.

The live run — an agent proposing while a human walks a REAL domain — is deliberately NOT
here. It needs an AD lab and a human present, and it is not something a test suite should
start on its own. Wired and ready; see docs/AD-ORCHESTRATION.md.

Hermetic: llm.chat is monkeypatched, no LLM/Docker/network. Run:  python test_adorch.py
"""
from __future__ import annotations

import json
from pathlib import Path

from adgraph import orchestrator as O
from adgraph import parser as P
from adgraph import paths as PA
from adgraph import sample_data as S
from cockpit import executor as E
from cockpit.models import EngagementRecord, ExecRequest

_CFG = {"provider": "stub", "model": "stub"}


class StubModel:
    """Swap the orchestrator's llm.chat for a canned reply; restore on exit."""

    def __init__(self, payload: dict | str):
        self.payload = payload if isinstance(payload, str) else json.dumps(payload)

    def __enter__(self):
        self._orig = O.llm.chat
        O.llm.chat = lambda system, user, cfg, max_tokens=500: self.payload
        return self

    def __exit__(self, *exc):
        O.llm.chat = self._orig


class RoutingModel:
    """A stub that always picks the candidate lying on the shortest route to the goal —
    i.e. what a competent agent should do. Used to drive the synthetic end-to-end walk."""

    def __init__(self, graph, goal):
        self.graph, self.goal = graph, goal

    def __enter__(self):
        self._orig = O.llm.chat

        def chat(system, user, cfg, max_tokens=500):
            # recover the candidate list from the prompt the orchestrator just built
            idx = self._pick_from_prompt(user)
            return json.dumps({"done": False, "pick": idx, "rationale": "shortens the route"})

        O.llm.chat = chat
        return self

    def _pick_from_prompt(self, user: str) -> int:
        lines = [ln for ln in user.splitlines() if ln.strip().startswith("[")]
        for i, ln in enumerate(lines):
            if "ON THE SHORTEST ROUTE" in ln:
                return i
        return 0

    def __exit__(self, *exc):
        O.llm.chat = self._orig


def _graph():
    return P.parse_collection(S.sample_collection())


def _start(g):
    owned = [n.id for n in g.nodes.values() if n.owned]
    return owned or [n.id for n in g.nodes.values() if n.type == "user"][:1]


# --------------------------------------------------------------------------- #
# state + frontier
# --------------------------------------------------------------------------- #
def test_frontier_is_what_you_can_reach_next() -> None:
    g = _graph()
    st = O.AdState(owned=tuple(_start(g)))
    f = O.frontier(g, st)
    assert f, "an owned principal should have reachable abusable edges"
    assert all(e.source in st.owned for e in f), "the frontier only leaves owned principals"
    assert all(e.abusable for e in f), "structural edges are never proposable"
    # an edge already walked leaves the frontier
    st2 = O.advance(st, f[0].source, f[0].target, f[0].kind)
    f2 = O.frontier(g, st2)
    assert not any(e.key() == f[0].key() for e in f2), "a traversed edge must not be re-proposed"
    print(f"  the frontier is the abusable edges out of owned principals ({len(f)}), and a "
          "walked edge leaves it: PASS")


def test_advance_is_pure_and_idempotent() -> None:
    st = O.AdState(owned=("a",))
    st2 = O.advance(st, "a", "b", "GenericAll")
    assert st.owned == ("a",) and st.traversed == (), "the input state must be untouched"
    assert st2.owned == ("a", "b") and len(st2.traversed) == 1
    st3 = O.advance(st2, "a", "b", "GenericAll")
    assert st3.owned == st2.owned and st3.traversed == st2.traversed, "advance is idempotent"
    print("  advance() is pure and idempotent: PASS")


# --------------------------------------------------------------------------- #
# proposals
# --------------------------------------------------------------------------- #
def test_a_proposal_is_well_formed() -> None:
    g = _graph()
    st = O.AdState(owned=tuple(_start(g)))
    goal = PA.default_high_value_target(g)
    with StubModel({"done": False, "pick": 0, "rationale": "it shortens the path"}):
        out = O.propose_next(g, st, goal, _CFG)
    p = out["proposal"]
    assert out["done"] is False and p is not None
    for key in ("edge", "technique", "command", "args", "rationale", "runnable",
                "gate_ok", "dangerous_flags", "requires_confirm", "destructive_technique"):
        assert key in p, f"a proposal must carry {key}"
    assert p["edge"]["source"] in st.owned, "the proposed edge must leave an owned principal"
    assert p["rationale"] == "it shortens the path"
    # a proposal also carries the NATIVE WINDOWS variant (for live WinRM execution)
    for key in ("windows_command", "windows_args", "windows_cmd_display", "windows_runnable",
                "windows_dangerous_flags", "windows_requires_confirm"):
        assert key in p, f"a proposal must carry {key}"
    print("  a proposal is well-formed and leaves an owned principal: PASS")


def test_proposal_exposes_a_native_windows_variant() -> None:
    """For a destructive edge the proposal offers a native PowerShell/PowerView/Rubeus command
    that runs on the Windows box over WinRM, with its own danger pre-check."""
    g = _graph()
    edge = next(e for e in g.edges if e.kind == "ForceChangePassword")
    p = O.proposal_for_edge(g, edge, "reset the password")
    assert p["windows_command"], "a destructive edge should have a native Windows variant"
    assert "Set-DomainUserPassword" in p["windows_cmd_display"]
    assert p["windows_requires_confirm"] is True, "a destructive Windows variant demands confirm"
    print("  a proposal exposes a native Windows (PowerView/Rubeus) variant + its danger flag: PASS")


def test_a_pick_outside_the_candidate_list_is_refused() -> None:
    """The structural guard. The model may only select a real edge from the list it was
    handed — a proposal we cannot tie back to the collection is not one a human should be
    asked to approve, so it is refused rather than repaired."""
    g = _graph()
    st = O.AdState(owned=tuple(_start(g)))
    goal = PA.default_high_value_target(g)
    for bad in (999, -1, "GenericAll", None, 1.5):
        with StubModel({"done": False, "pick": bad, "rationale": "x"}):
            out = O.propose_next(g, st, goal, _CFG)
        assert out["proposal"] is None, f"pick={bad!r} must not yield a proposal"
        assert "invalid edge selection" in (out["reason"] or "")
    print("  a model pick outside the candidate list yields NO proposal: PASS")


def test_done_conditions() -> None:
    g = _graph()
    goal = PA.default_high_value_target(g)
    # already owned
    out = O.propose_next(g, O.AdState(owned=(goal,)), goal, _CFG)
    assert out["done"] and out["proposal"] is None
    # a principal with no outgoing abusable edge -> no frontier, no model call needed
    leaf = next((n.id for n in g.nodes.values()
                 if not list(g.outgoing(n.id, abusable_only=True))), None)
    if leaf:
        out = O.propose_next(g, O.AdState(owned=(leaf,)), goal, _CFG)
        assert out["done"] and out["proposal"] is None and out["candidates"] == 0
    print("  done when the objective is owned, and when no frontier remains: PASS")


def test_skipping_an_edge_removes_it_from_the_next_proposal() -> None:
    g = _graph()
    st = O.AdState(owned=tuple(_start(g)))
    goal = PA.default_high_value_target(g)
    first = O.frontier(g, st)[0]
    key = f"{first.source}|{first.target}|{first.kind}"
    with StubModel({"done": False, "pick": 0, "rationale": "x"}):
        out = O.propose_next(g, st, goal, _CFG, avoid=[key])
    if out["proposal"] is not None:
        got = out["proposal"]["edge"]
        assert f"{got['source']}|{got['target']}|{got['kind']}" != key, "a skipped edge came back"
    print("  a skipped edge is not proposed again: PASS")


# --------------------------------------------------------------------------- #
# AO6 — SYNTHETIC end-to-end: the agent walks the sample domain to Domain Admin
# --------------------------------------------------------------------------- #
def _eng() -> EngagementRecord:
    return EngagementRecord(
        engagement_id="eng-adorch-e2e", target="dc01.sevenkingdoms.local", authorization="ok",
        active=True, entered_at="2026-07-25T00:00:00+00:00",
        scope="sevenkingdoms.local, dc01.sevenkingdoms.local",
        scope_include=["sevenkingdoms.local", "dc01.sevenkingdoms.local"],
        allowed_hosts=["dc01.sevenkingdoms.local"],
    )


def test_synthetic_walk_reaches_domain_admin_every_step_gated() -> None:
    """AO6. The agent proposes edge by edge over the SYNTHETIC collection until it reaches
    Domain Admins — and every runnable step it proposed is still refused by the executor when
    submitted unapproved. The reasoning is verified against synthetic data on purpose; the
    live run needs an AD lab and a human present."""
    g = _graph()
    goal = PA.default_high_value_target(g)
    st = O.AdState(owned=tuple(_start(g)))
    eng = _eng()
    orig = E.engagement.get_active
    E.engagement.get_active = lambda _id: eng  # type: ignore[assignment]

    sequence, refused, destructive = [], 0, 0
    try:
        with RoutingModel(g, goal):
            for _ in range(12):
                if st.is_owned(goal):
                    break
                out = O.propose_next(g, st, goal, _CFG)
                if out["done"] or out["proposal"] is None:
                    break
                p = out["proposal"]
                sequence.append(f"{p['edge']['source_label']} --{p['edge']['kind']}--> "
                                f"{p['edge']['target_label']}")
                if p["runnable"]:
                    # EVERY step, exactly as proposed, unapproved -> refused, nothing runs
                    rej = E.validate_request(ExecRequest(
                        command=p["command"], args=p["args"], approved=False,
                        engagement_id=eng.engagement_id))
                    assert rej is not None, f"unapproved step must be refused: {p['command']}"
                    refused += 1
                    if p["requires_confirm"]:
                        destructive += 1
                        # approved but NOT acked -> still refused, at the danger gate
                        rej2 = E.validate_request(ExecRequest(
                            command=p["command"], args=p["args"], approved=True,
                            engagement_id=eng.engagement_id))
                        assert rej2 is not None and rej2.gate == "danger", (
                            f"{p['command']} must demand the red confirm"
                        )
                # advance only as the UI would: after the step succeeded
                st = O.advance(st, p["edge"]["source"], p["edge"]["target"], p["edge"]["kind"])
    finally:
        E.engagement.get_active = orig

    assert st.is_owned(goal), (
        f"the agent did not reach {goal} over the synthetic graph; got: {sequence}"
    )
    assert refused == refused and refused > 0, "no runnable step was exercised"
    print(f"  SYNTHETIC E2E: agent reached Domain Admin in {len(sequence)} proposed steps; "
          f"all {refused} runnable steps refused unapproved, {destructive} demanded the red "
          "confirm: PASS")
    for s in sequence:
        print(f"      {s}")


# --------------------------------------------------------------------------- #
# the UI carries the same contract
# --------------------------------------------------------------------------- #
def test_the_ui_panel_has_no_batch_or_auto_run() -> None:
    """The frontend is where an 'approve all' button would plausibly get added, so the same
    claim is source-scanned there: one approval per step, and nothing that fires by itself."""
    panel = (Path(__file__).parent.parent / "frontend" / "src" / "components"
             / "CockpitADOrchestrator.tsx")
    if not panel.exists():  # backend-only checkout
        print("  (frontend not present — UI scan skipped)")
        return
    src = panel.read_text(encoding="utf-8")
    for tok in ("approveAll", "approve_all", "runAll", "run_all", "autoRun", "auto_run",
                "setInterval", "walkAll"):
        assert tok not in src, f"the AD orchestration panel must not contain {tok!r}"
    # `approved: true` appears exactly once in CODE. Comment lines are dropped first — the
    # header prose and the handler's own doc-comment both mention it, and a scan that counted
    # those would be asserting on documentation rather than on what the code does.
    def _is_comment(line: str) -> bool:
        return line.lstrip().startswith(("*", "/*", "//"))

    code_hits = [ln for ln in src.splitlines()
                 if "approved: true" in ln and not _is_comment(ln)]
    assert len(code_hits) == 1, f"approved:true must be set in exactly one place, got {code_hits}"
    # nothing may fire on its own — no effect hook in the panel at all
    assert "useEffect" not in src, "the panel must not run anything on mount"
    print("  the UI panel: one approval per step, no batch, nothing fires on its own: PASS")


if __name__ == "__main__":
    test_frontier_is_what_you_can_reach_next()
    test_advance_is_pure_and_idempotent()
    test_a_proposal_is_well_formed()
    test_proposal_exposes_a_native_windows_variant()
    test_a_pick_outside_the_candidate_list_is_refused()
    test_done_conditions()
    test_skipping_an_edge_removes_it_from_the_next_proposal()
    test_synthetic_walk_reaches_domain_admin_every_step_gated()
    test_the_ui_panel_has_no_batch_or_auto_run()
    print("ALL AD-orchestration tests pass")
