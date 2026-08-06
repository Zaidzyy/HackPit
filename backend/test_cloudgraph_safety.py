"""SAFETY INVARIANTS for cloud IAM orchestration — mirrors test_adorch_safety.py.

An agent DRAFTING cloud IAM abuse is different in kind from an agent drafting passive enumeration.
AttachRolePolicy grants a real principal AdministratorAccess. CreateAccessKey mints long-lived
credentials. UpdateFunctionCode overwrites production code. None of that is reversible by clicking
undo, which means "a human approves every single step" is carrying essentially the whole load.

The claims, tested rather than asserted in prose:

  1. THE AGENT PROPOSES, IT DOES NOT RUN. The cloud orchestrator has no process spawning, no path
     into the executor's run entrypoints, and no :kali path.
  2. IT CANNOT APPROVE. Nothing in it can set ``approved`` / ``dangerous_ack``; a proposal is data
     and the field does not appear in it.
  3. THE MODEL PICKS AN INDEX, NEVER A COMMAND. A pick outside the frontier is refused, not repaired.
  4. NEVER-AUTO-RUN. The exact proposal the agent produced, submitted unapproved, is REFUSED.
  5. NO SECOND EXECUTION PATH. Approval routes to the EXISTING gated executor; there is no run/batch
     endpoint here.
  6. ENUMERATION ADDS NO NEW GATE. The executing half (enumerate.py) reaches the SAME
     ``executor.validate_request`` BEFORE any spawn; its argv builders execute nothing; approval +
     red-confirm default FALSE; stop() is ungated.
  7. LAB MODE BYTE-FOR-BYTE UNCHANGED.

Hermetic: no Docker, no LLM, no network. Run:  python test_cloudgraph_safety.py
"""
from __future__ import annotations

import ast
import inspect
from pathlib import Path

from cloudgraph import enumerate as EN
from cloudgraph import orchestrator as O
from cloudgraph import parser as P
from cloudgraph import router as R
from cloudgraph import sample_data as S
from cloudgraph import schema as SC
from cloudgraph.schema import Edge
from cockpit import allowlist as A
from cockpit import executor as E
from cockpit.models import EngagementRecord, ExecRequest

_SRC = Path(O.__file__).read_text(encoding="utf-8")
_ROUTER_SRC = Path(R.__file__).read_text(encoding="utf-8")
_ENUM_SRC = Path(EN.__file__).read_text(encoding="utf-8")
_LAB = "hackpit-lab-target"


# --------------------------------------------------------------------------- #
# 1 + 2. the agent proposes; it cannot run and cannot approve
# --------------------------------------------------------------------------- #
def test_orchestrator_has_no_execution_path() -> None:
    banned = [
        "subprocess", "Popen", "os.system", "os.exec", "pty.spawn", "docker exec",
        "iter_run(", "run_command(", "run_kali", "KALI_OPEN", "/cockpit/kali",
    ]
    for tok in banned:
        assert tok not in _SRC, f"the cloud orchestrator must not reference {tok!r}"
    # AST: no call to subprocess/os.system anywhere in the module
    tree = ast.parse(_SRC)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = ast.dump(node.func)
            assert "subprocess" not in name and "system" not in name, f"exec-shaped call: {name}"
    print("  the cloud orchestrator has no execution path and no :kali path: PASS")


def test_orchestrator_cannot_approve() -> None:
    """It may READ the gates to pre-check a proposal; it must never be able to SATISFY one."""
    for tok in ("approved=True", "approved = True", "dangerous_ack=True", "dangerous_ack = True",
                "approved=req", "ExecRequest("):
        assert tok not in _SRC, f"the cloud orchestrator must not be able to set {tok!r}"
    g = P.parse_collection(S.sample_collection())
    edge = next(e for e in g.edges if e.kind == "AttachRolePolicy")
    prop = O.proposal_for_edge(g, edge, "why")
    for field in ("approved", "dangerous_ack", "run", "exec"):
        assert field not in prop, f"a proposal must not carry {field!r}"
    print("  the cloud orchestrator cannot set approved/dangerous_ack, and a proposal has no "
          "approval field: PASS")


def test_there_is_no_second_execution_path() -> None:
    routes = [r for r in _ROUTER_SRC.splitlines() if "@router." in r]
    orch = [r for r in routes if "orchestrate" in r]
    assert orch, "the orchestrate routes should exist"
    for r in orch:
        assert "/run" not in r and "/exec" not in r, f"orchestration must expose no run path: {r}"
    for tok in ("approve_all", "run_all", "run_path", "execute_path", "autorun", "auto_run"):
        assert tok not in _ROUTER_SRC and tok not in _SRC, f"no batch/auto affordance ({tok!r})"
    print("  no run endpoint, no batch, no approve-all — approval goes to the existing gated "
          "executor: PASS")


def test_proposer_cannot_resolve_an_engagement() -> None:
    for tok in ("get_active", "enter_engagement", "cockpit.engagement",
                "from cockpit import engagement"):
        assert tok not in _SRC, f"the cloud proposer must not reference {tok!r}"
    sig = inspect.signature(O.propose_next)
    assert "scope_ctx" in sig.parameters, "the scope context is HANDED IN, never resolved here"
    print("  the proposer is handed an inert scope context; it cannot resolve or enter one: PASS")


# --------------------------------------------------------------------------- #
# 3. the model picks an index, never a command
# --------------------------------------------------------------------------- #
def _stub_llm(json_str: str):
    orig = O.llm.chat
    O.llm.chat = lambda *a, **k: json_str  # type: ignore[assignment]
    return orig


def test_model_picks_an_index_never_a_command() -> None:
    g = P.parse_collection(S.sample_collection())
    state = O.CloudState(owned=(S.ALICE, S.DEVELOPERS, S.CI_DEPLOYER))
    cands = O.frontier(g, state)
    idx = next(i for i, e in enumerate(cands) if e.kind == "AttachRolePolicy")

    # a valid index resolves to the REAL edge's catalog command (the model authors nothing)
    orig = _stub_llm(f'{{"done": false, "pick": {idx}, "rationale": "x"}}')
    try:
        ok = O.propose_next(g, state, S.HIGH_VALUE_TARGET, {})
        # a pick outside the frontier is refused, not repaired
        O.llm.chat = lambda *a, **k: '{"done": false, "pick": 999, "rationale": "x"}'
        bad = O.propose_next(g, state, S.HIGH_VALUE_TARGET, {})
        # a command the model tries to smuggle in the JSON is simply ignored — there is no field
        # for it; only the index is read
        O.llm.chat = lambda *a, **k: '{"done": false, "pick": %d, "command": "rm -rf /", "rationale": "x"}' % idx
        smug = O.propose_next(g, state, S.HIGH_VALUE_TARGET, {})
    finally:
        O.llm.chat = orig
    assert ok["proposal"] and ok["proposal"]["command"] == "aws", ok
    assert bad["proposal"] is None and "invalid edge selection" in (bad["reason"] or ""), bad
    assert smug["proposal"]["command"] == "aws", "the model's command field is ignored"
    print("  the model returns an INDEX; an out-of-frontier pick is refused; a smuggled command "
          "field is ignored: PASS")


# --------------------------------------------------------------------------- #
# 4. NEVER-AUTO-RUN
# --------------------------------------------------------------------------- #
def _eng(scope: str, target: str) -> EngagementRecord:
    include = [p.strip() for p in scope.split(",") if not p.strip().startswith("!")]
    return EngagementRecord(
        engagement_id="eng-clg00000001", target=target, authorization="ok", active=True,
        entered_at="2026-08-06T00:00:00+00:00", scope=scope, scope_include=include,
        allowed_hosts=[target],
    )


def _patch(rec):
    orig = E.engagement.get_active
    E.engagement.get_active = lambda _id: rec  # type: ignore[assignment]
    return orig


def test_a_proposed_cloud_step_runs_nothing_unapproved() -> None:
    g = P.parse_collection(S.sample_collection())
    edge = next(e for e in g.edges if e.kind == "AttachRolePolicy")
    prop = O.proposal_for_edge(g, edge, "grants admin")
    assert prop["command"], "this edge should resolve to a real command"

    eng = _eng("123456789012, aws", "123456789012")
    orig = _patch(eng)
    try:
        req = ExecRequest(command=prop["command"], args=prop["args"], approved=False,
                          engagement_id=eng.engagement_id)
        rej = E.validate_request(req)
        assert rej is not None, "an unapproved cloud abuse step must be REFUSED"
        assert rej.gate in ("approval", "danger", "target"), rej
        print(f"  a proposed cloud step submitted unapproved is refused at the {rej.gate} "
              "gate — nothing runs: PASS")
    finally:
        E.engagement.get_active = orig


def test_proposal_is_argv_only() -> None:
    g = P.parse_collection(S.sample_collection())
    for e in g.edges:
        prop = O.proposal_for_edge(g, e, "")
        if not prop["runnable"]:
            continue
        assert isinstance(prop["command"], str) and " " not in prop["command"], prop["command"]
        assert isinstance(prop["args"], list)
        assert all(isinstance(a, str) for a in prop["args"])
        for shell_char in ("|", ">", "<", "&&", ";"):
            assert shell_char not in prop["command"], f"shell metachar in program: {prop}"
    print("  every proposal is argv-only — a program plus a token list: PASS")


def test_agent_cannot_advance_the_graph_by_itself() -> None:
    src_propose = inspect.getsource(O.propose_next)
    assert "advance(" not in src_propose, "propose_next must never advance the walk"
    st = O.CloudState(owned=("a",))
    st2 = O.advance(st, "a", "b", "AttachRolePolicy")
    assert st.owned == ("a",), "advance must not mutate the state it was given"
    assert st2.owned == ("a", "b")
    print("  the agent cannot advance the walk itself; advance() is pure and separate: PASS")


def test_advance_endpoint_is_evidence_gated_in_source() -> None:
    """The advance route ties advancement to an APPROVED, exit-0 run (the behavioural proof is in
    test_cloudgraph.py; this pins the guard in source so it cannot be quietly removed)."""
    src = inspect.getsource(R.cloud_orchestrate_advance)
    assert 'getattr(run, "approved"' in src, "advance must check the run was approved"
    assert "run.exit_code != 0" in src, "advance must check the run exited 0"
    print("  advance is evidence-gated: it requires an approved, exit-0 run: PASS")


def test_inherited_rights_edge_never_acquires_a_command() -> None:
    """A ``no_command`` edge (MemberOf) stays note-only EVEN WITH a grounder that offers a command
    — the KB may explain the edge, it may not manufacture an action for one that has none."""
    from cloudgraph import techniques as T

    g = P.parse_collection(S.sample_collection())

    def loud_grounder(_seeds: str) -> dict:
        return {"id": "ht-cloud-1", "title": "Some IAM abuse",
                "commands": [{"lang": "bash", "cmd": "aws iam attach-user-policy --user-name x"}]}

    assert T._CATALOG["MemberOf"].no_command, "MemberOf must be marked no_command"
    edge = Edge(source="a", target="b", kind="MemberOf")
    tech = T.technique_for_edge(edge, g, loud_grounder)
    cmds = [c.get("cmd", "") for c in tech.get("commands") or []]
    assert all(c.strip().startswith("#") for c in cmds), f"MemberOf must stay prose, got {cmds!r}"
    assert tech.get("entry_id") == "ht-cloud-1", "the KB citation is retained"
    prop = O.proposal_for_edge(g, edge, "why", loud_grounder)
    assert prop["resolution"] == "note-only" and prop["runnable"] is False, prop

    # POSITIVE CONTROL: an actionable edge still takes the grounder's command
    edge2 = Edge(source="a", target="b", kind="AttachUserPolicy")
    tech2 = T.technique_for_edge(edge2, g, loud_grounder)
    assert any("attach-user-policy" in (c.get("cmd") or "") for c in tech2["commands"]), tech2
    print("  inherited-rights edges never acquire a command, even from the KB grounder: PASS")


# --------------------------------------------------------------------------- #
# 6. ENUMERATION (the executing half) — no new gate
# --------------------------------------------------------------------------- #
def test_enumerate_argv_builders_execute_nothing() -> None:
    """The pure half — the ``*_argv`` builders + ``validate`` — must build argv and run NOTHING.
    AST-walk each: no call whose name touches subprocess / Popen / os.system / docker exec."""
    tree = ast.parse(_ENUM_SRC)
    pure = {"scoutsuite_argv", "prowler_argv", "cloudfox_argv", "pacu_argv", "_argv_for", "validate"}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name in pure:
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call):
                    dump = ast.dump(sub.func)
                    assert "subprocess" not in dump and "Popen" not in dump and "system" not in dump, (
                        f"{node.name} must execute nothing, found {dump}"
                    )
    print("  the enumeration argv builders + validate execute nothing (AST): PASS")


def test_enumerate_gates_before_any_spawn() -> None:
    """``start`` reaches ``_gate`` BEFORE anything spawns; the only ``subprocess`` in the module is
    in the worker, reached only after the gate."""
    start_src = inspect.getsource(EN.start)
    assert "_gate(" in start_src, "start must gate the sweep"
    assert "subprocess" not in start_src and "_spawn(" not in start_src, (
        "start must not spawn — spawning happens in the worker, after the gate"
    )
    # approval + red-confirm default FALSE so an omitted field is refused, not granted
    req = EN.CloudEnumRequest()
    assert req.approved is False and req.dangerous_ack is False, req
    print("  enumeration gates before any spawn; approval + red-confirm default FALSE: PASS")


def test_enumerate_is_engagement_bound_and_stop_is_ungated() -> None:
    # no active engagement -> refused, nothing spawns
    orig = EN.engagement.get_active
    EN.engagement.get_active = lambda _id: None  # type: ignore[assignment]
    try:
        try:
            EN.start(EN.CloudEnumRequest(provider="aws", approved=True, engagement_id=None))
            assert False, "enumeration with no engagement must be refused"
        except EN.CloudEnumRefused as exc:
            assert exc.gate == "engagement", exc.gate
    finally:
        EN.engagement.get_active = orig
    # stop is the panic button — ungated, and its source calls no gate
    assert EN.stop("no-such-job") is None
    stop_src = inspect.getsource(EN.stop)
    assert "_gate(" not in stop_src and "validate_request" not in stop_src, "stop must be ungated"
    print("  enumeration is engagement-bound (no engagement -> refused); stop() is ungated: PASS")


# --------------------------------------------------------------------------- #
# 7. lab unchanged
# --------------------------------------------------------------------------- #
def test_lab_mode_unchanged() -> None:
    ok, _ = E.check_target_lock(["-sV", _LAB], "nmap")
    assert ok
    ok, reason = E.check_target_lock(["-sV", "dc01.sevenkingdoms.local"], "nmap")
    assert not ok and reason == (
        "target 'dc01.sevenkingdoms.local' is not the lab — only the lab is allowed"
    )
    rej = E.validate_request(ExecRequest(command="nmap", args=["-sV", _LAB], approved=False))
    assert rej is not None and rej.gate == "approval"
    print("  LAB target-lock wording + gate order byte-for-byte unchanged: PASS")


if __name__ == "__main__":
    test_orchestrator_has_no_execution_path()
    test_orchestrator_cannot_approve()
    test_there_is_no_second_execution_path()
    test_proposer_cannot_resolve_an_engagement()
    test_model_picks_an_index_never_a_command()
    test_a_proposed_cloud_step_runs_nothing_unapproved()
    test_proposal_is_argv_only()
    test_agent_cannot_advance_the_graph_by_itself()
    test_advance_endpoint_is_evidence_gated_in_source()
    test_inherited_rights_edge_never_acquires_a_command()
    test_enumerate_argv_builders_execute_nothing()
    test_enumerate_gates_before_any_spawn()
    test_enumerate_is_engagement_bound_and_stop_is_ungated()
    test_lab_mode_unchanged()
    print("ALL cloud-graph safety-invariant tests pass")
