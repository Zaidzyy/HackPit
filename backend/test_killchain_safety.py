"""SAFETY INVARIANTS for the cross-domain kill-chain overlay — mirrors test_cloudgraph_safety.py.

The kill-chain overlay stitches three lanes into one routed chain. A chain that crosses
web→cloud→on-prem is real lateral movement, and each hop through the executor is approved
individually — so the same load the per-lane graphs carry, this overlay carries too, plus one more
claim unique to a read-and-stitch overlay: it must stay DECOUPLED from the two graph packages it
stitches (it reads their PUBLIC DICTS, never their internals).

The claims, tested rather than asserted in prose:

  1. THE AGENT PROPOSES, IT DOES NOT RUN. The orchestrator + service have no process spawning, no
     path into the executor's run entrypoints, and no :kali path (AST + token scan, with a control).
  2. IT CANNOT APPROVE. Nothing can set ``approved`` / ``dangerous_ack``; a proposal has no such field.
  3. THE MODEL PICKS AN INDEX, NEVER A COMMAND. A pick outside the frontier is refused, not repaired;
     a smuggled command field is ignored.
  4. NEVER-AUTO-RUN. The exact proposal, submitted unapproved, is REFUSED by the existing gate.
  5. NO SECOND EXECUTION PATH. Advance is evidence-gated (approved + exit-0); the routes expose no
     run/batch path; approval routes to the EXISTING gated executor.
  6. THE OVERLAY IS A READ-AND-STITCH OVERLAY: it imports NEITHER adgraph NOR cloudgraph (decoupling
     preserved — it consumes public dicts), and every killchain module executes nothing (AST).
  7. LAB MODE BYTE-FOR-BYTE UNCHANGED.

Hermetic: no Docker, no LLM, no network. Run:  python test_killchain_safety.py
"""
from __future__ import annotations

import ast
import inspect
from pathlib import Path

from killchain import bridges as B
from killchain import merge as M
from killchain import orchestrator as O
from killchain import paths as PA
from killchain import sample_data as S
from killchain import schema as SC
from killchain import service as SV
from cockpit import allowlist as A  # noqa: F401  (imported to prove it is only READ, below)
from cockpit import executor as E
from cockpit.models import EngagementRecord, ExecRequest

_PKG_DIR = Path(O.__file__).parent
_ORCH_SRC = Path(O.__file__).read_text(encoding="utf-8")
_SVC_SRC = Path(SV.__file__).read_text(encoding="utf-8")
_LAB = "hackpit-lab-target"

# The kill-chain routes live in main.py (the cross-cutting join over both stores). Read the source
# and AST-parse it so we can scan those three handlers without importing/booting the whole app.
_MAIN_PATH = Path("main.py")
_MAIN_SRC = _MAIN_PATH.read_text(encoding="utf-8") if _MAIN_PATH.exists() else ""
_KC_ROUTE_NAMES = {"killchain_graph", "killchain_propose", "killchain_advance"}


def _killchain_route_defs() -> list[ast.FunctionDef]:
    tree = ast.parse(_MAIN_SRC)
    return [n for n in ast.walk(tree)
            if isinstance(n, ast.FunctionDef) and n.name in _KC_ROUTE_NAMES]


# --------------------------------------------------------------------------- #
# 1 + 2. the agent proposes; it cannot run and cannot approve
# --------------------------------------------------------------------------- #
def test_orchestrator_and_service_have_no_execution_path() -> None:
    banned = ["subprocess", "Popen", "os.system", "os.exec", "pty.spawn", "docker exec",
              "iter_run(", "run_command(", "run_kali", "KALI_OPEN", "/cockpit/kali"]
    for src, name in ((_ORCH_SRC, "orchestrator"), (_SVC_SRC, "service")):
        for tok in banned:
            assert tok not in src, f"the kill-chain {name} must not reference {tok!r}"
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                dump = ast.dump(node.func)
                assert "subprocess" not in dump and "system" not in dump, f"exec-shaped call: {dump}"
    print("  the kill-chain orchestrator + service have no execution path and no :kali path: PASS")


def test_orchestrator_cannot_approve() -> None:
    for tok in ("approved=True", "approved = True", "dangerous_ack=True", "dangerous_ack = True",
                "approved=req", "ExecRequest("):
        assert tok not in _ORCH_SRC and tok not in _SVC_SRC, f"must not be able to set {tok!r}"
    g = S.sample_graph()
    edge = next(e for e in g.edges if e.kind == "CloudToOnprem")
    prop = O.proposal_for_edge(g, edge, "why")
    for field in ("approved", "dangerous_ack", "run", "exec"):
        assert field not in prop, f"a proposal must not carry {field!r}"
    print("  the kill-chain proposer cannot set approved/dangerous_ack, and a proposal has no "
          "approval field: PASS")


# --------------------------------------------------------------------------- #
# 3. the model picks an index, never a command
# --------------------------------------------------------------------------- #
def _stub_llm(json_str: str):
    orig = O.llm.chat
    O.llm.chat = lambda *a, **k: json_str  # type: ignore[assignment]
    return orig


def test_model_picks_an_index_never_a_command() -> None:
    g = S.sample_graph()
    state = O.KillchainState(owned=(S.OWNED_START,))
    cands = O.frontier(g, state)
    idx = next(i for i, e in enumerate(cands) if e.kind == "SsrfToImds")

    orig = _stub_llm(f'{{"done": false, "pick": {idx}, "rationale": "x"}}')
    try:
        ok = O.propose_next(g, state, S.HIGH_VALUE_TARGET, {})
        O.llm.chat = lambda *a, **k: '{"done": false, "pick": 999, "rationale": "x"}'
        bad = O.propose_next(g, state, S.HIGH_VALUE_TARGET, {})
        O.llm.chat = lambda *a, **k: '{"done": false, "pick": %d, "command": "rm -rf /", "rationale": "x"}' % idx
        smug = O.propose_next(g, state, S.HIGH_VALUE_TARGET, {})
    finally:
        O.llm.chat = orig
    assert ok["proposal"] and ok["proposal"]["command"] == "curl", ok
    assert bad["proposal"] is None and "invalid edge selection" in (bad["reason"] or ""), bad
    assert smug["proposal"]["command"] == "curl", "the model's command field is ignored"
    print("  the model returns an INDEX; an out-of-frontier pick is refused; a smuggled command "
          "field is ignored: PASS")


# --------------------------------------------------------------------------- #
# 4. NEVER-AUTO-RUN
# --------------------------------------------------------------------------- #
def _eng(scope: str, target: str) -> EngagementRecord:
    include = [p.strip() for p in scope.split(",") if not p.strip().startswith("!")]
    return EngagementRecord(
        engagement_id="eng-kc000000001", target=target, authorization="ok", active=True,
        entered_at="2026-08-08T00:00:00+00:00", scope=scope, scope_include=include,
        allowed_hosts=[target],
    )


def test_a_proposed_seam_step_runs_nothing_unapproved() -> None:
    g = S.sample_graph()
    edge = next(e for e in g.edges if e.kind == "CloudToOnprem")
    prop = O.proposal_for_edge(g, edge, "secret reuse")
    assert prop["runnable"] and prop["command"], "the CloudToOnprem seam should resolve to a command"

    eng = _eng(f"{S.DC_HOST}", S.DC_HOST)
    orig = E.engagement.get_active
    E.engagement.get_active = lambda _id: eng  # type: ignore[assignment]
    try:
        req = ExecRequest(command=prop["command"], args=prop["args"], approved=False,
                          engagement_id=eng.engagement_id)
        rej = E.validate_request(req)
        assert rej is not None, "an unapproved cross-domain step must be REFUSED"
        assert rej.gate in ("approval", "danger", "target"), rej
        print(f"  a proposed seam step submitted unapproved is refused at the {rej.gate} gate — "
              "nothing runs: PASS")
    finally:
        E.engagement.get_active = orig


def test_proposal_is_argv_only() -> None:
    g = S.sample_graph()
    for e in g.edges:
        prop = O.proposal_for_edge(g, e, "")
        if not prop["runnable"]:
            continue
        assert isinstance(prop["command"], str) and " " not in prop["command"], prop["command"]
        assert isinstance(prop["args"], list) and all(isinstance(a, str) for a in prop["args"])
        for shell_char in ("|", ">", "<", "&&", ";"):
            assert shell_char not in prop["command"], f"shell metachar in program: {prop}"
    print("  every runnable proposal is argv-only — a program plus a token list: PASS")


def test_agent_cannot_advance_the_graph_by_itself() -> None:
    src_propose = inspect.getsource(O.propose_next)
    assert "advance(" not in src_propose, "propose_next must never advance the chain"
    st = O.KillchainState(owned=("a",))
    st2 = O.advance(st, "a", "b", "SsrfToImds")
    assert st.owned == ("a",), "advance must not mutate the state it was given"
    assert st2.owned == ("a", "b")
    print("  the agent cannot advance the chain itself; advance() is pure and separate: PASS")


# --------------------------------------------------------------------------- #
# 5. no second execution path — advance is evidence-gated; routes expose no run path
# --------------------------------------------------------------------------- #
def test_advance_is_evidence_gated_in_source() -> None:
    src = inspect.getsource(SV.advance_step)
    assert 'getattr(run, "approved"' in src, "advance must check the run was approved"
    assert "exit_code" in src and "!= 0" in src, "advance must check the run exited 0"
    print("  advance is evidence-gated: a runnable seam requires an approved, exit-0 run: PASS")


def test_routes_expose_no_run_or_batch_path() -> None:
    defs = _killchain_route_defs()
    assert defs, "the three killchain_* routes must exist in main.py"
    assert {d.name for d in defs} == _KC_ROUTE_NAMES, {d.name for d in defs}
    for d in defs:
        for node in ast.walk(d):
            if isinstance(node, ast.Call):
                dump = ast.dump(node.func)
                assert "subprocess" not in dump and "system" not in dump and "Popen" not in dump, (
                    f"a killchain route must execute nothing, found {dump} in {d.name}"
                )
    for tok in ("approve_all", "run_all", "run_path", "execute_path", "autorun", "auto_run"):
        assert tok not in _ORCH_SRC and tok not in _SVC_SRC, f"no batch/auto affordance ({tok!r})"
    print("  the three routes execute nothing (AST) and expose no run/batch/approve-all path: PASS")


# --------------------------------------------------------------------------- #
# 6. read-and-stitch: imports no graph internals; executes nothing
# --------------------------------------------------------------------------- #
def test_overlay_imports_no_graph_internals() -> None:
    """The DECOUPLING invariant: NO killchain module may import adgraph or cloudgraph — the overlay
    consumes each graph's PUBLIC DICT (handed in by the app layer), never their internals. This is
    what keeps the two graph packages independent of one another AND of the overlay."""
    offenders: list[str] = []
    for py in sorted(_PKG_DIR.glob("*.py")):
        tree = ast.parse(py.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.name.split(".")[0] in ("adgraph", "cloudgraph"):
                        offenders.append(f"{py.name}: import {a.name}")
            elif isinstance(node, ast.ImportFrom):
                if (node.module or "").split(".")[0] in ("adgraph", "cloudgraph"):
                    offenders.append(f"{py.name}: from {node.module} import ...")
    assert not offenders, f"the overlay must not import a graph package's internals: {offenders}"
    print("  read-and-stitch: no killchain module imports adgraph or cloudgraph (decoupling "
          "preserved — public dicts only): PASS")


def test_every_overlay_module_executes_nothing() -> None:
    """AST: no killchain module makes an exec-/network-shaped call or imports one. The orchestrator
    legitimately imports cockpit.executor/allowlist + llm (it READS the gate + heuristic + the
    model), so the check is on CALLS (subprocess/os.system/socket/eval/exec/compile) and dangerous
    IMPORTS, not on referencing the gate module."""
    banned_import_roots = {"subprocess", "socket", "requests", "http", "httpx", "ftplib",
                           "telnetlib", "asyncio"}
    banned_call_tokens = ("subprocess", "system", "Popen", "urlopen", "'connect'",
                          "socket", "os.exec", "os.popen", "run_kali", "eval", "compile")
    # a POSITIVE CONTROL: prove the scanner catches a planted violation
    planted = "import subprocess\nsubprocess.Popen(['x'])\n"
    ptree = ast.parse(planted)
    caught = any(isinstance(n, ast.Call) and "Popen" in ast.dump(n.func) for n in ast.walk(ptree))
    assert caught, "the AST scanner must catch a planted subprocess.Popen — it does not"

    for py in sorted(_PKG_DIR.glob("*.py")):
        tree = ast.parse(py.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    assert a.name.split(".")[0] not in banned_import_roots, f"{py.name}: import {a.name}"
            elif isinstance(node, ast.ImportFrom):
                assert (node.module or "").split(".")[0] not in banned_import_roots, \
                    f"{py.name}: from {node.module}"
            elif isinstance(node, ast.Call):
                dump = ast.dump(node.func)
                for tok in banned_call_tokens:
                    tok_clean = tok.strip("'")
                    assert tok_clean not in dump, f"{py.name}: {tok!r}-shaped call: {dump}"
    print("  every overlay module executes nothing (AST, with a positive control): PASS")


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
    test_orchestrator_and_service_have_no_execution_path()
    test_orchestrator_cannot_approve()
    test_model_picks_an_index_never_a_command()
    test_a_proposed_seam_step_runs_nothing_unapproved()
    test_proposal_is_argv_only()
    test_agent_cannot_advance_the_graph_by_itself()
    test_advance_is_evidence_gated_in_source()
    test_routes_expose_no_run_or_batch_path()
    test_overlay_imports_no_graph_internals()
    test_every_overlay_module_executes_nothing()
    test_lab_mode_unchanged()
    print("ALL kill-chain safety-invariant tests pass")
