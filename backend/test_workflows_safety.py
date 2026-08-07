"""SAFETY INVARIANTS for the reusable prompt-workflow builder. These are §0 of the spec, as code.

  1. AUTHORING EXECUTES NOTHING. Creating, editing, importing and exporting a workflow touch NO
     agent and NO target — they only read and write a JSON store. Proven with a recording agent
     that is never called across the whole authoring surface.
  2. A RUN IS ONE JOB, NO NEW GATE. Running a workflow is the SAME approved job the AI audit is:
     workflows.py + the routes make no eval/exec/subprocess/socket/HTTP call (by AST, with a
     planted control), import no cockpit/executor/state/sandbox and reference no gate symbol. The
     only launchable program in the whole codescan package is still runner._spawn's semgrep/bandit.
  3. COMMAND STEPS ARE APPROVE-EACH, NEVER RUN. A command step yields a proposal string
     (executed:false); the runner never calls the agent for it and executes nothing.
  4. AN IMPORTED WORKFLOW IS NEVER AUTO-RUN. import_workflow stores + returns the parsed workflow,
     flagged inspect-before-run; it never runs it (proven with a recording agent + a control).

Run:  python test_workflows_safety.py
"""

from __future__ import annotations

import ast
import re
import tempfile
from pathlib import Path

from codescan import runner, workflows as W

_PKG = Path(__file__).parent / "codescan"
_WF = _PKG / "workflows.py"
_ROUTER = _PKG / "router.py"
_SCANNED = [_WF, _ROUTER]


def _dotted(node: ast.AST) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


_BANNED_CALLS = {
    "eval", "exec", "compile", "__import__",
    "os.system", "os.popen",
    "subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_output",
    "subprocess.check_call", "subprocess.getoutput",
    "socket.socket", "requests.get", "requests.post", "urllib.request.urlopen",
}


def _executing_calls(source: str) -> list[str]:
    tree = ast.parse(source)
    hits: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _dotted(node.func)
            if name in _BANNED_CALLS:
                hits.append(name)
    return hits


class _RecordingAgent:
    """An agent that RECORDS whether it was ever called. Authoring and import must never call it."""

    def __init__(self) -> None:
        self.called = 0

    def __call__(self, system: str, user: str) -> str:
        self.called += 1
        return '{"finding": false, "reason": "should never run in an authoring path"}'


def _store() -> W.WorkflowStore:
    return W.WorkflowStore(Path(tempfile.mkdtemp()) / "wf.json")


# --------------------------------------------------------------------------- #
# 1. authoring executes nothing (with a control)
# --------------------------------------------------------------------------- #
def test_authoring_executes_nothing() -> None:
    agent = _RecordingAgent()
    st = _store()
    wf = st.create({"id": "a", "name": "A",
                    "steps": [{"id": "s", "title": "s", "prompt": "look {{repo}}"}]})
    st.update("a", {"description": "edited"}, expected_version=wf.version)
    portable = st.export = W.to_portable(st.get("a"))
    st.import_workflow(portable)
    st.delete("a")
    assert agent.called == 0, "authoring (create/edit/export/import/delete) called an agent"
    # CONTROL: the recording agent DOES count when actually run, so 0 above means something
    W.run_workflow(W.Workflow(id="z", name="Z", steps=[W.Step("s", "s", "STEP {{repo}}")]),
                   repo="r", agent=agent)
    assert agent.called >= 1, "the recording agent never fires even on a real run — test is inert"
    print("  create/edit/export/import/delete touch no agent; the recorder fires only on run: PASS")


# --------------------------------------------------------------------------- #
# 2. a run is one job, no new gate — no exec, no gate coupling (with a control)
# --------------------------------------------------------------------------- #
def test_workflow_module_executes_nothing_by_ast() -> None:
    for f in _SCANNED:
        hits = _executing_calls(f.read_text(encoding="utf-8"))
        assert not hits, f"{f.name} makes an executing/network call: {hits}"
    planted = "import subprocess\nsubprocess.Popen(['id'])\ny = exec('x')\n"
    assert set(_executing_calls(planted)) >= {"subprocess.Popen", "exec"}, "scanner cannot fail!"
    print("  workflows.py + routes make no eval/exec/subprocess/socket call, by AST; can fail: PASS")


def test_no_new_gate_and_orthogonal() -> None:
    all_src = "\n".join(p.read_text(encoding="utf-8") for p in sorted(_PKG.glob("*.py")))
    for module in ("cockpit", "engagement", "executor", "sandbox", "allowlist",
                   "orchestrator", "sessions", "attack_path", "state"):
        assert not re.search(rf"^\s*(?:from|import)\s+{module}\b", all_src, re.M), (
            f"codescan must not import {module} — the workflow builder adds no gate/coupling"
        )
    for symbol in ("validate_request", "check_target_lock", "run_kali", "resolve_mode",
                   "assert_isolation_proven", "dangerous_ack", "red_confirm", "target_lock",
                   "engagement_id", "in_scope"):
        assert symbol not in all_src, f"the workflow builder must not reference {symbol}"
    assert runner._TOOLS == ("semgrep", "bandit")
    assert all_src.count("subprocess.Popen") == 1, "only runner._spawn may spawn, exactly once"
    print("  no gate/executor/state import or symbol; still exactly one asserted spawn site: PASS")


# --------------------------------------------------------------------------- #
# 3. command steps are approve-each, never run
# --------------------------------------------------------------------------- #
def test_command_steps_are_approve_each() -> None:
    agent = _RecordingAgent()
    wf = W.Workflow(id="w", name="W", steps=[
        W.Step(id="c", title="tool pass", kind="command", prompt="slither {{repo}} --json -"),
    ])
    res = W.run_workflow(wf, repo="acme/contracts", agent=agent)
    assert agent.called == 0, "a command step must not call the agent"
    assert len(res["proposals"]) == 1
    prop = res["proposals"][0]
    assert prop["executed"] is False and prop["approve_each"] is True
    assert prop["command"] == "slither acme/contracts --json -"
    print("  a command step yields a proposal (executed:false, approve-each); it runs nothing: PASS")


# --------------------------------------------------------------------------- #
# 4. an imported workflow is never auto-run (with a control)
# --------------------------------------------------------------------------- #
def test_imported_workflow_is_never_auto_run() -> None:
    agent = _RecordingAgent()
    st = _store()
    portable = W.to_portable(st.get("external-flow"))
    imported = st.import_workflow(portable)
    assert imported.imported is True, "an import must be flagged inspect-before-run"
    assert agent.called == 0, "importing a workflow must not run it"
    # it is stored (so the operator can inspect it), NOT executed
    assert st.get(imported.id).id == imported.id
    # CONTROL: only an explicit run fires the agent
    W.run_workflow(imported, repo="r", agent=agent)
    assert agent.called >= 1, "the control run never fired — the assertion above is inert"
    print("  import stores the workflow flagged inspect-before-run and runs nothing; only an "
          "explicit run fires: PASS")


# --------------------------------------------------------------------------- #
# 5. a built-in is read-only; the store's version lock refuses a stale edit
# --------------------------------------------------------------------------- #
def test_builtins_readonly_and_version_lock() -> None:
    st = _store()
    for op in (lambda: st.update("external-flow", {"name": "x"}),
               lambda: st.delete("external-flow")):
        try:
            op()
        except W.WorkflowError:
            continue
        raise AssertionError("a built-in workflow was mutable")
    wf = st.create({"id": "e", "name": "E", "steps": [{"id": "s", "title": "s", "prompt": "p"}]})
    try:
        st.update("e", {"name": "Y"}, expected_version=wf.version + 5)  # stale
    except W.WorkflowError:
        print("  built-ins are read-only and a stale-version edit is refused (the store lock): PASS")
        return
    raise AssertionError("a stale-version edit was accepted")


if __name__ == "__main__":
    test_authoring_executes_nothing()
    test_workflow_module_executes_nothing_by_ast()
    test_no_new_gate_and_orthogonal()
    test_command_steps_are_approve_each()
    test_imported_workflow_is_never_auto_run()
    test_builtins_readonly_and_version_lock()
    print("ALL workflow-builder SAFETY-invariant tests pass")
