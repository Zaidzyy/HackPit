"""SAFETY INVARIANTS for engagement governance. These are §0 of the spec, as code.

  1. GOVERNANCE EXECUTES NOTHING. state/governance.py + state/killchain.py + governance_draft.py
     make no eval/exec/compile-builtin, no subprocess, no os.system/popen, no socket/HTTP of their
     own — by AST, WITH A CONTROL that plants a violation (so a green result means something).
     The drafter's ONLY power is the LLM call (llm.chat) — the same generative call attack_path.py
     makes — never a command it runs.
  2. NO NEW GATE. Governance is authored + human-approved documentation plus a formalised scope
     frame. state/governance.py + governance_draft.py import NOTHING from cockpit / the executor /
     the sandbox / the orchestrator, and reference NO gate symbol. The RoE-vs-scope check is
     ADVISORY and lives in the app layer; it can only flag, never block.
  3. GENERATION IS PROPOSE-ONLY. The drafter returns plain dicts — it PERSISTS nothing and ADVANCES
     no objective. It never calls save_doc / approve_doc / add_objective / update_objective; those
     are the human-driven route's job, after the human reviews the draft.
  4. THE RoE IS A FRAME, NOT A VETO. The state machine governs OBJECTIVE status only — nothing in
     governance can refuse, gate, or halt a command. Human approval stays the bound.

Run:  python test_governance_safety.py
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

_BACKEND = Path(__file__).parent
_GOV = _BACKEND / "state" / "governance.py"
_KILLCHAIN = _BACKEND / "state" / "killchain.py"
_DRAFT = _BACKEND / "governance_draft.py"
_DATA_MODULES = [_GOV, _KILLCHAIN]          # pure data — no LLM call at all
_ALL_MODULES = [_GOV, _KILLCHAIN, _DRAFT]


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
    "socket.socket", "requests.get", "requests.post", "requests.request",
    "urllib.request.urlopen",
}


def _executing_calls(source: str) -> list[str]:
    tree = ast.parse(source)
    return [
        _dotted(node.func)
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and _dotted(node.func) in _BANNED_CALLS
    ]


# --------------------------------------------------------------------------- #
# 1. governance executes nothing (with a control)
# --------------------------------------------------------------------------- #
def test_governance_executes_nothing_by_ast() -> None:
    for f in _ALL_MODULES:
        hits = _executing_calls(f.read_text(encoding="utf-8"))
        assert not hits, f"{f.name} makes an executing/network call: {hits}"
    # CONTROL: the scanner catches a planted violation
    planted = "import subprocess\nsubprocess.run(['id'])\nx = eval('1')\n"
    assert set(_executing_calls(planted)) >= {"subprocess.run", "eval"}, "scanner cannot fail!"
    print("  governance + killchain + drafter make no eval/exec/subprocess/socket call, by AST; scanner can fail: PASS")


def test_the_pure_modules_import_nothing_that_executes() -> None:
    """state/governance.py + state/killchain.py are inside the executes-nothing state package:
    no subprocess/socket/network import at all (yaml.safe_load reads a bundled file only)."""
    banned = {"subprocess", "socket", "requests", "httpx", "urllib", "docker", "pty", "ctypes"}
    for f in _DATA_MODULES:
        tree = ast.parse(f.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name.split(".")[0] not in banned, f"{f.name} imports {alias.name}"
            elif isinstance(node, ast.ImportFrom):
                assert (node.module or "").split(".")[0] not in banned, f"{f.name} imports from {node.module}"
    print("  the pure governance data modules import nothing that executes or reaches the network: PASS")


def test_the_drafter_power_is_the_llm_not_execution() -> None:
    """governance_draft's only side effect is the LLM call (llm.chat) — the same generative call
    attack_path.py makes. Power from generating, never from running a command."""
    src = _DRAFT.read_text(encoding="utf-8")
    assert re.search(r"\bllm\.chat\s*\(", src), "the drafter must call the LLM layer (llm.chat)"
    assert "extract_json" in src, "the drafter parses via the LLM layer (llm.extract_json)"
    print("  the drafter's only power is the LLM call (llm.chat / extract_json), not execution: PASS")


# --------------------------------------------------------------------------- #
# 2. no new gate — no gate import, no gate symbol
# --------------------------------------------------------------------------- #
def test_no_new_gate_no_gate_import_or_symbol() -> None:
    for f in _ALL_MODULES:
        src = f.read_text(encoding="utf-8")
        for module in ("cockpit", "executor", "sandbox", "allowlist", "orchestrator"):
            assert not re.search(rf"^\s*(?:from|import)\s+{module}\b", src, re.M), (
                f"{f.name} imports {module} — governance adds no gate and no executor coupling"
            )
        for symbol in ("validate_request", "check_target_lock", "run_kali", "resolve_mode",
                       "assert_isolation_proven", "dangerous_ack", "red_confirm", "_gate"):
            assert symbol not in src, f"{f.name} references the gate symbol {symbol}"
    print("  governance + drafter import no cockpit/executor/sandbox and name no gate symbol: PASS")


# --------------------------------------------------------------------------- #
# 3. generation is propose-only — the drafter persists nothing, advances nothing
# --------------------------------------------------------------------------- #
def test_drafter_is_propose_only() -> None:
    """The drafter must not persist or advance anything: no save_doc / approve_doc /
    add_objective / update_objective / expand / collapse / delete call in its source. Those are
    the human-driven route's job, AFTER the human reviews the propose-only draft."""
    tree = ast.parse(_DRAFT.read_text(encoding="utf-8"))
    persisting = {
        "save_doc", "approve_doc", "add_objective", "update_objective",
        "expand_objective", "collapse_objective", "delete_objective",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _dotted(node.func)
            leaf = name.split(".")[-1]
            assert leaf not in persisting, f"the drafter calls a persisting function {name} — it must propose only"
    print("  the drafter persists nothing and advances no objective — propose-only, by AST: PASS")


# --------------------------------------------------------------------------- #
# 4. the RoE is a frame, not a veto — the state machine governs status, not commands
# --------------------------------------------------------------------------- #
def test_state_machine_governs_objective_status_only() -> None:
    """The only thing the transition table governs is an OBJECTIVE's status. There is no path by
    which governance refuses, gates, or halts a COMMAND — that would make the RoE a machine veto,
    which the standing model forbids (human approval is the bound)."""
    from state import governance as gov

    # the transition table's keys/values are all objective statuses — nothing command-shaped
    for src, targets in gov._VALID_TRANSITIONS.items():
        assert src in gov.OBJECTIVE_STATUSES
        assert all(t in gov.OBJECTIVE_STATUSES for t in targets)
    # completed + cancelled are terminal (no outgoing transitions)
    assert gov._VALID_TRANSITIONS[gov.STATUS_COMPLETED] == frozenset()
    assert gov._VALID_TRANSITIONS[gov.STATUS_CANCELLED] == frozenset()
    # governance exposes no command/approval/execute entry point
    public = [n for n in dir(gov) if not n.startswith("_")]
    for banned in ("validate", "approve_command", "execute", "run", "gate", "spawn"):
        assert banned not in public, f"governance exposes a command-shaped symbol: {banned}"
    print("  the state machine governs objective status only; no command veto anywhere: PASS")


def test_the_advisory_check_never_raises() -> None:
    """main._roe_scope_advisory must never raise on a malformed scope — a bad RoE scope is FLAGGED,
    never an error that blocks the engagement view."""
    import main

    for spec in ("", "*", "!only-exclusion", "***", "10.0.0.0/99", "*.example.com, !prod.example.com"):
        res = main._roe_scope_advisory("nonexistent-session", {"scope_spec": spec})
        assert res["advisory"] is True and "status" in res, res
    print("  the RoE-vs-scope advisory flags every malformed scope and never raises: PASS")


def _run_all() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
    print(f"\nAll governance SAFETY invariants hold ({len(tests)} tests).")
    return 0


if __name__ == "__main__":
    sys.exit(_run_all())
