"""SAFETY INVARIANTS for the AI code-audit fan-out. These are §0 of the spec, as code.

  1. THE PROPOSER EXECUTES NOTHING. ai_audit.py + the AI-audit routes read source and call the
     LLM layer (an injected agent). By AST they contain no eval/exec/compile-builtin, no
     subprocess execution, no os.system/popen, no shell, no socket/HTTP of their own — and a
     PLANTED violation is caught (the scanner can fail).
  2. NO NEW GATE. The AI audit is ONE approved job (the ZAP/nuclei justification): it reaches no
     approval / executor / target-lock / danger gate — codescan imports none of them, and the
     new routes reference none of them. It runs no scanner against the code: the ONLY program the
     whole codescan package may launch is still runner._spawn's asserted semgrep/bandit.
  3. PoC IS APPROVE-EACH, NEVER AUTO-RUN. A finding's PoC is a STRING carried as data; nothing in
     the engine executes it. Confirmation is the operator's existing gated executor path.
  4. patched-since KEEPS subprocess OUT of codescan. The diff is produced by an INJECTED provider
     (a callback wired from main.py), so codescan gains no git/subprocess of its own.
  5. PERSISTENCE IS INJECTED. Findings reach engagement state through an injected sink, so
     codescan never imports `state` — the orthogonality lock still holds with the new files.

Run:  python test_ai_audit_safety.py
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from codescan import ai_audit, runner
from codescan import router as cs_router

_PKG = Path(__file__).parent / "codescan"
_ENGINE = _PKG / "ai_audit.py"
_ROUTER = _PKG / "router.py"
_NEW_FILES = [_ENGINE, _ROUTER]


def _dotted(node: ast.AST) -> str:
    """Reconstruct a (possibly dotted) call target name from an AST func node."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


# executing calls that must never appear in the proposer's own source
_BANNED_CALLS = {
    "eval", "exec", "compile", "__import__",
    "os.system", "os.popen",
    "subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_output",
    "subprocess.check_call", "subprocess.getoutput",
    "socket.socket", "requests.get", "requests.post", "urllib.request.urlopen",
}


def _executing_calls(source: str) -> list[str]:
    """Every banned executing/network call in a source string, by AST (not substring)."""
    tree = ast.parse(source)
    hits: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _dotted(node.func)
            if name in _BANNED_CALLS:
                hits.append(name)
    return hits


# --------------------------------------------------------------------------- #
# 1. the proposer executes nothing (with a control)
# --------------------------------------------------------------------------- #
def test_engine_executes_nothing_by_ast() -> None:
    for f in _NEW_FILES:
        hits = _executing_calls(f.read_text(encoding="utf-8"))
        assert not hits, f"{f.name} makes an executing/network call: {hits}"
    # CONTROL: the scanner catches a planted violation (so a green result means something)
    planted = "import subprocess\nsubprocess.run(['id'])\nx = eval('1')\n"
    assert set(_executing_calls(planted)) >= {"subprocess.run", "eval"}, "scanner cannot fail!"
    print("  ai_audit + routes make no eval/exec/subprocess/socket call, by AST; scanner can fail: PASS")


def test_engine_reads_source_and_calls_the_llm_layer() -> None:
    """The audit's power comes from reading source and calling the LLM — not from executing."""
    src = _ENGINE.read_text(encoding="utf-8")
    # it READS source (read_text) and hands it to an injected agent, then parses via the LLM layer
    assert "read_text" in src, "the audit must read source files"
    assert "extract_json" in src, "the audit must parse via the LLM layer (llm.extract_json)"
    assert re.search(r"\bagent\s*\(", src), "the audit must call the injected agent runner"
    # the agent is injected, not a hard-wired provider — default_agents binds it at call time
    assert "def default_agents" in src
    print("  the engine reads source + calls the injected LLM agent (llm.extract_json): PASS")


# --------------------------------------------------------------------------- #
# 2. no new gate — orthogonality holds, no scanner runs against the code
# --------------------------------------------------------------------------- #
def test_no_new_gate_and_orthogonal() -> None:
    all_src = "\n".join(p.read_text(encoding="utf-8") for p in sorted(_PKG.glob("*.py")))
    for module in ("cockpit", "engagement", "executor", "sandbox", "allowlist",
                   "orchestrator", "sessions", "attack_path", "state"):
        assert not re.search(rf"^\s*(?:from|import)\s+{module}\b", all_src, re.M), (
            f"codescan must not import {module} — the AI audit adds no gate and no coupling"
        )
    for symbol in ("validate_request", "check_target_lock", "run_kali", "resolve_mode",
                   "assert_isolation_proven", "dangerous_ack", "red_confirm", "target_lock"):
        assert symbol not in all_src, f"the AI audit must not reference the gate symbol {symbol}"
    # the ONLY launchable programs in the whole package are still the two scanners
    assert runner._TOOLS == ("semgrep", "bandit"), runner._TOOLS
    assert all_src.count("subprocess.Popen") == 1, "only runner._spawn may spawn, exactly once"
    print("  no gate/executor/state import or symbol anywhere; still exactly one asserted spawn: PASS")


# --------------------------------------------------------------------------- #
# 3. PoC is data, approve-each — never auto-run
# --------------------------------------------------------------------------- #
def test_poc_is_data_never_executed() -> None:
    # a concrete finding carries its PoC as a plain string; the engine returns it, never runs it
    r = ai_audit.run_heuristic_audit(_PKG / "sample_app")
    assert r["findings"], "the sample audit should produce findings"
    for f in r["findings"]:
        assert isinstance(f["poc"], str), "a PoC must be a string proposal, not a callable/handle"
    # nothing in the engine takes a finding and executes its PoC — the no-exec AST scan above
    # already proves the engine makes no executing call at all, so a PoC can only ever be data.
    print("  every finding's PoC is a string proposal; the engine executes none of them: PASS")


# --------------------------------------------------------------------------- #
# 4. patched-since keeps subprocess out of codescan (injected provider)
# --------------------------------------------------------------------------- #
def test_patched_since_provider_is_injected() -> None:
    src = _ROUTER.read_text(encoding="utf-8")
    # the router NEVER runs git itself — it calls an injected provider
    assert "_DIFF_PROVIDER" in src and "def set_diff_provider" in src
    assert not re.search(r"\bgit\b.*subprocess|subprocess.*\bgit\b", src), (
        "codescan must not run git itself — the diff provider is injected from main.py"
    )
    # engine-side: changed_paths is a plain set input, computed by nobody in codescan
    esrc = _ENGINE.read_text(encoding="utf-8")
    assert "changed_paths" in esrc and "subprocess" not in esrc
    print("  patched-since diff is injected; codescan runs no git/subprocess of its own: PASS")


# --------------------------------------------------------------------------- #
# 5. persistence is injected — codescan never imports state
# --------------------------------------------------------------------------- #
def test_persistence_is_injected() -> None:
    src = _ROUTER.read_text(encoding="utf-8")
    assert "def set_findings_sink" in src and "_FINDINGS_SINK" in src
    # the engine builds a plain dict payload; it never constructs a state.Finding itself
    esrc = _ENGINE.read_text(encoding="utf-8")
    assert "def to_state_findings" in esrc
    assert not re.search(r"^\s*(?:from|import)\s+state\b", esrc, re.M)
    print("  findings reach state through an injected sink; the engine imports no state: PASS")


# --------------------------------------------------------------------------- #
# 6. the rule-mode scan is untouched
# --------------------------------------------------------------------------- #
def test_rule_mode_scan_still_works() -> None:
    # resolve_target / the scanners' contract are unchanged by the AI-audit addition
    for bad in ("", "   ", "/definitely/not/here"):
        try:
            runner.resolve_target(bad)
        except runner.ScanError:
            continue
        raise AssertionError(f"resolve_target accepted {bad!r}")
    assert runner.DEFAULT_TIMEOUT_S <= runner.MAX_TIMEOUT_S
    print("  rule-mode codescan (resolve/bounds/scanner set) is unchanged: PASS")


if __name__ == "__main__":
    test_engine_executes_nothing_by_ast()
    test_engine_reads_source_and_calls_the_llm_layer()
    test_no_new_gate_and_orthogonal()
    test_poc_is_data_never_executed()
    test_patched_since_provider_is_injected()
    test_persistence_is_injected()
    test_rule_mode_scan_still_works()
    print("ALL AI code-audit SAFETY-invariant tests pass")
