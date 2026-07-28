"""Orchestrator-loop L1 regression-lock (backend/orchestrator.py).

The loop is where autonomy enters, so these tests fail loudly if the proposer ever
becomes able to run things or to stray off the recon/lab policy the executor enforces:

  1. THE PROPOSER NEVER EXECUTES. orchestrator.py must not exec, not import subprocess,
     not call the executor's run path (iter_run/run_command), and — like every non-route
     module — not reference the :kali shell. It only SUGGESTS; running is the M1
     executor's job, behind a human approval.
  2. PRE-CHECK MATCHES THE REAL GATES. A proposal is pre-checked against the actual M1
     allowlist + target-lock: a lab recon command passes (gate_ok); a non-lab target, a
     non-allowlisted command, or a shell metachar is flagged gate_ok=False — surfaced to
     the human, NEVER auto-run.
  3. done / empty proposals are handled (the loop can end).

Hermetic: llm.chat is monkeypatched, so no LLM/Docker. Run:  python test_loop.py
"""
from __future__ import annotations

import ast
from pathlib import Path

import llm
import orchestrator as O
from cockpit import config
from test_support import scans

# The PROPOSER PATH: orchestrator.py + every reasoning/ module (the deeper proposer, Task 2).
# All of it SUGGESTS; none of it runs anything. This set is derived from the shared scanner's
# whole-tree file list (never a hand-rolled glob — that convention is why the :kali lock broke),
# filtered to the proposer path by repo-relative POSIX prefix.
_PROPOSER_PREFIXES = ("orchestrator.py", "reasoning/")
# Banned IMPORTS (subprocess/pty) and import-indirection (cockpit.kali/sandbox/...), caught by
# the shared AST scanner. These are code shapes, never string text — so a drafted payload that
# CONTAINS "os.system(...)" as literal exploit text is NOT a violation; a CALL to it is.
_EXEC_AST_TARGETS = ["subprocess", "pty", "cockpit.kali", "cockpit.sandbox", "cockpit.jobs",
                     "cockpit.terminal", "cockpit.tunnels", "cockpit.sliver", "cockpit.obfuscation"]
# Execution PRIMITIVES detected as CALLS via AST (module.attr), so string literals never trip
# them — the fix for the false positive a substring scan produces on payload-bearing modules.
_EXEC_CALL_MODULES = {"subprocess", "os", "pty", "executor"}
_EXEC_CALL_ATTRS = {"system", "popen", "run", "call", "check_output", "check_call",
                    "spawn", "fork", "execl", "execv", "execve", "iter_run", "run_command"}
# No way to approve many commands at once, anywhere in the proposer path or the frontier.
_AUTO_APPROVE_FORBIDDEN = [
    "approved=True", "approved = True", "auto_approve", "approve_all", "approve_many",
    "batch_approve", "run_all", "run_chain", "autorun", "auto_run",
]


def _proposer_files() -> list[Path]:
    return [p for p in scans.source_files() if scans.rel(p).startswith(_PROPOSER_PREFIXES)]


def _dotted(node: ast.AST) -> str:
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return ".".join(reversed(parts))


def _exec_call_hits(raw: str) -> list[str]:
    """Actual execution CALLS in this module — ``os.system(...)``, ``subprocess.run(...)``,
    ``executor.iter_run(...)``, bare ``Popen(...)``, ``run_kali(...)`` — via AST, so a payload
    STRING that merely contains those characters is never a hit."""
    try:
        tree = ast.parse(raw)
    except SyntaxError:  # pragma: no cover
        return []
    hits: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        callee = _dotted(node.func)
        last = callee.rsplit(".", 1)[-1]
        parts = callee.split(".")
        if last == "run_kali" or last == "Popen":
            hits.append(f"{callee}() (line {node.lineno})")
        elif len(parts) >= 2 and parts[-2] in _EXEC_CALL_MODULES and last in _EXEC_CALL_ATTRS:
            hits.append(f"{callee}() (line {node.lineno})")
    return hits

PLAN = {
    "goal": "recon the lab web app",
    "phases": [
        {
            "phase": "recon",
            "label": "Recon",
            "steps": [
                {
                    "id": "recon-1",
                    "title": "Port/service scan",
                    "commands": [{"lang": "bash", "cmd": "nmap -sV hackpit-lab-target"}],
                }
            ],
        }
    ],
}


class _LLM:
    """Swap orchestrator's llm.chat for a canned response; restore on exit."""

    def __init__(self, response: str):
        self.response = response
        self._orig = O.llm.chat

    def __enter__(self):
        O.llm.chat = lambda system, user, cfg, max_tokens=700: self.response
        return self

    def __exit__(self, *exc):
        O.llm.chat = self._orig
        return False


def test_proposer_cannot_execute() -> None:
    """orchestrator.py must not be able to RUN anything — it only proposes."""
    src = Path(O.__file__).read_text(encoding="utf-8")
    forbidden = [
        "import subprocess",
        "executor.iter_run",
        "executor.run_command",
        "run_kali",       # no path to the :kali shell
        "from .kali",
        "cockpit.kali",
        "subprocess.run",
        "Popen",
    ]
    hits = [f for f in forbidden if f in src]
    assert not hits, f"orchestrator must not execute / reach :kali — found: {hits}"
    # It may only pull PURE helpers from the cockpit package (allowlist/config/executor
    # pre-check), never the exec/sandbox/runstore machinery.
    assert "from cockpit import allowlist, config, executor" in src
    print("  proposer cannot execute (no exec, no :kali path): PASS")


def test_proposer_path_cannot_execute() -> None:
    """EXTENSION of the L1 lock onto the whole reasoning package (Task 2 invariant 1).

    orchestrator.py + every reasoning/ module must have NO execution path: no subprocess, no
    Popen, no executor run methods, no :kali/sandbox — by substring AND by AST indirection (an
    aliased import, an in-function import, ``import_module("cockpit."+"kali")``). Iterates the
    real proposer-path files; asserts on what it CHECKED; carries a positive control.
    """
    offenders: list[str] = []
    checked: list[str] = []
    for path in _proposer_files():
        raw = path.read_text(encoding="utf-8")
        hits = scans.ast_reference_hits(raw, _EXEC_AST_TARGETS)  # banned imports + indirection
        hits += _exec_call_hits(raw)                             # actual execution CALLS
        checked.append(scans.rel(path))
        if hits:
            offenders.append(f"{scans.rel(path)} ({hits})")
    assert not offenders, f"proposer path must not execute / reach :kali — found: {offenders}"
    # assert on what was CHECKED, and that it is really the whole package (not a narrowed set)
    assert "orchestrator.py" in checked, checked
    reasoning_checked = [c for c in checked if c.startswith("reasoning/")]
    assert len(reasoning_checked) >= 9, f"reasoning package under-scanned: {reasoning_checked}"
    # POSITIVE CONTROL — the SAME predicates must fire on planted violations, or they prove nothing
    assert _exec_call_hits("import subprocess\nx = subprocess.run(['id'])\n"), "call predicate cannot fail"
    assert _exec_call_hits("y = os.system('id')\n"), "os.system predicate cannot fail"
    assert scans.ast_reference_hits(
        "import importlib\nm = importlib.import_module('cockpit.' + 'kali')\n", _EXEC_AST_TARGETS
    ), "AST-indirection predicate cannot fail"
    # and a payload STRING containing the same text is NOT a false positive
    payload_src = "x = " + repr("run this: os.system(/bin/sh -p) and subprocess.run(id)") + "\n"
    assert not _exec_call_hits(payload_src), "a payload string must not trip the call scan"
    print(f"  proposer path (orchestrator + {len(reasoning_checked)} reasoning modules) cannot execute: PASS")


def test_no_auto_or_batch_approve() -> None:
    """No auto-approve / batch-approve / run-the-whole-chain anywhere in the proposer path or the
    frontier (Task 2 invariant 2). A proposal is data; a human approves each command."""
    offenders: list[str] = []
    for path in _proposer_files():
        code = scans.code_without_prose(path.read_text(encoding="utf-8"))
        hits = [f for f in _AUTO_APPROVE_FORBIDDEN if f in code]
        if hits:
            offenders.append(f"{scans.rel(path)} ({hits})")
    assert not offenders, f"the proposer path must never auto/batch-approve: {offenders}"
    # positive control
    assert any(f in "x = dict(approved=True)" for f in _AUTO_APPROVE_FORBIDDEN)
    print("  no auto-approve / batch-approve in the proposer path or frontier: PASS")


def test_lab_recon_proposal_passes_gate() -> None:
    resp = (
        '{"done": false, "command": "nmap", "args": ["-sV", "-p", "3000", '
        '"hackpit-lab-target"], "rationale": "scan services", "step_id": "recon-1"}'
    )
    with _LLM(resp):
        out = O.propose_next(PLAN, [], {}, [])
    assert out["done"] is False
    p = out["proposal"]
    assert p is not None
    assert p["command"] == "nmap" and p["gate_ok"] is True, "lab recon must pass the pre-check"
    assert p["step_id"] == "recon-1"
    # and the target-lock really is the lab
    assert config.LAB_TARGET_HOST in p["args"]
    print("  lab recon proposal passes the gate pre-check: PASS")


def test_non_lab_target_is_flagged() -> None:
    resp = (
        '{"done": false, "command": "curl", "args": ["-s", "http://example.com/"], '
        '"rationale": "fetch"}'
    )
    with _LLM(resp):
        out = O.propose_next(PLAN, [], {}, [])
    p = out["proposal"]
    assert p is not None and p["gate_ok"] is False, "a non-lab target must be flagged, not runnable"
    assert "lab" in p["gate_reason"].lower() or "target" in p["gate_reason"].lower()
    print("  non-lab target proposal is flagged (not runnable): PASS")


def test_any_command_against_lab_passes_gate() -> None:
    """The allowlist is gone: a former-non-allowlist command (nikto, gobuster) that targets
    the lab now PASSES the pre-check — the loop only flags a non-lab target."""
    resp = '{"done": false, "command": "nikto", "args": ["-h", "hackpit-lab-target"], "rationale": "scan"}'
    with _LLM(resp):
        out = O.propose_next(PLAN, [], {}, [])
    p = out["proposal"]
    assert p is not None and p["gate_ok"] is True, "any command targeting the lab must pass (no allowlist)"
    print("  any command targeting the lab passes the pre-check: PASS")


def test_metachar_arg_is_allowed_now() -> None:
    """Metacharacters are no longer flagged — they are valid payloads under argv exec. A
    curl to a lab URL containing a metachar passes the pre-check (target is the lab)."""
    resp = (
        '{"done": false, "command": "sqlmap", "args": ["-u", '
        '"http://hackpit-lab-target:3000/rest/products/search?q=1*", "--batch"], "rationale": "x"}'
    )
    with _LLM(resp):
        out = O.propose_next(PLAN, [], {}, [])
    p = out["proposal"]
    assert p is not None and p["gate_ok"] is True, "a metachar payload against the lab must pass now"
    print("  metachar payload against the lab is allowed (no metachar gate): PASS")


def test_precheck_direct() -> None:
    ok, _ = O.precheck("nmap", ["-sV", "hackpit-lab-target"])
    assert ok, "plain lab nmap must pass"
    # any binary is allowed now; the only pre-check reject is a non-lab / target-less command
    ok, _ = O.precheck("nmap", ["--script", "vuln", "hackpit-lab-target"])
    assert ok, "nmap --script is allowed now (no allowlist); it targets the lab"
    ok, reason = O.precheck("bash", ["-c", "id"])
    assert not ok and "lab" in reason.lower(), "bash -c id has no lab reference → target-lock rejects"
    ok, reason = O.precheck("nmap", ["-sV", "scanme.nmap.org"])
    assert not ok and "not the lab" in reason, "a non-lab host is still rejected"
    print("  precheck mirrors the surviving gates (target-lock only): PASS")


def test_done_and_empty_handled() -> None:
    with _LLM('{"done": true}'):
        out = O.propose_next(PLAN, [], {}, [])
    assert out["done"] is True and out["proposal"] is None, "done must end the loop"

    with _LLM('{"done": false, "command": "", "args": []}'):
        out = O.propose_next(PLAN, [], {}, [])
    assert out["done"] is True and out["proposal"] is None, "no command → loop ends cleanly"
    print("  done / empty proposal handled: PASS")


if __name__ == "__main__":
    test_proposer_cannot_execute()
    test_proposer_path_cannot_execute()
    test_no_auto_or_batch_approve()
    test_lab_recon_proposal_passes_gate()
    test_non_lab_target_is_flagged()
    test_any_command_against_lab_passes_gate()
    test_metachar_arg_is_allowed_now()
    test_precheck_direct()
    test_done_and_empty_handled()
    print("ALL orchestrator-loop L1 tests pass")
