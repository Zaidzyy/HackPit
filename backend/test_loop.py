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
        O.llm.chat = lambda system, user, cfg, max_tokens=700, json_mode=False: self.response
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


def test_ask_the_operator_proposal() -> None:
    """The model can ASK THE OPERATOR for a value instead of a command. The proposal is kind
    'ask', carries NO command (so nothing is runnable/executable), and the operator's answer
    round-trips into the NEXT prompt so the loop can continue past a human-only blocker."""
    ask_json = (
        '{"done": false, "ask": {"instructions": "Log in and paste your session cookie", '
        '"label": "session cookie"}, "rationale": "the endpoints need auth"}'
    )
    with _LLM(ask_json):
        out = O.propose_next(PLAN, [], {}, [])
    p = out["proposal"]
    assert out["done"] is False and p is not None, "an ask is a live proposal, not done"
    assert p["kind"] == "ask", p["kind"]
    assert p["command"] == "" and p["args"] == [], "an ask carries no command"
    assert p["gate_ok"] is False, "an ask is never runnable"
    assert p["ask_label"] == "session cookie" and p["ask_instructions"], p

    # A normal command proposal is tagged kind 'command' so the UI can tell them apart.
    with _LLM('{"done": false, "command": "curl", "args": ["http://%s/"]}' % config.LAB_TARGET_HOST):
        out = O.propose_next(PLAN, [], {}, [])
    assert out["proposal"]["kind"] == "command", out["proposal"]["kind"]

    # The operator's answer is stored and FED BACK into the next prompt (that is the whole point).
    from state import store as state_store

    state_store.init_db()
    sid = "test-ask-loop-fixture"
    state_store.add_operator_context(sid, "gdsid=SECRET123", "session cookie")
    prompt = O.build_user_prompt(PLAN, [], [], None, sid)
    assert "OPERATOR-PROVIDED CONTEXT" in prompt, "the answer block is missing from the prompt"
    assert "gdsid=SECRET123" in prompt, "the operator's answer did not reach the next prompt"
    print("  ask-the-operator: kind='ask' runs nothing; the answer feeds the next prompt: PASS")


def test_surface_action_proposal() -> None:
    """The model can propose a first-class SURFACE (a gated job) instead of a raw command. It
    carries no command (executes nothing here), names an allowed surface, and passes params
    through for the frontend to route to that surface's own gated endpoint. An UNKNOWN surface
    name must NOT become a surface proposal — it falls through to the command path."""
    sj = ('{"done": false, "surface": {"name": "discover", "params": {"mode": "content", '
          '"url": "https://api.target.com/", "impersonate": true}}, "rationale": "content-discover"}')
    with _LLM(sj):
        out = O.propose_next(PLAN, [], {}, [])
    p = out["proposal"]
    assert out["done"] is False and p is not None
    assert p["kind"] == "surface" and p["surface"] == "discover", p
    assert p["command"] == "" and p["args"] == [], "a surface carries no command"
    assert p["surface_params"]["mode"] == "content" and p["surface_params"]["impersonate"] is True, p
    assert p["gate_ok"] is False, "a surface is not an executor command"

    with _LLM('{"done": false, "surface": {"name": "nope", "params": {}}, "command": "curl", '
              '"args": ["http://%s/"]}' % config.LAB_TARGET_HOST):
        out = O.propose_next(PLAN, [], {}, [])
    assert out["proposal"]["kind"] == "command", "an unknown surface must fall through to command"
    print("  surface action: kind='surface' runs nothing; unknown surface falls through: PASS")


def test_json_mode_constrains_small_local_models() -> None:
    """A structured call (a loop proposal) forces Ollama's grammar-constrained JSON so a SMALL
    local model (qwen3:8b et al.) cannot emit unparseable output — the whole reason small models
    failed the loop with 'could not parse JSON'. A prose call (a report) must NOT constrain."""
    import llm

    seen: dict = {}
    orig = llm._post_json

    def _fake(url, payload, headers):
        seen["payload"] = payload
        return {"message": {"content": '{"done": true}'}}

    llm._post_json = _fake
    try:
        cfg = {"provider": "ollama", "model": "qwen3:8b", "host": "http://x"}
        llm.chat("s", "u", cfg, json_mode=True)
        assert seen["payload"].get("format") == "json", "a JSON call must force Ollama format:json"
        llm.chat("s", "u", cfg)  # prose default — no constraint
        assert "format" not in seen["payload"], "a prose call must NOT constrain the output"
    finally:
        llm._post_json = orig

    # ...and the loop proposer actually requests it, so the guided loop works on small models.
    src = Path(O.__file__).read_text(encoding="utf-8")
    assert "json_mode=True" in src, "propose_next must call llm.chat(..., json_mode=True)"
    print("  json_mode: a JSON call forces grammar-constrained Ollama output; prose does not: PASS")


def test_note_and_chat_steering() -> None:
    """The loop can TALK to the operator (an optional 'note' on any proposal) and the operator
    can STEER the loop (a chat message feeds the next prompt). Both ride the one chat transcript;
    neither makes the proposer able to run anything."""
    lab = config.LAB_TARGET_HOST

    # (1) a note rides on a command proposal — separate from rationale, attached verbatim.
    cmd_json = (
        '{"done": false, "command": "curl", "args": ["http://%s/"], '
        '"rationale": "fetch root", "note": "this 401 looks app-key gated, not a login problem"}'
        % lab
    )
    with _LLM(cmd_json):
        out = O.propose_next(PLAN, [], {}, [])
    p = out["proposal"]
    assert p["kind"] == "command", p["kind"]
    assert p["note"] == "this 401 looks app-key gated, not a login problem", p.get("note")
    assert p["rationale"] == "fetch root", "the note must not overwrite the rationale"

    # (2) a note also rides on an ask.
    ask_json = (
        '{"done": false, "ask": {"instructions": "paste your session cookie", "label": "cookie"}, '
        '"note": "I need auth before I can test cross-account access"}'
    )
    with _LLM(ask_json):
        out = O.propose_next(PLAN, [], {}, [])
    assert out["proposal"]["kind"] == "ask"
    assert out["proposal"]["note"] == "I need auth before I can test cross-account access"

    # (3) an omitted note is simply empty — additive, never required.
    with _LLM('{"done": false, "command": "curl", "args": ["http://%s/"]}' % lab):
        out = O.propose_next(PLAN, [], {}, [])
    assert out["proposal"]["note"] == "", "no note → empty string, not a missing field"

    # (4) STEERING: an operator chat message AND the loop's own note both reach the NEXT prompt.
    import sessions as sessions_db

    sessions_db.init_db()
    sid = sessions_db.create_session("recon the lab", "web", PLAN)
    sessions_db.append_chat(sid, "focus on Fishbowl IDOR only, skip Glassdoor", "understood", [])
    ts = sessions_db.append_agent_note(sid, "noting: the API key is app-side, not in the web bundle")
    assert ts, "append_agent_note must persist and return a ts"

    hist = sessions_db.get_session(sid)["chat_history"]
    note_turns = [t for t in hist if t.get("kind") == "note"]
    assert len(note_turns) == 1 and note_turns[0]["role"] == "assistant", note_turns
    assert note_turns[0]["content"].startswith("noting:"), note_turns

    prompt = O.build_user_prompt(PLAN, [], [], None, sid)
    assert "CONVERSATION WITH THE OPERATOR" in prompt, "the chat block is missing from the prompt"
    assert "focus on Fishbowl IDOR only" in prompt, "the operator's steer did not reach the prompt"
    assert "app-side" in prompt, "the loop's own note did not round-trip into the next prompt"
    print("  note rides any proposal; operator chat + loop notes steer the next prompt: PASS")


def test_chat_grounds_on_live_loop_state() -> None:
    """chat.answer folds the guided loop's live state (findings, endpoints) into the prompt so the
    assistant can talk about what the LOOP is doing — not only the pasted attack-path steps. The
    renderer is duck-typed and guarded: a None/empty state contributes nothing, never an error."""
    import chat as chat_mod

    class _F:
        severity = "high"
        title = "IDOR on /thread/{id}/messages"
        target = "api.fishbowlapp.com"

    class _E:
        method = "GET"
        url = "https://api.fishbowlapp.com/bowl/list"

    class _State:
        findings = [_F()]
        endpoints = [_E()]

        def counts(self):
            return {"hosts": 0, "services": 0, "endpoints": 1, "credentials": 0, "findings": 1}

    block = chat_mod.build_loop_state_block(_State())
    assert "LIVE LOOP STATE" in block, block
    assert "IDOR on /thread" in block and "api.fishbowlapp.com" in block, block
    assert "GET https://api.fishbowlapp.com/bowl/list" in block, block
    assert chat_mod.build_loop_state_block(None) == "", "None state must contribute nothing"
    print("  chat grounds on the live loop state (findings + endpoints): PASS")


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
    test_ask_the_operator_proposal()
    test_note_and_chat_steering()
    test_chat_grounds_on_live_loop_state()
    test_surface_action_proposal()
    test_json_mode_constrains_small_local_models()
    print("ALL orchestrator-loop L1 tests pass")
