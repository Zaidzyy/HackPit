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

from pathlib import Path

import llm
import orchestrator as O
from cockpit import config

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
    test_lab_recon_proposal_passes_gate()
    test_non_lab_target_is_flagged()
    test_any_command_against_lab_passes_gate()
    test_metachar_arg_is_allowed_now()
    test_precheck_direct()
    test_done_and_empty_handled()
    print("ALL orchestrator-loop L1 tests pass")
