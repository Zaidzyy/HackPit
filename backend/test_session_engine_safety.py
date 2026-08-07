"""Named-session engine SAFETY invariants (cockpit/session_engine.py).

The engine drives NAMED, PARALLEL, PERSISTENT, full-reach interactive sessions in the open
sandbox — msfconsole, sliver-client, evil-winrm, live REPLs. That is exactly as dangerous as
:kali and the raw pty, so it carries exactly the same containment, and these tests FAIL LOUDLY
if any of it is weakened. §0 of the build spec (do not weaken): adds NO new gate, stdin stays
HUMAN-ONLY / approve-each, the orchestrator must NEVER send input (Decepticon's `is_input`
autonomy is explicitly NOT adopted), containment unchanged, the two-sandbox separation intact.

  1. HUMAN-ONLY INPUT — the rule that matters most. Both input paths — `run_command` (send a
     command) and `send_input` (the `is_input` path: answer an interactive prompt) — may be
     referenced ONLY by the router + this test. An autonomous agent wired to a live msfconsole
     / sliver / evil-winrm = autonomous attacks on host/LAN/internet. Scanned across the WHOLE
     backend tree, exactly like the pty / :kali, WITH A PLANTED CONTROL.
  2. NO ORCHESTRATOR / PROPOSER PATH CAN SEND is_input. The executor and the orchestrator
     expose no session-engine hook at all, and neither imports the module.
  3. HARDCODED OPEN CONTAINER. Every exec targets config.KALI_OPEN_CONTAINER; the isolated
     sandbox never appears; the request models carry no container/target/shell field.
  4. NO NEW GATE / NO ISOLATION GATE. The engine imports no executor / sandbox / isolation
     module and names no gate symbol — the open box is intentionally not isolated (the human
     at the keyboard is the approval), and it must not grow a gate the pty does not have.
  5. THE :kali SENTINEL NEVER GETS A pty OR A tmux. The engine is additive on the OPEN side;
     kali.py keeps its sentinel-delimited, escape-free, pty-free per-command transcripts.

Hermetic (source scan + import checks). Run:  python test_session_engine_safety.py
"""
from __future__ import annotations

from pathlib import Path

from cockpit import config
from cockpit import session_engine as SE
from cockpit.session_engine import SessionOpenRequest, SessionRunRequest, SessionInputRequest
from test_support import scans


# --------------------------------------------------------------------------- #
# 1. HUMAN-ONLY input (the one that matters most)
# --------------------------------------------------------------------------- #
# NOTE the pattern choice: `run_command` and `kill_session` are NOT scanned as bare names —
# executor.py has its OWN gated `run_command` and router.py has the C2 `kill_session` route,
# both unrelated to this engine. Instead the scan keys on any REFERENCE TO THE MODULE (import
# or dotted), plus the two names only this module exports (`send_input`, `open_session`). A
# direct `from cockpit.session_engine import run_command` is still caught — by the module
# patterns — so nothing can reach the engine's input paths without tripping this.
_ALLOWED = {"cockpit/session_engine.py", "cockpit/router.py"}
_PATTERNS = [
    r"\bsend_input\b", r"\bopen_session\b",
    r"from \.session_engine", r"cockpit\.session_engine", r"\bimport session_engine\b",
]
_AST_TARGETS = ["cockpit.session_engine", "send_input", "open_session"]


def test_session_engine_input_is_human_only() -> None:
    """The engine must be reachable ONLY from the router + this test.

    A named-session engine wired to the agent = autonomous drive of a live C2 console. Scan the
    whole (non-venv, non-test) backend tree — the pty's lock proved a narrow glob ships green.
    """
    res = scans.scan_source_tree(
        patterns=_PATTERNS, allowed=_ALLOWED, ast_targets=_AST_TARGETS,
    )
    scans.assert_clean(
        res,
        what="the named-session engine must be HUMAN-ONLY — the orchestrator/agent/executor/"
             "proposer must have NO path to run_command or send_input",
        must_have_scanned=["orchestrator.py", "adgraph/orchestrator.py", "cockpit/executor.py",
                           "cockpit/session.py", "cockpit/proposals.py", "cockpit/terminal.py"],
        min_checked=60,
    )
    scans.assert_catches_a_planted_violation(
        plant="from cockpit.session_engine import send_input",
        patterns=_PATTERNS, allowed=_ALLOWED, ast_targets=_AST_TARGETS,
    )
    print("  the session engine is human-only (no agent/executor/proposer path): PASS")


def test_no_autonomous_is_input_path() -> None:
    """*** THE §0 INVARIANT: the orchestrator must NEVER send is_input. ***

    Decepticon's agent could set is_input to drive a prompt autonomously; HackPit does not adopt
    that. Belt-and-suspenders on top of the source scan: the exec path and the loop expose no
    session hook, and neither imports the engine.
    """
    # NB: executor has its OWN gated run_command — unrelated. We assert it exposes none of the
    # ENGINE's distinctive hooks and does not import the module.
    from cockpit import executor as EX
    for hook in ("session_engine", "send_input", "open_session", "is_input"):
        assert not hasattr(EX, hook), f"the executor must not expose {hook} — human-only"
    import orchestrator as ORCH
    for hook in ("session_engine", "send_input", "open_session", "is_input"):
        assert not hasattr(ORCH, hook), f"the orchestrator must not expose {hook}"
    from cockpit import proposals as PROP
    for hook in ("session_engine", "send_input", "open_session"):
        assert not hasattr(PROP, hook), f"the proposer must not expose {hook}"

    # ...and the `is_input` value the human passes is a real parameter of send_input, not a
    # field an orchestrator could reach through a model — send_input takes an explicit request.
    assert "enter" in SessionInputRequest.model_fields
    assert "data" in SessionInputRequest.model_fields
    print("  no orchestrator/executor/proposer path can send input (no is_input autonomy): PASS")


# --------------------------------------------------------------------------- #
# 2. hardcoded open container; no request field can redirect the exec
# --------------------------------------------------------------------------- #
def test_container_is_hardcoded_open_not_isolated() -> None:
    src = (Path(__file__).parent / "cockpit" / "session_engine.py").read_text(encoding="utf-8")
    # The container is read from config, never built from a request.
    assert "config.KALI_OPEN_CONTAINER" in src
    assert "SANDBOX_CONTAINER" not in src, "the isolated sandbox must never appear here"

    for model in (SessionOpenRequest, SessionRunRequest, SessionInputRequest):
        fields = set(model.model_fields)
        for banned in ("container", "target", "host", "shell", "image", "sandbox"):
            assert banned not in fields, f"{model.__name__} must not accept '{banned}'"
    # SessionOpenRequest carries only a name + optional engagement id.
    assert set(SessionOpenRequest.model_fields) == {"name", "session_id"}
    print("  container hardcoded to the OPEN sandbox; no request field can redirect it: PASS")


# --------------------------------------------------------------------------- #
# 3. no new gate / no isolation gate (the open box is intentionally not isolated)
# --------------------------------------------------------------------------- #
def test_no_new_gate_and_no_isolation_gate() -> None:
    src = (Path(__file__).parent / "cockpit" / "session_engine.py").read_text(encoding="utf-8")
    for banned in ("assert_isolation_proven", "from .sandbox", "from cockpit.sandbox",
                   "import sandbox", "from .executor", "validate_request", "resolve_mode"):
        assert banned not in src, f"session_engine.py must not reference {banned} (no new gate)"
    assert not hasattr(SE, "assert_isolation_proven")
    # The engine imports nothing that executes a gate — it is human-only + audit, like the pty.
    st = SE.engine_status()
    assert st["isolated"] is False, "the banner must never claim isolation — full-reach box"
    assert st["container"] == config.KALI_OPEN_CONTAINER
    print("  engine adds no gate and no isolation claim (open box, human-approved): PASS")


# --------------------------------------------------------------------------- #
# 4. the :kali sentinel is untouched — no pty, no tmux
# --------------------------------------------------------------------------- #
def test_sentinel_shell_untouched_and_engine_uses_tmux_not_pty() -> None:
    kali_src = (Path(__file__).parent / "cockpit" / "kali.py").read_text(encoding="utf-8")
    assert "sentinel" in kali_src and "__HACKPIT_KALI_" in kali_src
    for grew in ("pty.fork", "TIOCSWINSZ", "openpty", "tmux new-session", "hpsx_"):
        assert grew not in kali_src, (
            f"kali.py grew {grew} — the sentinel shell must stay pty-free AND tmux-free")

    engine_src = (Path(__file__).parent / "cockpit" / "session_engine.py").read_text(
        encoding="utf-8")
    # The engine is a tmux surface, NOT a second pty in the sentinel shell, and does not call
    # into :kali's runners.
    assert "tmux" in engine_src
    assert "pty.fork" not in engine_src and "openpty" not in engine_src
    assert "run_kali" not in engine_src and "run_in_shell" not in engine_src
    print("  :kali sentinel stays pty-free + tmux-free; the engine is a separate tmux surface: PASS")


# --------------------------------------------------------------------------- #
# 5. no persistent stdin writer (the lifecycle-safety shape) — input is per-line send-keys
# --------------------------------------------------------------------------- #
def test_no_persistent_stdin_writer() -> None:
    """Unlike a caught C2 shell, a session is driven by discrete `tmux send-keys` — there is no
    long-lived proc.stdin object anyone can write to, so there is no autonomous typing channel
    to leak. Every send goes through the human-only _send_keys, one line at a time."""
    src = (Path(__file__).parent / "cockpit" / "session_engine.py").read_text(encoding="utf-8")
    assert "send-keys" in src, "input must be discrete send-keys, not a held stdin"
    assert "stdin=subprocess.PIPE" not in src, "the engine must not hold a session's stdin open"
    print("  input is discrete human-only send-keys, no held stdin writer: PASS")


if __name__ == "__main__":
    test_session_engine_input_is_human_only()
    test_no_autonomous_is_input_path()
    test_container_is_hardcoded_open_not_isolated()
    test_no_new_gate_and_no_isolation_gate()
    test_sentinel_shell_untouched_and_engine_uses_tmux_not_pty()
    test_no_persistent_stdin_writer()
    print("ALL session-engine SAFETY tests pass")
