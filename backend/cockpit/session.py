"""Live interactive SESSIONS — catch a shell, stream it, type into it over time.

This is the one C2 slice: ONE long-lived process you drive by hand. It is NOT a C2
subsystem — there is no beacon management, no multi-implant dashboard, no pivoting and
no lateral automation. A session is a single `docker exec -i` into the mode's sandbox
whose stdin stays open, so a listener (`nc -lvnp 4444`, a pty handler, socat) survives
past the request that started it and you can keep typing into what connects back.

THE SAFETY MODEL — two loads, both must hold:

1. STARTING a session is a GATED COMMAND. :func:`start` calls the REAL
   ``executor.validate_request`` — not a copy — so a session-start clears exactly the
   gates a one-shot command clears, in the same order:
       LAB:        target-lock -> approval -> heuristic danger -> ISOLATION
       ENGAGEMENT: engagement  -> target-lock (program scope) -> approval -> danger
   A listener/handler (nc/ncat/socat, an interpreter) trips
   ``dangerous_command_heuristic``, so it additionally needs an explicit
   ``dangerous_ack``. Session-start is NOT a new capability — it is a command that
   happens to be long-lived, and it buys no bypass of anything.

2. A LIVE SESSION'S STDIN IS HUMAN-ONLY. :func:`write_stdin` is the ONLY way to reach a
   running process's stdin, and it is reachable ONLY from the HTTP route in router.py
   that a human's UI action drives. The orchestrator / agent / loop has ZERO code path
   to it — the same rule as :kali, and regression-locked the same way by a source scan
   (test_session.py::test_session_stdin_is_human_only). The loop may PROPOSE starting a
   session (that is just a command a human approves); it can NEVER type into one. A live
   session must not become an un-gated execution channel for autonomy.

CONTAINMENT is whatever the mode it started in gives it — this module adds no reach and
removes none. LAB binds to the isolated, egress-less sandbox (the isolation gate is
asserted at start); ENGAGEMENT binds to the fully-open engagement sandbox, where
human-approve-each is the only bound. The container comes from
``executor.resolve_mode`` — the same mapping one-shot runs use — never from the request.

THE DECLARED BIND TARGET. A listener has no target by definition (`nc -lvnp 4444` has no
host-shaped token), so a start request carries an explicit ``target`` and the gate runs
over ``args + [target]``. This is strictly MORE strict than gating ``args`` alone: the
extra token can only satisfy "a target was named" or add heuristic reasons — it can
never mask a bad host sitting in the real args, which are still scanned and still
rejected. The argv that actually runs is ``command + args`` (no target appended), and
the UI header shows this gate-validated target, so what you see bound is what passed.

NO PTY. The exec is `docker exec -i` (stdin only, no `-t`). Line-oriented shells and
listeners work; full-screen curses programs do not. That is deliberate — no TTY means
no terminal-escape handling and a transcript that stays readable in the report.
"""

from __future__ import annotations

import atexit
import subprocess
import threading
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from typing import Any, Iterator

from pydantic import BaseModel, Field

from . import config, executor, runstore
from .models import ExecRequest, ExecRejected, RunRecord

# --- Bounds. A live shell must not hang forever, flood memory, or pile up. ---------
# No I/O in either direction for this long -> the session is reaped.
SESSION_IDLE_TIMEOUT_SECONDS = 900  # 15 min
# Absolute ceiling regardless of activity.
SESSION_MAX_LIFETIME_SECONDS = 14_400  # 4 h
# Full transcript kept for the RECORD (report evidence); past this it is truncated.
SESSION_TRANSCRIPT_CAP = 200_000  # chars — matches :kali's KALI_OUTPUT_CAP
# Rolling tail kept in memory for the LIVE view + reconnect replay.
SESSION_LIVE_EVENTS = 4_000  # events
# How many sessions may be live at once.
MAX_LIVE_SESSIONS = 8
# Cap one stdin write (a paste bomb is not a feature).
STDIN_MAX_BYTES = 8_192

# Transcript marker for a line the HUMAN typed, so the report can tell input from
# output at a glance. Output is appended verbatim.
STDIN_MARK = "$ "


class SessionStartRequest(BaseModel):
    """Start ONE long-lived session. Gated exactly like a one-shot command.

    ``target`` is the DECLARED BIND TARGET (see module docstring): it must itself pass
    the mode's target-lock — a lab alias in LAB mode, an in-scope host in ENGAGEMENT
    mode. It is NOT appended to the argv that runs.

    NOTE — deliberately there is NO container / sandbox field. The container is derived
    from the mode via ``executor.resolve_mode``; nothing in this request can redirect
    the exec to another box.
    """

    command: str = Field(..., min_length=1, description="Command name, e.g. 'nc'.")
    args: list[str] = Field(default_factory=list, description="Argv tokens (no shell).")
    target: str = Field(
        ...,
        min_length=1,
        description="The DECLARED target this session is bound to. Validated by the "
        "mode's target-lock (lab alias / in-scope host) — not appended to the argv.",
    )
    approved: bool = Field(
        False, description="Per-command human approval. Starting refuses unless true."
    )
    dangerous_ack: bool = Field(
        False,
        description="Explicit second confirmation. A listener/handler (nc, socat, an "
        "interpreter) trips the danger heuristic, so this is required in practice.",
    )
    engagement_id: str | None = Field(
        None,
        description="When set to an ACTIVE engagement id, the session binds to the "
        "real-target engagement sandbox. Omit for isolated LAB mode.",
    )
    session_id: str | None = Field(
        None, description="Engagement session to record this session's transcript against."
    )
    step_id: str | None = Field(None, description="Optional attack-path step id.")


class SessionStdinRequest(BaseModel):
    """One line a HUMAN typed into a live session (see :func:`write_stdin`).

    Deliberately minimal: a line of text and nothing else. There is no command/target/
    container field — a session is already bound to its sandbox and mode, and stdin
    cannot re-point it anywhere.
    """

    data: str = Field(..., description="The line to send. A trailing newline is added.")


class SessionInfo(BaseModel):
    """The public state of one session. ``sid`` is the LIVE SESSION id.

    Note the two distinct ids: ``sid`` identifies this live session; ``session_id``
    keeps its repo-wide meaning — the engagement the transcript is recorded against.
    """

    sid: str
    state: str  # "active" | "exited" | "killed"
    mode: str  # "lab" | "engagement"
    container: str
    target: str
    command: str
    args: list[str]
    run_id: str
    engagement_id: str | None = None
    session_id: str | None = None
    step_id: str | None = None
    started_at: str
    finished_at: str | None = None
    exit_code: int | None = None
    truncated: bool = False
    detail: str = ""


class SessionRefused(RuntimeError):
    """Raised when a session cannot be started. Carries the gate that refused it."""

    def __init__(self, reason: str, gate: str = "session"):
        super().__init__(reason)
        self.reason = reason
        self.gate = gate


class SessionNotFound(KeyError):
    """No live-or-recent session with that sid."""


class _Live:
    """The mutable innards of one session. Not exported — callers see SessionInfo."""

    def __init__(self, info: SessionInfo, proc: subprocess.Popen, record: RunRecord):
        self.info = info
        self.proc = proc
        self.record = record
        self.cond = threading.Condition()
        self.events: deque[tuple[int, dict[str, Any]]] = deque(maxlen=SESSION_LIVE_EVENTS)
        self.next_seq = 0
        self.transcript: list[str] = []
        self.transcript_len = 0
        self.last_io = time.monotonic()
        self.started_mono = time.monotonic()
        self.threads: list[threading.Thread] = []

    # -- transcript + event fan-out (callers must NOT hold self.cond) --------------

    def emit(self, event: dict[str, Any], transcript_text: str | None = None) -> None:
        """Append to the transcript (capped) and publish an event to subscribers."""
        with self.cond:
            if transcript_text:
                if self.transcript_len < SESSION_TRANSCRIPT_CAP:
                    room = SESSION_TRANSCRIPT_CAP - self.transcript_len
                    chunk = transcript_text[:room]
                    self.transcript.append(chunk)
                    self.transcript_len += len(chunk)
                    if len(transcript_text) > room:
                        self.transcript.append("\n…[transcript truncated]…")
                        self.info.truncated = True
                else:
                    self.info.truncated = True
            self.events.append((self.next_seq, event))
            self.next_seq += 1
            self.last_io = time.monotonic()
            self.cond.notify_all()

    def transcript_text(self) -> str:
        with self.cond:
            return "".join(self.transcript)


_sessions: dict[str, _Live] = {}
_registry_lock = threading.Lock()
_reaper: threading.Thread | None = None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------- #
# START — a GATED command that happens to be long-lived.
# --------------------------------------------------------------------------- #


def _gate_request(req: SessionStartRequest) -> ExecRequest:
    """The ExecRequest the GATES see: the real argv PLUS the declared bind target.

    Gating the superset is strictly at-least-as-strict as gating ``args`` alone (see
    the module docstring): the extra token can only satisfy the "a target was named"
    requirement or add heuristic reasons. Every host-shaped token in the REAL args is
    still scanned and still rejected if it is off-target/out-of-scope.
    """
    return ExecRequest(
        command=req.command,
        args=[*req.args, req.target],
        approved=req.approved,
        dangerous_ack=req.dangerous_ack,
        engagement_id=req.engagement_id,
        session_id=req.session_id,
        step_id=req.step_id,
    )


def validate_start(req: SessionStartRequest) -> ExecRejected | None:
    """Run the mode's real gates against a session-start. None means it may start."""
    return executor.validate_request(_gate_request(req))


def start(req: SessionStartRequest) -> SessionInfo:
    """Gate, then launch a long-lived `docker exec -i` and register it.

    Raises :class:`SessionRefused` (nothing runs) if any gate refuses, if the session
    cap is reached, or if docker is unavailable. On success the process is live with an
    open stdin, two reader threads are pumping its output, and a RunRecord already
    exists so the transcript is recorded even if the backend dies mid-session.
    """
    rejected = validate_start(req)
    if rejected is not None:
        raise SessionRefused(rejected.reason, gate=rejected.gate)

    # The container comes from the SAME mapping one-shot runs use — never the request.
    try:
        resolved = executor.resolve_mode(_gate_request(req))
    except executor.EngagementInactive as exc:
        raise SessionRefused(str(exc), gate="engagement")

    with _registry_lock:
        live_count = sum(1 for s in _sessions.values() if s.info.state == "active")
        if live_count >= MAX_LIVE_SESSIONS:
            raise SessionRefused(
                f"too many live sessions ({live_count}/{MAX_LIVE_SESSIONS}) — kill one first",
                gate="limit",
            )

    sid = uuid.uuid4().hex[:12]
    run_id = uuid.uuid4().hex[:12]
    started_at = _now()
    # `-i` keeps stdin open (that is the whole feature). No `-t`: no PTY — see module docstring.
    argv = ["docker", "exec", "-i", resolved.container, req.command, *req.args]

    try:
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
    except FileNotFoundError:
        raise SessionRefused("docker CLI not found on PATH", gate="unavailable")

    info = SessionInfo(
        sid=sid,
        state="active",
        mode=resolved.mode,
        container=resolved.container,
        # The gate-validated declared target — what the UI header shows.
        target=req.target,
        command=req.command,
        args=list(req.args),
        run_id=run_id,
        engagement_id=req.engagement_id,
        session_id=req.session_id,
        step_id=req.step_id,
        started_at=started_at,
    )
    record = RunRecord(
        run_id=run_id,
        command="session",
        args=[req.command, *req.args],
        target=req.target,
        approved=True,  # it cleared the approval gate above
        mode=resolved.mode,
        started_at=started_at,
        session_id=req.session_id,
        step_id=req.step_id,
    )

    live = _Live(info, proc, record)
    with _registry_lock:
        _sessions[sid] = live

    live.emit(
        {
            "type": "start",
            "sid": sid,
            "run_id": run_id,
            "mode": resolved.mode,
            "container": resolved.container,
            "target": req.target,
            "command": req.command,
            "args": list(req.args),
            "started_at": started_at,
        }
    )

    def _pump(stream, kind: str) -> None:
        try:
            for line in iter(stream.readline, ""):
                live.emit({"type": kind, "line": line.rstrip("\n")}, transcript_text=line)
        finally:
            try:
                stream.close()
            except Exception:  # pragma: no cover - stream already gone
                pass

    def _waiter() -> None:
        code = proc.wait()
        _finish(live, state="exited" if live.info.state == "active" else live.info.state,
                exit_code=code)

    live.threads = [
        threading.Thread(target=_pump, args=(proc.stdout, "stdout"), daemon=True),
        threading.Thread(target=_pump, args=(proc.stderr, "stderr"), daemon=True),
        threading.Thread(target=_waiter, daemon=True),
    ]
    for t in live.threads:
        t.start()

    _save(live)
    _ensure_reaper()
    return info


# --------------------------------------------------------------------------- #
# STDIN — *** HUMAN-ONLY ***. The load-bearing invariant of this module.
# --------------------------------------------------------------------------- #


def write_stdin(sid: str, data: str) -> SessionInfo:
    """Write one line to a LIVE session's stdin. *** HUMAN-ONLY — see below. ***

    THIS IS THE INVARIANT. This function is the ONLY way to reach a running process's
    stdin, and it may be called ONLY from the HTTP route in router.py that a human's UI
    action drives. The orchestrator / agent / loop MUST have ZERO code path here: a live
    session is an already-approved, already-running process, so anything able to type
    into it would be executing un-gated commands — exactly the autonomy the approve-each
    model exists to prevent. Regression-locked by a source scan over the whole backend
    tree (test_session.py::test_session_stdin_is_human_only), the same lock :kali has.

    The typed line is echoed into the transcript (marked with ``$ ``) so the recording
    shows what a human typed versus what the shell returned.
    """
    live = _get_live(sid)
    if live.info.state != "active":
        raise SessionRefused(
            f"session is {live.info.state} — cannot write to a finished session", gate="state"
        )
    if live.proc.stdin is None or live.proc.stdin.closed:
        raise SessionRefused("session stdin is closed", gate="state")

    line = data if data.endswith("\n") else data + "\n"
    if len(line.encode("utf-8", "replace")) > STDIN_MAX_BYTES:
        raise SessionRefused(
            f"input too large (cap {STDIN_MAX_BYTES} bytes for one write)", gate="limit"
        )

    # Echo FIRST so the transcript records the intent even if the write then fails.
    live.emit({"type": "stdin", "line": line.rstrip("\n")}, transcript_text=STDIN_MARK + line)
    try:
        live.proc.stdin.write(line)
        live.proc.stdin.flush()
    except (BrokenPipeError, OSError, ValueError) as exc:
        live.emit({"type": "error", "reason": f"write failed: {exc}"})
        raise SessionRefused(f"session is no longer accepting input: {exc}", gate="state")
    _save(live)
    return live.info


# --------------------------------------------------------------------------- #
# Lifecycle + read-only views.
# --------------------------------------------------------------------------- #


def _get_live(sid: str) -> _Live:
    with _registry_lock:
        live = _sessions.get(sid)
    if live is None:
        raise SessionNotFound(sid)
    return live


def get(sid: str) -> SessionInfo:
    return _get_live(sid).info


def list_sessions() -> list[SessionInfo]:
    """Every session this process knows about, newest last."""
    with _registry_lock:
        return [s.info for s in sorted(_sessions.values(), key=lambda s: s.info.started_at)]


def kill(sid: str, reason: str = "killed by operator") -> SessionInfo:
    """Terminate a live session and flush its transcript. Idempotent."""
    live = _get_live(sid)
    if live.info.state != "active":
        return live.info
    live.info.state = "killed"
    live.info.detail = reason
    live.emit({"type": "killed", "reason": reason})
    _terminate(live)
    # The waiter thread calls _finish; do it here too so a caller sees final state
    # immediately even if the process is slow to reap. _finish is idempotent.
    _finish(live, state="killed", exit_code=live.proc.poll(), detail=reason)
    return live.info


def _terminate(live: _Live) -> None:
    """Close stdin then kill the docker exec client. Never raises."""
    try:
        if live.proc.stdin and not live.proc.stdin.closed:
            live.proc.stdin.close()
    except Exception:  # pragma: no cover - best effort
        pass
    try:
        live.proc.kill()
    except Exception:  # pragma: no cover - already dead
        pass


_finish_lock = threading.Lock()


def _finish(live: _Live, state: str, exit_code: int | None, detail: str = "") -> None:
    """Mark a session finished and persist its final transcript. Idempotent."""
    with _finish_lock:
        if live.info.finished_at is not None:
            return
        live.info.state = state
        live.info.exit_code = exit_code
        live.info.finished_at = _now()
        if detail:
            live.info.detail = detail
    live.emit({"type": "exit", "sid": live.info.sid, "code": exit_code, "state": state})
    _save(live)


def _save(live: _Live) -> None:
    """Persist the session as a RunRecord so it lands in the report. Never raises.

    The interleaved transcript (human input marked ``$ ``, output verbatim) is the
    record's stdout; stderr carries session-level notes (kill reason, reaper detail).
    Re-saved on every write/flush via INSERT OR REPLACE, so a crash mid-session still
    leaves the transcript-so-far on disk.
    """
    rec = live.record
    rec.stdout = live.transcript_text()
    rec.stderr = live.info.detail
    rec.exit_code = live.info.exit_code
    rec.finished_at = live.info.finished_at
    try:
        runstore.save_run(rec)
    except Exception:  # persistence must never crash a session
        pass


# --------------------------------------------------------------------------- #
# Output stream (SSE). Cursor-based so a reconnect replays the rolling tail.
# --------------------------------------------------------------------------- #


def iter_events(sid: str, after: int = -1) -> Iterator[dict[str, Any]]:
    """Yield this session's events, starting after sequence ``after``, then live ones.

    Read-only: subscribing never writes to the process. Ends when the session finishes
    and its backlog is drained, so the SSE response closes cleanly.
    """
    live = _get_live(sid)
    cursor = after
    while True:
        with live.cond:
            pending = [(seq, ev) for seq, ev in live.events if seq > cursor]
            if not pending:
                if live.info.finished_at is not None:
                    return
                live.cond.wait(timeout=1.0)
                pending = [(seq, ev) for seq, ev in live.events if seq > cursor]
        for seq, ev in pending:
            cursor = seq
            yield {**ev, "seq": seq}


# --------------------------------------------------------------------------- #
# Reaper — idle timeout / max lifetime / teardown. A caught shell left open is a
# liability, so an unattended session does not live forever.
# --------------------------------------------------------------------------- #


def _reap_once(now: float | None = None) -> list[str]:
    """Kill sessions past their idle timeout or max lifetime. Returns the sids killed."""
    now = time.monotonic() if now is None else now
    killed: list[str] = []
    with _registry_lock:
        candidates = list(_sessions.values())
    for live in candidates:
        if live.info.state != "active":
            continue
        if now - live.started_mono > SESSION_MAX_LIFETIME_SECONDS:
            kill(live.info.sid, reason=f"max lifetime {SESSION_MAX_LIFETIME_SECONDS}s reached")
            killed.append(live.info.sid)
        elif now - live.last_io > SESSION_IDLE_TIMEOUT_SECONDS:
            kill(live.info.sid, reason=f"idle for {SESSION_IDLE_TIMEOUT_SECONDS}s")
            killed.append(live.info.sid)
    return killed


def _ensure_reaper() -> None:
    """Start the idle-reaper thread once, lazily."""
    global _reaper
    with _registry_lock:
        if _reaper is not None and _reaper.is_alive():
            return
        t = threading.Thread(target=_reaper_loop, daemon=True, name="hackpit-session-reaper")
        _reaper = t
    t.start()


def _reaper_loop() -> None:  # pragma: no cover - background timing
    while True:
        time.sleep(30)
        try:
            _reap_once()
        except Exception:
            pass


def shutdown_all(reason: str = "backend shutting down") -> None:
    """Kill every live session — clean teardown on backend stop.

    Registered with :mod:`atexit` from inside this module rather than called from
    main.py ON PURPOSE: main.py hosts the orchestrator-loop endpoint, so importing this
    module there would force the human-only source scan to whitelist it. Keeping
    teardown self-contained keeps that allowlist at {session.py, router.py}.

    Best-effort, like any exit hook — a SIGKILL'd backend runs nothing. The idle reaper
    and the max-lifetime ceiling are the backstop for anything this misses.
    """
    with _registry_lock:
        sids = [s.info.sid for s in _sessions.values() if s.info.state == "active"]
    for sid in sids:
        try:
            kill(sid, reason=reason)
        except Exception:  # pragma: no cover - best effort
            pass


atexit.register(shutdown_all)


def session_status() -> dict[str, Any]:
    """Counts + bounds for the UI panel. Makes no isolation claim of its own."""
    with _registry_lock:
        sessions = list(_sessions.values())
    return {
        "live": sum(1 for s in sessions if s.info.state == "active"),
        "total": len(sessions),
        "max_live": MAX_LIVE_SESSIONS,
        "idle_timeout_seconds": SESSION_IDLE_TIMEOUT_SECONDS,
        "max_lifetime_seconds": SESSION_MAX_LIFETIME_SECONDS,
    }
