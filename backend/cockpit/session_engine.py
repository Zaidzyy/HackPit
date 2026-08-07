"""Named persistent tmux sessions — the interactive-tool engine, HUMAN-DRIVEN.

WHAT THIS IS (and why it is a THIRD surface, not a replacement)
`:kali` drives the open sandbox over a sentinel-delimited pipe (clean per-command
transcripts, the thing reports are built from). `terminal.py` adds a raw pty for
full-screen curses tooling. Both are one-shot-ish: neither gives you a *named*, *parallel*,
*persistent* session whose cwd/env/background-jobs survive across calls, and neither knows
when a program is sitting at an interactive prompt waiting for the next line.

This module is that engine. It drives NAMED tmux sessions inside the SAME open sandbox the
pty uses, so `msfconsole`, `sliver-client`, `evil-winrm` and ordinary REPLs become
first-class: you open a named session, run a command, and the engine tells you when the tool
is **waiting at an interactive prompt** so the operator can send the next line. Long scans
run in the background with a completion notification. Different names are independent parallel
sessions. Ported from Decepticon's `tools/bash/bash.py` + `tools/bash/prompt.py`
(Apache-2.0 — see THIRD_PARTY_LICENSES / NOTICE).

THE ONE THING WE DO NOT PORT — Decepticon's autonomy over stdin. In Decepticon the AGENT
drives everything, including sending a line to an interactive prompt (`is_input`). HackPit
takes the session *mechanics* and nothing else: **every input path here is HUMAN-ONLY**. Both
:func:`run_command` (send a command) and :func:`send_input` (answer a prompt / send a control
key, the `is_input` path) may be reached ONLY from the HTTP routes a human's UI action drives.
The orchestrator / agent / executor / proposer have ZERO code path to either — the same rule
:kali and the pty carry, source-scan locked by test_session_engine_safety.py. A named session
is a full-reach interactive process; anything able to type into it autonomously would be
autonomous attacks on host/LAN/internet.

CONTAINMENT — mirrors terminal.py / :kali exactly:

1. HARDCODED TARGET CONTAINER. Every tmux command is
       docker exec -i <KALI_OPEN_CONTAINER> tmux ...
   with the container taken from ``config.KALI_OPEN_CONTAINER`` — a code constant, NEVER a
   request field. The request models carry no container/target/host field, so nothing a
   client sends can redirect the exec. (Locked in test_session_engine_safety.py.)

2. HUMAN-ONLY input — the rule that matters most (above).

3. NO NEW GATE, NO ISOLATION GATE. Same as the pty: the open sandbox is intentionally not
   isolated, so there is nothing to assert, and this module must NOT import the isolation
   module, the executor, or call any gate. The human at the keyboard IS the approval, exactly
   as on the pty surface — "gated exactly as today" means neither surface's posture changes.

4. TWO-SANDBOX SEPARATION IS PRESERVED. The engine lives on the OPEN/terminal side. :kali's
   sentinel shell must never grow a pty *or* a tmux; this module never touches kali.py.

5. AUDIT. Each session's captured output is recorded to the run store (target = the open
   container) and tmux ``pipe-pane`` mirrors the raw stream to a per-session log under the
   engagement workspace's ``.sessions/`` — which a kill deliberately preserves.

PURE vs IMPURE. Every heuristic — prompt detection, output management, wedge and
pipe-degradation signatures, ANSI stripping, repetitive-line compression — is a pure function
tested directly against fixtures. The only impure boundary is :func:`_tmux`, one place that
shells out; the tests monkeypatch it, so the whole suite runs with no Docker and no tmux.
"""

from __future__ import annotations

import re
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, Field

from . import config, loot, runstore
from .models import RunRecord

# --------------------------------------------------------------------------- #
# Bounds + markers.
# --------------------------------------------------------------------------- #
# A foreground run that has not returned to a prompt within this window is AUTO-BACKGROUNDED,
# so a slow scan can never wedge the request that launched it. Ported from Decepticon's 60s.
AUTO_BACKGROUND_SECONDS = float(__import__("os").environ.get("HACKPIT_SX_AUTOBG", "60"))
# How long a single foreground poll waits between captures while watching for completion.
POLL_INTERVAL_SECONDS = float(__import__("os").environ.get("HACKPIT_SX_POLL", "0.5"))
# Output management thresholds (Decepticon's ≤15K inline / >15K to scratch / >5M watchdog).
INLINE_OUTPUT_CAP = 15_000       # chars returned inline
WATCHDOG_OUTPUT_CAP = 5_000_000  # chars past which output is force-truncated, never buffered
# Scrollback captured from a pane, in lines. Bounds one capture regardless of tmux history.
CAPTURE_LINES = 2_000
# How many sessions may be live at once.
MAX_LIVE_SESSIONS = int(__import__("os").environ.get("HACKPIT_SX_MAX_LIVE", "8"))
# The audited transcript cap per session, matching the pty surface.
TRANSCRIPT_CAP = 200_000
# Cap one human input line (a paste bomb is not a feature) — matches the C2 panel.
INPUT_MAX_BYTES = 8_192

# The PROMPT sentinel. The session shell's PROMPT_COMMAND prints this with the last command's
# exit code AND the current working directory every time it is about to draw a prompt, so
# "idle at a shell prompt", "a command just finished (rc=N)" and "which directory this session
# is in" are all detectable from a capture, without a pty. This is what makes each named
# session's cwd track independently. A CONSTANT — never interpolated with anything a client
# sends. Modelled on :kali's per-command sentinel.
MARKER = "__HACKPIT_SX__"
# __HACKPIT_SX__:<rc>:<cwd>:__  — cwd is [^:] so a rare colon in a path degrades to "not
# parsed" rather than a wrong value.
_MARKER_RE = re.compile(re.escape(MARKER) + r":(-?\d+):([^:\n]*):" + re.escape("__"))

# The tmux session-name prefix. A named session "web" becomes tmux session "hpsx_web".
TMUX_PREFIX = "hpsx"

# Session names: a plain safe token, refused (not sanitised) otherwise — the same discipline
# loot.py uses, because the name lands in a tmux target and a host log path.
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$")


# --------------------------------------------------------------------------- #
# 1. PURE HEURISTICS — the tested core. No I/O anywhere below this line until _tmux.
# --------------------------------------------------------------------------- #
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07]*\x07|\r")


def strip_ansi(text: str) -> str:
    """Remove ANSI/OSC escape sequences and bare CRs, leaving readable text.

    A capture of msfconsole or a coloured shell is dense with escapes; the report and the
    prompt detector both want the plain characters. Newlines are kept; a lone ``\\r`` (a
    progress bar rewinding a line) is dropped so the compression pass sees distinct lines.
    """
    return _ANSI_RE.sub("", text)


def compress_repeats(text: str, *, keep: int = 3) -> str:
    """Collapse a run of identical lines to ``keep`` plus a count note.

    A stuck progress loop or a `yes`-like flood turns a capture into thousands of identical
    lines that tell an operator nothing. Runs of the SAME line are compressed; distinct lines
    are untouched, so real output is never lost.
    """
    out: list[str] = []
    lines = text.split("\n")
    i = 0
    while i < len(lines):
        j = i
        while j < len(lines) and lines[j] == lines[i]:
            j += 1
        run = j - i
        if run > keep + 1:
            out.extend([lines[i]] * keep)
            out.append(f"…[previous line repeated {run - keep} more times]…")
        else:
            out.extend(lines[i:j])
        i = j
    return "\n".join(out)


# The interactive-prompt table. ORDER MATTERS: the shell marker is checked first (an idle
# shell is not "interactive — awaiting input"), then the named tools, then generic REPLs and
# yes/no/password prompts. Each entry is (program-label, compiled-regex-over-the-last-line).
_PROMPT_PATTERNS: list[tuple[str, "re.Pattern[str]"]] = [
    ("msfconsole", re.compile(r"^\s*msf\d*\s.*?>\s*$|^\s*msf\d*\s*>\s*$")),
    ("msfconsole", re.compile(r"^\s*(meterpreter|msf\d*\s+\w+\([^)]*\))\s*>\s*$")),
    ("sliver", re.compile(r"^\s*sliver(\s*\([^)]*\))?\s*>\s*$")),
    ("evil-winrm", re.compile(r"\*Evil-WinRM\*\s+PS\s.*?>\s*$")),
    ("powershell", re.compile(r"^\s*PS\s+[A-Za-z]:\\.*?>\s*$")),
    ("python", re.compile(r"^>>>\s*$|^\.\.\.\s*$")),
    ("ruby-irb", re.compile(r"^irb\(.*\)[:>]\s*$")),
    ("sql", re.compile(r"^\s*(mysql|MariaDB \[[^\]]*\]|SQL|postgres(=#)?)\s*>?\s*$")),
    ("ftp", re.compile(r"^ftp>\s*$")),
    ("cmd-prompt", re.compile(r"^[A-Za-z]:\\.*?>\s*$")),
    # A tool waiting on a free-text answer: yes/no, a password, a "Press enter", a colon prompt.
    ("awaiting-answer", re.compile(
        r"(\[[yY]/[nN]\]|\([yY]es/[nN]o\)|password\s*:|passphrase\s*:|"
        r"press\s+(enter|any\s+key)|continue\?|\benter\b.*:)\s*$", re.IGNORECASE)),
]


@dataclass(frozen=True)
class PromptState:
    """What a captured pane's tail says the session is doing right now.

    ``kind`` is one of:
        "idle"        — sitting at the shell prompt (our MARKER), ready for a command;
        "interactive" — a program is WAITING AT AN INTERACTIVE PROMPT for the next line
                        (this is the headline: the UI raises "interactive — send input");
        "running"     — a command is in flight, no prompt visible yet.
    ``program`` names the interactive tool when known (msfconsole/sliver/…); "" otherwise.
    ``rc`` is the last command's exit code when an idle marker carried one, else None.
    """

    kind: str
    program: str = ""
    prompt_line: str = ""
    rc: int | None = None
    cwd: str = ""


def _last_nonempty_lines(text: str, n: int = 4) -> list[str]:
    lines = [ln.rstrip() for ln in text.split("\n")]
    while lines and not lines[-1].strip():
        lines.pop()
    return lines[-n:]


def detect_prompt(pane_text: str) -> PromptState:
    """Classify the tail of a (already ANSI-stripped or raw) capture. PURE.

    The whole upgrade over the one-shot surfaces rests on this: knowing that a program has
    stopped and is waiting for the human, versus still running, versus back at a shell.
    """
    text = strip_ansi(pane_text)
    tail = _last_nonempty_lines(text, 4)
    if not tail:
        return PromptState(kind="running")
    last = tail[-1]

    # An idle SHELL prompt: our marker was the last thing printed. Not "interactive" — the
    # shell is ready for a command, and a command run is the human clicking run, not a prompt.
    for line in reversed(tail):
        m = _MARKER_RE.search(line)
        if m:
            # The marker is only "idle now" if it is the LAST marker and nothing followed it
            # on a later line that looks like new program output waiting for input.
            if line is last or _MARKER_RE.search(last):
                return PromptState(kind="idle", program="shell",
                                   rc=int(m.group(1)), cwd=m.group(2))
            break

    # An interactive TOOL prompt.
    for program, rx in _PROMPT_PATTERNS:
        if rx.search(last):
            return PromptState(kind="interactive", program=program, prompt_line=last)

    return PromptState(kind="running")


@dataclass(frozen=True)
class OutputResult:
    """The result of preparing captured output for return (Decepticon's tiering)."""

    inline: str
    saved_path: str | None
    total_chars: int
    truncated: bool
    watchdog: bool


def manage_output(
    text: str,
    *,
    name: str,
    save=None,
    inline_cap: int = INLINE_OUTPUT_CAP,
    watchdog_cap: int = WATCHDOG_OUTPUT_CAP,
) -> OutputResult:
    """Tier one blob of captured output. PURE except for the injected ``save`` writer.

    ≤ inline_cap        -> returned inline, nothing saved.
    inline_cap..watchdog -> a HEAD+TAIL preview returned inline, the FULL text handed to
                            ``save(name, text) -> path`` and the path returned.
    > watchdog_cap       -> force-truncated to the watchdog cap BEFORE anything is buffered or
                            written, so a runaway producer cannot exhaust memory or disk; the
                            preview says so.

    ``save`` is injected (never called at import) so the tests exercise every tier with no
    filesystem. When ``save`` is None the full text is not persisted — only the preview and
    the honest ``truncated`` flag come back.
    """
    total = len(text)
    watchdog = total > watchdog_cap
    body = text[:watchdog_cap] if watchdog else text

    if len(body) <= inline_cap and not watchdog:
        return OutputResult(inline=body, saved_path=None, total_chars=total,
                            truncated=False, watchdog=False)

    head = body[: inline_cap // 2]
    tail = body[-inline_cap // 2:]
    note = (f"\n…[{total - inline_cap} chars omitted"
            + (" — WATCHDOG: output exceeded the 5M cap and was truncated at source" if watchdog
               else "")
            + "]…\n")
    preview = head + note + tail
    saved_path = None
    if save is not None:
        try:
            saved_path = save(name, body)
        except Exception:  # persistence is a convenience, never fatal to a capture
            saved_path = None
    return OutputResult(inline=preview, saved_path=saved_path, total_chars=total,
                        truncated=True, watchdog=watchdog)


@dataclass(frozen=True)
class RecoveryVerdict:
    """A wedge / pipe-degradation diagnosis plus the operator-facing recovery ladder."""

    triggered: bool
    reasons: list[str]
    actions: list[str]


def detect_wedge(
    *,
    command_pending: bool,
    seconds_since_send: float,
    pane_changed: bool,
    marker_returned: bool,
    threshold: float = AUTO_BACKGROUND_SECONDS,
) -> RecoveryVerdict:
    """The WEDGED-SESSION signature (three conditions), with a recovery ladder. PURE.

    A session is wedged, not merely slow, when ALL of:
        (1) a command was sent and is still pending (no completion marker),
        (2) it has been longer than the threshold since it was sent, AND
        (3) the pane is NOT changing between captures (no progress at all).
    A slow-but-alive scan fails (3) — its pane keeps changing — so it is backgrounded, not
    flagged wedged. Only the genuinely stuck case (a full-screen program that died, a prompt
    the pty never delivered) lights all three.

    The ladder is operator-facing (this module never sends input autonomously): send a newline,
    then Ctrl-C, then Ctrl-Q/Ctrl-C for a flow-controlled pane, then respawn the pane.
    """
    reasons: list[str] = []
    if command_pending:
        reasons.append("a command is still pending (no completion marker)")
    if seconds_since_send >= threshold:
        reasons.append(f"no prompt for {seconds_since_send:.0f}s (≥ {threshold:.0f}s)")
    if not pane_changed:
        reasons.append("the pane has not changed between two captures (no progress)")
    triggered = command_pending and not marker_returned and seconds_since_send >= threshold \
        and not pane_changed
    actions = ([
        "send a newline (the program may be waiting on one)",
        "send Ctrl-C to interrupt",
        "send Ctrl-Q then Ctrl-C (a flow-controlled pane frozen by Ctrl-S)",
        "respawn the pane (tmux respawn-pane) — the session and its cwd survive",
    ] if triggered else [])
    return RecoveryVerdict(triggered=triggered, reasons=reasons, actions=actions)


def detect_pipe_degradation(
    *,
    pane_changed: bool,
    log_grew: bool,
    capture_works: bool,
) -> RecoveryVerdict:
    """The tmux PIPE-PANE DEGRADATION signature (three conditions). PURE.

    ``pipe-pane`` mirrors a pane to a log file; the pipe can silently break (the child of the
    pipe dies) while the pane itself is perfectly healthy. The signature is:
        (1) the pane IS changing (the session is alive and producing output), BUT
        (2) the log file is NOT growing, AND
        (3) capture-pane still works (so it is the PIPE that degraded, not the session).
    The recovery is to re-establish the pipe — never to touch the session — so the audit log
    resumes without disturbing what the operator is doing.
    """
    reasons: list[str] = []
    if pane_changed:
        reasons.append("the pane is changing (the session is alive and producing output)")
    if not log_grew:
        reasons.append("the pipe-pane log has stopped growing")
    if capture_works:
        reasons.append("capture-pane still works (the session is fine — only the pipe broke)")
    triggered = pane_changed and not log_grew and capture_works
    actions = ([
        "re-establish logging: tmux pipe-pane -o -t <session> 'cat >> <log>'",
        "the session, its cwd and its running program are untouched by this",
    ] if triggered else [])
    return RecoveryVerdict(triggered=triggered, reasons=reasons, actions=actions)


# --------------------------------------------------------------------------- #
# 2. Public models.
# --------------------------------------------------------------------------- #
class SessionOpenRequest(BaseModel):
    """Open a named persistent session in the OPEN sandbox.

    NOTE — deliberately NO container / target / host / shell field. The box and the shell are
    code constants; the request contributes a name and an optional engagement to file the
    transcript under, and nothing that can redirect the exec (containment rule #1).
    """

    name: str = Field(..., min_length=1, max_length=32,
                      description="Session name — a plain token [A-Za-z0-9_-]. Different "
                                  "names are independent parallel sessions.")
    session_id: str | None = Field(
        None, description="Optional engagement to record this session's transcript against.")


class SessionRunRequest(BaseModel):
    """Run ONE command in a named session. HUMAN-ONLY (the human clicked run)."""

    command: str = Field(..., min_length=1, description="The command line to run in the session.")
    background: bool = Field(
        False, description="Start detached; return a job id immediately and notify on "
                           "completion. A long scan runs here without holding the request.")


class SessionInputRequest(BaseModel):
    """One line a HUMAN typed to a session's interactive prompt (the ``is_input`` path).

    This is the msfconsole/sliver/evil-winrm answer path: a raw line (or a control key) sent
    to a program waiting at a prompt. HUMAN-ONLY, exactly like the command path.
    """

    data: str = Field(..., description="The line/keys to send. A newline is appended unless "
                                       "``enter`` is false.")
    enter: bool = Field(True, description="Append Enter after the data (false to send raw keys, "
                                          "e.g. a bare Ctrl-C).")


class BackgroundJobInfo(BaseModel):
    """One backgrounded command in a session."""

    job_id: str
    session: str
    command: str
    started_at: str
    state: str  # "running" | "done" | "consumed"
    rc: int | None = None
    notified: bool = False


class SessionInfo(BaseModel):
    """The public state of one named session (no live output — capture returns that)."""

    name: str
    tmux: str
    container: str
    run_id: str
    state: str  # "active" | "killed"
    started_at: str
    cwd: str
    program: str  # the interactive tool detected, or "" / "shell"
    prompt_kind: str  # "idle" | "interactive" | "running"
    awaiting_input: bool
    log_path: str
    background_jobs: list[BackgroundJobInfo] = Field(default_factory=list)
    session_id: str | None = None


class SessionRefused(RuntimeError):
    """The session engine could not do the thing (nothing ran). AVAILABILITY, not a gate."""


class SessionNotFound(KeyError):
    """No live session with that name."""


# --------------------------------------------------------------------------- #
# 3. The registry + the ONE impure boundary.
# --------------------------------------------------------------------------- #
@dataclass
class _BgJob:
    job_id: str
    session: str
    command: str
    started_at: str
    started_mono: float
    state: str = "running"
    rc: int | None = None
    notified: bool = False


@dataclass
class _Session:
    name: str
    tmux: str
    run_id: str
    started_at: str
    started_mono: float
    log_path: str
    session_id: str | None
    cwd: str = "~"
    program: str = "shell"
    prompt_kind: str = "idle"
    state: str = "active"
    last_capture: str = ""
    last_io: float = 0.0
    transcript: list[str] = field(default_factory=list)
    transcript_len: int = 0
    truncated: bool = False
    jobs: dict[str, _BgJob] = field(default_factory=dict)
    lock: "threading.Lock" = field(default_factory=threading.Lock)


_sessions: dict[str, _Session] = {}
_sessions_lock = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _mono() -> float:
    return time.monotonic()


def _container_running(name: str) -> bool:
    """True iff the named container exists and is running (availability only)."""
    try:
        p = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", name],
            capture_output=True, text=True, timeout=10.0,
        )
        return p.returncode == 0 and p.stdout.strip() == "true"
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def _tmux(args: list[str], *, input_text: str | None = None, timeout: float = 15.0):
    """THE ONE IMPURE BOUNDARY. Run ``tmux <args>`` inside the hardcoded open container.

    Everything above this is pure and everything below routes through here, so the whole test
    suite runs by monkeypatching this single function — no Docker, no tmux. ``-i`` is used only
    when we feed keystrokes on stdin (send-keys -l via ``load-buffer -`` style is avoided; we
    pass literal data as an argv token so no shell parses it).

    Returns the CompletedProcess. Never raises for a non-zero tmux rc — the caller decides what
    a failure means; only a missing docker CLI degrades to a refusal upstream.
    """
    argv = ["docker", "exec"]
    if input_text is not None:
        argv.append("-i")
    argv += [config.KALI_OPEN_CONTAINER, "tmux", *args]
    return subprocess.run(
        argv, capture_output=True, text=True,
        input=input_text, timeout=timeout,
    )


# The container-side session bootstrap: set a PROMPT_COMMAND that prints the MARKER with the
# last exit code before every prompt, and point pipe-pane at the per-session log. A CONSTANT
# format string; only the (validated) tmux name and the (constant-shaped) log path are filled,
# never anything a client typed as free text.
def _bootstrap_commands(tmux_name: str, log_path: str) -> list[list[str]]:
    ps = (f"export PROMPT_COMMAND='printf \"\\n{MARKER}:%s:%s:__\\n\" \"$?\" \"$PWD\"'; "
          f"export PS1='' ; clear")
    return [
        ["send-keys", "-t", tmux_name, ps, "Enter"],
        # -o: only pipe new output; the log lives in the engagement workspace's .sessions/.
        ["pipe-pane", "-o", "-t", tmux_name, f"cat >> {log_path}"],
    ]


# --------------------------------------------------------------------------- #
# 4. Lifecycle (impure — but only via _tmux, so hermetic under a fake).
# --------------------------------------------------------------------------- #
def _sessions_root() -> Path:
    """Host path for the per-session logs — under the :kali workspace's .sessions/."""
    base = loot.host_dir(loot.KALI_DIRNAME) / ".sessions"
    return base


def open_session(req: SessionOpenRequest) -> SessionInfo:
    """Create a named tmux session in the OPEN sandbox. HUMAN-ONLY (route-driven).

    Availability check only — there is no isolation gate for the open box. The container, the
    shell and the bootstrap are constants; the request contributes a validated name and an
    optional engagement id.
    """
    name = (req.name or "").strip()
    if not _SAFE_NAME.match(name):
        raise SessionRefused(f"invalid session name {name!r} — use [A-Za-z0-9_-], ≤32 chars")

    with _sessions_lock:
        if name in _sessions and _sessions[name].state == "active":
            raise SessionRefused(f"session {name!r} already exists")
        live = sum(1 for s in _sessions.values() if s.state == "active")
        if live >= MAX_LIVE_SESSIONS:
            raise SessionRefused(
                f"too many live sessions ({live}/{MAX_LIVE_SESSIONS}) — kill one first")

    if not _container_running(config.KALI_OPEN_CONTAINER):
        raise SessionRefused(
            f"open sandbox '{config.KALI_OPEN_CONTAINER}' is not running — bring the stack up "
            "(docker compose -f docker/docker-compose.yml up -d)")

    tmux_name = f"{TMUX_PREFIX}_{name}"
    # Start in the engagement workspace so a session's downloads survive a compose down, and
    # so pipe-pane can write its log there. Container-side path.
    workdir = loot.kali_workdir() or "/root"
    log_host = _sessions_root()
    try:
        log_host.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    log_container = f"{loot.container_dir(loot.KALI_DIRNAME)}/.sessions/{name}.log"

    try:
        _tmux(["new-session", "-d", "-s", tmux_name, "-x", "220", "-y", "50", "-c", workdir])
    except FileNotFoundError:
        raise SessionRefused("docker CLI not found on PATH")
    for cmd in _bootstrap_commands(tmux_name, log_container):
        try:
            _tmux(cmd)
        except FileNotFoundError:
            raise SessionRefused("docker CLI not found on PATH")

    run_id = uuid.uuid4().hex[:12]
    sess = _Session(
        name=name, tmux=tmux_name, run_id=run_id, started_at=_now(), started_mono=_mono(),
        log_path=str(log_host / f"{name}.log"), session_id=req.session_id,
        cwd=workdir, last_io=_mono(),
    )
    with _sessions_lock:
        _sessions[name] = sess
    _record(sess, finished=False)
    return _info(sess)


def _get(name: str) -> _Session:
    with _sessions_lock:
        sess = _sessions.get(name)
    if sess is None:
        raise SessionNotFound(name)
    return sess


def get_session(name: str) -> SessionInfo:
    return _info(_get(name))


def list_sessions() -> list[SessionInfo]:
    with _sessions_lock:
        sessions = sorted(_sessions.values(), key=lambda s: s.started_at)
    return [_info(s) for s in sessions]


# --------------------------------------------------------------------------- #
# 5. INPUT — *** HUMAN-ONLY ***. The load-bearing invariant of this module.
# --------------------------------------------------------------------------- #
def _send_keys(sess: _Session, data: str, *, enter: bool) -> None:
    """Send literal keystrokes to a session's tmux pane. Internal to the human-only paths.

    ``-l`` sends the data literally so a token like ``$(id)`` is typed, not interpreted by
    send-keys' own key parsing. The bytes are one argv token, so no shell parses them either.
    """
    if len(data.encode("utf-8", "replace")) > INPUT_MAX_BYTES:
        raise SessionRefused(f"input too large (cap {INPUT_MAX_BYTES} bytes for one line)")
    _tmux(["send-keys", "-t", sess.tmux, "-l", data])
    if enter:
        _tmux(["send-keys", "-t", sess.tmux, "Enter"])
    sess.last_io = _mono()


def run_command(name: str, req: SessionRunRequest, *, sleep=None, clock=None) -> dict:
    """Run ONE command in a named session. *** HUMAN-ONLY — see the module docstring. ***

    This is the human clicking "run" in the session panel. It sends the command, then watches
    for the completion marker up to :data:`AUTO_BACKGROUND_SECONDS`:

        completes in time            -> the output (managed/tiered) comes back inline;
        background=True              -> returns immediately, [BACKGROUND], with a job id;
        still running past the window -> AUTO-BACKGROUNDED, [AUTO-BACKGROUND], with a job id.

    The orchestrator has NO path here — a named session is a full-reach interactive process, so
    the only thing that may drive it is a human at the keyboard. ``sleep`` / ``clock`` are
    injected so the auto-background window is exercised instantly in tests.
    """
    sess = _get(name)
    if sess.state != "active":
        raise SessionRefused(f"session {name!r} is {sess.state}")
    sleep = sleep or time.sleep
    clock = clock or _mono

    job = _BgJob(job_id=uuid.uuid4().hex[:8], session=name, command=req.command,
                 started_at=_now(), started_mono=clock())
    with sess.lock:
        sess.jobs[job.job_id] = job

    # Echo the command into the transcript, then send it.
    _observe(sess, f"$ {req.command}\n")
    _send_keys(sess, req.command, enter=True)

    if req.background:
        job.state = "running"
        return {"marker": "[BACKGROUND]", "job_id": job.job_id,
                "detail": f"running in the background in session {name!r}", "output": ""}

    start = clock()
    while clock() - start < AUTO_BACKGROUND_SECONDS:
        sleep(POLL_INTERVAL_SECONDS)
        pane = _capture_raw(sess)
        done = _completion(pane, since=job.started_at)
        if done is not None:
            job.state = "done"
            job.rc = done
            job.notified = True  # a foreground completion is delivered in the return value
            out = _prepare_capture(sess, pane)
            return {"marker": "[DONE]", "job_id": job.job_id, "rc": done,
                    "output": out.inline, "saved_path": out.saved_path,
                    "prompt": _prompt_dict(pane)}
        prompt = detect_prompt(pane)
        if prompt.kind == "interactive":
            # The program is waiting on the human — stop watching, surface it, let them answer.
            out = _prepare_capture(sess, pane)
            return {"marker": "[INTERACTIVE]", "job_id": job.job_id,
                    "output": out.inline, "prompt": _prompt_dict(pane),
                    "detail": f"{prompt.program} is awaiting input — send the next line"}

    # Window elapsed with no prompt: hand it to the background tracker.
    job.state = "running"
    return {"marker": "[AUTO-BACKGROUND]", "job_id": job.job_id,
            "detail": f"still running after {AUTO_BACKGROUND_SECONDS:.0f}s — moved to the "
                      f"background in session {name!r}; a completion will notify once",
            "output": _prepare_capture(sess, _capture_raw(sess)).inline}


def send_input(name: str, req: SessionInputRequest) -> SessionInfo:
    """Send one line/keys to a session's interactive prompt (the ``is_input`` path).

    *** HUMAN-ONLY. *** This is the operator answering msfconsole / sliver / evil-winrm — a
    program sitting at an interactive prompt. It is a sibling of :func:`run_command`, and it
    carries the SAME rule: reachable only from the human-driven HTTP route, never from the
    orchestrator / agent / executor / proposer. In Decepticon the agent could set ``is_input``
    to drive a prompt autonomously; HackPit does not adopt that — the value of a live prompt is
    exactly what an autonomous agent must never be handed.
    """
    sess = _get(name)
    if sess.state != "active":
        raise SessionRefused(f"session {name!r} is {sess.state}")
    _observe(sess, f"$ {req.data}\n")
    _send_keys(sess, req.data, enter=req.enter)
    _record(sess, finished=False)
    return _info(sess)


# --------------------------------------------------------------------------- #
# 6. Capture, background polling, kill.
# --------------------------------------------------------------------------- #
def _capture_raw(sess: _Session) -> str:
    """Capture the pane (bounded scrollback). ANSI-stripped. READ-ONLY."""
    try:
        p = _tmux(["capture-pane", "-t", sess.tmux, "-p", "-S", f"-{CAPTURE_LINES}"])
    except FileNotFoundError:
        return ""
    text = strip_ansi(getattr(p, "stdout", "") or "")
    return compress_repeats(text)


def _completion(pane: str, *, since: str) -> int | None:
    """The exit code of the most recent completed command, or None if still running.

    A command is "done" when a fresh MARKER (with its rc) is the last marker in the pane and
    it is at or after the tail — i.e. the shell has drawn a new prompt since the command was
    sent. ``since`` is accepted for symmetry with a timestamped model; detection is by the
    marker being the current tail, which is what actually proves the prompt returned.
    """
    prompt = detect_prompt(pane)
    if prompt.kind == "idle" and prompt.rc is not None:
        return prompt.rc
    return None


def _prompt_dict(pane: str) -> dict:
    p = detect_prompt(pane)
    return {"kind": p.kind, "program": p.program, "line": p.prompt_line,
            "awaiting_input": p.kind == "interactive"}


def _save_to_scratch(name: str, text: str) -> str | None:
    """Write oversize output to the workspace .scratch/ and return the CONTAINER path."""
    try:
        host = loot.host_dir(loot.KALI_DIRNAME) / ".scratch"
        host.mkdir(parents=True, exist_ok=True)
        fn = f"{name}-{uuid.uuid4().hex[:8]}.txt"
        (host / fn).write_text(text, encoding="utf-8", errors="replace")
        return f"{loot.container_dir(loot.KALI_DIRNAME)}/.scratch/{fn}"
    except OSError:
        return None


def _prepare_capture(sess: _Session, pane: str) -> OutputResult:
    """Update the session's derived state from a capture, record it, and tier the output."""
    prompt = detect_prompt(pane)
    with sess.lock:
        sess.last_capture = pane
        sess.prompt_kind = prompt.kind
        if prompt.program:
            sess.program = prompt.program
        # Each named session's cwd tracks independently — parsed from ITS OWN marker.
        if prompt.cwd:
            sess.cwd = prompt.cwd
    _observe(sess, "")  # touch last_io / checkpoint without duplicating pane text
    return manage_output(pane, name=sess.name, save=_save_to_scratch)


def capture(name: str) -> dict:
    """The live view of a session: managed output + the current prompt state. READ-ONLY."""
    sess = _get(name)
    pane = _capture_raw(sess)
    out = _prepare_capture(sess, pane)
    return {"name": name, "output": out.inline, "saved_path": out.saved_path,
            "truncated": out.truncated, "watchdog": out.watchdog,
            "prompt": _prompt_dict(pane), "state": sess.state,
            "jobs": [_job_info(j).model_dump() for j in sess.jobs.values()]}


def poll_jobs() -> list[BackgroundJobInfo]:
    """Check every running background job and return newly-completed ones — notified ONCE.

    Mirrors HackPit's job/OBSERVE notification contract: a completion is inlined exactly once
    (``notified`` flips), and the same job read again reports state "consumed" and is not
    re-notified. READ-ONLY with respect to the sessions — it only captures.
    """
    fresh: list[BackgroundJobInfo] = []
    with _sessions_lock:
        sessions = list(_sessions.values())
    for sess in sessions:
        if sess.state != "active":
            continue
        pane = _capture_raw(sess)
        rc = _completion(pane, since=sess.started_at)
        with sess.lock:
            for job in sess.jobs.values():
                if job.state == "running" and rc is not None:
                    job.state = "done"
                    job.rc = rc
                if job.state == "done" and not job.notified:
                    job.notified = True
                    fresh.append(_job_info(job))
    return fresh


def consume_job(name: str, job_id: str) -> BackgroundJobInfo:
    """Mark a completed job's notification consumed, so the tracker stops flagging it."""
    sess = _get(name)
    with sess.lock:
        job = sess.jobs.get(job_id)
        if job is None:
            raise SessionNotFound(f"{name}:{job_id}")
        if job.state == "done":
            job.state = "consumed"
        return _job_info(job)


def kill_session(name: str, reason: str = "killed by operator") -> SessionInfo:
    """Kill a named session's tmux — PRESERVING its log under .sessions/. Idempotent.

    The log is deliberately NOT removed: it is the audit trail of an interactive session, and
    a kill is exactly when you most want to keep it. The run record is finalised too.
    """
    sess = _get(name)
    if sess.state == "killed":
        return _info(sess)
    try:
        _tmux(["kill-session", "-t", sess.tmux])
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    with sess.lock:
        sess.state = "killed"
    _record(sess, finished=True)
    return _info(sess)


# --------------------------------------------------------------------------- #
# 7. Audit + views.
# --------------------------------------------------------------------------- #
def _observe(sess: _Session, text: str) -> None:
    """Accumulate the audited transcript, capped, and touch last_io."""
    sess.last_io = _mono()
    if text and not sess.truncated:
        room = TRANSCRIPT_CAP - sess.transcript_len
        if room <= 0:
            sess.truncated = True
        else:
            chunk = text[:room]
            sess.transcript.append(chunk)
            sess.transcript_len += len(chunk)
            if len(text) > room:
                sess.truncated = True


def _transcript(sess: _Session) -> str:
    text = "".join(sess.transcript)
    if sess.truncated:
        text += "\n…[transcript truncated]…"
    return text


def _record(sess: _Session, *, finished: bool) -> None:
    """Write (or update) this session's run record. Never raises."""
    try:
        runstore.save_run(RunRecord(
            run_id=sess.run_id,
            command="session",
            args=["tmux", sess.name],
            target=config.KALI_OPEN_CONTAINER,
            approved=True,  # a human at the keyboard IS the approval, same as :kali / the pty
            exit_code=None,
            stdout=_transcript(sess),
            stderr="" if not finished else f"[session {sess.state}]",
            started_at=sess.started_at,
            finished_at=_now() if finished else None,
            session_id=sess.session_id,
            step_id=None,
        ))
    except Exception:  # persistence must never crash a live session
        pass


def _job_info(job: _BgJob) -> BackgroundJobInfo:
    return BackgroundJobInfo(
        job_id=job.job_id, session=job.session, command=job.command,
        started_at=job.started_at, state=job.state, rc=job.rc, notified=job.notified)


def _info(sess: _Session) -> SessionInfo:
    return SessionInfo(
        name=sess.name, tmux=sess.tmux, container=config.KALI_OPEN_CONTAINER,
        run_id=sess.run_id, state=sess.state, started_at=sess.started_at, cwd=sess.cwd,
        program=sess.program, prompt_kind=sess.prompt_kind,
        awaiting_input=sess.prompt_kind == "interactive", log_path=sess.log_path,
        background_jobs=[_job_info(j) for j in sess.jobs.values()],
        session_id=sess.session_id)


def engine_status() -> dict:
    """Availability of the named-session engine — drives the UI banner.

    Makes NO isolation claim (there is none): the banner says 'full network reach · NOT
    isolated', exactly like :kali's and the pty's.
    """
    up = _container_running(config.KALI_OPEN_CONTAINER)
    with _sessions_lock:
        live = sum(1 for s in _sessions.values() if s.state == "active")
    return {
        "container": config.KALI_OPEN_CONTAINER,
        "isolated": False,  # intentionally — the open sandbox has full network reach
        "up": up,
        "ready": up,
        "live": live,
        "max_live": MAX_LIVE_SESSIONS,
        "auto_background_seconds": AUTO_BACKGROUND_SECONDS,
        "detail": "" if up else "open sandbox container is not running",
    }
