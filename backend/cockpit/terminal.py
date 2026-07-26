"""Raw PTY terminal — a SECOND :kali surface, not a replacement for the sentinel shell.

WHY THIS EXISTS (and why the old shell stays exactly as it is)
`kali.py` drives the open sandbox over a plain pipe, delimiting each command with a
per-command sentinel. That buys clean, per-command, escape-free transcripts — the thing
reports and the audit log are built from — at the cost of full-screen tooling: `vim`,
`top`, an interactive `msfconsole`, a raw `evil-winrm` shell and `python -c 'pty.spawn'`
upgrades all need a real terminal.

This module adds the real terminal as a SEPARATE surface. It does not touch, wrap or
replace either runner in `kali.py` — the one-shot exec and the persistent sentinel shell
both keep producing the clean, escape-free per-command transcripts reports are built from.
You get both: auditable per-command blocks on `/kali`, full-screen interaction here.
(Their names are deliberately not spelled out here: :kali's own human-only test matches on
a PLAIN SUBSTRING across the tree, so naming them would make this module look like an
agent-side caller of the shell.)

CONTAINMENT — mirrors :kali exactly (see kali.py's header for the full model):

1. HARDCODED TARGET CONTAINER. Every spawn is
       docker exec -i <KALI_OPEN_CONTAINER> python3 -u -c <driver>
   with the container name taken from ``config.KALI_OPEN_CONTAINER`` — a code constant,
   NEVER a field in the request. ``TerminalStartRequest`` carries no container/target/host
   field, and the driver source is a module constant with no interpolation, so nothing a
   client sends can redirect the exec or change what runs. (Locked in test_terminal.py.)

2. HUMAN-ONLY — the rule that matters most. This is a full-reach interactive terminal, so
   an autonomous agent wired to it = autonomous attacks on the host, LAN and internet.
   ``open_terminal`` / ``write_input`` may be referenced ONLY by the WebSocket route in
   router.py; the orchestrator / agent / executor must have ZERO path here. (Locked by
   test_terminal_is_human_only, which scans the source tree exactly like :kali's.)

3. NO ISOLATION GATE — same as :kali, and for the same reason: the open sandbox is
   intentionally not isolated, so there is nothing to assert. This module must NOT import
   the isolation module or call its proof assertion; the cockpit executor's isolation gate
   is separate and stays untouched. Only an availability check remains. (The test that
   locks this matches on a PLAIN SUBSTRING, so do not name that function anywhere in this
   file — the same trap the cockpit/arsenal decoupling test sets.)

4. AUDIT. The RAW stream is recorded to the M1 run store under one run id per terminal
   session (target = the open container). A pty echoes what is typed, so the raw transcript
   is a complete record of both directions. It is capped and checkpointed as it grows, so a
   crashed backend still leaves the transcript behind.

5. LOCAL-ONLY, AUTH REQUIRED BEFORE EXPOSURE. Identical to :kali, and if anything more
   load-bearing: this is an unauthenticated interactive terminal onto a box that reaches
   your host and LAN. The route additionally pins the WebSocket Origin to localhost:3000.

HOW THE PTY IS ALLOCATED (and why not `docker exec -it`)
`docker exec -t` refuses unless the CLIENT's stdin is a terminal, and a WebSocket handler
has no TTY to offer. So the pty is allocated INSIDE the container by a small driver
(``_PTY_DRIVER``) that `pty.fork()`s a shell and multiplexes it over the plain stdin/stdout
pipes `docker exec -i` gives us. That also makes the window size controllable: the driver
speaks a tiny framed protocol on its stdin —

    b'\\x00' + uint32 length + payload   ->  write payload to the pty master (keystrokes)
    b'\\x01' + uint32 length + b'COLSxROWS' -> ioctl TIOCSWINSZ on the pty master

— while its stdout is the raw pty byte stream, unframed, so it can go straight to xterm.js.
Framing the INPUT side is what makes resize possible without stealing bytes out of the
keystroke stream (an in-band escape would be indistinguishable from something the operator
actually typed). Nothing is parsed by a shell anywhere in that path.
"""

from __future__ import annotations

import os
import struct
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from pydantic import BaseModel, Field

from . import config, loot, runstore
from .models import RunRecord

# --------------------------------------------------------------------------- #
# Bounds. An interactive terminal must not accumulate forever or flood the log.
# --------------------------------------------------------------------------- #
TERMINAL_IDLE_SECONDS = int(os.environ.get("HACKPIT_PTY_IDLE", "1800"))          # 30m
TERMINAL_MAX_LIFETIME_SECONDS = int(os.environ.get("HACKPIT_PTY_MAX", "14400"))  # 4h
TERMINAL_MAX_LIVE = int(os.environ.get("HACKPIT_PTY_MAX_LIVE", "3"))
# Cap the audited transcript. Full-screen tools emit a LOT of escape bytes (a single `top`
# refresh is a few KB), so this bounds one session's row in the run store. The live stream
# to the browser is never capped — only what is persisted.
TERMINAL_TRANSCRIPT_CAP = 200_000  # chars
# How often the growing transcript is checkpointed to the run store, so a crash or a hard
# disconnect still leaves an audit trail instead of losing the whole session.
TERMINAL_CHECKPOINT_SECONDS = 30.0

# Frame types on the driver's stdin (backend -> driver). See the module docstring.
FRAME_DATA = 0x00
FRAME_RESIZE = 0x01

# The shell the pty runs. A constant, like the container — never a request field.
TERMINAL_SHELL = "/bin/bash"

# --------------------------------------------------------------------------- #
# The in-container driver.
#
# This is a CONSTANT string with no interpolation of any kind: nothing a client sends can
# change a byte of what runs in the container (containment rule #1). It is passed as one
# argv element to `python3 -c`, so no shell parses it either.
#
# It pty.fork()s the shell, then selects over (pty master, framed stdin) forwarding both
# ways. Writing TIOCSWINSZ to the master makes the KERNEL deliver SIGWINCH to the pty's
# foreground process group, which is why vim/top reflow without the driver signalling
# anything itself.
# --------------------------------------------------------------------------- #
_PTY_DRIVER = r"""
import os, pty, select, struct, sys, termios, fcntl

SHELL = "/bin/bash"

def set_size(fd, cols, rows):
    try:
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    except Exception:
        pass

def main():
    pid, fd = pty.fork()
    if pid == 0:
        os.environ["TERM"] = "xterm-256color"
        os.environ["LANG"] = os.environ.get("LANG") or "C.UTF-8"
        try:
            os.execv(SHELL, [SHELL, "-i"])
        except Exception:
            os.execv("/bin/sh", ["/bin/sh", "-i"])
        os._exit(127)
    set_size(fd, 80, 24)
    stdin_fd = sys.stdin.fileno()
    out = sys.stdout.buffer
    buf = b""
    while True:
        try:
            ready, _, _ = select.select([fd, stdin_fd], [], [], 1.0)
        except (OSError, ValueError):
            break
        if fd in ready:
            try:
                data = os.read(fd, 65536)
            except OSError:
                data = b""
            if not data:
                break
            out.write(data)
            out.flush()
        if stdin_fd in ready:
            try:
                chunk = os.read(stdin_fd, 65536)
            except OSError:
                chunk = b""
            if not chunk:
                break
            buf += chunk
            while len(buf) >= 5:
                kind = buf[0]
                n = struct.unpack(">I", buf[1:5])[0]
                if len(buf) < 5 + n:
                    break
                payload = buf[5:5 + n]
                buf = buf[5 + n:]
                if kind == 0:
                    try:
                        os.write(fd, payload)
                    except OSError:
                        pass
                elif kind == 1:
                    try:
                        cols, rows = payload.decode("ascii", "replace").split("x")
                        set_size(fd, int(cols), int(rows))
                    except Exception:
                        pass
    try:
        os.close(fd)
    except Exception:
        pass

main()
"""


# --------------------------------------------------------------------------- #
# Wire protocol helpers (pure — unit-tested directly).
# --------------------------------------------------------------------------- #
def encode_frame(kind: int, payload: bytes) -> bytes:
    """One framed message for the driver's stdin: type byte + uint32 length + payload."""
    return bytes([kind]) + struct.pack(">I", len(payload)) + payload


def encode_resize(cols: int, rows: int) -> bytes:
    """A resize frame. Sizes are clamped to a sane terminal range, never passed raw."""
    cols = max(1, min(int(cols), 1000))
    rows = max(1, min(int(rows), 1000))
    return encode_frame(FRAME_RESIZE, f"{cols}x{rows}".encode("ascii"))


class TerminalRefused(RuntimeError):
    """The raw terminal could not be started (nothing ran).

    Like :kali's refusal this is an AVAILABILITY / capacity check, NOT an isolation gate —
    the open sandbox is intentionally not isolated.
    """


class TerminalStartRequest(BaseModel):
    """Open a raw PTY terminal in the open sandbox.

    NOTE — deliberately NO container / target / host / shell / command field. The box and
    the shell are code constants; nothing in this request can redirect the exec or choose
    what runs (containment rule #1). Only the initial window size and an optional
    engagement to file the transcript under.
    """

    session_id: str | None = Field(
        None, description="Optional engagement to record this terminal's transcript against."
    )
    cols: int = Field(80, ge=1, le=1000, description="Initial terminal width in columns.")
    rows: int = Field(24, ge=1, le=1000, description="Initial terminal height in rows.")


class TerminalInfo(BaseModel):
    """The state of a raw terminal (no output — that streams over the WebSocket)."""

    tid: str
    run_id: str
    container: str
    shell: str
    state: str  # "active" | "closed"
    started_at: str
    bytes_out: int
    session_id: str | None = None


@dataclass
class _LiveTerminal:
    tid: str
    run_id: str
    proc: "subprocess.Popen[bytes]"
    started_at: str
    session_id: str | None
    started_mono: float
    last_io: float
    bytes_out: int = 0
    closed: bool = False
    # The audited transcript: the RAW pty stream, capped. A pty echoes input, so this is a
    # complete record of the session in both directions.
    transcript: list[str] = field(default_factory=list)
    transcript_len: int = 0
    truncated: bool = False
    last_checkpoint: float = 0.0
    lock: "threading.Lock" = field(default_factory=threading.Lock)


_terminals: dict[str, _LiveTerminal] = {}
_terminals_lock = threading.Lock()
_reaper: "threading.Thread | None" = None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _mono() -> float:
    return time.monotonic()


def _container_running(name: str) -> bool:
    """True iff the named container exists and is running (availability only)."""
    try:
        p = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", name],
            capture_output=True,
            text=True,
            timeout=10.0,
        )
        return p.returncode == 0 and p.stdout.strip() == "true"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def open_terminal(req: TerminalStartRequest) -> TerminalInfo:
    """Spawn a raw PTY terminal in the OPEN sandbox. HUMAN-ONLY (route-driven).

    Availability check only — there is no isolation gate for the open box (rule #3). The
    container, the driver and the shell are all constants; the request contributes nothing
    but a window size and an optional session id.
    """
    if not _container_running(config.KALI_OPEN_CONTAINER):
        raise TerminalRefused(
            f"open sandbox '{config.KALI_OPEN_CONTAINER}' is not running — bring the "
            "stack up (docker compose -f docker/docker-compose.yml up -d)"
        )

    with _terminals_lock:
        live = sum(1 for t in _terminals.values() if not t.closed)
        if live >= TERMINAL_MAX_LIVE:
            raise TerminalRefused(
                f"too many live raw terminals ({live}/{TERMINAL_MAX_LIVE}) — close one first"
            )

    tid = uuid.uuid4().hex[:12]
    run_id = uuid.uuid4().hex[:12]
    started_at = _now()

    # Same working directory as :kali so downloads and tool output survive a
    # `docker compose down`. Still a constant, never a request field.
    workdir = loot.kali_workdir()
    argv = [
        "docker", "exec", "-i", *loot.exec_flags(workdir),
        config.KALI_OPEN_CONTAINER, "python3", "-u", "-c", _PTY_DRIVER,
    ]
    try:
        # BINARY pipes, deliberately: the pty stream is raw bytes (escape sequences, UTF-8
        # fragments split across reads). Text mode would also re-introduce the Windows
        # '\n' -> '\r\n' stdin translation bug the persistent shell had to fix.
        proc = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            bufsize=0,
        )
    except FileNotFoundError:
        raise TerminalRefused("docker CLI not found on PATH")

    term = _LiveTerminal(
        tid=tid, run_id=run_id, proc=proc, started_at=started_at,
        session_id=req.session_id, started_mono=_mono(), last_io=_mono(),
        last_checkpoint=_mono(),
    )
    with _terminals_lock:
        _terminals[tid] = term

    # Hand the driver the browser's actual window size before the first keystroke, so the
    # very first `top` renders at the right dimensions instead of the 80x24 default.
    _write_raw(term, encode_resize(req.cols, req.rows))
    _record(term, finished=False)
    _ensure_reaper()
    return _info(term)


def _info(term: _LiveTerminal) -> TerminalInfo:
    return TerminalInfo(
        tid=term.tid,
        run_id=term.run_id,
        container=config.KALI_OPEN_CONTAINER,
        shell=TERMINAL_SHELL,
        state="closed" if term.closed else "active",
        started_at=term.started_at,
        bytes_out=term.bytes_out,
        session_id=term.session_id,
    )


def get_terminal(tid: str) -> _LiveTerminal | None:
    with _terminals_lock:
        return _terminals.get(tid)


def terminal_info(tid: str) -> TerminalInfo | None:
    term = get_terminal(tid)
    return _info(term) if term is not None else None


def list_terminals() -> list[TerminalInfo]:
    with _terminals_lock:
        terms = list(_terminals.values())
    return [_info(t) for t in terms if not t.closed]


def _write_raw(term: _LiveTerminal, data: bytes) -> None:
    """Write already-framed bytes to the driver. Closes the terminal on a dead pipe."""
    if term.closed:
        raise TerminalRefused(f"terminal {term.tid} is closed")
    try:
        with term.lock:
            assert term.proc.stdin is not None
            term.proc.stdin.write(data)
            term.proc.stdin.flush()
        term.last_io = _mono()
    except (BrokenPipeError, ValueError, OSError):
        close_terminal(term.tid)
        raise TerminalRefused(f"terminal {term.tid} stdin is closed")


def write_input(tid: str, data: bytes) -> None:
    """Send keystrokes to the terminal. HUMAN-ONLY — called only from the WebSocket route.

    The bytes go into a DATA frame, so they can never be mistaken for a control message
    however they are crafted; the driver writes them verbatim to the pty master.
    """
    term = get_terminal(tid)
    if term is None or term.closed:
        raise TerminalRefused(f"no live terminal {tid}")
    _write_raw(term, encode_frame(FRAME_DATA, data))


def resize(tid: str, cols: int, rows: int) -> None:
    """Resize the pty (ioctl TIOCSWINSZ in the container; the kernel sends SIGWINCH)."""
    term = get_terminal(tid)
    if term is None or term.closed:
        raise TerminalRefused(f"no live terminal {tid}")
    _write_raw(term, encode_resize(cols, rows))


def read_output(tid: str, size: int = 65536) -> bytes:
    """Block until the pty produces output; b"" means the terminal ended.

    Called from a worker thread by the WebSocket route (the pipe read is blocking).
    """
    term = get_terminal(tid)
    if term is None or term.closed or term.proc.stdout is None:
        return b""
    # ONE read syscall's worth — never wait for `size` bytes to accumulate, or an
    # interactive prompt would sit in the pipe until something else pushed it out. With
    # bufsize=0 Popen hands back a raw FileIO whose .read() is already that single syscall;
    # a buffered stream would block, so prefer .read1() when the object has it.
    stream = term.proc.stdout
    read_available = getattr(stream, "read1", stream.read)
    try:
        data = read_available(size)
    except (ValueError, OSError):
        return b""
    if data:
        _observe(term, data)
    return data


def _observe(term: _LiveTerminal, data: bytes) -> None:
    """Accumulate the raw stream for the audit record, capped, checkpointing as it grows."""
    term.last_io = _mono()
    term.bytes_out += len(data)
    if not term.truncated:
        text = data.decode("utf-8", "replace")
        room = TERMINAL_TRANSCRIPT_CAP - term.transcript_len
        if room <= 0:
            term.truncated = True
        else:
            if len(text) > room:
                text = text[:room]
                term.truncated = True
            term.transcript.append(text)
            term.transcript_len += len(text)
    if _mono() - term.last_checkpoint >= TERMINAL_CHECKPOINT_SECONDS:
        _record(term, finished=False)


def _transcript(term: _LiveTerminal) -> str:
    text = "".join(term.transcript)
    if term.truncated:
        text += "\n…[transcript truncated]…"
    return text


def _record(term: _LiveTerminal, *, finished: bool) -> None:
    """Write (or update) this terminal's run record. Never raises."""
    term.last_checkpoint = _mono()
    try:
        runstore.save_run(RunRecord(
            run_id=term.run_id,
            # Honest about what actually ran: a pty-hosted interactive shell, not `sh -c`.
            command="pty",
            args=[TERMINAL_SHELL, "-i"],
            target=config.KALI_OPEN_CONTAINER,
            approved=True,  # a human at the keyboard IS the approval, same as :kali
            exit_code=term.proc.poll() if finished else None,
            stdout=_transcript(term),
            stderr="" if finished else "[terminal still open — transcript in progress]",
            started_at=term.started_at,
            finished_at=_now() if finished else None,
            session_id=term.session_id,
            step_id=None,
        ))
    except Exception:  # persistence must never crash a live terminal
        pass


def close_terminal(tid: str) -> TerminalInfo:
    """Close one terminal and finalise its audit record. Idempotent."""
    term = get_terminal(tid)
    if term is None:
        raise TerminalRefused(f"no terminal {tid}")
    _finalize(term)
    return _info(term)


def _finalize(term: _LiveTerminal) -> None:
    if term.closed:
        return
    term.closed = True
    try:
        if term.proc.stdin and not term.proc.stdin.closed:
            term.proc.stdin.close()
    except Exception:
        pass
    try:
        term.proc.kill()
    except Exception:
        pass
    _record(term, finished=True)


def terminal_status() -> dict:
    """Availability of the raw-terminal surface — drives the UI banner.

    Makes NO isolation claim (there is none): the banner must say 'full network reach ·
    NOT isolated', exactly like :kali's.
    """
    up = _container_running(config.KALI_OPEN_CONTAINER)
    return {
        "container": config.KALI_OPEN_CONTAINER,
        "shell": TERMINAL_SHELL,
        "isolated": False,  # intentionally — the open sandbox has full network reach
        "up": up,
        "ready": up,
        "live": len(list_terminals()),
        "max_live": TERMINAL_MAX_LIVE,
        "detail": "" if up else "open sandbox container is not running",
    }


def _ensure_reaper() -> None:
    global _reaper
    with _terminals_lock:
        if _reaper is not None and _reaper.is_alive():
            return
        t = threading.Thread(target=_reaper_loop, name="pty-terminal-reaper", daemon=True)
        _reaper = t
    t.start()


def _reaper_loop() -> None:  # pragma: no cover - background timing
    while True:
        time.sleep(30)
        now = _mono()
        with _terminals_lock:
            terms = list(_terminals.values())
        for term in terms:
            try:
                if (
                    term.closed
                    or term.proc.poll() is not None
                    or now - term.last_io > TERMINAL_IDLE_SECONDS
                    or now - term.started_mono > TERMINAL_MAX_LIFETIME_SECONDS
                ):
                    _finalize(term)
            except Exception:
                pass
        with _terminals_lock:
            for tid, term in list(_terminals.items()):
                if term.closed:
                    _terminals.pop(tid, None)
