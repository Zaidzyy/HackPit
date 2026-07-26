""":kali — the human-only interactive shell with FULL NETWORK REACH.

This is the ONE feature that runs arbitrary commands. It runs ``sh -c "<command>"`` inside
a SEPARATE, intentionally NON-isolated sandbox (``hackpit-kali-open``) that has NAT egress
— it reaches the internet, the host, and the LAN. That is Zaid's informed decision. It is
NOT made safe by input filtering (there is none, on purpose — do not add fake sanitisation
that pretends arbitrary shell is "safe").

WHY THIS DOESN'T TOUCH THE COCKPIT'S SAFETY NET:
The cockpit executor + the future autonomous agent exec into a DIFFERENT container,
``config.SANDBOX_CONTAINER`` (``hackpit-kali-sandbox``), which stays egress-less
(``internal: true``) and behind all four gates — including ``assert_isolation_proven``.
:kali uses its own ``config.KALI_OPEN_CONTAINER`` and does NOT run the isolation gate
(it is intentionally not isolated). The two never mix.

WHAT STILL HOLDS FOR :kali (the containment that remains):

1. HARDCODED TARGET CONTAINER. Every exec is
       docker exec <KALI_OPEN_CONTAINER> sh -c "<command>"
   with the container name taken from ``config.KALI_OPEN_CONTAINER`` — a code constant,
   NEVER a field in the request. No input can redirect the exec to another container.
   (Regression-locked in test_kali.py.)

2. HUMAN-ONLY — the rule that matters MOST now. :kali is a full-reach shell, so an
   autonomous agent wired to it = autonomous attacks on the host, the LAN and the
   internet. The orchestrator / agent / executor MUST have ZERO code path to
   ``run_kali``; nothing in that path imports this module. (Regression-locked by
   test_kali_is_human_only, which scans the source tree.)

3. DISPOSABLE + HARDENED. The open sandbox still runs cap_drop ALL + no-new-privileges
   and resets via ``docker compose down -v``.

4. AUDIT + LIMITS. Every command + output is recorded to the engagement session (reuses
   the M1 run store), with a per-command timeout and an output-size cap.

5. LOCAL-ONLY, AUTH REQUIRED BEFORE EXPOSURE — now far more load-bearing. An exposed
   :kali endpoint reaches your HOST and LAN, not just a disposable lab. It has NO auth;
   if this app is ever exposed or deployed, this endpoint MUST be put behind
   authentication first. See the matching note on the route in router.py.
"""

from __future__ import annotations

import os
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from pydantic import BaseModel, Field

from . import config, loot, runstore
from .models import RunRecord

# Per-command bounds. A free shell must neither hang nor flood the audit log.
#
# This used to be a hardcoded 60s with no override at all, which made `:kali` useless for
# exactly the work a full shell is for — a port sweep, a long fuzz, a nuclei run. It is now
# the shared cockpit default (180s) and a request may ask for more, clamped to the same
# hard ceiling every other run obeys (config.MAX_TIMEOUT_SECONDS).
KALI_TIMEOUT_SECONDS = config.EXEC_TIMEOUT_SECONDS
# Cap EACH stream; a runaway `yes` or huge dump gets truncated (marked in the record).
KALI_OUTPUT_CAP = 200_000  # chars per stream


class KaliRequest(BaseModel):
    """A request to run ONE arbitrary shell command inside the open sandbox.

    NOTE — deliberately there is NO container / target / host field. The container is a
    code constant (config.KALI_OPEN_CONTAINER); nothing in this request can redirect the
    exec anywhere else. Adding such a field would break containment rule #1.
    """

    command: str = Field(..., min_length=1, description="Shell command to run via `sh -c`.")
    session_id: str | None = Field(
        None, description="Optional engagement to record this run against."
    )
    timeout_seconds: int | None = Field(
        None,
        ge=1,
        description="How long this command may run before it is killed. Omit for the 180s "
        "default; values above the hard ceiling (3600s) are CLAMPED, not refused.",
    )


class KaliResult(BaseModel):
    """The captured result of one shell run (also persisted to the run store)."""

    run_id: str
    command: str
    container: str
    exit_code: int | None
    stdout: str
    stderr: str
    started_at: str
    finished_at: str
    timed_out: bool = False
    truncated: bool = False
    session_id: str | None = None


class KaliRefused(RuntimeError):
    """Raised when the open sandbox isn't available (nothing was executed).

    NOTE: this is an AVAILABILITY check (is the container running?), NOT an isolation
    gate — :kali is intentionally not isolated. The cockpit executor keeps the real
    isolation gate; :kali does not.
    """


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


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


def _cap(text: str) -> tuple[str, bool]:
    """Truncate a stream to the output cap; return (text, truncated?)."""
    if len(text) > KALI_OUTPUT_CAP:
        return text[:KALI_OUTPUT_CAP] + "\n…[output truncated]…", True
    return text, False


def run_kali(request: KaliRequest) -> KaliResult:
    """Run one arbitrary shell command inside the OPEN sandbox and capture its result.

    :kali is intentionally NOT isolated, so there is NO ``assert_isolation_proven`` gate
    here (that gate lives on the cockpit executor's isolated sandbox and would correctly
    refuse every full-reach command). The only pre-check is availability: if the open
    container isn't running, this raises ``KaliRefused`` and nothing runs. Otherwise the
    command runs as ``docker exec <KALI_OPEN_CONTAINER> sh -c "<command>"`` (container
    hardcoded) with a hard timeout and an output cap, and the run is recorded.
    """
    # Availability (NOT isolation): refuse cleanly if the open sandbox isn't up.
    if not _container_running(config.KALI_OPEN_CONTAINER):
        raise KaliRefused(
            f"open sandbox '{config.KALI_OPEN_CONTAINER}' is not running — bring the "
            "stack up (docker compose -f docker/docker-compose.yml up -d)"
        )

    run_id = uuid.uuid4().hex[:12]
    started_at = _now()

    # The container is a CONSTANT, never from the request. `sh -c` is intentional: the
    # human operator gets a full shell — here, one with full network reach. The working
    # directory is `:kali`'s own loot directory so downloads and tool output survive a
    # `docker compose down`; it is still a constant, never a request field.
    timeout_seconds = config.clamp_timeout(request.timeout_seconds)
    workdir = loot.kali_workdir()
    argv = [
        "docker", "exec", *loot.exec_flags(workdir),
        config.KALI_OPEN_CONTAINER, "sh", "-c", request.command,
    ]

    timed_out = False
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
        stdout, stderr, exit_code = proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        stdout = exc.stdout or ""
        # TimeoutExpired gives bytes when the call was made without text=True upstream;
        # normalise so a timed-out run still reports whatever it managed to produce.
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", "replace")
        partial_err = exc.stderr or ""
        if isinstance(partial_err, bytes):
            partial_err = partial_err.decode("utf-8", "replace")
        stderr = partial_err + f"\n[killed: exceeded {timeout_seconds}s timeout]"
        exit_code = None
    except FileNotFoundError:
        stdout, stderr, exit_code = "", "docker CLI not found on PATH", 127

    stdout, t1 = _cap(stdout)
    stderr, t2 = _cap(stderr)
    finished_at = _now()

    # Audit: record every run to the engagement session (reusing the M1 run store). The
    # command line is stored as the args of a `sh -c` invocation so the log is honest
    # about what actually ran. target = the open sandbox (the box the shell reached).
    record = RunRecord(
        run_id=run_id,
        command="sh -c",
        args=[request.command],
        target=config.KALI_OPEN_CONTAINER,
        approved=True,  # a human typing the command IS the approval
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        started_at=started_at,
        finished_at=finished_at,
        session_id=request.session_id,
        step_id=None,
    )
    try:
        runstore.save_run(record)
    except Exception:  # persistence must never crash the response
        pass

    return KaliResult(
        run_id=run_id,
        command=request.command,
        container=config.KALI_OPEN_CONTAINER,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        started_at=started_at,
        finished_at=finished_at,
        timed_out=timed_out,
        truncated=t1 or t2,
        session_id=request.session_id,
    )


def kali_status() -> dict:
    """Availability of the :kali OPEN sandbox — drives the UI banner.

    Reports whether the open container is up. It makes NO isolation claim (there is none):
    the banner must say 'full network reach · NOT isolated', never 'isolated'.
    """
    up = _container_running(config.KALI_OPEN_CONTAINER)
    return {
        "container": config.KALI_OPEN_CONTAINER,
        "isolated": False,  # intentionally — :kali has full network reach
        "up": up,
        "ready": up,
        "detail": "" if up else "open sandbox container is not running",
    }


# =========================================================================== #
# Persistent :kali shell (step 13) — ONE long-lived shell you drive over time
# =========================================================================== #
#
# The one-shot `run_kali` above is a fresh `docker exec` per command, so `cd`, exported
# variables and backgrounded jobs vanish between commands — it is a command runner, not a
# shell. This is the persistent version: a single long-lived `docker exec -i
# <KALI_OPEN_CONTAINER> sh` whose stdin stays open, so state carries across commands (cd
# holds, a `nc -lvnp 4444 &` keeps listening, `export` sticks).
#
# It preserves EVERY :kali containment invariant that run_kali has, because the same
# invariants apply — this is still the one arbitrary-shell feature:
#   * the container is the hardcoded constant, NEVER a request field (containment rule #1);
#   * human-only — driven only from the HTTP route, never the agent/executor (test_kali
#     scans the tree for exactly this);
#   * no isolation gate (there is none to assert on the open box), only an availability check;
#   * every command + its output is recorded to the run store (audit);
#   * output is capped per command and the shell is reaped on idle / max lifetime.
#
# NO PTY. Commands are delimited over the pipe with a per-command SENTINEL: each command is
# written to the shell's stdin followed by an echo of a unique marker plus `$?`, and output
# is collected up to that marker. That gives clean per-command blocks and a real exit code
# over a plain pipe — no terminal-escape handling, so the transcript stays readable. The
# cost (accepted in the design decision) is that full-screen TUIs — vim, top — do not work;
# they need a real terminal.

# Bounds — a persistent open shell must not accumulate forever or flood the audit log.
KALI_SHELL_IDLE_SECONDS = int(os.environ.get("HACKPIT_KALI_SHELL_IDLE", "1800"))  # 30m
KALI_SHELL_MAX_LIFETIME_SECONDS = int(os.environ.get("HACKPIT_KALI_SHELL_MAX", "14400"))  # 4h
KALI_SHELL_MAX_LIVE = int(os.environ.get("HACKPIT_KALI_SHELL_MAX_LIVE", "3"))
# Per-command output cap (chars, each stream). A runaway `yes` is truncated, not fatal.
KALI_SHELL_CMD_CAP = 200_000


class KaliShellRefused(RuntimeError):
    """The persistent shell could not start / accept input (nothing ran)."""


class KaliShellStartRequest(BaseModel):
    """Start a persistent :kali shell. NO container/target field — same containment rule as
    KaliRequest: the box is a constant, nothing in the request can redirect it."""

    session_id: str | None = Field(
        None, description="Optional engagement to record this shell's commands against."
    )


class KaliShellInputRequest(BaseModel):
    """Run one command line in an existing persistent shell. Human-typed = approved."""

    command: str = Field(..., min_length=1, description="Shell command line to run.")
    timeout_seconds: int | None = Field(
        None, ge=1,
        description="How long to wait for this command before giving up on its output. "
        "Omit for the 180s default; clamped to the same ceiling as every other run.",
    )


class KaliShellInfo(BaseModel):
    """The state of a persistent shell (no output — that comes from the command result)."""

    sid: str
    container: str
    state: str  # "active" | "closed"
    started_at: str
    last_active: str
    command_count: int
    session_id: str | None = None


class KaliCommandResult(BaseModel):
    """The captured result of ONE command run in a persistent shell."""

    sid: str
    run_id: str
    command: str
    exit_code: int | None
    stdout: str
    stderr: str
    started_at: str
    finished_at: str
    timed_out: bool = False
    truncated: bool = False
    shell_closed: bool = False


@dataclass
class _LiveShell:
    sid: str
    proc: "subprocess.Popen[str]"
    started_at: str
    session_id: str | None
    last_io: float
    started_mono: float
    command_count: int = 0
    closed: bool = False
    # stdout/stderr are pumped here by reader threads; a command reads its slice out.
    out_buf: list[str] = field(default_factory=list)
    err_buf: list[str] = field(default_factory=list)
    cond: "threading.Condition" = field(default_factory=threading.Condition)
    # Serialises commands: a persistent shell is one FIFO, one command at a time.
    run_lock: "threading.Lock" = field(default_factory=threading.Lock)


_shells: dict[str, _LiveShell] = {}
_shells_lock = threading.Lock()
_shell_reaper: "threading.Thread | None" = None


def _mono() -> float:
    return time.monotonic()


def _pump(shell: _LiveShell, stream, buf: list[str]) -> None:
    """Reader thread: append each line to the shell's buffer and wake any waiter."""
    try:
        for line in iter(stream.readline, ""):
            with shell.cond:
                buf.append(line)
                shell.cond.notify_all()
    except (ValueError, OSError):
        pass
    finally:
        try:
            stream.close()
        except Exception:
            pass
        with shell.cond:
            shell.cond.notify_all()


def start_shell(req: KaliShellStartRequest) -> KaliShellInfo:
    """Launch a persistent shell in the OPEN sandbox. Refuses if it isn't up or the cap is hit.

    Same availability check as run_kali (NOT an isolation gate — there is none for the open
    box). The container is the hardcoded constant; the request cannot name one.
    """
    if not _container_running(config.KALI_OPEN_CONTAINER):
        raise KaliShellRefused(
            f"open sandbox '{config.KALI_OPEN_CONTAINER}' is not running — bring the "
            "stack up (docker compose -f docker/docker-compose.yml up -d)"
        )

    with _shells_lock:
        live = sum(1 for s in _shells.values() if not s.closed)
        if live >= KALI_SHELL_MAX_LIVE:
            raise KaliShellRefused(
                f"too many live :kali shells ({live}/{KALI_SHELL_MAX_LIVE}) — close one first"
            )

    sid = uuid.uuid4().hex[:12]
    started_at = _now()
    # The working directory is :kali's loot dir so downloads persist (same as run_kali).
    # `sh` with stdin kept open IS the persistence: one process for the whole session.
    workdir = loot.kali_workdir()
    argv = [
        "docker", "exec", "-i", *loot.exec_flags(workdir),
        config.KALI_OPEN_CONTAINER, "sh",
    ]
    try:
        proc = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1,
        )
    except FileNotFoundError:
        raise KaliShellRefused("docker CLI not found on PATH")

    # CRITICAL (Windows): text-mode stdin translates '\n' -> '\r\n', so the Linux shell would
    # receive `pwd\r` (command not found) and `printf …\r` (bad format). Disable translation
    # on stdin so a written '\n' stays a bare LF on the wire. Same class of bug as the
    # reconcile probe. stdout/stderr keep universal-newline reading, which is harmless.
    try:
        if proc.stdin is not None:
            proc.stdin.reconfigure(newline="")
    except (AttributeError, ValueError):  # pragma: no cover - non-Windows / already-detached
        pass

    shell = _LiveShell(
        sid=sid, proc=proc, started_at=started_at,
        session_id=req.session_id, last_io=_mono(), started_mono=_mono(),
    )
    threading.Thread(target=_pump, args=(shell, proc.stdout, shell.out_buf),
                     name=f"kali-shell-{sid}-out", daemon=True).start()
    threading.Thread(target=_pump, args=(shell, proc.stderr, shell.err_buf),
                     name=f"kali-shell-{sid}-err", daemon=True).start()
    with _shells_lock:
        _shells[sid] = shell
    _ensure_shell_reaper()
    return _info(shell)


def _info(shell: _LiveShell) -> KaliShellInfo:
    return KaliShellInfo(
        sid=shell.sid,
        container=config.KALI_OPEN_CONTAINER,
        state="closed" if shell.closed else "active",
        started_at=shell.started_at,
        last_active=_now(),
        command_count=shell.command_count,
        session_id=shell.session_id,
    )


def run_in_shell(sid: str, req: KaliShellInputRequest) -> KaliCommandResult:
    """Run ONE command line in a persistent shell and return its output + exit code.

    HUMAN-ONLY, like the whole module: this is called only from the HTTP route. The command
    is written to the shell's stdin (state persists across calls) and delimited with a
    per-command sentinel so its output and exit code can be read back over a plain pipe.
    """
    with _shells_lock:
        shell = _shells.get(sid)
    if shell is None or shell.closed:
        raise KaliShellRefused(f"no live :kali shell {sid} (unknown or already closed)")
    if shell.proc.poll() is not None:
        _finalize(shell)
        raise KaliShellRefused(f":kali shell {sid} has exited")

    timeout = config.clamp_timeout(req.timeout_seconds)
    run_id = uuid.uuid4().hex[:12]
    started_at = _now()
    sentinel = f"__HACKPIT_KALI_{uuid.uuid4().hex}__"

    # One command at a time per shell — the pipe is a single FIFO.
    with shell.run_lock:
        with shell.cond:
            out_start, err_start = len(shell.out_buf), len(shell.err_buf)
        # Write the command, then echo the sentinel + the command's exit code. A bare
        # newline is a no-op that does not touch $?, so $? here is the command's own exit.
        payload = f"{req.command}\nprintf '%s %d\\n' '{sentinel}' \"$?\"\n"
        try:
            assert shell.proc.stdin is not None
            shell.proc.stdin.write(payload)
            shell.proc.stdin.flush()
        except (BrokenPipeError, ValueError, OSError):
            _finalize(shell)
            raise KaliShellRefused(f":kali shell {sid} stdin is closed")

        shell.last_io = _mono()
        exit_code, timed_out, closed = _await_sentinel(shell, out_start, sentinel, timeout)

        with shell.cond:
            out_lines = shell.out_buf[out_start:]
            err_lines = shell.err_buf[err_start:]

    # Drop the sentinel line from the visible stdout.
    stdout = "".join(ln for ln in out_lines if sentinel not in ln)
    stderr = "".join(err_lines)
    if timed_out:
        stderr += f"\n[no sentinel within {timeout}s — output may be partial; shell still live]"
    stdout, t1 = _cap(stdout)
    stderr, t2 = _cap(stderr)
    finished_at = _now()

    shell.command_count += 1

    # Audit — every command recorded, exactly like run_kali, honestly logged as sh -c.
    try:
        runstore.save_run(RunRecord(
            run_id=run_id, command="sh -c", args=[req.command],
            target=config.KALI_OPEN_CONTAINER, approved=True, exit_code=exit_code,
            stdout=stdout, stderr=stderr, started_at=started_at, finished_at=finished_at,
            session_id=shell.session_id, step_id=None,
        ))
    except Exception:
        pass

    return KaliCommandResult(
        sid=sid, run_id=run_id, command=req.command, exit_code=exit_code,
        stdout=stdout, stderr=stderr, started_at=started_at, finished_at=finished_at,
        timed_out=timed_out, truncated=t1 or t2, shell_closed=closed,
    )


def _await_sentinel(
    shell: _LiveShell, out_start: int, sentinel: str, timeout: float
) -> tuple[int | None, bool, bool]:
    """Wait until the sentinel line appears in stdout. Returns (exit_code, timed_out, closed)."""
    deadline = _mono() + timeout
    while True:
        with shell.cond:
            for ln in shell.out_buf[out_start:]:
                if sentinel in ln:
                    # "<sentinel> <code>" — parse the trailing exit code.
                    try:
                        return int(ln.rsplit(" ", 1)[-1].strip()), False, False
                    except (ValueError, IndexError):
                        return None, False, False
            if shell.proc.poll() is not None:
                return None, False, True  # shell exited (e.g. the human typed `exit`)
            remaining = deadline - _mono()
            if remaining <= 0:
                return None, True, False
            shell.cond.wait(timeout=min(remaining, 1.0))


def close_shell(sid: str) -> KaliShellInfo:
    """Close one persistent shell (EOF its stdin, then kill). Never raises."""
    with _shells_lock:
        shell = _shells.get(sid)
    if shell is None:
        raise KaliShellRefused(f"no :kali shell {sid}")
    _finalize(shell)
    return _info(shell)


def _finalize(shell: _LiveShell) -> None:
    """Close stdin and kill the process. Idempotent."""
    if shell.closed:
        return
    shell.closed = True
    try:
        if shell.proc.stdin and not shell.proc.stdin.closed:
            shell.proc.stdin.close()
    except Exception:
        pass
    try:
        shell.proc.kill()
    except Exception:
        pass
    with shell.cond:
        shell.cond.notify_all()


def shell_info(sid: str) -> KaliShellInfo | None:
    with _shells_lock:
        shell = _shells.get(sid)
    return _info(shell) if shell is not None else None


def list_shells() -> list[KaliShellInfo]:
    with _shells_lock:
        shells = list(_shells.values())
    return [_info(s) for s in shells if not s.closed]


def _ensure_shell_reaper() -> None:
    global _shell_reaper
    with _shells_lock:
        if _shell_reaper is not None and _shell_reaper.is_alive():
            return
        t = threading.Thread(target=_shell_reaper_loop, name="kali-shell-reaper", daemon=True)
        _shell_reaper = t
    t.start()


def _shell_reaper_loop() -> None:  # pragma: no cover - background timing
    while True:
        time.sleep(30)
        now = _mono()
        with _shells_lock:
            shells = list(_shells.items())
        for _sid, shell in shells:
            try:
                if (
                    shell.closed
                    or shell.proc.poll() is not None
                    or now - shell.last_io > KALI_SHELL_IDLE_SECONDS
                    or now - shell.started_mono > KALI_SHELL_MAX_LIFETIME_SECONDS
                ):
                    _finalize(shell)
            except Exception:
                pass
        # Drop long-closed shells from the registry so it does not grow unbounded.
        with _shells_lock:
            for sid, shell in list(_shells.items()):
                if shell.closed:
                    _shells.pop(sid, None)
