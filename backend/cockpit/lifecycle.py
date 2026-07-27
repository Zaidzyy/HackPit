"""Spawning a listener and PROVING it came up — the difference between assigned and observed.

Three lifecycle surfaces raise a long-lived server process inside the engage sandbox: the Sliver
C2 daemon (``cockpit/sliver.py``), the pivot listener (``cockpit/tunnels.py``) and the DNS-tunnel
listener (``cockpit/obfuscation.py``). All three used to do the same two things in the same
order, and the second one was wrong:

    proc = subprocess.Popen(argv, stdin=DEVNULL, ...)
    model = Tunnel(..., status="listening", ...)

``status="listening"`` was ASSIGNED at Popen time. Nothing ever looked at the process again
before the model reached the operator. That is not a small inaccuracy — for two of the three
binaries it was simply false:

    ligolo-proxy    is an interactive console. Launched with no usable stdin it prints its
                    banner, reads EOF and exits 0. Observed: poll() == 0 within three seconds.
    dnscat2-server  is a Ruby console. Same shape — it logs "Input thread is over" and exits.

So the panel said the pivot was live while nothing was listening, and the operator's next move
was to paste an agent one-liner at a port with nothing behind it. A gate that refuses correctly
and a surface that reports fiction are different failures, but they cost the same on an
engagement.

THIS MODULE FIXES BOTH HALVES.

1. THE PROCESS IS GIVEN A STDIN THAT DOES NOT END. ``docker exec`` without ``-i`` hands the
   container process a closed stdin no matter what the host process got, so the console binaries
   could never have survived. :func:`exec_argv` adds ``-i`` for the interactive ones and
   :func:`spawn_watched` gives the child the READ end of a pipe whose write end this process
   holds open and never writes to.

   *** THE WRITE END IS A RAW FILE DESCRIPTOR, DELIBERATELY. *** Passing an int fd rather than
   ``subprocess.PIPE`` means ``proc.stdin is None`` — there is no writer object on the Popen for
   any caller, present or future, to reach for. Holding a listener's stdin open is a liveness
   requirement; being able to TYPE INTO a live C2 console is a capability, and this module grants
   the first without the second. Regression-locked by
   test_lifecycle_safety.py::test_watched_listeners_expose_no_stdin_writer.

2. THE STATUS IS OBSERVED, NOT ASSIGNED. :func:`observe` waits a settle window, then reports what
   is actually true:

       process exited            -> "down"      (with the exit code and the output it died on)
       alive, port bound         -> "listening" (confirmed with `ss` INSIDE the container)
       alive, port not bound yet -> "starting"  (honest: up, not yet accepting)

   The port probe is read-only — it runs ``ss -lntuH`` in the container and parses it. If ``ss``
   is missing or the probe errors, ``bound`` is None and the status degrades to "starting"
   rather than claiming a listener that was never confirmed. A probe that could not run must
   never be reported as a probe that passed.

OUTPUT IS DRAINED, so a listener cannot wedge itself. stdout/stderr are pipes; a chatty server
(dnscat2 is very chatty) fills the 64 KB OS buffer and blocks forever on its next write, which
would look exactly like a hung tunnel. A daemon thread drains both into a bounded ring buffer,
which also supplies the diagnostic tail when a process dies on us.
"""

from __future__ import annotations

import os as _os
import subprocess
import threading
import time
from dataclasses import dataclass, field

# How long to let a listener settle before believing anything about it. A container-side process
# launched through `docker exec` needs a moment; the console binaries that used to die did so
# well inside a second.
SETTLE_SECONDS = float(_os.environ.get("HACKPIT_LISTENER_SETTLE", "3.0"))

# Bound on the retained output tail. Enough to diagnose a death, small enough to keep in memory
# for the life of a listener.
TAIL_BYTES = 8192

# The read-only liveness probe's own timeout.
PROBE_TIMEOUT = 10.0


# --------------------------------------------------------------------------- #
# what we observed
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Liveness:
    """What was ACTUALLY true about a spawned listener after the settle window.

    ``bound`` is a tri-state on purpose: True (seen in ``ss``), False (probed, not there), or
    None (could not probe). None must never be rendered as "listening".
    """

    alive: bool
    bound: bool | None
    exit_code: int | None
    detail: str = ""

    @property
    def status(self) -> str:
        """The status string the surface models use — derived from observation only."""
        if not self.alive:
            return "down"
        return "listening" if self.bound else "starting"


@dataclass
class Watched:
    """A spawned listener plus the machinery that keeps it honest and unwedged.

    ``stdin_fd`` is the WRITE end of the child's stdin pipe, held open purely so the child never
    reads EOF. It is an int, not a file object, and nothing in this codebase writes to it — see
    the module docstring.
    """

    proc: "subprocess.Popen[bytes]"
    stdin_fd: int | None = None
    _buf: bytearray = field(default_factory=bytearray)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def _drain(self, stream) -> None:
        """Consume a pipe forever into the ring buffer. Never lets the child block on write."""
        try:
            for chunk in iter(lambda: stream.read(4096), b""):
                with self._lock:
                    self._buf.extend(chunk)
                    if len(self._buf) > TAIL_BYTES:
                        del self._buf[: len(self._buf) - TAIL_BYTES]
        except Exception:  # pragma: no cover - the pipe closing is a normal end
            pass

    def start_drains(self) -> None:
        for stream in (self.proc.stdout, self.proc.stderr):
            if stream is not None:
                threading.Thread(target=self._drain, args=(stream,), daemon=True).start()

    def tail(self) -> str:
        """The last few KB the process emitted, as text. Read-only, never blocks."""
        with self._lock:
            return bytes(self._buf).decode("utf-8", "replace")

    def close_stdin(self) -> None:
        """Let the child see EOF — how a console binary is asked to leave politely."""
        if self.stdin_fd is not None:
            try:
                _os.close(self.stdin_fd)
            except OSError:  # pragma: no cover - already closed
                pass
            self.stdin_fd = None

    def kill(self, *, container: str = "", server_argv: list[str] | None = None) -> None:
        """Stop the listener: EOF, kill the client, then make sure the SERVER is actually gone.

        *** KILLING A `docker exec` CLIENT DOES NOT KILL THE PROCESS INSIDE THE CONTAINER. ***
        This is the mirror of the bug this module exists for, and the live-fire run found it the
        same way: after a stop that reported ``status="down"``, ``ss`` inside the sandbox still
        showed ``iodined`` holding UDP/53 and two ``chisel server`` processes still listening.
        The next start then failed with EADDRINUSE — a refusal about a listener the operator had
        been told was already stopped.

        For a CONSOLE binary the EOF is enough: ligolo-proxy and dnscat2-server exit when their
        stdin closes. A daemon ignores it, so when the caller tells us where it lives we reap it
        by its own argv. ``pkill -f`` matches the full command line, and a listener's argv carries
        its port (``-laddr 0.0.0.0:11601``, ``-p 8080``), so this targets THIS listener rather
        than every process of the same kind — a blanket ``pkill -f chisel`` would stop somebody
        else's tunnel.

        Idempotent and never raises: a stop that cannot reach docker still marks the model down,
        because the alternative is a listener the operator can neither see nor stop.
        """
        self.close_stdin()
        try:
            self.proc.kill()
        except Exception:  # pragma: no cover - already dead
            pass
        if container and server_argv:
            try:
                subprocess.run(
                    ["docker", "exec", container, "pkill", "-f", " ".join(server_argv)],
                    capture_output=True, text=True, timeout=PROBE_TIMEOUT,
                )
            except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
                pass


# --------------------------------------------------------------------------- #
# spawning
# --------------------------------------------------------------------------- #
def exec_argv(container: str, server_argv: list[str], *, interactive: bool) -> list[str]:
    """The ``docker exec`` argv for a listener. PURE — builds a list, runs nothing.

    ``interactive`` adds ``-i``, which is what actually forwards the host process's stdin into
    the container. Without it the container process gets a closed stdin regardless of how the
    host process was spawned, which is precisely why the console binaries exited instantly.

    It is a per-binary property, not a default: the Sliver daemon is a real daemon and needs no
    stdin at all, so it is spawned WITHOUT ``-i`` and gets no stdin pipe — least privilege where
    the binary allows it.
    """
    prefix = ["docker", "exec", "-i", container] if interactive else ["docker", "exec", container]
    return [*prefix, *server_argv]


def spawn_watched(argv: list[str], *, interactive: bool) -> Watched:
    """Spawn a listener with a non-ending stdin (when interactive) and drained output.

    Raises FileNotFoundError if the docker CLI is missing — callers translate that into their
    own "nothing ran" refusal.
    """
    stdin_fd: int | None = None
    child_stdin: int = subprocess.DEVNULL
    if interactive:
        # The child gets the READ end; we keep the WRITE end open so it never sees EOF. Passing
        # a raw fd (not subprocess.PIPE) leaves proc.stdin as None — no writer object exists.
        read_fd, stdin_fd = _os.pipe()
        child_stdin = read_fd

    try:
        proc = subprocess.Popen(
            argv, stdin=child_stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
    except BaseException:
        if stdin_fd is not None:
            for fd in (child_stdin, stdin_fd):
                try:
                    _os.close(fd)
                except OSError:
                    pass
        raise
    finally:
        if interactive:
            # The child holds its own copy; ours must go or the pipe never reports EOF on close.
            try:
                _os.close(child_stdin)
            except OSError:  # pragma: no cover
                pass

    watched = Watched(proc=proc, stdin_fd=stdin_fd)
    watched.start_drains()
    return watched


# --------------------------------------------------------------------------- #
# observing
# --------------------------------------------------------------------------- #
def port_is_bound(container: str, port: int, proto: str) -> bool | None:
    """Is ``port`` actually listening inside ``container``? READ-ONLY.

    Returns True/False from a real ``ss`` reading, or None when the probe itself could not run
    (no docker, no ``ss``, timeout). None is not False: an unprobed port must degrade to
    "starting", never be reported as a confirmed listener.

    ``ss -lntuH`` prints one socket per line, e.g.::

        tcp LISTEN 0 4096  *:31337  *:*
        udp UNCONN 0 0     *:53     *:*

    so the local endpoint is field 4 and the protocol is field 0.
    """
    try:
        p = subprocess.run(
            ["docker", "exec", container, "ss", "-lntuH"],
            capture_output=True, text=True, timeout=PROBE_TIMEOUT,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None
    if p.returncode != 0:
        return None

    want = f":{port}"
    for line in p.stdout.splitlines():
        fields = line.split()
        if len(fields) < 5 or not fields[0].startswith(proto):
            continue
        if fields[4].endswith(want):
            return True
    return False


def refresh_status(
    watched: Watched | None,
    current: str,
    *,
    container: str,
    port: int | None = None,
    proto: str = "tcp",
) -> str:
    """Re-observe a listener's status for a read-only listing. Returns the status to show.

    *** OBSERVED ONCE IS NOT OBSERVED. *** :func:`observe` looks at a listener after a settle
    window, and a server that has not bound its port yet is honestly reported ``starting``. Left
    there, that verdict would be permanent: the list functions only ever demoted a status to
    ``down``, so a listener that bound its port a second after the window closed stayed
    ``starting`` for its whole life — and ``route_for`` will not route through a tunnel whose
    bind is unconfirmed. The live-fire run hit exactly that on a freshly recreated container,
    where ligolo took longer than the window to bind.

    So the refresh moves in BOTH directions, and only ever on evidence:
        process gone            -> "down"
        "starting" + now bound  -> "listening"
        anything else           -> unchanged

    Only a ``starting`` listener is re-probed. A ``listening`` one is not, because that would
    mean a ``docker exec`` per tunnel on every poll of the panel to re-confirm something already
    confirmed; ``starting`` is a transient state and the probe ends with it.
    """
    if watched is None:
        return current
    if watched.proc.poll() is not None:
        return "down"
    if current == "starting" and port:
        if port_is_bound(container, port, proto) is True:
            return "listening"
    return current


def observe(
    watched: Watched,
    *,
    container: str,
    port: int | None = None,
    proto: str = "tcp",
    settle: float | None = None,
) -> Liveness:
    """Wait out the settle window, then report what is TRUE about this listener.

    This is the whole point of the module: every caller of it reports a status it looked at,
    rather than one it assumed the instant Popen returned.
    """
    time.sleep(SETTLE_SECONDS if settle is None else settle)

    code = watched.proc.poll()
    if code is not None:
        tail = watched.tail().strip().replace("\n", " | ")[-600:]
        return Liveness(
            alive=False, bound=False, exit_code=code,
            detail=f"the server process exited immediately (code={code}): {tail or '<no output>'}",
        )

    bound = port_is_bound(container, port, proto) if port else None
    if bound is True:
        detail = f"process alive and {proto}/{port} confirmed listening inside {container}"
    elif bound is False:
        detail = (
            f"process alive but {proto}/{port} is NOT bound inside {container} yet — reported as "
            "starting, not listening"
        )
    else:
        detail = (
            "process alive; the port probe could not run (no ss / no docker), so the bind is "
            "UNCONFIRMED and this is reported as starting"
        )
    return Liveness(alive=True, bound=bound, exit_code=None, detail=detail)
