"""SAFETY INVARIANTS for the shared listener lifecycle (cockpit/lifecycle.py).

Build #7 gave three surfaces — the Sliver C2 daemon, the pivot listener and the DNS-tunnel
listener — one shared way to spawn a server and then LOOK at it. That fixed a real defect (a
status assigned at Popen time and never observed) by granting a real thing: two of the three
binaries are interactive consoles, so their stdin has to stay open or they read EOF and exit.

Holding a console's stdin open is a liveness requirement. Being able to TYPE INTO a live C2
console is a capability, and it is one nothing in HackPit is allowed to have on a listener. This
file is the lock on that distinction:

  1. *** NO WRITER OBJECT EXISTS. *** The child is given the READ end of an OS pipe as a raw fd,
     not ``subprocess.PIPE``, so ``proc.stdin is None`` on every watched listener. There is no
     ``.stdin.write`` for a future caller to reach for, whether or not they read this comment.
  2. *** NOTHING WRITES TO A LISTENER'S STDIN. *** Source-scanned across the whole backend tree
     WITH a positive control. The one legitimate stdin write in the codebase — the Sliver
     `generate` console line — goes to a `subprocess.run(input=...)` that is a GATED, one-shot
     build and is not a tracked listener at all; it is allow-listed by file and asserted to be
     exactly that.
  3. THE STATUS IS DERIVED FROM OBSERVATION ONLY. Every branch of the derivation is exercised,
     including the one that matters most: a probe that COULD NOT RUN degrades to "starting" and
     is never reported as a confirmed listener.
  4. A DEAD PROCESS IS REPORTED DEAD, with the output it died on — the exact case that used to
     be reported as `listening`.
  5. `-i` IS PER-BINARY AND OFF BY DEFAULT. exec_argv only forwards stdin when explicitly asked.
  6. A STOP ACTUALLY STOPS. Killing a `docker exec` client does NOT kill the process inside the
     container — the live-fire run found stopped listeners still holding their ports, and the
     next start failing with EADDRINUSE. The reap is asserted to happen AND to be targeted at
     the listener's own argv rather than the tool in general.

Hermetic: no Docker daemon and no network — `subprocess.Popen` / `subprocess.run` are
monkeypatched by manual save/restore (this repo has NO pytest).

Run:  backend/.venv/Scripts/python.exe backend/test_lifecycle_safety.py
"""
from __future__ import annotations

import os
import re
import subprocess
import types
from pathlib import Path

from cockpit import lifecycle as L
from test_support import scans

BACKEND = Path(__file__).resolve().parent


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
class _FakePopen:
    """Records how it was spawned. Mirrors the real Popen's stdin contract exactly.

    A real Popen handed a raw fd for stdin sets ``self.stdin = None``; the fake must too, or
    invariant 1 would be testing the fake rather than the code.
    """

    instances: list["_FakePopen"] = []

    def __init__(self, argv, **kw):
        self.argv = list(argv)
        self.kwargs = dict(kw)
        self.stdin = None if isinstance(kw.get("stdin"), int) else kw.get("stdin")
        self.stdout = None
        self.stderr = None
        self.alive = True
        self.killed = False
        _FakePopen.instances.append(self)

    def poll(self):
        return None if self.alive else 0

    def kill(self):
        self.killed = True


class _Spawn:
    """Hermetic spawn + probe. `bound` drives what the port probe reports."""

    def __init__(self, *, bound: bool | None = True):
        self.bound = bound
        self._orig = ()

    def __enter__(self):
        _FakePopen.instances = []
        self._orig = (L.subprocess.Popen, L.port_is_bound, L.SETTLE_SECONDS)
        L.subprocess.Popen = _FakePopen
        L.port_is_bound = lambda container, port, proto: self.bound
        L.SETTLE_SECONDS = 0.0
        return self

    def __exit__(self, *exc):
        L.subprocess.Popen, L.port_is_bound, L.SETTLE_SECONDS = self._orig
        return False


# --------------------------------------------------------------------------- #
# 1. NO WRITER OBJECT EXISTS ON A WATCHED LISTENER
# --------------------------------------------------------------------------- #
def test_watched_listeners_expose_no_stdin_writer() -> None:
    """*** THE INVARIANT. *** A listener's stdin is held open by a raw fd, never a writer.

    Both modes are checked, because the interactive one is the only one that could regress:
      * interactive=True  -> the child gets a raw READ fd; proc.stdin is None
      * interactive=False -> the child gets DEVNULL; proc.stdin is None

    If this ever came back as ``subprocess.PIPE``, ``proc.stdin`` would be a writable file object
    on a live C2 console and the only thing standing between it and an ungated command would be
    that nobody had written the line yet.
    """
    with _Spawn():
        for interactive in (True, False):
            w = L.spawn_watched(["docker", "exec", "x"], interactive=interactive)
            assert w.proc.stdin is None, (
                f"interactive={interactive}: proc.stdin is {w.proc.stdin!r} — a watched listener "
                "must expose NO writer object; the child's stdin is a raw fd this process holds"
            )
            passed = w.proc.kwargs.get("stdin")
            if interactive:
                assert isinstance(passed, int) and passed != subprocess.DEVNULL, (
                    f"an interactive listener must be handed a raw pipe fd, got {passed!r}"
                )
                assert isinstance(w.stdin_fd, int), "the write end must be held as a bare fd"
            else:
                assert passed == subprocess.DEVNULL, (
                    f"a daemon needs no stdin at all — expected DEVNULL, got {passed!r}"
                )
                assert w.stdin_fd is None, "a non-interactive listener must hold no write end"
            w.kill()

    # And killing closes it: the fd is released, not leaked for the process's lifetime.
    with _Spawn():
        w = L.spawn_watched(["docker", "exec", "x"], interactive=True)
        fd = w.stdin_fd
        w.kill()
        assert w.stdin_fd is None, "kill must release the held write end"
        try:
            os.write(fd, b"x")
            raise AssertionError("the held stdin fd is still open after kill")
        except OSError:
            pass
    print("  a watched listener exposes NO stdin writer; the held fd is raw and released: PASS")


# --------------------------------------------------------------------------- #
# 2. NOTHING IN THE TREE WRITES TO A LISTENER'S STDIN
# --------------------------------------------------------------------------- #
# The handles that could reach a watched listener's stdin. THIS is the scope of the invariant:
# not "who writes to any stdin anywhere" — `:kali`, the live-session panel and the PTY terminal
# all legitimately do, each behind its own human-only lock — but "who can reach the write end
# this module holds open on a LISTENER".
#
# `\.stdin_fd` and not `\bstdin_fd\b`: the PTY driver in cockpit/terminal.py has a LOCAL variable
# of that name (`stdin_fd = sys.stdin.fileno()`) inside the container-side script, which is an
# unrelated file descriptor on an unrelated surface. Matching the bare word would have made this
# lock fail on a correct module — and the usual repair for that is to allow-list terminal.py,
# which would then have silently permitted a real handle grab there forever. Match the ATTRIBUTE
# ACCESS instead, which is the only way to reach a listener's held write end.
_HANDLE_PATTERNS = [r"\.stdin_fd\b", r"\.watched\b", r"\bWatched\b"]

# The modules that own a listener, plus the module that defines the handle. Anything else naming
# it would be a new route to a live console's stdin.
_HANDLE_ALLOWED = {
    "cockpit/lifecycle.py",
    "cockpit/tunnels.py",
    "cockpit/obfuscation.py",
    "cockpit/sliver.py",
}

# What "typing into a live process" looks like, scanned inside the listener modules only.
_STDIN_WRITE_PATTERNS = [
    r"\.stdin\s*\.\s*write\b",
    r"\.stdin\s*\.\s*writelines\b",
    r"\.stdin\s*\.\s*flush\b",
    r"\.communicate\s*\(",
    r"\bos\.write\s*\(",
]

_LISTENER_MODULES = ("cockpit/lifecycle.py", "cockpit/tunnels.py", "cockpit/obfuscation.py",
                     "cockpit/sliver.py")


def test_nothing_writes_to_a_listener_stdin() -> None:
    """The four listener modules never type into a live process, and nothing else holds the handle.

    Deliberately NOT a whole-tree ban on stdin writes. `:kali`, the live-session panel and the
    PTY terminal all write to a process's stdin BY DESIGN — that is what those surfaces are —
    and each carries its own human-only lock. Scanning for the wrong thing would either fail
    against three correct modules or, worse, get "fixed" by widening the allow-list until it
    stopped meaning anything. The invariant here is narrower and real: THE WRITE END THIS MODULE
    HOLDS OPEN ON A LISTENER HAS NO WRITER, anywhere.
    """
    # 1. Nobody outside the four owning modules can even name the handle.
    res = scans.scan_source_tree(patterns=_HANDLE_PATTERNS, allowed=_HANDLE_ALLOWED)
    scans.assert_clean(
        res,
        what="only the listener modules may hold a Watched handle",
        must_have_scanned=["orchestrator.py", "cockpit/executor.py", "cockpit/session.py",
                           "cockpit/kali.py", "main.py"],
        min_checked=60,
    )
    scans.assert_catches_a_planted_violation(
        plant="os.write(tunnel.watched.stdin_fd, b'whoami\\n')",
        patterns=_HANDLE_PATTERNS, allowed=_HANDLE_ALLOWED,
        where="orchestrator.py",
    )

    # 2. And inside those modules, nothing writes to a live process handle.
    for rel in _LISTENER_MODULES:
        src = (BACKEND / rel).read_text(encoding="utf-8")
        # Comments and docstrings discuss this at length; strip them so prose cannot trip it and,
        # more importantly, so prose cannot HIDE it either.
        code = "\n".join(
            line for line in src.splitlines() if not line.lstrip().startswith("#")
        )
        for pattern in _STDIN_WRITE_PATTERNS:
            hits = [m.group(0) for m in re.finditer(pattern, code)]
            # os.close on the held fd is the one permitted operation — releasing it, not writing.
            assert not hits, (
                f"{rel} writes to a spawned process's stdin ({hits}) — holding a console's "
                "stdin open is a liveness requirement; typing into it is a capability"
            )

    # 3. THE ALLOW-LIST IS NOT A BLANK CHEQUE. sliver.py DOES write a child's stdin exactly once
    # — the gated implant build's console line — and that must stay a one-shot
    # `subprocess.run(input=...)` against a process that is not a tracked listener at all.
    sliver_src = (BACKEND / "cockpit" / "sliver.py").read_text(encoding="utf-8")
    inputs = re.findall(r"\binput\s*=\s*(\w+)", sliver_src)
    assert inputs == ["console_input"], (
        f"the only stdin write in sliver.py must be the gated build's console line, got {inputs}"
    )
    assert "generate_console_line" in sliver_src and "SliverRefused" in sliver_src, sliver_src[:0]
    # The build's process is never registered as a listener: the server registry is keyed on
    # start_server's spawn, and generate_implant must not touch it.
    import ast

    gen = next(
        n for n in ast.walk(ast.parse(sliver_src))
        if isinstance(n, ast.FunctionDef) and n.name == "generate_implant"
    )
    gen_src = ast.get_source_segment(sliver_src, gen) or ""
    assert "spawn_watched" not in gen_src, (
        "an implant build must not spawn a TRACKED listener — its console session ends with the "
        "build, and giving it a held-open stdin would be a live C2 console nobody asked for"
    )
    print(f"  {len(res.checked)} modules scanned: only the listener modules hold the handle, "
          "and none writes to it (+ planted-violation control): PASS")


# --------------------------------------------------------------------------- #
# 3. THE STATUS IS DERIVED FROM OBSERVATION ONLY
# --------------------------------------------------------------------------- #
def test_status_is_derived_only_from_what_was_observed() -> None:
    """Every branch, including the one that must NOT claim a listener: an unrunnable probe."""
    cases = [
        # (alive, bound) -> status
        ((True, True), "listening"),
        ((True, False), "starting"),
        ((True, None), "starting"),
        ((False, False), "down"),
        ((False, None), "down"),
    ]
    for (alive, bound), want in cases:
        got = L.Liveness(alive=alive, bound=bound, exit_code=None).status
        assert got == want, f"alive={alive} bound={bound!r} -> {got!r}, want {want!r}"

    # The tri-state matters: None is "could not probe", and it must never read as True.
    assert L.Liveness(alive=True, bound=None, exit_code=None).status != "listening", (
        "an UNPROBED port must never be reported as a confirmed listener — that is the whole "
        "difference between an observed status and an assigned one"
    )

    # And end to end through observe(), with the probe genuinely unable to run.
    with _Spawn(bound=None):
        w = L.spawn_watched(["docker", "exec", "x"], interactive=False)
        live = L.observe(w, container="c", port=1234, proto="tcp")
        assert live.status == "starting" and live.bound is None, live
        assert "UNCONFIRMED" in live.detail, live.detail
        w.kill()

    with _Spawn(bound=True):
        w = L.spawn_watched(["docker", "exec", "x"], interactive=False)
        live = L.observe(w, container="c", port=1234, proto="tcp")
        assert live.status == "listening" and live.bound is True, live
        assert "confirmed listening" in live.detail, live.detail
        w.kill()

    # No port to probe at all -> still not a confirmed listener.
    with _Spawn(bound=True):
        w = L.spawn_watched(["docker", "exec", "x"], interactive=False)
        live = L.observe(w, container="c", port=None)
        assert live.status == "starting" and live.bound is None, live
        w.kill()
    print("  status comes only from observation; an unprobed port is never 'listening': PASS")


def test_the_port_probe_is_read_only_and_fails_closed() -> None:
    """`ss` parsing is exercised on real output, and every failure mode returns None, not False.

    None vs False is load-bearing: False means "probed, not bound" (a real reading), None means
    "no reading". Collapsing them would let a broken probe read as a definite answer.
    """
    sample = (
        "udp UNCONN 0      0      127.0.0.11:45257 0.0.0.0:*\n"
        "tcp LISTEN 0      4096   127.0.0.11:33995 0.0.0.0:*\n"
        "tcp LISTEN 0      4096            *:31337       *:*\n"
        "udp UNCONN 0      0               *:53          *:*\n"
    )
    seen: list[list[str]] = []

    def fake_run(argv, **kw):
        seen.append(list(argv))
        return types.SimpleNamespace(returncode=0, stdout=sample, stderr="")

    orig = L.subprocess.run
    try:
        L.subprocess.run = fake_run
        assert L.port_is_bound("c", 31337, "tcp") is True
        assert L.port_is_bound("c", 53, "udp") is True
        assert L.port_is_bound("c", 9999, "tcp") is False, "a real reading of 'absent' is False"
        # Protocol is not ignored: 53 is UDP here, so asking for TCP/53 must not match.
        assert L.port_is_bound("c", 53, "tcp") is False
    finally:
        L.subprocess.run = orig

    # The probe is READ-ONLY: `ss -lntuH`, nothing else, no shell.
    for argv in seen:
        assert argv[:3] == ["docker", "exec", "c"] and argv[3] == "ss", argv
        assert "sh" not in argv and "-c" not in argv, argv

    # Every failure mode -> None (unknown), never False (a definite answer).
    for boom in (FileNotFoundError("docker"), subprocess.TimeoutExpired("ss", 1), OSError("x")):
        def _raise(argv, **kw):
            raise boom

        orig = L.subprocess.run
        try:
            L.subprocess.run = _raise
            assert L.port_is_bound("c", 1, "tcp") is None, f"{boom!r} must degrade to None"
        finally:
            L.subprocess.run = orig

    orig = L.subprocess.run
    try:
        L.subprocess.run = lambda argv, **kw: types.SimpleNamespace(
            returncode=127, stdout="", stderr="ss: not found")
        assert L.port_is_bound("c", 1, "tcp") is None, "a failed probe must degrade to None"
    finally:
        L.subprocess.run = orig
    print("  the port probe is read-only and every failure degrades to 'unknown': PASS")


# --------------------------------------------------------------------------- #
# 4. A DEAD PROCESS IS REPORTED DEAD
# --------------------------------------------------------------------------- #
def test_a_dead_process_is_reported_dead_with_its_output() -> None:
    """*** THE BUG THIS MODULE EXISTS FOR. ***

    ligolo-proxy and dnscat2-server, launched with no usable stdin, print a banner and exit 0.
    Before build #7 that came back as `status="listening"`. Now it comes back dead, carrying the
    output it died on so the operator can see WHY rather than being told a port is open.
    """
    with _Spawn():
        w = L.spawn_watched(["docker", "exec", "x"], interactive=True)
        w.proc.alive = False
        w._buf.extend(b"level=info msg=\"Loading configuration file ligolo-ng.yaml\"")
        live = L.observe(w, container="c", port=11601, proto="tcp")

        assert live.alive is False and live.status == "down", live
        assert live.exit_code == 0, (
            "exit code 0 is exactly the case that fooled the old code — a clean exit is still "
            "an exit"
        )
        assert "exited immediately" in live.detail, live.detail
        assert "ligolo-ng.yaml" in live.detail, (
            "the diagnostic must carry what the process actually said, not just a verdict"
        )
        w.kill()

    # A dead process with NO output still reports honestly rather than rendering an empty tail.
    with _Spawn():
        w = L.spawn_watched(["docker", "exec", "x"], interactive=True)
        w.proc.alive = False
        live = L.observe(w, container="c", port=1, proto="tcp")
        assert live.status == "down" and "<no output>" in live.detail, live.detail
        w.kill()
    print("  a process that exited is reported down, with the output it died on: PASS")


# --------------------------------------------------------------------------- #
# 5. `-i` IS PER-BINARY AND OFF BY DEFAULT
# --------------------------------------------------------------------------- #
def test_exec_argv_forwards_stdin_only_when_asked() -> None:
    """`-i` is the flag that actually forwards stdin into the container. It is never a default."""
    plain = L.exec_argv("box", ["chisel", "server"], interactive=False)
    assert plain == ["docker", "exec", "box", "chisel", "server"], plain
    assert "-i" not in plain, "a daemon must not be handed a forwarded stdin"

    inter = L.exec_argv("box", ["ligolo-proxy"], interactive=True)
    assert inter == ["docker", "exec", "-i", "box", "ligolo-proxy"], inter

    # It is keyword-only, so `interactive` can never be passed positionally by accident.
    try:
        L.exec_argv("box", ["x"], True)  # type: ignore[misc]
        raise AssertionError("interactive must be keyword-only")
    except TypeError:
        pass

    # PURE: building an argv must execute nothing.
    orig = L.subprocess.Popen
    try:
        def _boom(*a, **kw):
            raise AssertionError("exec_argv must execute NOTHING")

        L.subprocess.Popen = _boom
        L.exec_argv("box", ["x"], interactive=True)
    finally:
        L.subprocess.Popen = orig
    print("  `-i` is per-binary, keyword-only and never defaulted; exec_argv is pure: PASS")


def test_stopping_reaps_the_server_inside_the_container() -> None:
    """*** KILLING A `docker exec` CLIENT DOES NOT KILL WHAT IT STARTED. ***

    Found by the live-fire run, not by a unit test: after stops that reported `status="down"`,
    `ss` inside the sandbox still showed `iodined` on UDP/53 and two `chisel server` processes
    listening, and the NEXT start failed with EADDRINUSE — a refusal about a listener the
    operator had been told was already stopped. Same family as the bug this module exists for:
    a state reported rather than observed.

    The reap must be TARGETED. `pkill -f chisel` would stop every chisel on the box, including a
    second operator's tunnel; the pattern is this listener's own argv, which carries its port.
    """
    reaped: list[list[str]] = []

    def fake_run(argv, **kw):
        reaped.append(list(argv))
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    with _Spawn():
        orig = L.subprocess.run
        try:
            L.subprocess.run = fake_run
            w = L.spawn_watched(["docker", "exec", "box", "chisel", "server"], interactive=False)
            w.kill(container="box", server_argv=["chisel", "server", "-p", "8080", "--reverse"])
        finally:
            L.subprocess.run = orig

    assert reaped, (
        "a stop must reap the container-side server — killing the `docker exec` client leaves it "
        "running and holding its port"
    )
    argv = reaped[-1]
    assert argv[:3] == ["docker", "exec", "box"], argv
    assert argv[3:5] == ["pkill", "-f"], argv
    assert argv[5] == "chisel server -p 8080 --reverse", (
        f"the reap must target THIS listener's own argv, not the tool in general — got {argv[5]!r}"
    )
    assert argv[5] != "chisel", "a bare tool name would stop somebody else's tunnel too"

    # No container/argv -> no reap. A console binary exits on EOF, and a caller that cannot say
    # where the server lives must not be given a blanket pkill.
    reaped.clear()
    with _Spawn():
        orig = L.subprocess.run
        try:
            L.subprocess.run = fake_run
            w = L.spawn_watched(["docker", "exec", "box", "x"], interactive=True)
            w.kill()
        finally:
            L.subprocess.run = orig
    assert not reaped, f"a kill with no container/argv must issue no pkill at all, got {reaped}"
    print("  a stop reaps the container-side server, targeted at its own argv: PASS")


def test_output_is_drained_so_a_listener_cannot_wedge() -> None:
    """A chatty server must not fill the 64 KB pipe buffer and block on its next write.

    dnscat2 is very chatty. Without a drain the listener would wedge mid-engagement and look
    exactly like a hung tunnel — a failure that would be blamed on the network, not on us.
    """
    import io

    with _Spawn():
        w = L.spawn_watched(["docker", "exec", "x"], interactive=True)
        w.proc.stdout = io.BytesIO(b"A" * (L.TAIL_BYTES * 3))
        w.proc.stderr = io.BytesIO(b"boom")
        w.start_drains()
        for _ in range(200):
            if len(w.tail()) >= L.TAIL_BYTES:
                break
        tail = w.tail()
        assert len(tail) <= L.TAIL_BYTES, (
            f"the retained tail must be BOUNDED, got {len(tail)} bytes — an unbounded buffer on "
            "a long-lived listener is its own leak"
        )
        assert tail, "the drain must actually consume the pipe"
        w.kill()
    print(f"  output is drained into a bounded {L.TAIL_BYTES}-byte tail: PASS")


if __name__ == "__main__":
    test_watched_listeners_expose_no_stdin_writer()
    test_nothing_writes_to_a_listener_stdin()
    test_status_is_derived_only_from_what_was_observed()
    test_the_port_probe_is_read_only_and_fails_closed()
    test_a_dead_process_is_reported_dead_with_its_output()
    test_exec_argv_forwards_stdin_only_when_asked()
    test_stopping_reaps_the_server_inside_the_container()
    test_output_is_drained_so_a_listener_cannot_wedge()
    print("ALL listener-lifecycle safety invariants hold")
