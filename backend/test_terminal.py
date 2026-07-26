"""Raw PTY terminal containment regression-lock (cockpit/terminal.py).

The raw terminal is a SECOND surface onto the same open sandbox `:kali` uses — an
interactive pty, so full-screen tools render. It is exactly as dangerous as `:kali` (full
network reach, arbitrary interactive shell), so it carries exactly the same containment,
and these tests FAIL LOUDLY if any of it is weakened:

  1. HARDCODED TARGET CONTAINER + HARDCODED PAYLOAD. The argv always execs
     config.KALI_OPEN_CONTAINER — the OPEN sandbox, never the isolated one — and the
     in-container driver is a CONSTANT with no interpolation, so no request field can
     redirect the exec or change what runs. TerminalStartRequest has no container /
     target / host / shell / command field at all.
  2. NO ISOLATION GATE, BUT THE COCKPIT KEEPS ITS OWN. terminal.py must not import the
     sandbox isolation module or call assert_isolation_proven (the open box is
     intentionally not isolated). The cockpit executor's gate is asserted separately in
     test_cockpit.py — unchanged.
  3. HUMAN-ONLY — the rule that matters most. An autonomous agent wired to an interactive
     full-reach terminal = autonomous attacks on host/LAN/internet. The terminal may be
     referenced ONLY by the WebSocket route (router.py) + this test. Scanned across the
     source tree, exactly like run_kali / repeater.send / tunnels.
  4. THE SENTINEL SHELL IS UNTOUCHED. The new surface is additive: kali.py must still
     drive its persistent shell over a sentinel-delimited pipe, and must not have grown a
     pty. Reports keep their clean per-command transcripts.
  5. AVAILABILITY + AUDIT + LIMITS. If the open container isn't running, nothing spawns.
     Every session is recorded to the run store (target = the open sandbox), the raw
     transcript is capped, and the live-terminal count is bounded.

Hermetic: _container_running, subprocess.Popen and runstore.save_run are monkeypatched, so
no Docker daemon, no pty and no real DB writes. Run:  python test_terminal.py
"""
from __future__ import annotations

import struct
from pathlib import Path

from cockpit import config
from cockpit import terminal as T
from cockpit.terminal import (
    FRAME_DATA,
    FRAME_RESIZE,
    TerminalRefused,
    TerminalStartRequest,
    encode_frame,
    encode_resize,
)


class _FakePopen:
    """Stands in for the `docker exec` process: records what was written to the driver."""

    def __init__(self, argv, **kwargs):
        self.argv = argv
        self.kwargs = kwargs
        self.written = b""
        self.killed = False
        self.stdin = self
        self.stdout = self
        self.closed = False
        self._out = []

    # --- stdin side ---
    def write(self, data):
        self.written += data
        return len(data)

    def flush(self):
        pass

    def close(self):
        self.closed = True

    # --- stdout side ---
    def feed(self, data: bytes) -> None:
        self._out.append(data)

    def read1(self, _size):
        return self._out.pop(0) if self._out else b""

    # --- process side ---
    def poll(self):
        return 0 if self.killed else None

    def kill(self):
        self.killed = True


class _Spy:
    """Swaps the availability check, Popen and save_run for fakes."""

    def __init__(self, *, up=True):
        self.up = up
        self.proc = None            # the _FakePopen that was created
        self.spawned = False        # was Popen called at all?
        self.saved = []             # every RunRecord passed to save_run
        self._orig = (T._container_running, T.subprocess.Popen, T.runstore.save_run)

    def __enter__(self):
        def fake_up(_name):
            return self.up

        def fake_popen(argv, **kwargs):
            self.spawned = True
            self.proc = _FakePopen(argv, **kwargs)
            return self.proc

        def fake_save(record):
            self.saved.append(record)

        T._container_running = fake_up
        T.subprocess.Popen = fake_popen
        T.runstore.save_run = fake_save
        T._terminals.clear()
        return self

    def __exit__(self, *exc):
        T._container_running, T.subprocess.Popen, T.runstore.save_run = self._orig
        T._terminals.clear()
        return False


# --------------------------------------------------------------------------- #
# 1. hardcoded container + hardcoded payload
# --------------------------------------------------------------------------- #
def test_container_is_hardcoded_and_open_not_isolated() -> None:
    """The argv execs the OPEN sandbox, taken from config — never a request field."""
    with _Spy() as spy:
        T.open_terminal(TerminalStartRequest(cols=120, rows=40))
        argv = spy.proc.argv

    assert argv[0] == "docker" and argv[1] == "exec", argv
    # Assert the container RELATIVE to a fixed later token, not a fixed index: loot flags
    # (`-w <dir>`) sit between `exec` and the container name, so a positional assert would
    # silently stop checking containment the moment another flag is added.
    assert "python3" in argv, argv
    assert argv[argv.index("python3") - 1] == config.KALI_OPEN_CONTAINER, argv
    # The ISOLATED sandbox must never appear — this surface is the open box, by design.
    assert config.SANDBOX_CONTAINER not in argv, argv
    print("  container is hardcoded to the OPEN sandbox: PASS")


def test_request_carries_no_container_or_command_field() -> None:
    """No field of TerminalStartRequest can redirect the exec or choose what runs."""
    fields = set(TerminalStartRequest.model_fields)
    assert fields == {"session_id", "cols", "rows"}, fields
    for banned in ("container", "target", "host", "shell", "command", "argv", "image"):
        assert banned not in fields, f"TerminalStartRequest must not accept '{banned}'"
    print("  request has no container/target/shell/command field: PASS")


def test_driver_is_a_constant_with_no_interpolation() -> None:
    """The in-container payload is a fixed string — nothing client-supplied lands in it."""
    src = (Path(__file__).parent / "cockpit" / "terminal.py").read_text(encoding="utf-8")
    # The driver is assigned from a raw string literal, not built with format/%/f-string.
    assert "_PTY_DRIVER = r\"\"\"" in src, "the driver must be a plain raw-string constant"
    driver = T._PTY_DRIVER
    assert "{" not in driver.replace("{}", ""), "driver must contain no format placeholders"
    with _Spy() as spy:
        T.open_terminal(TerminalStartRequest(session_id="s1"))
        assert spy.proc.argv[-1] == T._PTY_DRIVER, "the driver must be passed verbatim"
    # And it is passed as ONE argv element to `python3 -c` — no shell parses it.
    assert "sh" not in spy.proc.argv[:-1] or "-c" not in spy.proc.argv[:-2], spy.proc.argv
    print("  in-container driver is a constant, passed verbatim as one argv element: PASS")


# --------------------------------------------------------------------------- #
# 2. no isolation gate here (the cockpit keeps its own)
# --------------------------------------------------------------------------- #
def test_no_isolation_gate_on_the_raw_terminal() -> None:
    """terminal.py must not import the isolation module or assert isolation.

    The open sandbox is intentionally NOT isolated, so asserting isolation here would
    correctly refuse every command. The executor's gate is separate and must stay green.
    """
    src = (Path(__file__).parent / "cockpit" / "terminal.py").read_text(encoding="utf-8")
    for banned in ("assert_isolation_proven", "from .sandbox", "from cockpit.sandbox",
                   "import sandbox"):
        assert banned not in src, f"terminal.py must not reference {banned}"
    assert not hasattr(T, "assert_isolation_proven")
    print("  raw terminal adds no isolation gate (open box, by design): PASS")


# --------------------------------------------------------------------------- #
# 3. HUMAN-ONLY (the one that matters most)
# --------------------------------------------------------------------------- #
def test_terminal_is_human_only() -> None:
    """The raw terminal must be reachable ONLY from the WebSocket route + this test.

    An interactive full-reach terminal wired to the agent = autonomous attacks on
    host/LAN/internet. Scan the whole (non-venv, non-test) backend tree.
    """
    backend = Path(__file__).parent
    allowed = {"terminal.py", "router.py"}
    py_files = list(backend.glob("*.py")) + list((backend / "cockpit").glob("*.py"))
    offenders = []
    for f in py_files:
        if f.name in allowed or f.name.startswith("test_"):
            continue
        text = f.read_text(encoding="utf-8")
        if ("open_terminal" in text or "write_input" in text
                or "from .terminal" in text or "cockpit.terminal" in text
                or "import terminal" in text):
            offenders.append(f.name)
    assert not offenders, (
        f"the raw terminal must be HUMAN-ONLY — non-route modules reference it: {offenders}. "
        "The orchestrator/agent/executor must have NO path to a pty in the open sandbox."
    )
    # Belt-and-suspenders: the autonomous exec path exposes no terminal hook.
    from cockpit import executor as EX
    for hook in ("terminal", "open_terminal", "write_input", "read_output"):
        assert not hasattr(EX, hook), f"the executor must not expose {hook} — human-only"
    # ...and neither does the orchestrator loop.
    import orchestrator as ORCH
    for hook in ("terminal", "open_terminal", "write_input"):
        assert not hasattr(ORCH, hook), f"the orchestrator must not expose {hook}"
    print("  the raw terminal is human-only (no agent/executor path): PASS")


# --------------------------------------------------------------------------- #
# 4. the sentinel shell is untouched — this surface is ADDITIVE
# --------------------------------------------------------------------------- #
def test_sentinel_shell_is_unchanged_and_separate() -> None:
    """:kali keeps its sentinel-delimited pipe; the pty lives in its own module.

    The whole point of the design is having BOTH: clean per-command transcripts (which
    reports are built from) AND full-screen interaction. If the pty ever migrated into
    kali.py, the clean transcript would be the thing that quietly died.
    """
    kali_src = (Path(__file__).parent / "cockpit" / "kali.py").read_text(encoding="utf-8")
    assert "sentinel" in kali_src, ":kali must still delimit commands with a sentinel"
    assert "__HACKPIT_KALI_" in kali_src, ":kali's per-command sentinel is gone"
    for pty_ish in ("pty.fork", "TIOCSWINSZ", "_PTY_DRIVER", "openpty"):
        assert pty_ish not in kali_src, (
            f"kali.py grew a pty ({pty_ish}) — the sentinel shell must stay pty-free so "
            "its transcripts stay escape-free"
        )
    # And the reverse: the raw terminal does not reuse :kali's runner.
    term_src = (Path(__file__).parent / "cockpit" / "terminal.py").read_text(encoding="utf-8")
    assert "run_kali" not in term_src and "run_in_shell" not in term_src, (
        "the raw terminal must not call into :kali's runners — it is a separate surface"
    )
    print("  the sentinel shell is untouched; the pty is a separate surface: PASS")


# --------------------------------------------------------------------------- #
# 5. the wire protocol (pure — this is what makes resize possible without in-band escapes)
# --------------------------------------------------------------------------- #
def test_frame_codec() -> None:
    frame = encode_frame(FRAME_DATA, b"whoami\n")
    assert frame[0] == FRAME_DATA
    assert struct.unpack(">I", frame[1:5])[0] == 7
    assert frame[5:] == b"whoami\n"

    r = encode_resize(120, 40)
    assert r[0] == FRAME_RESIZE
    assert r[5:] == b"120x40"

    # Sizes are clamped, never trusted raw — a bogus size can't become a huge ioctl value.
    assert encode_resize(0, 0)[5:] == b"1x1"
    assert encode_resize(999999, 999999)[5:] == b"1000x1000"

    # Arbitrary keystroke bytes stay DATA — they can never be mistaken for a control frame,
    # which is exactly why the input side is framed instead of using an in-band escape.
    evil = bytes([FRAME_RESIZE]) + struct.pack(">I", 4) + b"1x1"
    f = encode_frame(FRAME_DATA, evil)
    assert f[0] == FRAME_DATA and f[5:] == evil
    print("  frame codec (data/resize, clamped, no in-band escape): PASS")


def test_initial_size_is_sent_before_any_keystroke() -> None:
    """The browser's real window size reaches the pty before the first byte is typed."""
    with _Spy() as spy:
        T.open_terminal(TerminalStartRequest(cols=132, rows=43))
        assert spy.proc.written == encode_resize(132, 43), spy.proc.written
    print("  initial window size is pushed at spawn: PASS")


def test_keystrokes_and_resize_are_framed() -> None:
    with _Spy() as spy:
        info = T.open_terminal(TerminalStartRequest())
        before = len(spy.proc.written)
        T.write_input(info.tid, b"top\n")
        T.resize(info.tid, 100, 30)
        wire = spy.proc.written[before:]
        assert wire == encode_frame(FRAME_DATA, b"top\n") + encode_resize(100, 30), wire
    print("  keystrokes and resize go out as distinct frames: PASS")


# --------------------------------------------------------------------------- #
# 6. availability, audit, limits
# --------------------------------------------------------------------------- #
def test_refuses_when_sandbox_down_and_nothing_spawns() -> None:
    with _Spy(up=False) as spy:
        try:
            T.open_terminal(TerminalStartRequest())
            assert False, "must refuse when the open sandbox is down"
        except TerminalRefused as exc:
            assert config.KALI_OPEN_CONTAINER in str(exc)
        assert not spy.spawned, "nothing may spawn when the sandbox is unavailable"
    print("  refuses cleanly when the open sandbox is down: PASS")


def test_session_is_recorded_to_the_run_store() -> None:
    """The RAW stream is audited: one run record per terminal, target = the open sandbox."""
    with _Spy() as spy:
        info = T.open_terminal(TerminalStartRequest(session_id="eng-1"))
        spy.proc.feed(b"root@kali:~# whoami\r\nroot\r\n")
        T.read_output(info.tid)
        T.close_terminal(info.tid)

    assert spy.saved, "the terminal session must be recorded"
    final = spy.saved[-1]
    assert final.target == config.KALI_OPEN_CONTAINER
    assert final.session_id == "eng-1"
    assert final.approved is True  # a human at the keyboard IS the approval
    assert final.command == "pty"  # honest about what ran — not a fake `sh -c`
    assert "whoami" in final.stdout and "root" in final.stdout
    assert final.finished_at is not None
    # Checkpointed at spawn too, so a crash mid-session still leaves a trail.
    assert spy.saved[0].run_id == final.run_id
    print("  every terminal session is recorded (raw stream, open sandbox): PASS")


def test_transcript_is_capped() -> None:
    """A flood of escape bytes can't blow up the audit row."""
    with _Spy() as spy:
        info = T.open_terminal(TerminalStartRequest())
        spy.proc.feed(b"A" * (T.TERMINAL_TRANSCRIPT_CAP + 50_000))
        T.read_output(info.tid)
        T.close_terminal(info.tid)
    saved = spy.saved[-1]
    assert len(saved.stdout) <= T.TERMINAL_TRANSCRIPT_CAP + 100, len(saved.stdout)
    assert "truncated" in saved.stdout
    print("  the audited transcript is capped: PASS")


def test_live_terminal_cap() -> None:
    with _Spy():
        for _ in range(T.TERMINAL_MAX_LIVE):
            T.open_terminal(TerminalStartRequest())
        try:
            T.open_terminal(TerminalStartRequest())
            assert False, "must refuse past the live-terminal cap"
        except TerminalRefused as exc:
            assert "too many" in str(exc)
    print("  live-terminal count is bounded: PASS")


def test_writing_to_a_closed_terminal_is_refused() -> None:
    with _Spy():
        info = T.open_terminal(TerminalStartRequest())
        T.close_terminal(info.tid)
        for call in (lambda: T.write_input(info.tid, b"x"), lambda: T.resize(info.tid, 80, 24)):
            try:
                call()
                assert False, "a closed terminal must refuse input"
            except TerminalRefused:
                pass
    print("  a closed terminal refuses input: PASS")


def test_status_never_claims_isolation() -> None:
    with _Spy():
        st = T.terminal_status()
    assert st["isolated"] is False, "the banner must never claim isolation"
    assert st["container"] == config.KALI_OPEN_CONTAINER
    print("  status reports full-reach, never isolated: PASS")


# --------------------------------------------------------------------------- #
# 7. the route pins the WebSocket origin
# --------------------------------------------------------------------------- #
def test_websocket_origin_is_pinned() -> None:
    """CORSMiddleware does not cover WebSockets, so the route enforces the origin itself."""
    src = (Path(__file__).parent / "cockpit" / "router.py").read_text(encoding="utf-8")
    assert "_ALLOWED_WS_ORIGINS" in src, "the WS route must pin the allowed origins"
    from cockpit import router as R
    assert R._ALLOWED_WS_ORIGINS == {"http://localhost:3000", "http://127.0.0.1:3000"}
    print("  the WebSocket route pins its allowed origins: PASS")


if __name__ == "__main__":
    test_container_is_hardcoded_and_open_not_isolated()
    test_request_carries_no_container_or_command_field()
    test_driver_is_a_constant_with_no_interpolation()
    test_no_isolation_gate_on_the_raw_terminal()
    test_terminal_is_human_only()
    test_sentinel_shell_is_unchanged_and_separate()
    test_frame_codec()
    test_initial_size_is_sent_before_any_keystroke()
    test_keystrokes_and_resize_are_framed()
    test_refuses_when_sandbox_down_and_nothing_spawns()
    test_session_is_recorded_to_the_run_store()
    test_transcript_is_capped()
    test_live_terminal_cap()
    test_writing_to_a_closed_terminal_is_refused()
    test_status_never_claims_isolation()
    test_websocket_origin_is_pinned()
    print("ALL raw-terminal containment tests pass")
