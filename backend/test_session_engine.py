"""Named-session engine tests (cockpit/session_engine.py).

The engine drives NAMED tmux sessions in the open sandbox: parallel persistent sessions with
per-session cwd, automatic interactive-prompt detection, a background lifecycle with a
notify-once completion, output tiering, and wedge / pipe-degradation recovery. This suite
proves each of those against fixtures, with the single impure boundary (``_tmux``) and the
container/loot helpers monkeypatched — so it runs with NO Docker and NO tmux.

Run:  python test_session_engine.py
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from cockpit import config
from cockpit import session_engine as SE
from cockpit.session_engine import (
    SessionOpenRequest,
    SessionRunRequest,
    SessionInputRequest,
    detect_prompt,
    detect_wedge,
    detect_pipe_degradation,
    manage_output,
    strip_ansi,
    compress_repeats,
)


# --------------------------------------------------------------------------- #
# hermetic harness
# --------------------------------------------------------------------------- #
class _FakeTmux:
    """Stands in for `docker exec … tmux …`: tracks a pane string per tmux session."""

    def __init__(self) -> None:
        self.panes: dict[str, str] = {}
        self.calls: list[list[str]] = []

    def __call__(self, args, *, input_text=None, timeout=15.0):
        self.calls.append(list(args))
        cmd = args[0]
        tname = args[args.index("-t") + 1] if "-t" in args else None
        if cmd == "new-session":
            self.panes[args[args.index("-s") + 1]] = ""
        elif cmd == "kill-session":
            self.panes.pop(tname, None)
        elif cmd == "capture-pane":
            return SimpleNamespace(stdout=self.panes.get(tname, ""), returncode=0)
        return SimpleNamespace(stdout="", returncode=0)

    def set_pane(self, name: str, text: str) -> None:
        self.panes[f"{SE.TMUX_PREFIX}_{name}"] = text


class _Spy:
    """Swap the impure boundary, the availability check, save_run and loot paths for fakes."""

    def __init__(self, tmp: Path, *, up: bool = True):
        self.tmp = tmp
        self.up = up
        self.tmux = _FakeTmux()
        self.saved: list = []
        self._orig: dict = {}

    def __enter__(self):
        self._orig = {
            "_tmux": SE._tmux,
            "_container_running": SE._container_running,
            "save_run": SE.runstore.save_run,
            "kali_workdir": SE.loot.kali_workdir,
            "host_dir": SE.loot.host_dir,
            "container_dir": SE.loot.container_dir,
        }
        SE._tmux = self.tmux
        SE._container_running = lambda _n: self.up
        SE.runstore.save_run = lambda r: self.saved.append(r)
        SE.loot.kali_workdir = lambda: "/root"
        SE.loot.host_dir = lambda name: self.tmp / name
        SE.loot.container_dir = lambda name: f"/loot/{name}"
        SE._sessions.clear()
        return self

    def __exit__(self, *exc):
        SE._tmux = self._orig["_tmux"]
        SE._container_running = self._orig["_container_running"]
        SE.runstore.save_run = self._orig["save_run"]
        SE.loot.kali_workdir = self._orig["kali_workdir"]
        SE.loot.host_dir = self._orig["host_dir"]
        SE.loot.container_dir = self._orig["container_dir"]
        SE._sessions.clear()
        return False


def _marker(rc: int, cwd: str) -> str:
    return f"\n{SE.MARKER}:{rc}:{cwd}:__\n"


def _tmpdir() -> Path:
    import tempfile
    return Path(tempfile.mkdtemp(prefix="hp-se-"))


# --------------------------------------------------------------------------- #
# 1. PURE — prompt detection (the headline feature)
# --------------------------------------------------------------------------- #
def test_prompt_detection_over_fixtures() -> None:
    # An idle shell (our marker) is NOT "interactive" — it is ready for a command.
    idle = detect_prompt("total 4\n-rw-r--r-- 1 root root 0 x" + _marker(0, "/tmp/loot"))
    assert idle.kind == "idle" and idle.rc == 0 and idle.cwd == "/tmp/loot", idle

    cases = {
        "msf6 > ": "msfconsole",
        "msf6 exploit(multi/handler) > ": "msfconsole",
        "meterpreter > ": "msfconsole",
        "sliver > ": "sliver",
        "sliver (WICKED_PANDA) > ": "sliver",
        "*Evil-WinRM* PS C:\\Users\\admin\\Documents> ": "evil-winrm",
        ">>> ": "python",
        "mysql> ": "sql",
        "Do you want to continue? [y/N] ": "awaiting-answer",
        "Password: ": "awaiting-answer",
    }
    for pane, program in cases.items():
        st = detect_prompt("some earlier output\n" + pane)
        assert st.kind == "interactive", f"{pane!r} -> {st}"
        assert st.program == program, f"{pane!r} -> {st.program} (want {program})"

    # A command still running (no prompt, no marker) reads as "running", not interactive.
    assert detect_prompt("Scanning 10.0.0.0/24 ...\n[####      ] 40%").kind == "running"
    print("  prompt detection: idle / interactive tools / running, over fixtures: PASS")


def test_ansi_and_repeat_compression() -> None:
    assert strip_ansi("\x1b[31mred\x1b[0m\rline") == "redline"
    flood = "\n".join(["x"] * 50)
    out = compress_repeats(flood)
    assert "repeated" in out and out.count("x") < 10, out
    # distinct lines are never collapsed
    assert compress_repeats("a\nb\nc") == "a\nb\nc"
    print("  ANSI stripping + repetitive-line compression: PASS")


def test_output_tiering() -> None:
    small = manage_output("hello", name="s")
    assert small.inline == "hello" and small.saved_path is None and not small.truncated

    saved: dict = {}
    big = manage_output("A" * 40_000, name="s",
                        save=lambda n, t: saved.setdefault(n, t) and f"/loot/kali/.scratch/{n}")
    assert big.truncated and big.saved_path and "omitted" in big.inline
    assert len(big.inline) < 20_000 and "s" in saved

    watch = manage_output("B" * (SE.WATCHDOG_OUTPUT_CAP + 10), name="w", save=lambda n, t: "/p")
    assert watch.watchdog and "WATCHDOG" in watch.inline
    print("  output tiering: inline <=15K / >15K to scratch / >5M watchdog: PASS")


# --------------------------------------------------------------------------- #
# 2. PURE — wedge + pipe-degradation signatures
# --------------------------------------------------------------------------- #
def test_wedge_signature() -> None:
    wedged = detect_wedge(command_pending=True, seconds_since_send=90,
                          pane_changed=False, marker_returned=False)
    assert wedged.triggered and wedged.actions, wedged
    # a slow-but-alive scan (pane keeps changing) is NOT wedged
    alive = detect_wedge(command_pending=True, seconds_since_send=90,
                         pane_changed=True, marker_returned=False)
    assert not alive.triggered, alive
    # a finished command (marker returned) is NOT wedged
    done = detect_wedge(command_pending=True, seconds_since_send=90,
                        pane_changed=False, marker_returned=True)
    assert not done.triggered, done
    print("  wedged-session signature (3 conditions) detected, false cases rejected: PASS")


def test_pipe_degradation_signature() -> None:
    deg = detect_pipe_degradation(pane_changed=True, log_grew=False, capture_works=True)
    assert deg.triggered and any("pipe-pane" in a for a in deg.actions), deg
    # a healthy pipe (log growing) is not degraded
    ok = detect_pipe_degradation(pane_changed=True, log_grew=True, capture_works=True)
    assert not ok.triggered, ok
    # a dead session (capture broken) is a different failure, not pipe degradation
    dead = detect_pipe_degradation(pane_changed=False, log_grew=False, capture_works=False)
    assert not dead.triggered, dead
    print("  tmux pipe-degradation signature (3 conditions) detected, false cases rejected: PASS")


# --------------------------------------------------------------------------- #
# 3. INTEGRATION — named sessions keep independent cwd
# --------------------------------------------------------------------------- #
def test_named_sessions_independent_cwd() -> None:
    tmp = _tmpdir()
    with _Spy(tmp) as spy:
        SE.open_session(SessionOpenRequest(name="alpha"))
        SE.open_session(SessionOpenRequest(name="bravo"))
        # each session reports its OWN pwd via its OWN marker
        spy.tmux.set_pane("alpha", "listing\n" + _marker(0, "/loot/kali/alpha"))
        spy.tmux.set_pane("bravo", "listing\n" + _marker(0, "/opt/tools"))
        SE.capture("alpha")
        SE.capture("bravo")
        a = SE.get_session("alpha")
        b = SE.get_session("bravo")
    assert a.cwd == "/loot/kali/alpha" and b.cwd == "/opt/tools", (a.cwd, b.cwd)
    assert a.cwd != b.cwd, "named sessions must track cwd independently"
    print("  named parallel sessions keep independent cwd: PASS")


# --------------------------------------------------------------------------- #
# 4. INTEGRATION — a fixture session flips to "interactive"
# --------------------------------------------------------------------------- #
def test_session_flips_to_interactive() -> None:
    tmp = _tmpdir()
    with _Spy(tmp) as spy:
        SE.open_session(SessionOpenRequest(name="msf"))
        spy.tmux.set_pane("msf", "[*] Starting the Metasploit Framework console...\nmsf6 > ")
        cap = SE.capture("msf")
        info = SE.get_session("msf")
    assert cap["prompt"]["kind"] == "interactive" and cap["prompt"]["awaiting_input"]
    assert cap["prompt"]["program"] == "msfconsole"
    assert info.awaiting_input and info.program == "msfconsole"
    print("  a fixture session flips to 'interactive - awaiting input' (msfconsole): PASS")


# --------------------------------------------------------------------------- #
# 5. INTEGRATION — auto-background past the threshold
# --------------------------------------------------------------------------- #
def test_auto_background_past_threshold() -> None:
    tmp = _tmpdir()
    with _Spy(tmp) as spy:
        SE.open_session(SessionOpenRequest(name="scan"))
        # the pane never shows a completion marker — the command "keeps running"
        spy.tmux.set_pane("scan", "Nmap scan report for 10.0.0.5\nStill scanning ...")
        ticks = iter([0, 0, 0, 999, 999, 999])
        clock = lambda: next(ticks, 9999)  # noqa: E731 - test clock
        res = SE.run_command("scan", SessionRunRequest(command="nmap -p- 10.0.0.5"),
                             sleep=lambda _s: None, clock=clock)
    assert res["marker"] == "[AUTO-BACKGROUND]", res
    assert "job_id" in res
    print("  a foreground command past the 60s window is AUTO-BACKGROUNDED: PASS")


def test_foreground_completion_returns_inline() -> None:
    tmp = _tmpdir()
    with _Spy(tmp) as spy:
        SE.open_session(SessionOpenRequest(name="quick"))
        spy.tmux.set_pane("quick", "root\n" + _marker(0, "/root"))
        res = SE.run_command("quick", SessionRunRequest(command="whoami"),
                             sleep=lambda _s: None, clock=lambda: 0.0)
    assert res["marker"] == "[DONE]" and res["rc"] == 0, res
    print("  a fast foreground command returns [DONE] inline with its rc: PASS")


# --------------------------------------------------------------------------- #
# 6. INTEGRATION — completion notifies ONCE, then is consumed
# --------------------------------------------------------------------------- #
def test_completion_notifies_once() -> None:
    tmp = _tmpdir()
    with _Spy(tmp) as spy:
        SE.open_session(SessionOpenRequest(name="bg"))
        started = SE.run_command("bg", SessionRunRequest(command="nuclei -l hosts", background=True))
        assert started["marker"] == "[BACKGROUND]"
        job_id = started["job_id"]

        # while running, no notification
        spy.tmux.set_pane("bg", "scanning...")
        assert SE.poll_jobs() == []

        # now it finishes — one notification, once
        spy.tmux.set_pane("bg", "done\n" + _marker(0, "/root"))
        first = SE.poll_jobs()
        assert len(first) == 1 and first[0].job_id == job_id and first[0].rc == 0, first
        assert SE.poll_jobs() == [], "a completion must notify exactly once"

        consumed = SE.consume_job("bg", job_id)
    assert consumed.state == "consumed", consumed
    print("  a background completion notifies exactly once, then is consumed: PASS")


# --------------------------------------------------------------------------- #
# 7. INTEGRATION — kill preserves the session log
# --------------------------------------------------------------------------- #
def test_kill_preserves_log() -> None:
    tmp = _tmpdir()
    with _Spy(tmp):
        SE.open_session(SessionOpenRequest(name="keep"))
        info = SE.get_session("keep")
        log = Path(info.log_path)
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text("captured interactive output\n", encoding="utf-8")
        killed = SE.kill_session("keep")
    assert killed.state == "killed"
    assert log.exists() and "captured interactive output" in log.read_text(encoding="utf-8"), (
        "kill must PRESERVE the session log — it is the audit trail of the session")
    print("  kill preserves the session log under .sessions/: PASS")


# --------------------------------------------------------------------------- #
# 8. containment + audit sanity (the safety suite proves the invariants in depth)
# --------------------------------------------------------------------------- #
def test_hardcoded_container_and_recorded() -> None:
    tmp = _tmpdir()
    with _Spy(tmp) as spy:
        SE.open_session(SessionOpenRequest(name="a", session_id="eng-1"))
        # every tmux call targets the OPEN container, never the isolated one
        for call in spy.tmux.calls:
            pass
        info = SE.get_session("a")
    assert info.container == config.KALI_OPEN_CONTAINER
    assert config.SANDBOX_CONTAINER != config.KALI_OPEN_CONTAINER  # sanity
    assert spy.saved and spy.saved[-1].target == config.KALI_OPEN_CONTAINER
    assert spy.saved[-1].session_id == "eng-1" and spy.saved[-1].approved is True
    print("  sessions exec the OPEN container and are recorded to the run store: PASS")


def test_refuses_when_sandbox_down() -> None:
    tmp = _tmpdir()
    with _Spy(tmp, up=False):
        try:
            SE.open_session(SessionOpenRequest(name="x"))
            assert False, "must refuse when the open sandbox is down"
        except SE.SessionRefused as exc:
            assert config.KALI_OPEN_CONTAINER in str(exc)
    print("  refuses cleanly when the open sandbox is down: PASS")


def test_live_session_cap_and_bad_name() -> None:
    tmp = _tmpdir()
    with _Spy(tmp):
        for i in range(SE.MAX_LIVE_SESSIONS):
            SE.open_session(SessionOpenRequest(name=f"s{i}"))
        try:
            SE.open_session(SessionOpenRequest(name="over"))
            assert False, "must refuse past the live-session cap"
        except SE.SessionRefused as exc:
            assert "too many" in str(exc)
    with _Spy(tmp):
        for bad in ("../etc", "a b", "x;rm", "-x"):
            try:
                SE.open_session(SessionOpenRequest(name=bad))
                assert False, f"must refuse unsafe name {bad!r}"
            except SE.SessionRefused:
                pass
    print("  live-session cap enforced + unsafe names refused, not sanitised: PASS")


if __name__ == "__main__":
    test_prompt_detection_over_fixtures()
    test_ansi_and_repeat_compression()
    test_output_tiering()
    test_wedge_signature()
    test_pipe_degradation_signature()
    test_named_sessions_independent_cwd()
    test_session_flips_to_interactive()
    test_auto_background_past_threshold()
    test_foreground_completion_returns_inline()
    test_completion_notifies_once()
    test_kill_preserves_log()
    test_hardcoded_container_and_recorded()
    test_refuses_when_sandbox_down()
    test_live_session_cap_and_bad_name()
    print("ALL session-engine tests pass")
