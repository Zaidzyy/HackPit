""":kali containment regression-lock (cockpit/kali.py) — OPEN-sandbox model.

:kali is the ONE feature that runs arbitrary shell (`sh -c`), now inside a SEPARATE,
intentionally NON-isolated sandbox (hackpit-kali-open) with full network reach. It drops
the isolation gate (that sandbox is not isolated by design) but MUST keep the containment
that still applies. These tests FAIL LOUDLY if any of that is weakened:

  1. HARDCODED TARGET CONTAINER. No field of KaliRequest can change it; the argv always
     execs config.KALI_OPEN_CONTAINER — the OPEN sandbox, NOT the isolated one — even when
     the command *string* smuggles another container name.
  2. NO ISOLATION GATE ON :kali, BUT THE COCKPIT KEEPS ITS OWN. kali.py must not import the
     sandbox isolation module; run_kali must not call assert_isolation_proven. (The cockpit
     executor's isolation gate is asserted separately in test_cockpit.py — unchanged.)
  3. HUMAN-ONLY — the rule that matters most now. A full-reach shell reachable by the
     autonomous agent = autonomous attacks on host/LAN/internet. run_kali may be referenced
     ONLY by the HTTP route (router.py) + this test — never the executor/agent path. Scanned
     across the source tree.
  4. AVAILABILITY + AUDIT + LIMITS. If the open container isn't running, run_kali refuses
     (nothing runs). Every run is recorded to the session (target = the open sandbox), with
     the timeout + output cap enforced.

Hermetic: _container_running, subprocess.run and runstore.save_run are monkeypatched, so no
Docker daemon and no real DB writes. Run:  python test_kali.py
"""
from __future__ import annotations

import subprocess
import types
from pathlib import Path

from cockpit import config
from cockpit import kali as K
from cockpit.kali import KaliRefused, KaliRequest, run_kali


class _Spy:
    """Swaps kali's availability check, subprocess.run and save_run for fakes.

    up:         if False, the patched _container_running reports the open sandbox down.
    run_result: (stdout, stderr, returncode) the fake subprocess.run returns.
    timeout:    if True, the fake subprocess.run raises TimeoutExpired instead.
    """

    def __init__(self, *, up=True, run_result=("ok\n", "", 0), timeout=False):
        self.up = up
        self.run_result = run_result
        self.timeout = timeout
        self.argv = None          # argv captured from subprocess.run
        self.ran = False          # was subprocess.run called at all?
        self.saved = None         # RunRecord captured from runstore.save_run
        self._orig = (K._container_running, K.subprocess.run, K.runstore.save_run)

    def __enter__(self):
        def fake_up(name):
            return self.up

        def fake_run(argv, **kwargs):
            self.ran = True
            self.argv = argv
            if self.timeout:
                raise subprocess.TimeoutExpired(cmd=argv, timeout=kwargs.get("timeout", 60),
                                                output="partial\n", stderr="")
            out, err, rc = self.run_result
            return types.SimpleNamespace(stdout=out, stderr=err, returncode=rc)

        def fake_save(record):
            self.saved = record

        K._container_running = fake_up
        K.subprocess.run = fake_run
        K.runstore.save_run = fake_save
        return self

    def __exit__(self, *exc):
        K._container_running, K.subprocess.run, K.runstore.save_run = self._orig
        return False


def test_refuses_when_open_sandbox_down() -> None:
    """If the open container isn't running, run_kali refuses and NOTHING runs.

    NOTE: this is an availability check, NOT an isolation gate — :kali is intentionally
    not isolated. It just fails cleanly instead of emitting a raw docker error."""
    with _Spy(up=False) as spy:
        raised = False
        try:
            run_kali(KaliRequest(command="id"))
        except KaliRefused:
            raised = True
        assert raised, "run_kali MUST refuse when the open sandbox is not running"
        assert not spy.ran, "a refused run MUST NOT touch subprocess (nothing executed)"
        assert spy.saved is None, "a refused run MUST NOT be recorded"
    print("  refuses when open sandbox down (nothing runs): PASS")


def test_target_container_is_hardcoded_to_open() -> None:
    """No request field can redirect the exec. The argv always execs the constant
    KALI_OPEN_CONTAINER (the OPEN sandbox, not the isolated one) via `sh -c`, even when the
    command tries to smuggle another target into the string."""
    hostile_commands = [
        "id",
        "docker exec hackpit-kali-sandbox id",           # try to hop to the ISOLATED box
        "echo hackpit-kali-sandbox; nc evil 1",          # another container/host name
        "sh -c 'ls' --target=host",                       # a fake flag
    ]
    for cmd in hostile_commands:
        with _Spy() as spy:
            run_kali(KaliRequest(command=cmd))
            # `docker exec` may carry flags (e.g. -w for the loot working directory), so
            # locate the container POSITIONALLY: it is the first argv token after the
            # flags, i.e. immediately before `sh -c`. Asserting on a fixed index would
            # silently stop testing containment the next time a flag is added.
            assert spy.argv[:2] == ["docker", "exec"], f"must be a docker exec, got {spy.argv!r}"
            assert "sh" in spy.argv, "must run the command via sh -c"
            sh_at = spy.argv.index("sh")
            container = spy.argv[sh_at - 1]
            assert container == config.KALI_OPEN_CONTAINER, (
                f"exec target must be the hardcoded OPEN sandbox, got {container!r}"
            )
            # And it must NEVER be the isolated cockpit sandbox.
            assert container != config.SANDBOX_CONTAINER, (
                ":kali must NOT exec into the isolated cockpit sandbox"
            )
            assert spy.argv[sh_at:sh_at + 2] == ["sh", "-c"], "must run the command via sh -c"
            assert spy.argv[sh_at + 2] == cmd, "the command is the ONLY thing that varies"
            # Every flag before the container must be a constant chosen by the code, never
            # anything derived from the request.
            for tok in spy.argv[2:sh_at - 1]:
                assert cmd not in tok, (
                    f"no request-derived value may reach the docker flags, got {tok!r}"
                )

    fields = set(KaliRequest.model_fields.keys())
    assert fields == {"command", "session_id", "timeout_seconds"}, (
        f"KaliRequest must expose only command + session_id + timeout_seconds, got {fields} "
        "— a container/target/host field would break containment rule #1"
    )
    print("  target container is hardcoded to the OPEN sandbox: PASS")


def test_no_isolation_gate_on_kali() -> None:
    """:kali is intentionally not isolated: kali.py must not import the sandbox isolation
    module and run_kali must not call assert_isolation_proven. (The cockpit executor keeps
    its isolation gate — that is verified, unchanged, in test_cockpit.py.)"""
    src = (Path(K.__file__)).read_text(encoding="utf-8")
    # No import of the isolation gate anywhere in kali.py.
    assert "import assert_isolation_proven" not in src, "kali.py must not import the isolation gate"
    assert "from .sandbox" not in src and "from cockpit.sandbox" not in src, (
        "kali.py must not import the sandbox module at all"
    )
    # The module has no such attribute (it was previously imported; ensure it's gone).
    assert not hasattr(K, "assert_isolation_proven"), (
        "kali module must not expose assert_isolation_proven (isolation gate removed from :kali)"
    )
    print("  no isolation gate on :kali (cockpit keeps its own): PASS")


def test_kali_is_human_only() -> None:
    """run_kali must be reachable ONLY from the HTTP route + this test — NEVER the
    autonomous executor/agent path. A full-reach shell wired to the agent = autonomous
    attacks on host/LAN/internet. Scan the whole (non-venv) source tree."""
    backend = Path(__file__).parent
    # Only kali.py (defines) + router.py (the HTTP route) may reference the shell.
    # Test files are skipped: they are not the runtime agent path, and several
    # legitimately name run_kali inside assertions that a module must NOT call it.
    allowed = {"kali.py", "router.py"}
    py_files = list(backend.glob("*.py")) + list((backend / "cockpit").glob("*.py"))
    offenders = []
    for f in py_files:
        if f.name in allowed or f.name.startswith("test_"):
            continue
        text = f.read_text(encoding="utf-8")
        if "run_kali" in text or "import kali" in text or "from .kali" in text or "cockpit.kali" in text:
            offenders.append(f.name)
    assert not offenders, (
        f":kali must be HUMAN-ONLY — these non-route modules reference the shell: {offenders}. "
        "The orchestrator/agent/executor must have NO path to run_kali."
    )
    # Belt-and-suspenders: the cockpit executor (the autonomous exec path) exposes no kali hook.
    from cockpit import executor as EX
    assert not hasattr(EX, "run_kali") and not hasattr(EX, "kali"), (
        "the cockpit executor must not reference the :kali shell"
    )
    print("  :kali is human-only (no agent/executor path): PASS")


def test_run_is_recorded_to_session() -> None:
    """Every run is recorded to the engagement session, target = the OPEN sandbox."""
    with _Spy(run_result=("root\n", "", 0)) as spy:
        result = run_kali(KaliRequest(command="whoami", session_id="eng-123"))
        rec = spy.saved
        assert rec is not None, "the run MUST be recorded (audit)"
        assert rec.session_id == "eng-123", "record must attach to the engagement"
        assert rec.command == "sh -c" and rec.args == ["whoami"], (
            "record must honestly log the sh -c invocation + the command line"
        )
        assert rec.target == config.KALI_OPEN_CONTAINER, "target must be the OPEN sandbox"
        assert rec.approved is True, "a human-typed command counts as approved"
        assert result.exit_code == 0 and result.stdout == "root\n"
        assert result.container == config.KALI_OPEN_CONTAINER
    print("  run is recorded to the session (audit): PASS")


def test_timeout_is_contained() -> None:
    """A command that overruns the timeout is killed and reported, not hung."""
    with _Spy(timeout=True) as spy:
        result = run_kali(KaliRequest(command="sleep 999"))
        assert result.timed_out is True, "an overrun must be marked timed_out"
        assert result.exit_code is None, "a killed command has no exit code"
        assert "timeout" in result.stderr.lower(), "the kill reason must be reported"
        assert spy.saved is not None, "even a timed-out run is recorded"
    print("  timeout is contained (killed + reported): PASS")


def test_output_is_capped() -> None:
    """A flood of output is truncated so it can't blow up the audit log / response."""
    flood = "A" * (K.KALI_OUTPUT_CAP + 5000)
    with _Spy(run_result=(flood, "", 0)):
        result = run_kali(KaliRequest(command="yes"))
        assert result.truncated is True, "over-cap output must be marked truncated"
        assert len(result.stdout) <= K.KALI_OUTPUT_CAP + 64, "stdout must be capped"
    print("  output is capped (no flood): PASS")


# --------------------------------------------------------------------------- #
# Persistent :kali shell (step 13) — same containment, state persists
# --------------------------------------------------------------------------- #
class _ShellSpy:
    """Fake for the persistent shell: patches the availability check and the Popen so no
    real container is touched, capturing the argv the shell WOULD have launched."""

    def __init__(self, *, up=True):
        self.up = up
        self.argv = None
        self.stdin_writes: list[str] = []
        self._orig = (K._container_running, K.subprocess.Popen, K.runstore.save_run)
        self.saved: list = []

    def __enter__(self):
        outer = self

        class _FakeStdin:
            closed = False
            def write(self, data): outer.stdin_writes.append(data)
            def flush(self): pass
            def reconfigure(self, **kw): pass
            def close(self): self.closed = True

        class _FakeStream:
            def readline(self): return ""
            def close(self): pass

        class _FakeProc:
            def __init__(self):
                self.stdin = _FakeStdin()
                self.stdout = _FakeStream()
                self.stderr = _FakeStream()
            def poll(self): return None
            def kill(self): pass

        def fake_popen(argv, **kwargs):
            outer.argv = argv
            return _FakeProc()

        K._container_running = lambda name: self.up
        K.subprocess.Popen = fake_popen
        K.runstore.save_run = lambda rec: self.saved.append(rec)
        return self

    def __exit__(self, *exc):
        K._container_running, K.subprocess.Popen, K.runstore.save_run = self._orig
        return False


def test_persistent_shell_refuses_when_sandbox_down() -> None:
    with _ShellSpy(up=False) as spy:
        raised = False
        try:
            K.start_shell(K.KaliShellStartRequest())
        except K.KaliShellRefused:
            raised = True
        assert raised, "starting a shell MUST refuse when the open sandbox is down"
        assert spy.argv is None, "nothing may launch when refused"
    print("  persistent shell refuses when the open sandbox is down: PASS")


def test_persistent_shell_container_is_hardcoded_to_open() -> None:
    """The persistent shell execs the OPEN container constant, never the isolated lab, and
    the start request exposes no field that could redirect it."""
    with _ShellSpy() as spy:
        info = K.start_shell(K.KaliShellStartRequest(session_id="eng-x"))
        assert spy.argv[:3] == ["docker", "exec", "-i"], spy.argv
        assert config.KALI_OPEN_CONTAINER in spy.argv, "must exec the OPEN container"
        assert config.SANDBOX_CONTAINER not in spy.argv, "must NOT reach the isolated lab box"
        assert config.ENGAGE_SANDBOX_CONTAINER not in spy.argv, "must NOT reach the engage box"
        assert spy.argv[-1] == "sh", "a persistent shell is a bare `sh`, no -c"
        assert info.container == config.KALI_OPEN_CONTAINER
        K.close_shell(info.sid)

    start_fields = set(K.KaliShellStartRequest.model_fields)
    assert start_fields == {"session_id"}, (
        f"KaliShellStartRequest must expose only session_id, got {start_fields} — a "
        "container/target field would break containment"
    )
    input_fields = set(K.KaliShellInputRequest.model_fields)
    assert input_fields == {"command", "timeout_seconds"}, (
        f"KaliShellInputRequest must expose only command + timeout, got {input_fields}"
    )
    print("  persistent shell container hardcoded to OPEN; requests carry no target: PASS")


def test_persistent_shell_is_human_only_and_no_isolation_gate() -> None:
    """The persistent shell shares :kali's model — the human-only source scan and the
    no-isolation-gate invariant already cover kali.py as a whole, so this just asserts the
    new entry points did not import the isolation gate or an agent hook."""
    src = (Path(__file__).parent / "cockpit" / "kali.py").read_text(encoding="utf-8")
    # Match the existing no-isolation test's specificity: forbid the IMPORT/CALL, not any
    # docstring that merely names the gate to explain why :kali does not use one.
    assert "import assert_isolation_proven" not in src, "must not import the isolation gate"
    assert "from .sandbox" not in src and "from cockpit.sandbox" not in src, (
        "the persistent shell must not import the isolation module"
    )
    from cockpit import executor as EX
    for hook in ("start_shell", "run_in_shell", "kali"):
        assert not hasattr(EX, hook), f"the executor must not expose {hook} — human-only"
    print("  persistent shell is human-only and adds no isolation gate: PASS")


def test_persistent_shell_records_every_command() -> None:
    """Audit is preserved: each command run in the shell is recorded, honestly as sh -c."""
    with _ShellSpy() as spy:
        info = K.start_shell(K.KaliShellStartRequest(session_id="eng-audit"))
        # Drive run_in_shell but short-circuit the sentinel wait to a clean exit.
        orig = K._await_sentinel
        K._await_sentinel = lambda shell, out_start, sentinel, timeout: (0, False, False)
        try:
            K.run_in_shell(info.sid, K.KaliShellInputRequest(command="whoami"))
        finally:
            K._await_sentinel = orig
        recs = [r for r in spy.saved if r.command == "sh -c" and r.args == ["whoami"]]
        assert recs, "the command must be recorded as an sh -c invocation"
        assert recs[0].session_id == "eng-audit", "record must attach to the engagement"
        assert recs[0].target == config.KALI_OPEN_CONTAINER, "target = the OPEN sandbox"
        assert recs[0].approved is True, "a human-typed command counts as approved"
        K.close_shell(info.sid)
    print("  every persistent-shell command is recorded (audit): PASS")


def test_persistent_shell_stdin_stays_bare_lf() -> None:
    """Regression: the payload written to the shell's stdin must use bare LF, never CRLF.
    On Windows a text-mode stdin translates \\n -> \\r\\n, and the Linux shell then reads
    `pwd\\r` (command not found) — the exact bug this shell hit in development."""
    with _ShellSpy() as spy:
        info = K.start_shell(K.KaliShellStartRequest())
        orig = K._await_sentinel
        K._await_sentinel = lambda shell, out_start, sentinel, timeout: (0, False, False)
        try:
            K.run_in_shell(info.sid, K.KaliShellInputRequest(command="pwd"))
        finally:
            K._await_sentinel = orig
        written = "".join(spy.stdin_writes)
        assert written, "a command must have been written to stdin"
        assert "\r" not in written, "stdin payload must contain NO carriage returns (CRLF breaks sh)"
        assert written.startswith("pwd\n"), "the command must be a bare-LF-terminated line"
        K.close_shell(info.sid)
    print("  persistent shell writes bare-LF stdin (no CRLF corruption): PASS")


if __name__ == "__main__":
    test_refuses_when_open_sandbox_down()
    test_target_container_is_hardcoded_to_open()
    test_no_isolation_gate_on_kali()
    test_kali_is_human_only()
    test_run_is_recorded_to_session()
    test_timeout_is_contained()
    test_persistent_shell_refuses_when_sandbox_down()
    test_persistent_shell_container_is_hardcoded_to_open()
    test_persistent_shell_is_human_only_and_no_isolation_gate()
    test_persistent_shell_records_every_command()
    test_persistent_shell_stdin_stays_bare_lf()
    test_output_is_capped()
    print("ALL :kali containment tests pass")
