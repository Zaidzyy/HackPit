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
            assert spy.argv[:3] == ["docker", "exec", config.KALI_OPEN_CONTAINER], (
                f"exec target must be the hardcoded OPEN sandbox, got {spy.argv[:3]!r}"
            )
            assert spy.argv[2] == config.KALI_OPEN_CONTAINER, "container must be the constant"
            # And it must NEVER be the isolated cockpit sandbox.
            assert spy.argv[2] != config.SANDBOX_CONTAINER, (
                ":kali must NOT exec into the isolated cockpit sandbox"
            )
            assert spy.argv[3:5] == ["sh", "-c"], "must run the command via sh -c"
            assert spy.argv[5] == cmd, "the command is the ONLY thing that varies"

    fields = set(KaliRequest.model_fields.keys())
    assert fields == {"command", "session_id"}, (
        f"KaliRequest must expose only command + session_id, got {fields} — a "
        "container/target/host field would break containment rule #1"
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


if __name__ == "__main__":
    test_refuses_when_open_sandbox_down()
    test_target_container_is_hardcoded_to_open()
    test_no_isolation_gate_on_kali()
    test_kali_is_human_only()
    test_run_is_recorded_to_session()
    test_timeout_is_contained()
    test_output_is_capped()
    print("ALL :kali containment tests pass")
