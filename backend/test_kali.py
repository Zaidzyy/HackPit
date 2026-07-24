""":kali containment regression-lock (cockpit/kali.py).

:kali is the ONE feature that runs arbitrary shell (`sh -c`) inside the sandbox. It
drops M1's allowlist / target-lock / per-command-approval gates (a human typing is the
operator) but it MUST keep the containment that makes a free shell safe. These tests
FAIL LOUDLY if any of that is ever weakened:

  1. ISOLATION IS RE-CHECKED, AND REFUSAL MEANS NOTHING RUNS. If the sandbox is not
     provably isolated, run_kali raises KaliRefused and subprocess is never touched.
  2. THE TARGET CONTAINER IS HARDCODED. No field of KaliRequest can change it; the argv
     always execs config.SANDBOX_CONTAINER, even when the command *string* contains
     another container name or its own `docker exec`.
  3. EVERY RUN IS RECORDED to the engagement session (audit), with target = the sandbox.

Hermetic: assert_isolation_proven, subprocess.run and runstore.save_run are all
monkeypatched, so no Docker daemon and no real DB writes. Run:  python test_kali.py
"""
from __future__ import annotations

import subprocess
import types

from cockpit import config
from cockpit import kali as K
from cockpit.kali import KaliRefused, KaliRequest, run_kali


class _Spy:
    """Swaps kali's isolation gate, subprocess.run and save_run for fakes.

    isolated:   if False, the patched gate raises (simulating a non-isolated sandbox).
    run_result: (stdout, stderr, returncode) the fake subprocess.run returns.
    timeout:    if True, the fake subprocess.run raises TimeoutExpired instead.
    """

    def __init__(self, *, isolated=True, run_result=("ok\n", "", 0), timeout=False):
        self.isolated = isolated
        self.run_result = run_result
        self.timeout = timeout
        self.argv = None          # argv captured from subprocess.run
        self.ran = False          # was subprocess.run called at all?
        self.saved = None         # RunRecord captured from runstore.save_run
        self._orig = (K.assert_isolation_proven, K.subprocess.run, K.runstore.save_run)

    def __enter__(self):
        def fake_gate():
            if not self.isolated:
                raise K.__dict__.get("SandboxError", RuntimeError)("simulated: not isolated")

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

        # Import SandboxError lazily so fake_gate can raise the real type.
        from cockpit.sandbox import SandboxError
        K.__dict__["SandboxError"] = SandboxError
        K.assert_isolation_proven = fake_gate
        K.subprocess.run = fake_run
        K.runstore.save_run = fake_save
        return self

    def __exit__(self, *exc):
        K.assert_isolation_proven, K.subprocess.run, K.runstore.save_run = self._orig
        K.__dict__.pop("SandboxError", None)
        return False


def test_refuses_when_not_isolated() -> None:
    """If isolation can't be proven, run_kali refuses and NOTHING runs."""
    with _Spy(isolated=False) as spy:
        raised = False
        try:
            run_kali(KaliRequest(command="id"))
        except KaliRefused:
            raised = True
        assert raised, "run_kali MUST refuse when the sandbox is not provably isolated"
        assert not spy.ran, "a refused run MUST NOT touch subprocess (nothing executed)"
        assert spy.saved is None, "a refused run MUST NOT be recorded"
    print("  refuses when not isolated (nothing runs): PASS")


def test_target_container_is_hardcoded() -> None:
    """No request field can redirect the exec. The argv always execs the constant
    SANDBOX_CONTAINER via `sh -c`, even when the command tries to smuggle another
    target into the string."""
    hostile_commands = [
        "id",
        "docker exec some-other-container id",           # a docker-in-the-string attempt
        "echo hackpit-lab-target; nc evil 1",            # another container/host name
        "sh -c 'ls' --target=host",                       # a fake flag
    ]
    for cmd in hostile_commands:
        with _Spy() as spy:
            run_kali(KaliRequest(command=cmd))
            assert spy.argv[:3] == ["docker", "exec", config.SANDBOX_CONTAINER], (
                f"exec target must be the hardcoded sandbox, got {spy.argv[:3]!r}"
            )
            assert spy.argv[2] == config.SANDBOX_CONTAINER, "container must be the constant"
            assert spy.argv[3:5] == ["sh", "-c"], "must run the command via sh -c"
            assert spy.argv[5] == cmd, "the command is the ONLY thing that varies"

    # Structural: the request model exposes NO way to name a container/target/host.
    fields = set(KaliRequest.model_fields.keys())
    assert fields == {"command", "session_id"}, (
        f"KaliRequest must expose only command + session_id, got {fields} — a "
        "container/target/host field would break containment rule #1"
    )
    print("  target container is hardcoded (no request field redirects it): PASS")


def test_run_is_recorded_to_session() -> None:
    """Every run is recorded to the engagement session, target = the sandbox itself."""
    with _Spy(run_result=("root\n", "", 0)) as spy:
        result = run_kali(KaliRequest(command="whoami", session_id="eng-123"))
        rec = spy.saved
        assert rec is not None, "the run MUST be recorded (audit)"
        assert rec.session_id == "eng-123", "record must attach to the engagement"
        assert rec.command == "sh -c" and rec.args == ["whoami"], (
            "record must honestly log the sh -c invocation + the command line"
        )
        assert rec.target == config.SANDBOX_CONTAINER, "target must be the sandbox box"
        assert rec.approved is True, "a human-typed command counts as approved"
        assert result.exit_code == 0 and result.stdout == "root\n"
        assert result.container == config.SANDBOX_CONTAINER
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
    test_refuses_when_not_isolated()
    test_target_container_is_hardcoded()
    test_run_is_recorded_to_session()
    test_timeout_is_contained()
    test_output_is_capped()
    print("ALL :kali containment tests pass")
