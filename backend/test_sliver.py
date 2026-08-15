"""Sliver C2 surface (cockpit/sliver.py) — containment regression-lock.

Sliver is the first thing in the cockpit that BUILDS AN ARTIFACT meant to run on someone
else's machine, so the split between its two surfaces is the whole safety story and these
tests fail loudly if either half drifts:

  1. SERVER LIFECYCLE IS HUMAN-ONLY. start_server / stop_server run the operator's OWN C2
     server inside the hardcoded engage sandbox. There is no target and no gate beyond "a
     human clicked Start" — exactly the posture cockpit/tunnels.py has for a pivot listener,
     for the same reason (operator infrastructure, not an action against a target). What
     makes that safe is that the orchestrator / agent / loop has ZERO code path to it: a C2
     server an agent could raise is an autonomous C2. Scanned across the source tree.

  2. IMPLANT GENERATION IS A GATED COMMAND. generate_implant builds an ExecRequest and runs
     the REAL executor gates — not a copy — so it clears exactly what a one-shot command
     clears: scope/target-lock -> per-command human approval -> the heuristic red-confirm
     (a payload generator trips it, so dangerous_ack is required in practice). An
     unapproved, unacked or out-of-scope generate produces NOTHING.

  3. <listener> IS OPERATOR-SIDE AND PASSES THROUGH VERBATIM. The callback address belongs
     to the operator, never to the system under test, so the target is NEVER substituted
     into it. This is load-bearing: substituting the target would point a beacon at the
     client's own network.

  4. ARGV-ONLY, CONTAINER FROM THE MODE. No shell anywhere, no request field can redirect
     the exec, and the artifact path is server-chosen (the loot directory), never supplied
     by the caller.

  5. EVERYTHING IS RECORDED. start / stop / generate each land as a RunRecord.

Generation only. Deploying an implant, catching a beacon and driving a live Sliver session
are DEFERRED — nothing here delivers or executes what it builds.

Hermetic: subprocess.run / subprocess.Popen, runstore.save_run and loot.ensure are
monkeypatched, so no Docker daemon, no real DB writes and no host directories are created.

Run:  backend/.venv/Scripts/python.exe backend/test_sliver.py
"""
from __future__ import annotations

import re
from pathlib import Path

from cockpit import config
from cockpit import executor as EX
from cockpit import sliver as S
from cockpit.sliver import ImplantRequest, SliverRefused, SliverServerRequest
from test_support import listeners

BACKEND = Path(__file__).parent


# --------------------------------------------------------------------------- #
# hermetic fakes — manual save/restore (this repo has NO pytest, so no fixtures)
# --------------------------------------------------------------------------- #
class _FakeCompleted:
    def __init__(self, argv, returncode=0, stdout="", stderr=""):
        self.args = argv
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class _FakeProc:
    """Stand-in for the docker exec client that hosts the sliver server."""

    def __init__(self, argv):
        self.argv = argv
        self._alive = True

    def poll(self):
        return None if self._alive else 0

    def kill(self):
        self._alive = False


class _Spy:
    """Swap subprocess, save_run and loot.ensure for fakes; restore on exit.

    Manual save/restore in __exit__ — the same shape test_session.py's _Spy uses and the
    same discipline test_detection_safety.py uses for llm.chat. There is no pytest in this
    project, so there is no monkeypatch fixture to lean on.
    """

    def __init__(self, *, up=True, docker_missing=False, returncode=0, isolated=True,
                 artifact_size: int | None = 14401536, alive=True, bound=True):
        self.up = up
        self.docker_missing = docker_missing
        self.returncode = returncode
        self.isolated = isolated
        # A build now runs TWO subprocesses: the console session that builds, then the `stat`
        # that reads the artifact back. `artifact_size=None` means the build wrote nothing —
        # the case that must come back `failed` even though the console exited 0.
        self.artifact_size = artifact_size
        self.runs: list[list[str]] = []
        self.stat_argv: list[str] | None = None
        self.console_input: str | None = None
        self.spawn = listeners.FakeListenerSpawn(alive=alive, bound=bound)
        self.saved: list = []
        # Loot directory names actually created — asserted EMPTY for lab builds, because the
        # isolated lab sandbox has no /loot mount and must not mkdir a host directory.
        self.loot_calls: list[str] = []
        self._orig = (
            S._container_running,
            S.subprocess.run,
            S.runstore.save_run,
            S.loot.ensure,
            EX.assert_isolation_proven,
        )

    # The listener spawn moved into cockpit/lifecycle.py, so the server-lifecycle fakes live in
    # the shared shim. These properties keep the existing assertions reading the same way.
    @property
    def popen_argv(self) -> list[str] | None:
        return self.spawn.argv

    @property
    def procs(self) -> list:
        return self.spawn.procs

    @property
    def run_argv(self) -> list[str] | None:
        """The BUILD's argv — not the `stat` read-back that follows it.

        Keyed on the argv itself rather than on call order: `run_argv` used to be "whatever ran
        last", which after build #7 silently became the artifact probe, so assertions about the
        build were quietly testing `stat -c %s` instead.
        """
        for argv in self.runs:
            if S.SLIVER_SERVER_BIN in argv:
                return argv
        return None

    def __enter__(self):
        def fake_run(argv, **kw):
            if self.docker_missing:
                raise FileNotFoundError("docker")
            self.runs.append(list(argv))
            if "stat" in argv:
                self.stat_argv = list(argv)
                if self.artifact_size is None:
                    return _FakeCompleted(argv, returncode=1, stdout="", stderr="No such file")
                return _FakeCompleted(argv, returncode=0, stdout=f"{self.artifact_size}\n")
            self.console_input = kw.get("input")
            return _FakeCompleted(argv, returncode=self.returncode, stdout="implant built")

        def fake_ensure(name):
            self.loot_calls.append(name)
            return f"/loot/{name}"

        def fake_isolation():
            if not self.isolated:
                from cockpit.sandbox import SandboxError

                raise SandboxError("sandbox is attached to non-internal network(s)")

        S._container_running = lambda name: self.up
        S.subprocess.run = fake_run
        S.runstore.save_run = lambda rec: self.saved.append(rec)
        S.loot.ensure = fake_ensure
        EX.assert_isolation_proven = fake_isolation
        self.spawn.__enter__()
        if self.docker_missing:
            def _boom(argv, **kw):
                raise FileNotFoundError("docker")
            S.lifecycle.subprocess.Popen = _boom
        return self

    def __exit__(self, *exc):
        self.spawn.__exit__(*exc)
        (
            S._container_running,
            S.subprocess.run,
            S.runstore.save_run,
            S.loot.ensure,
            EX.assert_isolation_proven,
        ) = self._orig
        S.reset()
        return False


def _fake_engagement():
    from cockpit.models import EngagementRecord

    return EngagementRecord(
        engagement_id="eng-sliver0000",
        target="scanme.nmap.org",
        authorization="authorized test target",
        active=True,
        entered_at="2026-07-27T00:00:00+00:00",
        scope="scanme.nmap.org",
        scope_include=["scanme.nmap.org"],
        allowed_hosts=["scanme.nmap.org"],
    )


def _patch_active(rec):
    """Make the executor resolve THIS engagement (mirrors test_session.py)."""
    from cockpit import engagement as ENG

    orig = ENG.get_active
    ENG.get_active = lambda eid: rec if (rec and eid == rec.engagement_id) else None
    return lambda: setattr(ENG, "get_active", orig)


def _srv(**over) -> SliverServerRequest:
    """A C2-server start that CLEARS the gates. Build #7 made this surface gated, so a bare
    `SliverServerRequest()` is now a refusal — every test that means to exercise the lifecycle
    has to name the engagement and carry both confirms, like every other execution surface."""
    base = dict(engagement_id="eng-sliver0000", approved=True, dangerous_ack=True)
    base.update(over)
    return SliverServerRequest(**base)


def _req(**over) -> ImplantRequest:
    base = dict(
        os="windows",
        arch="amd64",
        fmt="exe",
        listener="<listener>",
        target="scanme.nmap.org",
        engagement_id="eng-sliver0000",
        approved=True,
        dangerous_ack=True,
    )
    base.update(over)
    return ImplantRequest(**base)


# --------------------------------------------------------------------------- #
# 1. PURE argv + the <listener> passthrough invariant
# --------------------------------------------------------------------------- #
def test_implant_argv_is_pure_and_never_substitutes_listener() -> None:
    """_implant_argv builds argv and runs NOTHING, and <listener> survives verbatim."""
    req = ImplantRequest(
        os="windows", arch="amd64", listener="<listener>", target="10.0.0.5",
        fmt="exe", approved=True, dangerous_ack=True,
    )

    # PURE: with subprocess blown up, argv construction must still succeed.
    orig = (S.subprocess.run, S.subprocess.Popen, S.loot.ensure)
    calls: list[str] = []
    try:
        def _boom(*a, **kw):
            calls.append("exec")
            raise AssertionError("_implant_argv must execute NOTHING")

        S.subprocess.run = _boom
        S.subprocess.Popen = _boom
        S.loot.ensure = lambda name: (_ for _ in ()).throw(
            AssertionError("_implant_argv must do no I/O")
        )
        argv = S._implant_argv(req)
        argv2 = S._implant_argv(req)
    finally:
        S.subprocess.run, S.subprocess.Popen, S.loot.ensure = orig

    assert not calls, "argv construction must not execute anything"
    assert argv == argv2, "argv construction must be deterministic (pure)"
    # sliver-server, not sliver-client: Sliver 1.5 has no `generate` SUBCOMMAND on either binary
    # (`sliver-client --help` offers only completion/help/import/version) — `generate` is a
    # CONSOLE command, and sliver-server run with no subcommand is what hosts the console. This
    # test used to assert SLIVER_CLIENT_BIN, which pinned an argv Sliver could never accept.
    assert argv[0] == S.SLIVER_SERVER_BIN, argv
    assert "generate" in argv, argv
    assert "<listener>" in argv, "operator-side listener placeholder must pass through verbatim"

    # *** THE INVARIANT ***: the target is NEVER substituted into the callback address.
    listener_value = argv[argv.index("--mtls") + 1]
    assert listener_value == "<listener>", listener_value
    assert "10.0.0.5" not in argv, (
        "the TARGET must never be substituted into the implant argv — the callback address "
        "belongs to the operator, not the system under test"
    )
    # A real operator address is likewise carried through untouched.
    other = S._implant_argv(ImplantRequest(listener="10.8.0.2:8888", target="10.0.0.5"))
    assert other[other.index("--mtls") + 1] == "10.8.0.2:8888", other
    assert "10.0.0.5" not in other, other

    # argv is a LIST of tokens — never a shell string.
    assert all(isinstance(t, str) for t in argv) and not any(
        (" " in t and ";" in t) for t in argv
    ), argv
    print("  _implant_argv is pure; <listener> passes through verbatim, never substituted: PASS")


def test_implant_fields_are_bounded_and_carry_no_container() -> None:
    """os/arch/format come from a fixed set, and no request field can redirect the exec."""
    fields = set(ImplantRequest.model_fields.keys())
    assert "container" not in fields and "sandbox" not in fields, (
        f"a container/sandbox field would break containment — got {sorted(fields)}"
    )
    assert "container" not in set(SliverServerRequest.model_fields.keys())

    for bad in (dict(os="; rm -rf /"), dict(arch="$(id)"), dict(fmt="../../etc/passwd")):
        raised = False
        try:
            ImplantRequest(**bad)
        except Exception:
            raised = True
        assert raised, f"an out-of-set value must be refused, not interpolated: {bad}"
    print("  implant os/arch/format are bounded; no container field on either request: PASS")


# --------------------------------------------------------------------------- #
# 2. GENERATION IS GATED — the real executor gates, scope-checked.
# --------------------------------------------------------------------------- #
def test_generate_is_gated_and_scope_checked() -> None:
    """Out-of-scope / unapproved / unacked generates are REFUSED; nothing is produced."""
    eng = _fake_engagement()
    restore = _patch_active(eng)
    try:
        with _Spy() as spy:
            # OUT OF SCOPE -> WARNS at the scope gate (handrail, override-able), nothing generated
            # without the override.
            rejected = S.validate_generate(_req(target="evil.com"))
            assert rejected is not None and rejected.gate == "scope", rejected
            assert "scope" in rejected.reason.lower(), rejected.reason
            raised = False
            try:
                S.generate_implant(_req(target="evil.com"))
            except SliverRefused as exc:
                raised = True
                assert exc.gate == "scope", exc.gate
            assert raised, "an out-of-scope implant generate MUST refuse"
            assert spy.run_argv is None, "a refused generate MUST NOT run anything"
            assert not spy.saved, "a refused generate MUST NOT be recorded"
            assert not S.list_implants(), "a refused generate MUST NOT register an implant"

            # NO APPROVAL -> approval gate (there is no autonomous / approve-all path).
            rejected = S.validate_generate(_req(approved=False))
            assert rejected is not None and rejected.gate == "approval", rejected

            # NO RED-CONFIRM -> danger gate. A payload generator must trip the heuristic.
            rejected = S.validate_generate(_req(dangerous_ack=False))
            assert rejected is not None and rejected.gate == "danger", rejected
            assert rejected.dangerous_flags, "the confirm must name why it was flagged"

            # An unknown / exited engagement is refused — never downgraded to lab.
            rejected = S.validate_generate(_req(engagement_id="eng-gone000000"))
            assert rejected is not None and rejected.gate == "engagement", rejected

            assert spy.run_argv is None and not spy.saved, "no gate failure may run or record"

            # IN SCOPE + approved + acked -> it clears.
            assert S.validate_generate(_req()) is None, "an in-scope acked generate must clear"
    finally:
        restore()
    print("  generate runs the REAL gates: scope -> approval -> red-confirm: PASS")


def test_generate_uses_the_mode_container_and_records_a_run() -> None:
    """A cleared generate execs the MODE's container, saves the artifact in loot, records it."""
    eng = _fake_engagement()
    restore = _patch_active(eng)
    try:
        with _Spy() as spy:
            implant = S.generate_implant(_req(session_id="eng-report", step_id="c2-1"))
            argv = spy.run_argv
            assert argv is not None, "a cleared generate must run"
            # Container comes from resolve_mode, never the request. `-i` is present because the
            # build is driven into the Sliver CONSOLE over stdin — Sliver 1.5 has no `generate`
            # subcommand — but the argv itself is still a LIST and still names the mode's box.
            assert argv[:4] == ["docker", "exec", "-i", config.ENGAGE_SANDBOX_CONTAINER], argv[:4]
            assert argv[4] == S.SLIVER_SERVER_BIN and len(argv) == 5, argv
            assert config.SANDBOX_CONTAINER not in argv, "must NOT reach the isolated lab box"
            assert config.KALI_OPEN_CONTAINER not in argv, "must NOT reach the :kali open box"
            # argv-only: no shell. The console line goes over STDIN, never through `sh -c`.
            assert "sh" not in argv and "-c" not in argv, "generation is argv-only (no shell)"

            # The pure tokens are carried verbatim by the console line, plus a SERVER-CHOSEN
            # artifact path. This is where the build's parameters now live.
            line = implant.console_line
            assert line == spy.console_input.splitlines()[0], (
                f"the recorded console line must be the one actually written to stdin: {line!r} "
                f"vs {spy.console_input!r}"
            )
            assert spy.console_input.endswith("exit\n"), spy.console_input
            for tok in S._implant_argv(_req())[1:]:
                assert tok in line.split(), f"{tok!r} missing from the executed console line"
            save_path = line.split()[line.split().index("--save") + 1]
            assert save_path.startswith(f"/loot/{eng.engagement_id}/"), save_path
            assert save_path == implant.artifact_path, implant.artifact_path
            assert spy.loot_calls == [eng.engagement_id], (
                f"an engagement build lands in ITS OWN loot directory, got {spy.loot_calls}"
            )
            assert implant.run_id in save_path, "the artifact is named for its run (auditable)"
            # <listener> still verbatim in what actually ran.
            assert "<listener>" in line and "scanme.nmap.org" == implant.target

            # The artifact was READ BACK — status is not inferred from the console's exit code.
            assert spy.stat_argv is not None, (
                "the build must ASK THE FILESYSTEM whether an artifact exists; a piped console "
                "exits 0 whether or not the generate inside it worked"
            )
            assert spy.stat_argv[-1] == save_path, spy.stat_argv
            assert implant.size_bytes == spy.artifact_size, implant.size_bytes

            assert implant.mode == "engagement" and implant.status == "generated"
            assert implant.container == config.ENGAGE_SANDBOX_CONTAINER

            rec = spy.saved[-1]
            assert rec.command == "sliver-generate", rec.command
            assert rec.target == "scanme.nmap.org", rec.target
            assert rec.mode == "engagement", rec.mode
            assert rec.approved is True and rec.exit_code == 0
            assert rec.session_id == "eng-report" and rec.step_id == "c2-1"
            assert rec.run_id == implant.run_id

            # It is registered and retrievable.
            assert [i.id for i in S.list_implants()] == [implant.id]
            assert S.get_implant(implant.id) is not None
            assert S.get_implant("nope") is None
    finally:
        restore()
    print("  generate execs the MODE container, saves to loot, records the run: PASS")


def test_lab_mode_generate_lands_outside_the_loot_tree() -> None:
    """A LAB build execs the ISOLATED sandbox, which deliberately has NO /loot mount.

    Pinned because getting this wrong is silent: the isolated lab sandbox has no loot
    bind-mount (loot.py, "the one that deliberately does NOT"), so a ``--save /loot/…`` there
    would fail every lab build AND mkdir a host directory nothing could ever populate. Lab
    generation is kept WORKING rather than refused — the lab is the rehearsal surface, and
    refusing it would push an operator's first implant build onto a real engagement — at the
    cost that a lab artifact is container-local and not durable, like every other lab file.
    """
    with _Spy() as spy:
        req = _req(engagement_id=None, target=config.LAB_TARGET_HOST)
        assert S.validate_generate(req) is None, "an approved+acked lab build must clear"
        implant = S.generate_implant(req)

        argv = spy.run_argv
        assert argv[:4] == ["docker", "exec", "-i", config.SANDBOX_CONTAINER], argv[:4]
        assert config.ENGAGE_SANDBOX_CONTAINER not in argv, "a lab build must NOT reach engagement"
        assert config.KALI_OPEN_CONTAINER not in argv, "a lab build must NOT reach the open box"

        # The artifact is a BARE filename -> the image's own working directory.
        line = implant.console_line.split()
        save_path = line[line.index("--save") + 1]
        assert save_path == f"implant-{implant.run_id}.exe", save_path
        assert "/loot" not in implant.console_line, (
            "the isolated lab sandbox has no /loot mount — a /loot path would fail every build"
        )
        assert not spy.loot_calls, (
            f"a lab build must NOT create a host loot directory, created: {spy.loot_calls}"
        )
        assert implant.mode == "lab" and implant.artifact_path == save_path
        assert implant.container == config.SANDBOX_CONTAINER
        assert "<listener>" in line, "the listener passes through in lab mode too"

        rec = spy.saved[-1]
        assert rec.command == "sliver-generate" and rec.mode == "lab", rec
        assert rec.target == config.LAB_TARGET_HOST, rec.target

    # A lab build is still a LAB command: the isolation gate is the lab's real bound.
    with _Spy(isolated=False) as spy:
        req = _req(engagement_id=None, target=config.LAB_TARGET_HOST)
        rejected = S.validate_generate(req)
        assert rejected is not None and rejected.gate == "sandbox", rejected
        raised = False
        try:
            S.generate_implant(req)
        except SliverRefused as exc:
            raised = True
            assert exc.gate == "sandbox", exc.gate
        assert raised, "a non-isolated lab sandbox MUST refuse to build an implant"
        assert spy.run_argv is None and not spy.saved, "nothing runs when isolation fails"

    # And the lab target-lock still applies: an off-lab target is refused.
    with _Spy():
        rejected = S.validate_generate(_req(engagement_id=None, target="evil.com"))
        assert rejected is not None and rejected.gate == "target", rejected
        assert "not the lab" in rejected.reason, rejected.reason
    print("  lab build execs the isolated box, writes outside /loot, keeps its gates: PASS")


def test_generate_reports_a_failed_build_without_raising() -> None:
    """A build that produced nothing is recorded as failed — a tool failure is not a gate failure.

    *** WHAT DECIDES 'failed' CHANGED IN BUILD #7, AND THAT IS THE POINT. *** It used to be the
    exit code. A build now runs by piping a `generate` line into the Sliver console, and THE
    CONSOLE EXITS 0 WHETHER OR NOT THE BUILD INSIDE IT WORKED — so an exit code cannot decide
    this. The artifact is read back out of the container instead.

    Both directions are asserted, because either one alone would let the old bug back in:
      * console exited 0, nothing on disk -> FAILED   (the case the exit code would have missed)
      * console exited non-zero, artifact present -> GENERATED (a real artifact is a real build)
    """
    eng = _fake_engagement()
    restore = _patch_active(eng)
    try:
        # The console said 0 and wrote nothing. This is the case an exit-code check cannot see.
        with _Spy(returncode=0, artifact_size=None) as spy:
            implant = S.generate_implant(_req())
            assert implant.status == "failed", (
                "the console exited 0 but no artifact exists — an exit code cannot decide this"
            )
            assert implant.size_bytes is None, implant.size_bytes
            assert "no artifact was written" in implant.detail, implant.detail
            assert spy.stat_argv is not None, "the build must read the artifact back"

        # The console complained but the artifact is there — that IS a build.
        with _Spy(returncode=2, artifact_size=4096) as spy:
            implant = S.generate_implant(_req())
            assert implant.status == "generated" and implant.size_bytes == 4096, implant
            assert implant.exit_code == 2, "the console's exit code is still recorded, honestly"
            assert spy.saved[-1].exit_code == 2
    finally:
        restore()
    print("  'generated' vs 'failed' is decided by the ARTIFACT, not the console's exit: PASS")


def test_generate_refuses_when_docker_is_missing() -> None:
    eng = _fake_engagement()
    restore = _patch_active(eng)
    try:
        with _Spy(docker_missing=True):
            raised = False
            try:
                S.generate_implant(_req())
            except SliverRefused as exc:
                raised = True
                assert exc.gate == "unavailable", exc.gate
            assert raised, "a missing docker CLI must refuse"
            assert not S.list_implants()
    finally:
        restore()
    print("  a missing docker CLI refuses the generate: PASS")


# --------------------------------------------------------------------------- #
# 3. SERVER LIFECYCLE — human-only operator infrastructure.
# --------------------------------------------------------------------------- #
def test_server_lifecycle_records_a_run() -> None:
    """start_server execs the hardcoded engage sandbox and records the run; stop closes it."""
    restore = _patch_active(_fake_engagement())
    try:
      with _Spy() as spy:
        srv = S.start_server(_srv())
        argv = spy.popen_argv
        # NO `-i`: `sliver-server daemon` is a real daemon, not a console, so it is spawned
        # without a forwarded stdin — least privilege where the binary allows it.
        assert argv[:3] == ["docker", "exec", config.ENGAGE_SANDBOX_CONTAINER], argv[:3]
        assert "-i" not in argv, "the Sliver daemon needs no stdin and must not be given one"
        assert S.SLIVER_SERVER_BIN in argv, argv
        assert "sh" not in argv and "-c" not in argv, "the server is argv-only (no shell)"
        assert srv.status == "listening" and srv.container == config.ENGAGE_SANDBOX_CONTAINER

        started = spy.saved[-1]
        assert started.command == "sliver-server", started.command
        assert started.mode == "engagement", started.mode
        assert started.run_id == srv.run_id
        assert started.finished_at is None, "a live server has not finished"
        assert started.approved is True, "the start cleared the approval gate"

        assert [s.id for s in S.list_servers()] == [srv.id]

        stopped = S.stop_server(srv.id)
        assert stopped.status == "down"
        final = spy.saved[-1]
        assert final.run_id == srv.run_id, "stop updates the SAME run record"
        assert final.finished_at is not None, "stopping must close the record"
        assert S.get_server(srv.id).status == "down"

        # Stopping an unknown server refuses; stopping twice is harmless.
        S.stop_server(srv.id)
        raised = False
        try:
            S.stop_server("deadbeefdead")
        except SliverRefused as exc:
            raised = True
            assert exc.gate == "unknown", exc.gate
        assert raised, "an unknown server id must refuse"
    finally:
        restore()
    print("  server start/stop execs the hardcoded engage sandbox and records a run: PASS")


def test_starting_the_c2_server_needs_engagement_approval_and_the_red_confirm() -> None:
    """*** THE BUILD #7 GATE. ***

    This surface used to be ungated on the grounds that a C2 server is operator infrastructure
    with no target — an argument it made by CITING the pivot listener, which build #5's I2
    finding had already tightened. Re-argued on its own terms the claim is stronger here than it
    was there (a daemon opens no channel toward anything under test) but not sufficient: Sliver's
    server config can PERSIST listener jobs that come up with the daemon, so "starting it is
    inert" is a property of a config file, not of this code.
    """
    restore = _patch_active(_fake_engagement())
    try:
        with _Spy() as spy:
            # No engagement at all -> refused before any gate that could be mistaken for one.
            try:
                S.start_server(SliverServerRequest(approved=True, dangerous_ack=True))
                raise AssertionError("a C2 server started with no engagement named")
            except SliverRefused as exc:
                assert exc.gate == "engagement", f"expected engagement, got {exc.gate!r}"
            assert not spy.spawn.spawned, "a refused start must never spawn"

            try:
                S.start_server(_srv(approved=False))
                raise AssertionError("an UNAPPROVED C2 server started")
            except SliverRefused as exc:
                assert exc.gate == "approval", f"expected approval, got {exc.gate!r}"
            assert not spy.spawn.spawned, "a refused start must never spawn"

            try:
                S.start_server(_srv(dangerous_ack=False))
                raise AssertionError("a C2 server started with NO red-confirm")
            except SliverRefused as exc:
                assert exc.gate == "danger", f"expected danger, got {exc.gate!r}"
            assert not spy.spawn.spawned, "a refused start must never spawn"
            assert not spy.saved, "a refused start must record nothing"

            srv = S.start_server(_srv())
            assert srv.status == "listening" and spy.spawn.spawned
    finally:
        restore()
    print("  a C2 server needs engagement + approval + the red-confirm; a refusal runs "
          "nothing: PASS")


def test_the_c2_server_binary_actually_trips_the_heuristic() -> None:
    """THE POSITIVE CONTROL for the gate above — without it the danger leg passes vacuously.

    This is the failure mode `sliver` vs `sliver-client` already produced once: a danger-set
    entry that reads as coverage while never matching the name actually invoked.
    """
    from cockpit import allowlist

    reasons = allowlist.dangerous_command_heuristic(S.SLIVER_SERVER_BIN, [])
    assert reasons, (
        f"{S.SLIVER_SERVER_BIN!r} produces NO danger reason, so the red-confirm on a C2 server "
        "start would never fire"
    )
    print("  sliver-server trips the heuristic (the danger leg is live): PASS")


def test_a_c2_server_that_dies_is_a_refusal_not_a_live_server() -> None:
    """The status is OBSERVED after the settle window, never assigned at spawn time."""
    restore = _patch_active(_fake_engagement())
    try:
        with _Spy(alive=False) as spy:
            raised = None
            try:
                S.start_server(_srv())
            except SliverRefused as exc:
                raised = exc
            assert raised is not None, "a daemon that exited immediately must REFUSE"
            assert raised.gate == "unavailable" and "did not stay up" in raised.reason, raised
            assert spy.spawn.spawned, "the refusal must come from OBSERVING the spawn"
            assert not S.list_servers(), "a dead daemon must not be registered"

        for bound, want in ((None, "starting"), (False, "starting"), (True, "listening")):
            with _Spy(alive=True, bound=bound):
                srv = S.start_server(_srv())
                assert srv.status == want, f"probe {bound!r} -> {srv.status!r}, want {want!r}"
                assert srv.liveness, "the model must carry WHAT was observed"
    finally:
        restore()
    print("  a dead C2 daemon refuses; an unconfirmed bind is 'starting': PASS")


def test_server_refuses_when_sandbox_down_or_capped() -> None:
    restore = _patch_active(_fake_engagement())
    try:
        with _Spy(up=False) as spy:
            raised = False
            try:
                S.start_server(_srv())
            except SliverRefused as exc:
                raised = True
                assert exc.gate == "unavailable", exc.gate
            assert raised, "a down engage sandbox must refuse the start"
            assert spy.popen_argv is None and not spy.saved, "nothing runs or records on refusal"

        with _Spy() as spy:
            for _ in range(S.MAX_LIVE_SERVERS):
                S.start_server(_srv())
            raised = False
            try:
                S.start_server(_srv())
            except SliverRefused as exc:
                raised = True
                assert exc.gate == "limit", exc.gate
            assert raised, "the live-server cap must refuse"
    finally:
        restore()
    print("  a down sandbox / a hit cap refuses the start; nothing runs: PASS")


# --------------------------------------------------------------------------- #
# 4. *** THE INVARIANT *** — the whole surface is HUMAN-ONLY.
# --------------------------------------------------------------------------- #
def test_sliver_surface_is_human_only() -> None:
    """cockpit/sliver.py may be referenced ONLY by itself + main.py (the HTTP layer).

    THE LOAD-BEARING TEST. A C2 server an agent could raise is an autonomous C2, and an
    implant an agent could build is an autonomous payload factory. The orchestrator / agent /
    loop / executor / adgraph must have NO path here — the same rule :kali, the tunnels and
    live sessions have, scanned the same way, by RELATIVE PATH.

    cockpit/router.py was allow-listed provisionally while the routes were unwritten; they
    landed in main.py instead (the cockpit router keeps no handle on this surface), so the
    allow-list is tightened back to the two files that actually reference it.
    """
    # mcp_tools.py: `_run_surface` reaches start_server ONLY via `hackpit_surface`, registered ONLY
    # when HACKPIT_MCP_EXECUTE=1 (opt-in, off by default) — the env-gated execution path
    # test_mcp_safety already tolerates, not an accidental one (the planted control still catches those).
    allowed = {Path("cockpit/sliver.py"), Path("main.py"), Path("mcp_tools.py")}
    patterns = [
        r"\bstart_server\b",
        r"\bgenerate_implant\b",
        r"\bfrom\s+\.sliver\b",
        r"\bfrom\s+cockpit\.sliver\b",
        r"\bimport\s+cockpit\.sliver\b",
        r"\bfrom\s+cockpit\s+import\s+[^\n]*\bsliver\b",
        r"\bfrom\s+\.\s+import\s+[^\n]*\bsliver\b",
        r"\bcockpit\.sliver\b",
    ]
    py_files = (
        list(BACKEND.glob("*.py"))
        + list((BACKEND / "cockpit").glob("*.py"))
        + list((BACKEND / "adgraph").glob("*.py"))
        + list((BACKEND / "detection").glob("*.py"))
        + list((BACKEND / "state").glob("*.py"))
    )
    offenders: list[str] = []
    for f in py_files:
        rel = f.relative_to(BACKEND)
        if rel in allowed or f.name.startswith("test_"):
            continue
        text = f.read_text(encoding="utf-8")
        hits = [p for p in patterns if re.search(p, text)]
        if hits:
            offenders.append(f"{rel.as_posix()} ({', '.join(hits)})")
    assert not offenders, (
        "the Sliver surface must be HUMAN-ONLY — these modules can reach it: "
        f"{offenders}. The orchestrator/agent/executor must have NO path to a C2 server or "
        "an implant build."
    )
    print("  Sliver server + implant build are HUMAN-ONLY (no agent/loop/executor path): PASS")


def test_agent_path_modules_expose_no_sliver_hook() -> None:
    """Belt-and-suspenders: the autonomous path's modules carry no sliver attribute."""
    import orchestrator as O

    for mod, name in ((EX, "executor"), (O, "orchestrator")):
        for attr in ("sliver", "start_server", "generate_implant", "ImplantRequest"):
            assert not hasattr(mod, attr), (
                f"{name} must not expose '{attr}' — that would be an agent path to C2"
            )
    src = Path(O.__file__).read_text(encoding="utf-8")
    for bad in ("generate_implant", "start_server", "cockpit.sliver", "from .sliver"):
        assert bad not in src, f"orchestrator must not reference '{bad}'"

    # And sliver.py itself must not reach the agent/loop or the :kali open shell.
    # Import-shaped tokens only, so prose in the module docstring cannot trip this.
    ssrc = Path(S.__file__).read_text(encoding="utf-8")
    for bad in ("run_kali", "from .kali", "cockpit.kali", "KALI_OPEN_CONTAINER",
                "import orchestrator", "from orchestrator", "cockpit.agent", "propose_next"):
        assert bad not in ssrc, f"sliver.py must not reference '{bad}'"
    print("  executor/orchestrator expose no sliver hook; sliver has no agent/:kali path: PASS")


def test_sliver_builds_no_shell_and_copies_no_gate() -> None:
    """No shell anywhere, and the gates are the REAL executor's — never a local copy."""
    src = Path(S.__file__).read_text(encoding="utf-8")
    for banned in ("shell=True", "os.system", "os.popen", 'sh -c', '"sh", "-c"', "'sh', '-c'"):
        assert banned not in src, f"sliver.py must not contain {banned!r}"
    assert "executor.validate_request" in src, (
        "the gates must be the REAL executor's validate_request, not a copy"
    )
    assert "executor.resolve_mode" in src, (
        "the container must come from the shared resolver, never the request"
    )
    # Deployment / beacon-catch is DEFERRED: nothing here delivers or runs what it builds.
    for deferred in ("psexec", "smbclient", "docker cp", "beacon_catch", "write_stdin"):
        assert deferred not in src, f"sliver.py must not deliver/drive implants ({deferred!r})"
    print("  no shell, no copied gate, no deployment path: PASS")


def test_lab_and_engagement_gates_are_unchanged() -> None:
    """Importing/exercising sliver changes nothing about how a one-shot command is gated."""
    from cockpit.models import ExecRequest

    resolved = EX.resolve_mode(ExecRequest(command="nmap", args=["-sV", config.LAB_TARGET_HOST]))
    assert resolved.mode == "lab" and resolved.container == config.SANDBOX_CONTAINER

    r = EX.validate_request(ExecRequest(command="nmap", args=["-sV", "evil.com"], approved=True))
    assert r is not None and r.gate == "target", "the lab target-lock must be untouched"

    eng = _fake_engagement()
    restore = _patch_active(eng)
    try:
        r = EX.validate_request(
            ExecRequest(command="nmap", args=["scanme.nmap.org"], engagement_id=eng.engagement_id)
        )
        assert r is not None and r.gate == "approval", "never-auto-run must be untouched"
    finally:
        restore()
    print("  lab + engagement gates unchanged by the Sliver surface: PASS")


if __name__ == "__main__":
    test_implant_argv_is_pure_and_never_substitutes_listener()
    test_implant_fields_are_bounded_and_carry_no_container()
    test_generate_is_gated_and_scope_checked()
    test_generate_uses_the_mode_container_and_records_a_run()
    test_lab_mode_generate_lands_outside_the_loot_tree()
    test_generate_reports_a_failed_build_without_raising()
    test_generate_refuses_when_docker_is_missing()
    test_server_lifecycle_records_a_run()
    test_starting_the_c2_server_needs_engagement_approval_and_the_red_confirm()
    test_the_c2_server_binary_actually_trips_the_heuristic()
    test_a_c2_server_that_dies_is_a_refusal_not_a_live_server()
    test_server_refuses_when_sandbox_down_or_capped()
    test_sliver_surface_is_human_only()
    test_agent_path_modules_expose_no_sliver_hook()
    test_sliver_builds_no_shell_and_copies_no_gate()
    test_lab_and_engagement_gates_are_unchanged()
    print("ALL Sliver containment tests pass")
