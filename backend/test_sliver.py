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

    def __init__(self, *, up=True, docker_missing=False, returncode=0, isolated=True):
        self.up = up
        self.docker_missing = docker_missing
        self.returncode = returncode
        self.isolated = isolated
        self.popen_argv: list[str] | None = None
        self.run_argv: list[str] | None = None
        self.procs: list[_FakeProc] = []
        self.saved: list = []
        # Loot directory names actually created — asserted EMPTY for lab builds, because the
        # isolated lab sandbox has no /loot mount and must not mkdir a host directory.
        self.loot_calls: list[str] = []
        self._orig = (
            S._container_running,
            S.subprocess.Popen,
            S.subprocess.run,
            S.runstore.save_run,
            S.loot.ensure,
            EX.assert_isolation_proven,
        )

    def __enter__(self):
        def fake_popen(argv, **kw):
            if self.docker_missing:
                raise FileNotFoundError("docker")
            self.popen_argv = argv
            p = _FakeProc(argv)
            self.procs.append(p)
            return p

        def fake_run(argv, **kw):
            if self.docker_missing:
                raise FileNotFoundError("docker")
            self.run_argv = argv
            return _FakeCompleted(argv, returncode=self.returncode, stdout="implant built")

        def fake_ensure(name):
            self.loot_calls.append(name)
            return f"/loot/{name}"

        def fake_isolation():
            if not self.isolated:
                from cockpit.sandbox import SandboxError

                raise SandboxError("sandbox is attached to non-internal network(s)")

        S._container_running = lambda name: self.up
        S.subprocess.Popen = fake_popen
        S.subprocess.run = fake_run
        S.runstore.save_run = lambda rec: self.saved.append(rec)
        S.loot.ensure = fake_ensure
        EX.assert_isolation_proven = fake_isolation
        return self

    def __exit__(self, *exc):
        (
            S._container_running,
            S.subprocess.Popen,
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
    assert argv[0] == S.SLIVER_CLIENT_BIN, argv
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
            # OUT OF SCOPE -> target gate, nothing generated.
            rejected = S.validate_generate(_req(target="evil.com"))
            assert rejected is not None and rejected.gate == "target", rejected
            assert "scope" in rejected.reason.lower(), rejected.reason
            raised = False
            try:
                S.generate_implant(_req(target="evil.com"))
            except SliverRefused as exc:
                raised = True
                assert exc.gate == "target", exc.gate
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
            # Container comes from resolve_mode, never the request.
            assert argv[:3] == ["docker", "exec", config.ENGAGE_SANDBOX_CONTAINER], argv[:3]
            assert config.SANDBOX_CONTAINER not in argv, "must NOT reach the isolated lab box"
            assert config.KALI_OPEN_CONTAINER not in argv, "must NOT reach the :kali open box"
            # argv-only: no shell.
            assert "sh" not in argv and "-c" not in argv, "generation is argv-only (no shell)"
            # The pure argv is embedded verbatim, plus a SERVER-CHOSEN artifact path.
            for tok in S._implant_argv(_req()):
                assert tok in argv, f"{tok!r} missing from the executed argv"
            save_path = argv[argv.index("--save") + 1]
            assert save_path.startswith(f"/loot/{eng.engagement_id}/"), save_path
            assert save_path == implant.artifact_path, implant.artifact_path
            assert spy.loot_calls == [eng.engagement_id], (
                f"an engagement build lands in ITS OWN loot directory, got {spy.loot_calls}"
            )
            assert implant.run_id in save_path, "the artifact is named for its run (auditable)"
            # <listener> still verbatim in what actually ran.
            assert "<listener>" in argv and "scanme.nmap.org" == implant.target

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
        assert argv[:3] == ["docker", "exec", config.SANDBOX_CONTAINER], argv[:3]
        assert config.ENGAGE_SANDBOX_CONTAINER not in argv, "a lab build must NOT reach engagement"
        assert config.KALI_OPEN_CONTAINER not in argv, "a lab build must NOT reach the open box"

        # The artifact is a BARE filename -> the image's own working directory.
        save_path = argv[argv.index("--save") + 1]
        assert save_path == f"implant-{implant.run_id}.exe", save_path
        assert "/loot" not in " ".join(argv), (
            "the isolated lab sandbox has no /loot mount — a /loot path would fail every build"
        )
        assert not spy.loot_calls, (
            f"a lab build must NOT create a host loot directory, created: {spy.loot_calls}"
        )
        assert implant.mode == "lab" and implant.artifact_path == save_path
        assert implant.container == config.SANDBOX_CONTAINER
        assert "<listener>" in argv, "the listener passes through in lab mode too"

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
    """A non-zero build is recorded as failed — a tool failure is not a gate failure."""
    eng = _fake_engagement()
    restore = _patch_active(eng)
    try:
        with _Spy(returncode=2) as spy:
            implant = S.generate_implant(_req())
            assert implant.status == "failed" and implant.exit_code == 2, implant
            assert spy.saved[-1].exit_code == 2
    finally:
        restore()
    print("  a failed build is recorded, not raised as a refusal: PASS")


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
    with _Spy() as spy:
        srv = S.start_server(SliverServerRequest(engagement_id="eng-sliver0000"))
        argv = spy.popen_argv
        assert argv[:3] == ["docker", "exec", config.ENGAGE_SANDBOX_CONTAINER], argv[:3]
        assert S.SLIVER_SERVER_BIN in argv, argv
        assert "sh" not in argv and "-c" not in argv, "the server is argv-only (no shell)"
        assert srv.status == "listening" and srv.container == config.ENGAGE_SANDBOX_CONTAINER

        started = spy.saved[-1]
        assert started.command == "sliver-server", started.command
        assert started.mode == "engagement", started.mode
        assert started.run_id == srv.run_id
        assert started.finished_at is None, "a live server has not finished"
        assert started.approved is True, "clicking Start IS the approval for operator infra"

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
    print("  server start/stop execs the hardcoded engage sandbox and records a run: PASS")


def test_server_refuses_when_sandbox_down_or_capped() -> None:
    with _Spy(up=False) as spy:
        raised = False
        try:
            S.start_server(SliverServerRequest())
        except SliverRefused as exc:
            raised = True
            assert exc.gate == "unavailable", exc.gate
        assert raised, "a down engage sandbox must refuse the start"
        assert spy.popen_argv is None and not spy.saved, "nothing runs or records on refusal"

    with _Spy() as spy:
        for _ in range(S.MAX_LIVE_SERVERS):
            S.start_server(SliverServerRequest())
        raised = False
        try:
            S.start_server(SliverServerRequest())
        except SliverRefused as exc:
            raised = True
            assert exc.gate == "limit", exc.gate
        assert raised, "the live-server cap must refuse"
    print("  a down sandbox / a hit cap refuses the start; nothing runs: PASS")


# --------------------------------------------------------------------------- #
# 4. *** THE INVARIANT *** — the whole surface is HUMAN-ONLY.
# --------------------------------------------------------------------------- #
def test_sliver_surface_is_human_only() -> None:
    """cockpit/sliver.py may be referenced ONLY by itself + cockpit/router.py.

    THE LOAD-BEARING TEST. A C2 server an agent could raise is an autonomous C2, and an
    implant an agent could build is an autonomous payload factory. The orchestrator / agent /
    loop / executor / adgraph must have NO path here — the same rule :kali, the tunnels and
    live sessions have, scanned the same way, by RELATIVE PATH.
    """
    allowed = {Path("cockpit/sliver.py"), Path("cockpit/router.py")}
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
    test_server_refuses_when_sandbox_down_or_capped()
    test_sliver_surface_is_human_only()
    test_agent_path_modules_expose_no_sliver_hook()
    test_sliver_builds_no_shell_and_copies_no_gate()
    test_lab_and_engagement_gates_are_unchanged()
    print("ALL Sliver containment tests pass")
