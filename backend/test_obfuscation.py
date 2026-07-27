"""DNS-tunnel obfuscation surface (cockpit/obfuscation.py) — containment regression-lock.

A DNS tunnel has two halves and they carry completely different risk. This module owns
exactly ONE of them, and these tests fail loudly if that line ever moves:

  1. THE LISTENER IS OPERATOR INFRASTRUCTURE, HUMAN-ONLY. start_listener / stop_listener run
     the operator's OWN dnscat2/iodine server inside the hardcoded engage sandbox. There is
     no target and no gate beyond "a human clicked Start" — the same posture
     cockpit/tunnels.py gives a pivot listener and cockpit/sliver.py gives a C2 server, for
     the same reason. What makes it safe is that the orchestrator / agent / loop has ZERO
     code path to it: a covert channel an agent could raise is an autonomous covert channel.
     Scanned across the source tree.

  2. *** THE CLIENT HALF IS NEVER DELIVERED. *** operator_oneliner RETURNS A STRING. The
     client runs on the far side — a host the operator already has execution on — and
     HackPit must never ship it, drop it, or run it. This is THE load-bearing property of
     this module: it is a pure string builder with no I/O, no execution and no delivery
     primitive anywhere in the file.

  3. ARGV-ONLY, CONTAINER FROM A CODE CONSTANT. No shell anywhere; no request field can
     redirect the exec (there is no container/sandbox field on the request at all).

  4. THE OPERATOR'S ZONE AND TUNNEL NET ARE OPERATOR-OWNED. <tunnel-zone> is a zone the
     operator has had delegated and <tunnel-net> is the tunnel interface's own private
     range. Neither is ever the system under test, and neither is substituted with a target.

  5. EVERYTHING IS RECORDED, WITH THE PRE-SHARED SECRET REDACTED. start and stop each land
     as a RunRecord; the operator's tunnel password never reaches the audit trail.

Hermetic: subprocess.Popen/run, the container liveness probe and runstore.save_run are
monkeypatched by manual save/restore (this repo has NO pytest), so no Docker daemon, no
network and no DB writes.

Run:  backend/.venv/Scripts/python.exe backend/test_obfuscation.py
"""
from __future__ import annotations

import re
from pathlib import Path

from cockpit import config
from cockpit import executor as EX
from cockpit import obfuscation as O
from cockpit.obfuscation import ObfuscationRefused, ObfuscationRequest
from test_support import listeners

BACKEND = Path(__file__).parent


# --------------------------------------------------------------------------- #
# hermetic fakes — manual save/restore (mirrors test_sliver.py's _Spy)
# --------------------------------------------------------------------------- #
class _FakeProc:
    """Stand-in for the docker-exec'd tunnel server process."""

    def __init__(self, argv):
        self.argv = argv
        self._alive = True

    def poll(self):
        return None if self._alive else 0

    def kill(self):
        self._alive = False


# The engagement a start is attributed to. A DNS listener is GATED (build #7) and the gate runs
# the REAL executor.validate_request, so these tests need a REAL live engagement — a made-up id
# would refuse at the engagement gate and every start below would be testing that refusal instead
# of what it means to test. _Spy opens one and points this at it.
_ENG = {"id": "eng-dns000000"}


class _Spy:
    """Hermetic start: container up, spawn shimmed, run store captured, real engagement open.

    The spawn moved into ``cockpit/lifecycle.py`` in build #7, so faking ``O.subprocess.Popen``
    would fake a call this module no longer makes — an unused fake, and every "a refusal spawns
    nothing" assertion would pass vacuously. It fakes the one place the spawn now lives.
    """

    def __init__(self, *, up=True, docker_missing=False, alive=True, bound=True):
        self.up = up
        self.docker_missing = docker_missing
        self.saved: list = []
        self.spawn = listeners.FakeListenerSpawn(alive=alive, bound=bound)
        self._orig = None
        self._eng = None

    @property
    def popen_argv(self) -> list[str] | None:
        return self.spawn.argv

    @property
    def procs(self) -> list:
        return self.spawn.procs

    def __enter__(self):
        from cockpit import engagement

        self._orig = (O._container_running, O.runstore.save_run, _ENG["id"])
        O._container_running = lambda name: self.up
        O.runstore.save_run = lambda rec: self.saved.append(rec)
        self.spawn.__enter__()
        if self.docker_missing:
            def _boom(argv, **kw):
                raise FileNotFoundError("docker")
            O.lifecycle.subprocess.Popen = _boom

        engagement.init_db()
        self._eng = engagement.enter("10.10.10.5", "authorized", scope_spec="10.10.10.0/24")
        _ENG["id"] = self._eng.engagement_id
        return self

    def __exit__(self, *exc):
        from cockpit import engagement

        self.spawn.__exit__(*exc)
        O._container_running, O.runstore.save_run, _ENG["id"] = self._orig
        if self._eng is not None:
            try:
                engagement.exit_engagement(self._eng.engagement_id)
            except Exception:
                pass
        O.reset()
        return False


def _dnscat(**over) -> ObfuscationRequest:
    base = dict(kind="dnscat2", zone="tunnel.operator-owned.example",
                engagement_id=_ENG["id"], approved=True, dangerous_ack=True)
    base.update(over)
    return ObfuscationRequest(**base)


def _iodine(**over) -> ObfuscationRequest:
    base = dict(
        kind="iodine",
        zone="t.operator-owned.example",
        secret="s3cr3t-tunnel-pw",
        engagement_id=_ENG["id"],
        approved=True,
        dangerous_ack=True,
    )
    base.update(over)
    return ObfuscationRequest(**base)


# --------------------------------------------------------------------------- #
# 1. *** THE INVARIANT *** — operator_oneliner is PURE and is NEVER delivered.
# --------------------------------------------------------------------------- #
def test_operator_oneliner_is_pure_and_delivers_nothing() -> None:
    """It builds a STRING for the human to paste by hand. It must run and send NOTHING."""
    with _Spy() as spy:
        lis = O.start_listener(_dnscat(secret="pre-shared-key-9000"))
        iod = O.start_listener(_iodine())

        # PURE: with subprocess blown up, the one-liner must still be constructible.
        orig = (O.subprocess.Popen, O.subprocess.run)
        calls: list[str] = []
        try:
            def _boom(*a, **kw):
                calls.append("exec")
                raise AssertionError("operator_oneliner must execute NOTHING")

            O.subprocess.Popen = _boom
            O.subprocess.run = _boom
            line = O.operator_oneliner(lis)
            line2 = O.operator_oneliner(lis)
            iline = O.operator_oneliner(iod)
        finally:
            O.subprocess.Popen, O.subprocess.run = orig

        assert not calls, "building the client one-liner must not execute anything"
        assert line == line2, "the one-liner must be deterministic (pure)"
        assert isinstance(line, str) and isinstance(iline, str)

        # It names the CLIENT half and the OPERATOR's own zone.
        assert line.startswith(O.DNSCAT2_CLIENT_BIN), line
        assert "tunnel.operator-owned.example" in line, line
        assert "pre-shared-key-9000" in line, (
            "operator_oneliner is a FORMATTER: handed a listener carrying a real key it renders "
            "that key. What keeps the key off the wire is WHICH listener start_listener hands "
            "it (a masked copy) — asserted next."
        )
        assert O.DNSCAT2_SERVER_BIN not in line, "the one-liner is the CLIENT half, not the server"

        assert iline.startswith(O.IODINE_CLIENT_BIN + " "), iline
        assert "t.operator-owned.example" in iline, iline
        assert O.IODINE_SERVER_BIN not in iline.split()[0], iline

        # *** The stored one-liner is the MASKED render — built, not scrubbed. *** It is the
        # same pure function over a _mask_secret copy, so it matches token for token except
        # where the key was, and the operator's key is not in it at all.
        assert lis.client_command == O.operator_oneliner(O._mask_secret(lis)), lis.client_command
        assert iod.client_command == O.operator_oneliner(O._mask_secret(iod)), iod.client_command
        for stored, raw_key in ((lis.client_command, "pre-shared-key-9000"),
                                (iod.client_command, "s3cr3t-tunnel-pw")):
            assert raw_key not in stored, f"the operator's key is embedded in {stored!r}"
            assert O.SECRET_MASK in stored, stored
        # Masking must not corrupt the rest of the line: everything but the key survives.
        assert lis.client_command == line.replace("pre-shared-key-9000", O.SECRET_MASK), (
            f"masking changed a token it had no business changing: {lis.client_command!r}"
        )
        assert "tunnel.operator-owned.example" in lis.client_command, lis.client_command

        # Building it did not start, stop or record anything new.
        assert len(spy.procs) == 2, "operator_oneliner must not spawn a process"

    # And NOTHING in the module can ship it anywhere.
    src = Path(O.__file__).read_text(encoding="utf-8")
    for delivery in (
        "docker cp", "write_stdin", "communicate(", "stdin=subprocess.PIPE", "scp ", "psexec",
        "smbclient", "requests.", "urllib", "httpx", "socket.", "paramiko", "winrm",
        "sendline", "os.system", "os.popen",
    ):
        assert delivery not in src, (
            f"obfuscation.py must not be able to DELIVER the client half — found {delivery!r}"
        )
    print("  operator_oneliner is PURE, returns the client half, delivers nothing: PASS")


# --------------------------------------------------------------------------- #
# 2. request bounds — no container field, operator-owned values only
# --------------------------------------------------------------------------- #
def test_request_carries_no_container_and_bounds_its_fields() -> None:
    fields = set(ObfuscationRequest.model_fields.keys())
    assert "container" not in fields and "sandbox" not in fields, (
        f"a container/sandbox field would break containment — got {sorted(fields)}"
    )

    for bad in (
        dict(zone="evil.com; rm -rf /"),
        dict(zone="$(id)"),
        dict(zone="-oProxyCommand=x"),      # must never be readable as a flag
        dict(zone="zone with spaces"),
        dict(zone=""),
        dict(kind="nc"),
    ):
        raised = False
        try:
            ObfuscationRequest(**{"kind": "dnscat2", "zone": "ok.example", **bad})
        except Exception:
            raised = True
        assert raised, f"an out-of-set / unsafe value must be refused, not interpolated: {bad}"

    # The tunnel net is the tunnel interface's OWN private range — never a public range and
    # never something that could be mistaken for the system under test.
    for bad_net in ("8.8.8.8/24", "not-a-cidr", "example.com"):
        raised = False
        try:
            # NB: a valid-length secret, so what is on trial here is tunnel_net and nothing else.
            ObfuscationRequest(
                kind="iodine", zone="t.example", secret="tunnel-pw-01", tunnel_net=bad_net
            )
        except Exception:
            raised = True
        assert raised, f"tunnel_net {bad_net!r} must be refused"

    # iodine cannot come up without its pre-shared password.
    raised = False
    try:
        ObfuscationRequest(kind="iodine", zone="t.example")
    except Exception:
        raised = True
    assert raised, "iodine must require a pre-shared password"

    # A leading-dash secret would be read as a flag.
    raised = False
    try:
        ObfuscationRequest(kind="iodine", zone="t.example", secret="-P")
    except Exception:
        raised = True
    assert raised, "a flag-shaped secret must be refused"

    # A one- or two-character pre-shared key is not a legitimate value for the thing that
    # authenticates every client to the operator's tunnel server.
    for short in ("a", "pw", "1234567"):
        raised = False
        try:
            ObfuscationRequest(kind="iodine", zone="t.example", secret=short)
        except Exception:
            raised = True
        assert raised, f"a {len(short)}-character tunnel secret must be refused"
    ObfuscationRequest(kind="iodine", zone="t.example", secret="12345678")  # the boundary passes
    print("  no container field; zone/secret/tunnel_net are bounded and operator-owned: PASS")


# --------------------------------------------------------------------------- #
# 2b. THE LISTENER START IS GATED (build #7 — the stale-precedent finding)
#
# This surface used to be ungated, and it justified that by citing "the identical reasoning the
# pivot-listener lifecycle uses" — a precedent build #5's I2 finding had already overturned. The
# stale citation was the smaller problem; I2's actual argument applies here with full force. A
# DNS-tunnel listener is the SERVER END OF A COVERT EXFIL CHANNEL, whose whole purpose is to
# carry arbitrary traffic out of a network through that network's own resolvers. "No target" was
# true and beside the point, exactly as it was for the pivot listener.
#
# Human-only is preserved (the source-scan lock below is untouched); this is purely additive.
# --------------------------------------------------------------------------- #
def test_starting_a_dns_listener_needs_engagement_approval_and_the_red_confirm() -> None:
    """No engagement -> `engagement`; unapproved -> `approval`; unacked -> `danger`. Nothing runs."""
    with _Spy() as spy:
        eng_id = _ENG["id"]

        # No engagement at all -> refused before any gate that could be mistaken for one.
        try:
            O.start_listener(ObfuscationRequest(kind="dnscat2", zone="t.operator.example",
                                                approved=True, dangerous_ack=True))
            raise AssertionError("a DNS-tunnel listener started with no engagement named")
        except ObfuscationRefused as exc:
            assert exc.gate == "engagement", f"expected the engagement gate, got {exc.gate!r}"
        assert not spy.spawn.spawned, "a refused start must never spawn"

        unapproved = ObfuscationRequest(kind="dnscat2", zone="t.operator.example",
                                        engagement_id=eng_id)
        try:
            O.start_listener(unapproved)
            raise AssertionError("an UNAPPROVED DNS-tunnel listener started")
        except ObfuscationRefused as exc:
            assert exc.gate == "approval", f"expected the approval gate, got {exc.gate!r}"
        assert not spy.spawn.spawned, "a refused start must never spawn"

        # Approved, but a covert channel still needs the explicit confirm.
        approved = unapproved.model_copy(update={"approved": True})
        try:
            O.start_listener(approved)
            raise AssertionError("a DNS-tunnel listener started with NO red-confirm")
        except ObfuscationRefused as exc:
            assert exc.gate == "danger", f"expected the danger gate, got {exc.gate!r}"
            assert exc.dangerous_flags, "the confirm must carry its reasons"
        assert not spy.spawn.spawned, "a refused start must never spawn"

        # With all three, it runs.
        ok = unapproved.model_copy(update={"approved": True, "dangerous_ack": True})
        lis = O.start_listener(ok)
        assert lis.status == "listening" and spy.spawn.spawned
    print("  a DNS listener needs engagement + approval + the red-confirm; a refusal runs "
          "nothing: PASS")


def test_both_dns_server_binaries_actually_trip_the_heuristic() -> None:
    """THE POSITIVE CONTROL for the gate above.

    If neither server binary produced a danger reason, the red-confirm leg would pass vacuously
    and the test above would be asserting nothing. This is the `ligolo` vs `ligolo-proxy` failure
    mode: a danger-set entry that reads as coverage while never matching the invoked name.

    Drawn from the real requests this module builds, via the real `_server_args`, so a rename of
    either binary is caught by nobody remembering to update a hand-written list.
    """
    from cockpit import allowlist

    for req in (_dnscat(), _iodine()):
        argv = O._server_args(req)
        reasons = allowlist.dangerous_command_heuristic(argv[0], argv[1:])
        assert reasons, (
            f"{req.kind}: the server binary {argv[0]!r} produces NO danger reason, so the "
            "red-confirm on a DNS-tunnel start would never fire"
        )
    print("  both dnscat2-server and iodined trip the heuristic (the danger leg is live): PASS")


def test_only_the_console_binary_gets_a_forwarded_stdin() -> None:
    """`-i` is per-binary, and both halves are checked against the real spawn.

    dnscat2-server is a Ruby console: without a stdin that stays open it logs "Input thread is
    over" and exits, which is exactly the bug where a dead process was reported as `listening`.
    `iodined -f` is a plain foreground daemon and needs no stdin, so it must NOT get one.
    """
    for factory, kind, want_i in ((_dnscat, "dnscat2", True), (_iodine, "iodine", False)):
        with _Spy() as spy:
            O.start_listener(factory())
            assert O.needs_console_stdin(kind) is want_i, kind
            assert spy.spawn.interactive is want_i, (
                f"{kind}: docker exec -i present={spy.spawn.interactive}, expected {want_i}"
            )
    print("  only the console binary (dnscat2) gets `docker exec -i`; iodined does not: PASS")


def test_a_dns_listener_that_dies_is_a_refusal_not_a_live_channel() -> None:
    """*** THE BUILD #7 DEFECT, PINNED. ***

    `status` used to be assigned at Popen time and never observed, so a dnscat2-server that read
    EOF and exited came back as `status="listening"` with a client one-liner for a channel that
    did not exist. A dead process must now REFUSE, and an unconfirmed bind must report `starting`.
    """
    with _Spy(alive=False) as spy:
        raised = None
        try:
            O.start_listener(_dnscat())
        except ObfuscationRefused as exc:
            raised = exc
        assert raised is not None, "a listener that exited immediately must REFUSE"
        assert raised.gate == "unavailable", raised.gate
        assert "did not stay up" in raised.reason, raised.reason
        assert spy.spawn.spawned, "the refusal must come from OBSERVING the spawn, not skipping it"
        assert not O.list_listeners(), "a dead listener must not be registered"

    for bound, want in ((None, "starting"), (False, "starting"), (True, "listening")):
        with _Spy(alive=True, bound=bound):
            lis = O.start_listener(_dnscat())
            assert lis.status == want, f"probe {bound!r} -> status {lis.status!r}, want {want!r}"
            assert lis.liveness, "the model must carry WHAT was observed, not just a verdict"
    print("  a dead DNS listener refuses; an unconfirmed bind is 'starting': PASS")


# --------------------------------------------------------------------------- #
# 3. lifecycle — hardcoded engage sandbox, argv-only, recorded
# --------------------------------------------------------------------------- #
def test_dnscat2_listener_starts_in_the_hardcoded_engage_sandbox() -> None:
    with _Spy() as spy:
        lis = O.start_listener(_dnscat())
        argv = spy.popen_argv
        # dnscat2-server is a Ruby CONSOLE, so the exec carries `-i` to give it a stdin that
        # does not end (without one it logs "Input thread is over" and exits). The container is
        # still the hardcoded constant.
        assert argv[:4] == ["docker", "exec", "-i", config.ENGAGE_SANDBOX_CONTAINER], argv[:4]
        assert config.SANDBOX_CONTAINER not in argv, "must NOT reach the isolated lab box"
        assert config.KALI_OPEN_CONTAINER not in argv, "must NOT reach the :kali open box"
        assert O.DNSCAT2_SERVER_BIN in argv, argv
        assert "tunnel.operator-owned.example" in argv, argv
        assert "sh" not in argv and "-c" not in argv, "the listener is argv-only (no shell)"
        assert all(isinstance(t, str) for t in argv), argv

        assert lis.status == "listening"
        assert lis.container == config.ENGAGE_SANDBOX_CONTAINER
        assert lis.kind == "dnscat2"

        rec = spy.saved[-1]
        assert rec.command == O.DNSCAT2_SERVER_BIN, rec.command
        assert rec.run_id == lis.run_id
        assert rec.target == config.ENGAGE_SANDBOX_CONTAINER, (
            "the listener has NO target by definition — the audit row names the operator's box"
        )
        assert rec.approved is True, "the start cleared the approval gate"
        assert rec.mode == "engagement", rec.mode
        assert rec.finished_at is None, "a live listener has not finished"
        assert rec.session_id == _ENG["id"]

        assert [x.id for x in O.list_listeners()] == [lis.id]
        assert O.get_listener(lis.id) is not None and O.get_listener("nope") is None
    print("  dnscat2 listener execs the hardcoded engage sandbox and records a run: PASS")


def test_iodine_listener_carries_tunnel_net_and_redacts_the_secret() -> None:
    with _Spy() as spy:
        lis = O.start_listener(_iodine(tunnel_net="10.99.53.1/24"))
        argv = spy.popen_argv
        assert argv[:3] == ["docker", "exec", config.ENGAGE_SANDBOX_CONTAINER], argv[:3]
        assert O.IODINE_SERVER_BIN in argv, argv
        assert "10.99.53.1/24" in argv, argv
        assert "t.operator-owned.example" in argv, argv
        assert "s3cr3t-tunnel-pw" in argv, "the real password must reach the server process"
        assert lis.tunnel_net == "10.99.53.1/24"

        # *** but NEVER the audit trail ***
        rec = spy.saved[-1]
        blob = " ".join([rec.command, *rec.args, rec.target, rec.stdout, rec.stderr])
        assert "s3cr3t-tunnel-pw" not in blob, (
            f"the operator's tunnel password must be REDACTED in the run record — got {rec.args}"
        )
        assert any("***" in a for a in rec.args), rec.args
    print("  iodine listener carries the tunnel net; the secret is redacted in the record: PASS")


def test_stop_closes_the_same_run_record() -> None:
    with _Spy() as spy:
        lis = O.start_listener(_dnscat())
        started = spy.saved[-1]

        stopped = O.stop_listener(lis.id)
        assert stopped.status == "down" and stopped.stopped_at is not None
        final = spy.saved[-1]
        assert final.run_id == started.run_id, "stop updates the SAME run record"
        assert final.finished_at is not None, "stopping must close the record"
        assert O.get_listener(lis.id).status == "down"

        # Stopping twice is harmless; an unknown id refuses.
        n = len(spy.saved)
        O.stop_listener(lis.id)
        assert len(spy.saved) == n, "a second stop must not write another record"
        raised = False
        try:
            O.stop_listener("deadbeefdead")
        except ObfuscationRefused as exc:
            raised = True
            assert exc.gate == "unknown", exc.gate
        assert raised, "an unknown listener id must refuse"
    print("  stop closes the same run record; unknown id refuses: PASS")


def test_refuses_when_sandbox_down_capped_or_docker_missing() -> None:
    with _Spy(up=False) as spy:
        raised = False
        try:
            O.start_listener(_dnscat())
        except ObfuscationRefused as exc:
            raised = True
            assert exc.gate == "unavailable", exc.gate
        assert raised, "a down engage sandbox must refuse the start"
        assert spy.popen_argv is None and not spy.saved, "nothing runs or records on refusal"

    with _Spy(docker_missing=True) as spy:
        raised = False
        try:
            O.start_listener(_dnscat())
        except ObfuscationRefused as exc:
            raised = True
            assert exc.gate == "unavailable", exc.gate
        assert raised, "a missing docker CLI must refuse"
        assert not spy.saved and not O.list_listeners()

    with _Spy() as spy:
        for _ in range(O.MAX_LIVE_LISTENERS):
            O.start_listener(_dnscat())
        raised = False
        try:
            O.start_listener(_dnscat())
        except ObfuscationRefused as exc:
            raised = True
            assert exc.gate == "limit", exc.gate
        assert raised, "the live-listener cap must refuse"
    print("  a down sandbox / missing docker / a hit cap refuses; nothing runs: PASS")


# --------------------------------------------------------------------------- #
# 4. *** THE INVARIANT *** — the whole surface is HUMAN-ONLY.
# --------------------------------------------------------------------------- #
def test_obfuscation_surface_is_human_only() -> None:
    """cockpit/obfuscation.py may be referenced ONLY by itself + main.py (the HTTP layer).

    A DNS tunnel an agent could raise is an autonomous covert channel. The orchestrator /
    agent / loop / executor / adgraph must have NO path here — the same rule :kali, the
    tunnels, live sessions and Sliver have, scanned the same way, by RELATIVE PATH.

    cockpit/router.py was allow-listed provisionally while the routes were unwritten; they
    landed in main.py instead (the cockpit router keeps no handle on this surface), so the
    allow-list is tightened back to the two files that actually reference it.
    """
    allowed = {Path("cockpit/obfuscation.py"), Path("main.py")}
    patterns = [
        r"\bstart_listener\b",
        r"\bstop_listener\b",
        r"\bfrom\s+\.obfuscation\b",
        r"\bfrom\s+cockpit\.obfuscation\b",
        r"\bimport\s+cockpit\.obfuscation\b",
        r"\bfrom\s+cockpit\s+import\s+[^\n]*\bobfuscation\b",
        r"\bfrom\s+\.\s+import\s+[^\n]*\bobfuscation\b",
        r"\bcockpit\.obfuscation\b",
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
        "the DNS-tunnel surface must be HUMAN-ONLY — these modules can reach it: "
        f"{offenders}. The orchestrator/agent/executor must have NO path to a covert channel."
    )
    print("  DNS-tunnel listener lifecycle is HUMAN-ONLY (no agent/loop/executor path): PASS")


def test_agent_path_modules_expose_no_obfuscation_hook() -> None:
    """Belt-and-suspenders: the autonomous path's modules carry no obfuscation attribute."""
    import orchestrator as ORCH

    for mod, name in ((EX, "executor"), (ORCH, "orchestrator")):
        for attr in ("obfuscation", "start_listener", "operator_oneliner", "ObfuscationRequest"):
            assert not hasattr(mod, attr), (
                f"{name} must not expose '{attr}' — that would be an agent path to a DNS tunnel"
            )
    src = Path(ORCH.__file__).read_text(encoding="utf-8")
    for bad in ("start_listener", "operator_oneliner", "cockpit.obfuscation", "from .obfuscation"):
        assert bad not in src, f"orchestrator must not reference '{bad}'"

    # And obfuscation.py must not reach the agent/loop or the :kali open shell.
    # Import-shaped tokens only, so prose in the module docstring cannot trip this.
    osrc = Path(O.__file__).read_text(encoding="utf-8")
    for bad in ("run_kali", "from .kali", "cockpit.kali", "KALI_OPEN_CONTAINER",
                "import orchestrator", "from orchestrator", "cockpit.agent", "propose_next"):
        assert bad not in osrc, f"obfuscation.py must not reference '{bad}'"
    print("  executor/orchestrator expose no obfuscation hook; no agent/:kali path: PASS")


def test_obfuscation_builds_no_shell_and_hardcodes_its_container() -> None:
    src = Path(O.__file__).read_text(encoding="utf-8")
    for banned in ("shell=True", "os.system", "os.popen", "sh -c", '"sh", "-c"', "'sh', '-c'"):
        assert banned not in src, f"obfuscation.py must not contain {banned!r}"
    assert "config.ENGAGE_SANDBOX_CONTAINER" in src, (
        "the container must come from a CODE CONSTANT, never a request field"
    )
    print("  no shell; the container is a code constant: PASS")


def test_lab_and_engagement_gates_are_unchanged() -> None:
    """Importing/exercising the DNS-tunnel surface changes nothing about one-shot gating."""
    from cockpit.models import ExecRequest

    resolved = EX.resolve_mode(ExecRequest(command="nmap", args=["-sV", config.LAB_TARGET_HOST]))
    assert resolved.mode == "lab" and resolved.container == config.SANDBOX_CONTAINER

    r = EX.validate_request(ExecRequest(command="nmap", args=["-sV", "evil.com"], approved=True))
    assert r is not None and r.gate == "target", "the lab target-lock must be untouched"
    print("  lab + engagement gates unchanged by the DNS-tunnel surface: PASS")


if __name__ == "__main__":
    test_operator_oneliner_is_pure_and_delivers_nothing()
    test_request_carries_no_container_and_bounds_its_fields()
    test_starting_a_dns_listener_needs_engagement_approval_and_the_red_confirm()
    test_both_dns_server_binaries_actually_trip_the_heuristic()
    test_only_the_console_binary_gets_a_forwarded_stdin()
    test_a_dns_listener_that_dies_is_a_refusal_not_a_live_channel()
    test_dnscat2_listener_starts_in_the_hardcoded_engage_sandbox()
    test_iodine_listener_carries_tunnel_net_and_redacts_the_secret()
    test_stop_closes_the_same_run_record()
    test_refuses_when_sandbox_down_capped_or_docker_missing()
    test_obfuscation_surface_is_human_only()
    test_agent_path_modules_expose_no_obfuscation_hook()
    test_obfuscation_builds_no_shell_and_hardcodes_its_container()
    test_lab_and_engagement_gates_are_unchanged()
    print("ALL DNS-tunnel obfuscation containment tests pass")
