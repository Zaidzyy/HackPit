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


class _Spy:
    def __init__(self, *, up=True, docker_missing=False):
        self.up = up
        self.docker_missing = docker_missing
        self.popen_argv: list[str] | None = None
        self.procs: list[_FakeProc] = []
        self.saved: list = []
        self._orig = (
            O._container_running,
            O.subprocess.Popen,
            O.runstore.save_run,
        )

    def __enter__(self):
        def fake_popen(argv, **kw):
            if self.docker_missing:
                raise FileNotFoundError("docker")
            self.popen_argv = argv
            p = _FakeProc(argv)
            self.procs.append(p)
            return p

        O._container_running = lambda name: self.up
        O.subprocess.Popen = fake_popen
        O.runstore.save_run = lambda rec: self.saved.append(rec)
        return self

    def __exit__(self, *exc):
        (
            O._container_running,
            O.subprocess.Popen,
            O.runstore.save_run,
        ) = self._orig
        O.reset()
        return False


def _dnscat(**over) -> ObfuscationRequest:
    base = dict(kind="dnscat2", zone="tunnel.operator-owned.example", engagement_id="eng-dns000000")
    base.update(over)
    return ObfuscationRequest(**base)


def _iodine(**over) -> ObfuscationRequest:
    base = dict(
        kind="iodine",
        zone="t.operator-owned.example",
        secret="s3cr3t-tunnel-pw",
        engagement_id="eng-dns000000",
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
# 3. lifecycle — hardcoded engage sandbox, argv-only, recorded
# --------------------------------------------------------------------------- #
def test_dnscat2_listener_starts_in_the_hardcoded_engage_sandbox() -> None:
    with _Spy() as spy:
        lis = O.start_listener(_dnscat())
        argv = spy.popen_argv
        assert argv[:3] == ["docker", "exec", config.ENGAGE_SANDBOX_CONTAINER], argv[:3]
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
        assert rec.approved is True, "clicking Start IS the approval for operator infra"
        assert rec.mode == "engagement", rec.mode
        assert rec.finished_at is None, "a live listener has not finished"
        assert rec.session_id == "eng-dns000000"

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
    test_dnscat2_listener_starts_in_the_hardcoded_engage_sandbox()
    test_iodine_listener_carries_tunnel_net_and_redacts_the_secret()
    test_stop_closes_the_same_run_record()
    test_refuses_when_sandbox_down_capped_or_docker_missing()
    test_obfuscation_surface_is_human_only()
    test_agent_path_modules_expose_no_obfuscation_hook()
    test_obfuscation_builds_no_shell_and_hardcodes_its_container()
    test_lab_and_engagement_gates_are_unchanged()
    print("ALL DNS-tunnel obfuscation containment tests pass")
