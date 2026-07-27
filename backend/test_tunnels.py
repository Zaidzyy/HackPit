"""Pivot / tunnel routing (cockpit/tunnels.py + engagement.add_pivot_subnet) — Phase 4 item 4.

Option 1 — "manage the tunnel, rewrite before approval". These tests pin the properties that
keep it safe:

  1. HUMAN-ONLY listener lifecycle. start_tunnel/stop_tunnel may be referenced ONLY by the route
     (router.py) + this test — never the executor/orchestrator/agent path. A listener an agent
     could raise = an autonomous pivot. Scanned across the source tree.
  2. PURE routing + rewrite. route_for / wrap_command execute nothing; they only compute the
     proxychains-wrapped command the HUMAN approves. The prefix is VISIBLE in the returned argv
     (rewrite-before-approval), never applied after — that is why silent routing was rejected.
  3. ROUTE ON THE ADDRESS. Routing is decided on a numeric IP inside a tunnel's CIDR; a hostname
     never routes (no resolve-to-decide leak, same discipline as the scope matcher).
  4. SCOPE BY HAND. A tunnel's subnet enters engagement scope ONLY via the explicit, audited
     add_pivot_subnet — recon expansion still cannot widen scope. A command to the internal
     subnet is refused until it is added by hand.

Run:  python test_tunnels.py
"""
from __future__ import annotations

import subprocess
import types
from pathlib import Path

from cockpit import config
from cockpit import tunnels as T
from cockpit.tunnels import Tunnel, TunnelRefused, TunnelStartRequest
from test_support import listeners, scans


class _Spy:
    """Hermetic start: the container is 'up' and the spawn goes through the shared shim.

    The spawn moved into ``cockpit/lifecycle.py`` in build #7, so faking ``T.subprocess.Popen``
    here would fake a call this module no longer makes — the fake would sit unused and every
    "a refused start must never spawn" assertion would pass vacuously. It fakes the ONE place
    the spawn actually lives instead; ``alive``/``bound`` let a test drive the observed outcome.
    """

    def __init__(self, *, up=True, alive=True, bound=True):
        self.up = up
        self.spawn = listeners.FakeListenerSpawn(alive=alive, bound=bound)
        self._orig = None

    @property
    def popen_argv(self):
        """The argv that reached the spawn, or None if nothing spawned."""
        return self.spawn.argv

    def __enter__(self):
        self._orig = T._container_running
        T._container_running = lambda name: self.up
        self.spawn.__enter__()
        return self

    def __exit__(self, *exc):
        self.spawn.__exit__(*exc)
        T._container_running = self._orig


class _Engagement:
    """A live engagement to attribute a tunnel start to. Yields its id; exits on the way out."""

    def __init__(self, label: str = "eng-tun"):
        self.label = label
        self.eng_id = ""

    def __enter__(self) -> str:
        from cockpit import engagement

        engagement.init_db()
        eng = engagement.enter("10.10.10.5", "authorized", scope_spec="10.10.10.0/24")
        self.eng_id = eng.engagement_id
        return self.eng_id

    def __exit__(self, *exc):
        from cockpit import engagement

        try:
            engagement.exit_engagement(self.eng_id)
        except Exception:
            pass
        return False


def _tun(**kw) -> Tunnel:
    base = dict(
        id="t1", kind="chisel", routing="socks", lhost="10.8.0.2", listen_port=8080,
        socks_port=1080, subnets=["172.16.0.0/24"], status="listening",
        agent_command="chisel client 10.8.0.2:8080 R:socks", started_at="t",
    )
    base.update(kw)
    return Tunnel(**base)


# --------------------------------------------------------------------------- #
# 1. human-only
# --------------------------------------------------------------------------- #
_TUNNEL_ALLOWED = {"cockpit/tunnels.py", "cockpit/router.py"}
_TUNNEL_PATTERNS = [r"start_tunnel", r"\bimport tunnels\b", r"from \.tunnels", r"cockpit\.tunnels"]
_TUNNEL_AST_TARGETS = ["cockpit.tunnels", "start_tunnel"]


def test_tunnels_lifecycle_is_human_only() -> None:
    """Whole tree, path-keyed allow-list, AST pass — see test_scans.py. The old form globbed
    backend/*.py + cockpit/*.py, so a planted `from cockpit.tunnels import start_tunnel` in
    detection/resolver.py was missed."""
    res = scans.scan_source_tree(
        patterns=_TUNNEL_PATTERNS, allowed=_TUNNEL_ALLOWED, ast_targets=_TUNNEL_AST_TARGETS,
    )
    scans.assert_clean(
        res,
        what="tunnel lifecycle must be HUMAN-ONLY",
        must_have_scanned=["orchestrator.py", "adgraph/orchestrator.py", "cockpit/executor.py",
                           "detection/resolver.py"],
        min_checked=60,
    )
    scans.assert_catches_a_planted_violation(
        plant="from cockpit.tunnels import start_tunnel",
        patterns=_TUNNEL_PATTERNS, allowed=_TUNNEL_ALLOWED, ast_targets=_TUNNEL_AST_TARGETS,
        where="detection/resolver.py",
    )
    from cockpit import executor as EX
    assert not hasattr(EX, "tunnels") and not hasattr(EX, "start_tunnel")
    print(f"  tunnel start/stop is human-only across all {len(res.checked)} backend modules "
          "(+ planted-violation control): PASS")


# --------------------------------------------------------------------------- #
# 1b. THE LISTENER START IS GATED (finding I2 from the 2026-07-27 gate audit)
#
# `start_tunnel` reached `subprocess.Popen` directly, with NO call to
# `executor.validate_request`, and `POST /cockpit/tunnels` carried no `approved` /
# `dangerous_ack` field at all. The module docstring's claim that "the rewritten command still
# runs through the NORMAL gated executor" was true — and beside the point, because the LISTENER
# START is the tunnel primitive. A tunnel is a C2 path and an exfil path in one, moving
# arbitrary traffic to somewhere the operator has not been gated against, and it was raised on
# an unauthenticated POST with no approval and no red-confirm.
#
# Human-only is preserved (the source-scan lock above is untouched); this is purely additive.
# --------------------------------------------------------------------------- #
def test_starting_a_listener_needs_approval_and_the_red_confirm() -> None:
    """Unapproved refuses at `approval`; approved-without-ack refuses at `danger`. Nothing runs."""
    T.reset()
    with _Spy() as spy, _Engagement("eng-tun") as eng_id:
        # No engagement at all -> refused before any gate that could be mistaken for one.
        try:
            T.start_tunnel(TunnelStartRequest(kind="chisel", lhost="10.8.0.2"))
            raise AssertionError("a pivot listener started with no engagement named")
        except TunnelRefused as exc:
            assert exc.gate == "engagement", f"expected the engagement gate, got {exc.gate!r}"
        assert spy.popen_argv is None

        unapproved = TunnelStartRequest(kind="chisel", lhost="10.8.0.2",
                                        subnets=["172.16.0.0/24"], engagement_id=eng_id)
        try:
            T.start_tunnel(unapproved)
            raise AssertionError("an UNAPPROVED tunnel listener started — I2 is back")
        except TunnelRefused as exc:
            assert exc.gate == "approval", f"expected the approval gate, got {exc.gate!r}"
        assert spy.popen_argv is None, "a refused start must never reach subprocess.Popen"

        # Approved, but a tunnel is a C2/exfil channel — it still needs the explicit confirm.
        approved = unapproved.model_copy(update={"approved": True})
        try:
            T.start_tunnel(approved)
            raise AssertionError("a tunnel listener started with NO red-confirm")
        except TunnelRefused as exc:
            assert exc.gate == "danger", f"expected the danger gate, got {exc.gate!r}"
            assert exc.dangerous_flags, "the confirm must carry its reasons"
            assert any("chisel" in f.lower() for f in exc.dangerous_flags), exc.dangerous_flags
        assert spy.popen_argv is None, "a refused start must never reach subprocess.Popen"

        # With both, it runs.
        ok = unapproved.model_copy(update={"approved": True, "dangerous_ack": True})
        tun = T.start_tunnel(ok)
        assert tun.status == "listening" and spy.popen_argv is not None
    print("  a tunnel listener needs approval + the red-confirm; a refusal runs nothing: PASS")


def test_both_tunnel_binaries_actually_trip_the_heuristic() -> None:
    """THE POSITIVE CONTROL for the gate above. If neither server binary produced a reason, the
    danger leg would pass vacuously and the test above would be asserting nothing.

    This is exactly how `ligolo` failed before: the set entry was the string `ligolo` while the
    binary the repo runs is `ligolo-proxy`, so it could never match — an entry that reads as
    coverage while providing none."""
    from cockpit import allowlist

    for kind in ("chisel", "ligolo"):
        req = TunnelStartRequest(kind=kind, lhost="10.8.0.2")
        argv = T.server_argv_for(req)
        reasons = allowlist.dangerous_command_heuristic(argv[0], argv[1:])
        assert reasons, (
            f"{kind}: the server binary {argv[0]!r} produces NO danger reason, so the confirm "
            "on a tunnel start would never fire — this is the `ligolo` vs `ligolo-proxy` bug"
        )
    print("  both chisel and ligolo-proxy trip the heuristic (the danger leg is live): PASS")


def test_the_gated_argv_is_the_argv_that_runs() -> None:
    """The drift lock, and the lesson from Critical 2: gating a DIFFERENT string than the one
    that executes reproduces the bug somewhere new. Both come from `server_argv_for`."""
    T.reset()
    with _Spy() as spy, _Engagement() as eng_id:
        req = TunnelStartRequest(kind="ligolo", lhost="10.8.0.2", listen_port=11601,
                                 engagement_id=eng_id, approved=True, dangerous_ack=True)
        gated = T.server_argv_for(req)
        T.start_tunnel(req)
        # ligolo is a console binary, so the exec carries `-i`; the container is still the
        # hardcoded constant and the server tokens are still exactly what the gate classified.
        assert spy.popen_argv[:4] == ["docker", "exec", "-i", config.ENGAGE_SANDBOX_CONTAINER], \
            spy.popen_argv[:4]
        assert spy.spawn.container_argv() == gated, (
            f"the gate classified {gated} but the spawn ran {spy.spawn.container_argv()}"
        )
    print("  the argv the gate classified IS the argv that runs: PASS")


def test_only_the_console_binary_gets_a_forwarded_stdin() -> None:
    """`-i` is per-binary, and both halves of that claim are checked against the real spawn.

    ligolo-proxy is an interactive console: without a stdin that stays open it reads EOF and
    exits 0, which is exactly the bug where a dead process was reported as `listening`. chisel's
    server is a plain daemon and needs no stdin at all, so it must NOT get one — least privilege
    per binary rather than one blanket default.
    """
    for kind, want_i in (("ligolo", True), ("chisel", False)):
        T.reset()
        with _Spy() as spy, _Engagement() as eng_id:
            T.start_tunnel(TunnelStartRequest(
                kind=kind, lhost="10.8.0.2", engagement_id=eng_id,
                approved=True, dangerous_ack=True,
            ))
            assert T.needs_console_stdin(kind) is want_i, kind
            assert spy.spawn.interactive is want_i, (
                f"{kind}: docker exec -i present={spy.spawn.interactive}, expected {want_i} "
                f"(argv={spy.popen_argv[:4]})"
            )
            # The container process must never be handed a writer object either way.
            assert spy.spawn.child_stdin is not None, "stdin must be explicitly chosen, not left open"
    print("  only the console binary (ligolo) gets `docker exec -i`; chisel does not: PASS")


def test_a_listener_that_dies_is_a_refusal_not_a_live_tunnel() -> None:
    """*** THE BUILD #7 DEFECT, PINNED. ***

    `status` used to be assigned at Popen time and never observed, so a ligolo-proxy that read
    EOF and exited 0 came back as `status="listening"` with an agent one-liner for a port with
    nothing behind it. A dead process must now REFUSE, and an unconfirmed bind must report
    `starting` rather than claim a listener nobody looked at.
    """
    # 1. the process died -> refusal, nothing registered
    T.reset()
    with _Spy(alive=False) as spy, _Engagement() as eng_id:
        req = TunnelStartRequest(kind="ligolo", lhost="10.8.0.2", engagement_id=eng_id,
                                 approved=True, dangerous_ack=True)
        raised = None
        try:
            T.start_tunnel(req)
        except TunnelRefused as exc:
            raised = exc
        assert raised is not None, "a listener that exited immediately must REFUSE, not report up"
        assert raised.gate == "unavailable", raised.gate
        assert "did not stay up" in raised.reason, raised.reason
        assert spy.spawn.spawned, "the refusal must come from OBSERVING the spawn, not skipping it"
        assert not T.list_tunnels(), "a dead listener must not be registered as a tunnel"

    # 2. alive but the bind is unconfirmed -> 'starting', never 'listening'
    for bound, want in ((None, "starting"), (False, "starting"), (True, "listening")):
        T.reset()
        with _Spy(alive=True, bound=bound), _Engagement() as eng_id:
            tun = T.start_tunnel(TunnelStartRequest(
                kind="chisel", lhost="10.8.0.2", engagement_id=eng_id,
                approved=True, dangerous_ack=True,
            ))
            assert tun.status == want, f"port probe {bound!r} -> status {tun.status!r}, want {want!r}"
            assert tun.liveness, "the model must carry WHAT was observed, not just a verdict"
    print("  a dead listener refuses; an unconfirmed bind is 'starting', not 'listening': PASS")


def test_the_request_carries_the_gate_fields() -> None:
    """The route cannot demand an approval the model has no field for — the original defect was
    half a missing call and half a missing field."""
    fields = set(TunnelStartRequest.model_fields)
    for needed in ("approved", "dangerous_ack"):
        assert needed in fields, f"TunnelStartRequest has no {needed!r} field"
    # ...and both default to FALSE, so an old client that omits them is refused, never allowed.
    fresh = TunnelStartRequest(kind="chisel", lhost="10.8.0.2")
    assert fresh.approved is False and fresh.dangerous_ack is False, (
        "the gate fields must default to False — a default of True would mean an omitted field "
        "silently grants what it was added to require"
    )
    print("  the start request carries approved + dangerous_ack, both defaulting False: PASS")


def test_start_runs_in_engage_sandbox_hardcoded() -> None:
    T.reset()
    with _Spy() as spy, _Engagement() as eng_id:
        tun = T.start_tunnel(TunnelStartRequest(
            kind="chisel", lhost="10.8.0.2", subnets=["172.16.0.0/24"],
            engagement_id=eng_id, approved=True, dangerous_ack=True,
        ))
    argv = spy.popen_argv
    assert argv[:3] == ["docker", "exec", config.ENGAGE_SANDBOX_CONTAINER], argv[:3]
    assert "chisel" in argv and "server" in argv
    assert tun.agent_command == "chisel client 10.8.0.2:8080 R:socks"
    assert "172.16.0.0/24" in tun.subnets and tun.routing == "socks"
    T.reset()
    print("  start execs the hardcoded engage sandbox + returns the agent one-liner: PASS")


def test_refuses_when_sandbox_down_or_capped() -> None:
    T.reset()
    with _Spy(up=False), _Engagement() as eng_id:
        try:
            # Fully gated, so the ONLY thing left to refuse it is the down sandbox — otherwise
            # this would pass for the wrong reason and stop testing availability at all.
            T.start_tunnel(TunnelStartRequest(
                kind="chisel", lhost="10.8.0.2", engagement_id=eng_id,
                approved=True, dangerous_ack=True,
            ))
            assert False, "must refuse when the engage sandbox is down"
        except TunnelRefused as exc:
            assert exc.gate == "unavailable", f"refused for the wrong reason: {exc.gate!r}"
    T.reset()
    print("  a down sandbox refuses the start; nothing runs: PASS")


# --------------------------------------------------------------------------- #
# 2 + 3. pure routing + rewrite-before-approval
# --------------------------------------------------------------------------- #
def test_route_matches_on_ip_only() -> None:
    tuns = [_tun(subnets=["172.16.0.0/24"])]
    assert T.route_for("172.16.0.10", tuns) is not None, "an IP in the subnet routes"
    assert T.route_for("172.16.1.10", tuns) is None, "an IP outside the subnet does not"
    assert T.route_for("internal.corp.local", tuns) is None, "a hostname never routes (no resolve)"
    # a down tunnel does not route
    assert T.route_for("172.16.0.10", [_tun(status="down")]) is None
    print("  route_for matches on the numeric address only; down tunnels don't route: PASS")


def test_chisel_wrap_prefixes_visible_proxychains() -> None:
    cmd, args, note = T.wrap_command("nmap", ["-sV", "172.16.0.10"], _tun())
    assert cmd == "proxychains", "chisel routing wraps with proxychains"
    assert args == ["-q", "nmap", "-sV", "172.16.0.10"], args
    # the prefix is VISIBLE in the returned argv — this IS what the human approves
    assert "proxychains" in " ".join([cmd, *args])
    # idempotent: an already-proxychained command is not double-wrapped
    c2, a2, _ = T.wrap_command("proxychains", ["-q", "nmap"], _tun())
    assert c2 == "proxychains" and a2 == ["-q", "nmap"]
    print("  chisel wrap prefixes a VISIBLE proxychains; no double-wrap: PASS")


def test_ligolo_wrap_leaves_command_unchanged() -> None:
    tun = _tun(kind="ligolo", routing="interface", socks_port=None)
    cmd, args, note = T.wrap_command("nmap", ["-sV", "172.16.0.10"], tun)
    assert cmd == "nmap" and args == ["-sV", "172.16.0.10"], "interface routing runs unwrapped"
    assert "ligolo" in note and "route" in note.lower()
    print("  ligolo (interface) routing runs the command unwrapped, with a route note: PASS")


def test_routing_and_wrapping_execute_nothing() -> None:
    src = Path(T.__file__).read_text(encoding="utf-8")
    # route_for / wrap_command bodies must not run anything; the only subprocess use is the
    # lifecycle (start/stop) + the availability probe.
    for banned in ("os.system", "shell=True", "sh -c", "run_kali"):
        assert banned not in src, f"tunnels.py must not contain {banned!r}"
    print("  routing/wrapping helpers execute nothing: PASS")


# --------------------------------------------------------------------------- #
# 4. scope by hand
# --------------------------------------------------------------------------- #
def test_pivot_subnet_is_an_explicit_scope_amendment() -> None:
    from cockpit import engagement

    engagement.init_db()
    eng = engagement.enter("10.10.10.5", "authorized", scope_spec="10.10.10.0/24")
    # before: the internal host is OUT of scope
    before = engagement.resolved_scope(engagement.get_active(eng.engagement_id))
    assert not before.in_scope("172.16.0.10"), "internal host must start out of scope"

    # add the pivot subnet BY HAND
    amended = engagement.add_pivot_subnet(eng.engagement_id, "172.16.0.0/24")
    after = engagement.resolved_scope(engagement.get_active(eng.engagement_id))
    assert after.in_scope("172.16.0.10"), "after the hand amendment the internal host is in scope"
    assert after.in_scope("10.10.10.5"), "the original scope is preserved"
    assert "172.16.0.0/24" in (amended.scope or ""), amended.scope

    # idempotent + validated
    engagement.add_pivot_subnet(eng.engagement_id, "172.16.0.0/24")  # no error, no double
    try:
        engagement.add_pivot_subnet(eng.engagement_id, "not-a-cidr")
        assert False, "a bad CIDR must raise"
    except ValueError:
        pass
    try:
        engagement.add_pivot_subnet("eng-nope", "10.0.0.0/8")
        assert False, "an inactive engagement must raise"
    except ValueError:
        pass
    engagement.exit_engagement(eng.engagement_id)
    print("  a pivot subnet enters scope only via the explicit, validated, idempotent amendment: PASS")


def test_recon_expansion_still_cannot_widen() -> None:
    """The amendment is the ONLY widening path — recon expansion must remain unable to."""
    src = Path(__import__("cockpit.engagement", fromlist=["x"]).__file__).read_text(encoding="utf-8")
    # The recon-expansion docstring invariant must still be present, unedited.
    assert "Adding a host never widens" in src, "the recon-expansion no-widen invariant was lost"
    print("  recon-driven expansion still cannot widen scope (amendment is the only path): PASS")


if __name__ == "__main__":
    test_tunnels_lifecycle_is_human_only()
    test_starting_a_listener_needs_approval_and_the_red_confirm()
    test_both_tunnel_binaries_actually_trip_the_heuristic()
    test_the_gated_argv_is_the_argv_that_runs()
    test_only_the_console_binary_gets_a_forwarded_stdin()
    test_a_listener_that_dies_is_a_refusal_not_a_live_tunnel()
    test_the_request_carries_the_gate_fields()
    test_start_runs_in_engage_sandbox_hardcoded()
    test_refuses_when_sandbox_down_or_capped()
    test_route_matches_on_ip_only()
    test_chisel_wrap_prefixes_visible_proxychains()
    test_ligolo_wrap_leaves_command_unchanged()
    test_routing_and_wrapping_execute_nothing()
    test_pivot_subnet_is_an_explicit_scope_amendment()
    test_recon_expansion_still_cannot_widen()
    print("ALL tunnel tests pass")
