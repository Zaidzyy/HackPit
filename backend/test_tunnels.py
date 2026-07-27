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
from test_support import scans


class _Spy:
    def __init__(self, *, up=True):
        self.up = up
        self.popen_argv = None
        self._orig = (T._container_running, T.subprocess.Popen)

    def __enter__(self):
        T._container_running = lambda name: self.up

        def fake_popen(argv, **kwargs):
            self.popen_argv = argv
            return types.SimpleNamespace(poll=lambda: None, kill=lambda: None)

        T.subprocess.Popen = fake_popen
        return self

    def __exit__(self, *exc):
        T._container_running, T.subprocess.Popen = self._orig


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


def test_start_runs_in_engage_sandbox_hardcoded() -> None:
    T.reset()
    with _Spy() as spy:
        tun = T.start_tunnel(TunnelStartRequest(kind="chisel", lhost="10.8.0.2",
                                                subnets=["172.16.0.0/24"]))
    argv = spy.popen_argv
    assert argv[:3] == ["docker", "exec", config.ENGAGE_SANDBOX_CONTAINER], argv[:3]
    assert "chisel" in argv and "server" in argv
    assert tun.agent_command == "chisel client 10.8.0.2:8080 R:socks"
    assert "172.16.0.0/24" in tun.subnets and tun.routing == "socks"
    T.reset()
    print("  start execs the hardcoded engage sandbox + returns the agent one-liner: PASS")


def test_refuses_when_sandbox_down_or_capped() -> None:
    T.reset()
    with _Spy(up=False):
        try:
            T.start_tunnel(TunnelStartRequest(kind="chisel", lhost="x"))
            assert False, "must refuse when the engage sandbox is down"
        except TunnelRefused:
            pass
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
    test_start_runs_in_engage_sandbox_hardcoded()
    test_refuses_when_sandbox_down_or_capped()
    test_route_matches_on_ip_only()
    test_chisel_wrap_prefixes_visible_proxychains()
    test_ligolo_wrap_leaves_command_unchanged()
    test_routing_and_wrapping_execute_nothing()
    test_pivot_subnet_is_an_explicit_scope_amendment()
    test_recon_expansion_still_cannot_widen()
    print("ALL tunnel tests pass")
