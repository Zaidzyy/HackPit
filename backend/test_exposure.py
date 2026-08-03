"""Listener profile regressions (build #13, part 1).

WHERE A CALLBACK LANDS. HackPit reaches OUT to anything — the engage sandbox is fully open by
decision. Being reached IN needs a container port published on a host address the target can
route to, and before build #13 exactly one hand-written file did that, hardcoded to one
laptop's VMware VMnet8 address.

This file is the regression lock on the module that generalised it. Hermetic: no Docker, no
network, no third-party dependency. The docker calls are faked through an injected runner, the
same way test_kali fakes subprocess.run.
"""

from __future__ import annotations

import sys

from cockpit import exposure


def test_ports_derive_from_kinds() -> None:
    assert exposure.derive_ports(["dns-tunnel"], []) == [(53, "udp")]
    assert exposure.derive_ports(["sliver", "dns-tunnel"], []) == [(53, "udp"), (31337, "tcp")]
    print("  ports derive from ticked kinds: PASS")


def test_chisel_socks_is_never_publishable() -> None:
    """Proxychains reaches the SOCKS port from INSIDE the sandbox, so publishing it would
    widen the exposure surface for nothing."""
    for kind, ports in exposure.KIND_PORTS.items():
        assert ports[0] != 1080, f"{kind} would publish the SOCKS port"
    derived = exposure.derive_ports(list(exposure.KIND_PORTS), [])
    assert not any(p == 1080 for p, _ in derived), derived
    print("  chisel SOCKS 1080 is never publishable: PASS")


def test_extra_ports_merge_and_dedupe() -> None:
    got = exposure.derive_ports(["dns-tunnel"], [(4444, "tcp"), (53, "udp")])
    assert got == [(53, "udp"), (4444, "tcp")], got
    print("  explicit extra ports merge and de-duplicate: PASS")


def test_unknown_kind_is_refused() -> None:
    try:
        exposure.derive_ports(["not-a-kind"], [])
    except exposure.ExposureRefused as exc:
        assert "not-a-kind" in str(exc)
        print("  an unknown listener kind is refused: PASS")
        return
    raise AssertionError("unknown kind was accepted")


def test_ip_classification() -> None:
    """The predicate is `is_global`, not `is_private` — see the note in exposure.py. The CGNAT
    case below is the one that proves it: on Python 3.14 `is_private` is False for 100.64/10,
    so keying off it would call every Tailscale address public and demand an ack to bind it."""
    assert exposure.classify_ip("192.168.13.1") == "private"
    assert exposure.classify_ip("10.10.14.7") == "private"
    assert exposure.classify_ip("172.16.4.2") == "private"
    assert exposure.classify_ip("100.101.5.2") == "private"   # CGNAT / Tailscale
    assert exposure.classify_ip("127.0.0.1") == "private"
    assert exposure.classify_ip("169.254.7.7") == "private"   # link-local
    assert exposure.classify_ip("8.8.8.8") == "public"
    assert exposure.classify_ip("13.107.42.14") == "public"
    assert exposure.classify_ip("0.0.0.0") == "wildcard"
    assert exposure.classify_ip("::") == "wildcard"
    assert exposure.classify_ip("*") == "wildcard"
    assert exposure.classify_ip("hackpit-lab-target") == "invalid"
    assert exposure.classify_ip("10.10.14.300") == "invalid"
    print("  bind addresses classify private / public / wildcard / invalid: PASS")


def test_liveness_probe() -> None:
    """Loopback always exists; TEST-NET-3 (203.0.113.0/24, RFC 5737) never does."""
    assert exposure.address_is_live("127.0.0.1") is True
    assert exposure.address_is_live("203.0.113.9") is False
    # A wildcard binds everything, so liveness is vacuously true.
    assert exposure.address_is_live("0.0.0.0") is True
    print("  the bind probe reports which addresses exist on this host: PASS")


def _profile(**kw):
    base = dict(ip="192.168.13.1", container="engage-sandbox", kinds=["dns-tunnel"],
                extra=[], engagement=None, ack_wildcard=False, ack_public=False)
    base.update(kw)
    return exposure.ListenerProfile(**base)


def test_private_live_address_needs_no_ack() -> None:
    """The control. Without this, a confirm that fired on everything would still look correct."""
    v = exposure.validate(_profile(ip="127.0.0.1"))
    assert v.refusals == [], v.refusals
    assert v.needs_ack == [], v.needs_ack
    print("  a private, live address needs no acknowledgement: PASS")


def test_wildcard_needs_ack_both_directions() -> None:
    without = exposure.validate(_profile(ip="0.0.0.0"))
    assert any("wildcard" in r.lower() or "every interface" in r for r in without.refusals), \
        without.refusals
    with_ack = exposure.validate(_profile(ip="0.0.0.0", ack_wildcard=True))
    assert with_ack.refusals == [], with_ack.refusals
    print("  a wildcard bind is refused without the ack and permitted with it: PASS")


def test_public_needs_ack_both_directions() -> None:
    without = exposure.validate(_profile(ip="8.8.8.8"))
    assert any("public" in r for r in without.refusals), without.refusals
    with_ack = exposure.validate(_profile(ip="8.8.8.8", ack_public=True))
    assert with_ack.refusals == [], with_ack.refusals
    print("  a public bind is refused without the ack and permitted with it: PASS")


def test_dead_address_warns_but_does_not_refuse() -> None:
    """Docker fails LOUDLY on a dead bind ('cannot assign requested address'), so this check
    buys a better error earlier — not safety. Refusing would be wrong for the real case of
    writing a profile while off the VPN, intending to connect before applying it."""
    v = exposure.validate(_profile(ip="8.8.8.8", ack_public=True))
    assert v.refusals == [], v.refusals
    assert any("not an address on this host" in w for w in v.warnings), v.warnings
    live = exposure.validate(_profile(ip="127.0.0.1"))
    assert not any("not an address on this host" in w for w in live.warnings), live.warnings
    print("  an address that is not live warns and still writes: PASS")


def test_lab_sandbox_is_never_exposable() -> None:
    v = exposure.validate(_profile(container="kali-sandbox"))
    assert any("isolat" in r for r in v.refusals), v.refusals
    assert "kali-sandbox" not in exposure.EXPOSABLE
    print("  the isolated lab sandbox can never be exposed: PASS")


def test_port_ranges_are_refused() -> None:
    try:
        _profile(extra=[("4000-4100", "tcp")])
    except Exception as exc:
        assert "range" in str(exc).lower(), exc
        print("  a port range is refused: PASS")
        return
    raise AssertionError("a port range was accepted")


def test_a_profile_with_no_ports_is_refused() -> None:
    v = exposure.validate(_profile(kinds=[], extra=[]))
    assert any("no ports" in r for r in v.refusals), v.refusals
    print("  a profile that would publish nothing is refused: PASS")


_AT = "2026-08-03T09:12:04Z"


def test_render_publishes_exactly_the_derived_ports() -> None:
    text = exposure.render(_profile(ip="10.10.14.7", kinds=["dns-tunnel", "sliver"]), at=_AT)
    assert '"10.10.14.7:53:53/udp"' in text, text
    assert '"10.10.14.7:31337:31337/tcp"' in text, text
    assert "engage-sandbox:" in text
    assert text.count('- "') == 2, text
    print("  render publishes exactly the derived ports: PASS")


def test_ack_line_is_rendered_only_when_needed() -> None:
    """The scanner is a static text scan, so without a marker IN the file it cannot tell a
    deliberate broad bind from one that slipped through."""
    plain = exposure.render(_profile(ip="10.10.14.7"), at=_AT)
    assert "hackpit-ack" not in plain, plain
    wild = exposure.render(
        _profile(ip="0.0.0.0", ack_wildcard=True, engagement="e-4417"), at=_AT)
    assert "# hackpit-ack: wildcard  bind=0.0.0.0  engagement=e-4417" in wild, wild
    pub = exposure.render(_profile(ip="8.8.8.8", ack_public=True), at=_AT)
    assert "# hackpit-ack: public  bind=8.8.8.8  engagement=-" in pub, pub
    print("  the ack line is rendered only for a wildcard or public bind: PASS")


def test_render_is_deterministic() -> None:
    p = _profile(ip="10.10.14.7", kinds=["sliver", "dns-tunnel"])
    assert exposure.render(p, at=_AT) == exposure.render(p, at=_AT)
    print("  render is deterministic for a given profile and timestamp: PASS")


def test_generated_profile_is_gitignored() -> None:
    """The first profile generated on a client engagement holds THEIR internal address, and
    this repository is public. Same class as the hardcoded user path parameterised out of
    fix-vmnet8.ps1 before it was tracked."""
    import subprocess
    out = subprocess.run(
        ["git", "check-ignore", "docker/listener-profile.yml"],
        cwd=str(exposure.REPO_ROOT), capture_output=True, text=True,
    )
    assert out.returncode == 0, "docker/listener-profile.yml is NOT gitignored"
    print("  the generated profile is gitignored: PASS")


def test_compose_command_carries_both_files() -> None:
    argv = exposure.compose_command(_profile())
    assert argv[:2] == ["docker", "compose"], argv
    assert argv.count("-f") == 2, argv
    joined = " ".join(argv)
    assert "docker-compose.yml" in joined and "listener-profile.yml" in joined, argv
    assert argv[-3:] == ["up", "-d", "engage-sandbox"], argv
    print("  the compose command names both files and the one service: PASS")


def test_write_refuses_a_bad_profile_and_writes_a_good_one() -> None:
    import tempfile
    from pathlib import Path as _P
    original = exposure.PROFILE_PATH
    with tempfile.TemporaryDirectory() as d:
        exposure.PROFILE_PATH = _P(d) / "listener-profile.yml"
        try:
            try:
                exposure.write(_profile(ip="0.0.0.0"), at=_AT)   # unacknowledged wildcard
                raise AssertionError("an unacknowledged wildcard was written")
            except exposure.ExposureRefused:
                pass
            assert not exposure.PROFILE_PATH.exists(), "a refused profile still wrote a file"

            exposure.write(_profile(ip="127.0.0.1"), at=_AT)
            assert exposure.PROFILE_PATH.exists()
            assert '"127.0.0.1:53:53/udp"' in exposure.PROFILE_PATH.read_text(encoding="utf-8")
            assert exposure.clear() is True
            assert exposure.clear() is False
        finally:
            exposure.PROFILE_PATH = original
    print("  write refuses a bad profile without touching disk, and clear is idempotent: PASS")


def _fake_docker(mapping):
    import json as _json

    def run(_argv):
        return 0, _json.dumps(mapping), ""
    return run


def test_observe_reports_what_is_true() -> None:
    p = _profile(ip="10.10.14.7", kinds=["dns-tunnel"])

    active = _fake_docker({"53/udp": [{"HostIp": "10.10.14.7", "HostPort": "53"}]})
    assert exposure.observe(p, runner=active)["state"] == "active"

    pending = _fake_docker({})
    assert exposure.observe(p, runner=pending)["state"] == "pending-restart"

    drifted = _fake_docker({"53/udp": [{"HostIp": "192.168.1.5", "HostPort": "53"}]})
    assert exposure.observe(p, runner=drifted)["state"] == "drifted"

    def broken(_argv):
        return 127, "", "docker CLI not found on PATH"
    assert exposure.observe(p, runner=broken)["state"] == "unknown"

    assert exposure.observe(None, runner=pending)["state"] == "none"
    print("  observe reports active / pending-restart / drifted / unknown / none: PASS")


def test_observe_never_claims_active_on_a_mismatch() -> None:
    """The case that matters. A container publishing SOME of the profile is not active."""
    p = _profile(ip="10.10.14.7", kinds=["dns-tunnel", "sliver"])
    half = _fake_docker({"53/udp": [{"HostIp": "10.10.14.7", "HostPort": "53"}]})
    assert exposure.observe(p, runner=half)["state"] == "drifted"
    print("  a partially-published profile is drifted, never active: PASS")


def test_observe_mentions_the_firewall_when_active() -> None:
    """A published port is not an open port, and the surface should say so rather than leave
    the operator guessing when a callback does not land."""
    p = _profile(ip="10.10.14.7", kinds=["dns-tunnel"])
    active = _fake_docker({"53/udp": [{"HostIp": "10.10.14.7", "HostPort": "53"}]})
    assert "firewall" in exposure.observe(p, runner=active)["note"].lower()
    print("  an active profile says a published port is not an open port: PASS")


def test_apply_requires_approval() -> None:
    """Recreating a container kills every listener, session and background job inside it."""
    calls = []

    def runner(argv):
        calls.append(argv)
        return 0, "", ""
    try:
        exposure.apply(_profile(), approved=False, runner=runner)
    except exposure.ExposureRefused as exc:
        assert exc.gate == "approval", exc.gate
        assert calls == [], "compose ran despite the refusal"
        print("  applying a profile without approval refuses and runs nothing: PASS")
        return
    raise AssertionError("apply ran without approval")


def test_apply_runs_the_compose_command_it_showed() -> None:
    calls = []

    def runner(argv):
        calls.append(argv)
        return 0, "", ""
    exposure.apply(_profile(), approved=True, runner=runner)
    assert calls, "compose never ran"
    assert calls[0] == exposure.compose_command(_profile()), calls[0]
    print("  an approved apply runs exactly the compose command it showed: PASS")


def test_apply_surfaces_a_compose_failure() -> None:
    def runner(_argv):
        return 1, "", "bind: cannot assign requested address"
    try:
        exposure.apply(_profile(), approved=True, runner=runner)
    except exposure.ExposureRefused as exc:
        assert exc.gate == "compose", exc.gate
        assert "cannot assign" in exc.reason, exc.reason
        print("  a compose failure surfaces its real error: PASS")
        return
    raise AssertionError("a failing compose was reported as success")


if __name__ == "__main__":
    print("== listener profiles (build #13) ==")
    test_ports_derive_from_kinds()
    test_chisel_socks_is_never_publishable()
    test_extra_ports_merge_and_dedupe()
    test_unknown_kind_is_refused()
    test_ip_classification()
    test_liveness_probe()
    test_private_live_address_needs_no_ack()
    test_wildcard_needs_ack_both_directions()
    test_public_needs_ack_both_directions()
    test_dead_address_warns_but_does_not_refuse()
    test_lab_sandbox_is_never_exposable()
    test_port_ranges_are_refused()
    test_a_profile_with_no_ports_is_refused()
    test_render_publishes_exactly_the_derived_ports()
    test_ack_line_is_rendered_only_when_needed()
    test_render_is_deterministic()
    test_generated_profile_is_gitignored()
    test_compose_command_carries_both_files()
    test_write_refuses_a_bad_profile_and_writes_a_good_one()
    test_observe_reports_what_is_true()
    test_observe_never_claims_active_on_a_mismatch()
    test_observe_mentions_the_firewall_when_active()
    test_apply_requires_approval()
    test_apply_runs_the_compose_command_it_showed()
    test_apply_surfaces_a_compose_failure()
    print("all listener-profile tests passed")
    sys.exit(0)
