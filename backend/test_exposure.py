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


if __name__ == "__main__":
    print("== listener profiles (build #13) ==")
    test_ports_derive_from_kinds()
    test_chisel_socks_is_never_publishable()
    test_extra_ports_merge_and_dedupe()
    test_unknown_kind_is_refused()
    test_ip_classification()
    test_liveness_probe()
    print("all listener-profile tests passed")
    sys.exit(0)
