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


if __name__ == "__main__":
    print("== listener profiles (build #13) ==")
    test_ports_derive_from_kinds()
    test_chisel_socks_is_never_publishable()
    test_extra_ports_merge_and_dedupe()
    test_unknown_kind_is_refused()
    print("all listener-profile tests passed")
    sys.exit(0)
