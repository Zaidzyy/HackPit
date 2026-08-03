"""Listener profiles — WHERE a callback lands (build #13, part 1).

HackPit reaches OUT to anything: the engage sandbox is fully open by decision (Wall A down).
Being reached IN is a different problem. A callback is the target dialling *you*, and for that
to land, a container port must be published on a host address the target can route to. Before
this module exactly one file did that — hand-written, opt-in, and hardcoded to the VMware
VMnet8 address of one laptop.

This module owns that surface end to end: validate -> render -> write -> apply -> observe.

WHAT IT DOES NOT DO. It runs no attack tooling. Its only subprocess calls are `docker inspect`
(read-only) and `docker compose up -d` (approval-gated, because recreating a container kills
every listener, session and background job inside it). It publishes nothing on its own — the
rendered file is inert until it is applied.

THE LAB SANDBOX CAN NEVER BE EXPOSED. Its network is `internal: true`; publishing a port would
attach it to a non-internal network and `assert_isolation_proven()` would then refuse every lab
command. Exposure and lab isolation are mutually exclusive by construction, not by policy.
"""

from __future__ import annotations

import ipaddress
import socket

from .obfuscation import DNS_TUNNEL_PORT
from .sliver import SLIVER_DEFAULT_PORT
from .tunnels import CHISEL_DEFAULT_PORT, LIGOLO_DEFAULT_PORT


class ExposureRefused(RuntimeError):
    """A profile that will not be written or applied. Carries the gate that refused it."""

    def __init__(self, reason: str, gate: str = "exposure") -> None:
        super().__init__(reason)
        self.reason = reason
        self.gate = gate


# The port each listener kind's REMOTE side dials.
#
# IMPORTED, NEVER REPEATED. A profile has to publish the port the listener actually binds, and
# a literal here would drift the moment one of those defaults changed — the same failure the
# shared `server_argv_for` derivation exists to prevent.
#
# Chisel's SOCKS port (1080) is deliberately absent and must stay absent: proxychains reaches
# it from INSIDE the sandbox, so publishing it would widen the exposure surface for nothing.
# Locked by test_exposure.test_chisel_socks_is_never_publishable.
KIND_PORTS: dict[str, tuple[int, str]] = {
    "chisel": (CHISEL_DEFAULT_PORT, "tcp"),
    "ligolo": (LIGOLO_DEFAULT_PORT, "tcp"),
    "dns-tunnel": (DNS_TUNNEL_PORT, "udp"),
    "sliver": (SLIVER_DEFAULT_PORT, "tcp"),
}

# The bindings that mean "every interface on this machine". Same set the published-port scanner
# recognises.
WILDCARD_IPS: frozenset[str] = frozenset({"0.0.0.0", "::", "*"})

# 100.64.0.0/10 — carrier-grade NAT, which is what Tailscale and many mobile hotspots hand out.
# Checked explicitly rather than leaning on `is_private`, whose membership for this range
# changed across Python versions and would make the classification silently version-dependent.
_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def derive_ports(kinds: list[str], extra: list[tuple[int, str]]) -> list[tuple[int, str]]:
    """Ports for a profile: each ticked kind's default, plus explicit extras.

    Ticking a kind is a CONVENIENCE that fills in its port, not a cage. The four known kinds
    omit a plain reverse shell — netcat or pwncat on 443 or 4444, an msfconsole handler — which
    is the commonest callback there is, so `extra` carries whatever else is needed. Sorted and
    de-duplicated so the rendered file is stable for a given profile.
    """
    out: set[tuple[int, str]] = set()
    for kind in kinds:
        if kind not in KIND_PORTS:
            raise ExposureRefused(
                f"unknown listener kind {kind!r} — known kinds: {', '.join(sorted(KIND_PORTS))}"
            )
        out.add(KIND_PORTS[kind])
    for port, proto in extra:
        out.add((int(port), proto))
    return sorted(out)


def classify_ip(ip: str) -> str:
    """"wildcard" | "private" | "public" | "invalid" — what kind of bind address this is."""
    if ip in WILDCARD_IPS:
        return "wildcard"
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid"
    if addr.is_loopback or addr.is_private:
        return "private"
    if addr.version == 4 and addr in _CGNAT:
        return "private"
    return "public"


def address_is_live(ip: str) -> bool:
    """True iff something can bind this address on THIS host, right now.

    Enumerating interfaces portably needs a third-party package, which the hermetic suite
    forbids. Binding a throwaway UDP socket asks the operating system directly and answers the
    thing that actually matters — can a listener bind here — rather than inferring it from an
    interface table. Port 0 lets the OS pick, so nothing is occupied and nothing is disturbed.
    """
    if ip in WILDCARD_IPS:
        return True
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        sock.bind((ip, 0))
        return True
    except OSError:
        return False
    finally:
        sock.close()
