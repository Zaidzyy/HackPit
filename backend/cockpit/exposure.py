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
import re
import socket
from pathlib import Path
from dataclasses import dataclass, field

from pydantic import BaseModel, Field, field_validator

from . import config
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

# NOTE ON THE PREDICATE. The question this guard asks is "could the internet reach a listener
# bound here", so the right test is `is_global` — true for exactly the globally routable
# addresses — and NOT `is_private`, which is the obvious choice and is wrong twice over on
# Python 3.14:
#
#   100.101.5.2 (CGNAT — Tailscale, mobile hotspots)  is_private=False, is_global=False
#   203.0.113.9 (RFC 5737 documentation range)        is_private=True,  is_global=False
#
# The first is the one that would have hurt: keying off `is_private` would have called every
# Tailscale address PUBLIC and demanded an acknowledgement to bind it. Measured, not assumed.


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
    return "public" if addr.is_global else "private"


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


# Compose SERVICE names that may publish a port, mapped to the container they become.
#
# `kali-sandbox` is absent and must stay absent: its network is `internal: true`, so publishing
# a port would attach it to a non-internal network and assert_isolation_proven() would then
# refuse EVERY lab command. Exposure and lab isolation are mutually exclusive by construction —
# this is not a policy knob. Locked by test_exposure.test_lab_sandbox_is_never_exposable.
EXPOSABLE: dict[str, str] = {
    "engage-sandbox": config.ENGAGE_SANDBOX_CONTAINER,
    "kali-open": config.KALI_OPEN_CONTAINER,
}


class ListenerProfile(BaseModel):
    """One published-port posture. Inert until rendered, written and applied."""

    ip: str = Field(..., description="Host bind address, or a wildcard token with ack_wildcard.")
    container: str = Field("engage-sandbox", description="engage-sandbox | kali-open.")
    kinds: list[str] = Field(default_factory=list, description="Kinds to derive ports from.")
    extra: list[tuple[int, str]] = Field(default_factory=list, description="Explicit (port, proto).")
    engagement: str | None = Field(None, description="Recorded for audit. Scopes nothing.")
    ack_wildcard: bool = Field(False, description="Acknowledge binding EVERY interface.")
    ack_public: bool = Field(False, description="Acknowledge binding a publicly routable address.")

    @field_validator("extra", mode="before")
    @classmethod
    def _no_ranges(cls, v: list) -> list:
        """Individual ports only.

        A range is how one typo publishes hundreds of ports, and it makes the exposure summary
        unreadable — which defeats the invariant that a reviewer can see the whole surface at a
        glance. `mode="before"` so a string like "4000-4100" is caught here rather than dying in
        pydantic's int coercion with a message that explains nothing.
        """
        out = []
        for port, proto in v or []:
            if isinstance(port, str) and ("-" in port or ":" in port):
                raise ValueError(f"port range {port!r} is not allowed — list ports individually")
            if proto not in ("tcp", "udp"):
                raise ValueError(f"protocol {proto!r} is not tcp or udp")
            out.append((int(port), proto))
        return out


@dataclass
class Validation:
    """What the gates said. Refusals stop the write; warnings do not."""

    refusals: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    needs_ack: list[str] = field(default_factory=list)
    ports: list[tuple[int, str]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.refusals


def validate(profile: ListenerProfile) -> Validation:
    """Run the bind rules. Returns refusals and warnings SEPARATELY.

    Public and wildcard binds are RED-CONFIRMS, not refusals. This codebase's danger gate
    already sets the pattern — "NEVER blocks outright; requires the confirm. Over-inclusive
    assist — human is the gate" — and a broad bind is exactly that shape. Inventing a second,
    stricter pattern here would be inconsistent for no gain, because a wildcard buys real
    things: a binding that survives a VPN or DHCP address change, and a fallback when a
    specific bind misbehaves under Docker Desktop's networking.
    """
    v = Validation()

    if profile.container not in EXPOSABLE:
        if profile.container == "kali-sandbox":
            v.refusals.append(
                "the lab sandbox runs on an isolated network — publishing a port would break "
                "its isolation gate and refuse every lab command; it can never be exposed"
            )
        else:
            v.refusals.append(
                f"unknown container {profile.container!r} — "
                f"exposable: {', '.join(sorted(EXPOSABLE))}"
            )

    kind = classify_ip(profile.ip)
    if kind == "invalid":
        v.refusals.append(f"{profile.ip!r} is not a literal IP address")
    elif kind == "wildcard" and not profile.ack_wildcard:
        v.needs_ack.append("wildcard")
        v.refusals.append(
            f"{profile.ip} binds EVERY interface on this machine, including whatever network "
            "you are on right now — acknowledge with ack_wildcard=true, or name the interface"
        )
    elif kind == "public" and not profile.ack_public:
        v.needs_ack.append("public")
        v.refusals.append(
            f"{profile.ip} is publicly routable — acknowledge with ack_public=true"
        )

    if kind in ("private", "public") and not address_is_live(profile.ip):
        v.warnings.append(
            f"{profile.ip} is not an address on this host right now — `docker compose up` will "
            "fail with 'bind: cannot assign requested address' unless you are on that network "
            "by then"
        )

    try:
        v.ports = derive_ports(profile.kinds, profile.extra)
    except ExposureRefused as exc:
        v.refusals.append(exc.reason)

    if not v.ports and not v.refusals:
        v.refusals.append("a profile with no ports publishes nothing — tick a kind or add a port")

    return v


REPO_ROOT = Path(__file__).resolve().parents[2]
PROFILE_PATH = REPO_ROOT / "docker" / "listener-profile.yml"
DEFAULT_COMPOSE_PATH = REPO_ROOT / "docker" / "docker-compose.yml"

# The marker that makes a broad bind auditable in the file itself. The published-port scanner
# requires one of these covering EVERY wildcard or public binding it finds.
ACK_RE = re.compile(
    r"^#\s*hackpit-ack:\s*(?P<why>wildcard|public)\s+bind=(?P<ip>\S+)\s+engagement=(?P<eng>\S+)"
)

_HEADER = """\
# HackPit — GENERATED listener profile. DO NOT COMMIT.
#
# Written by backend/cockpit/exposure.py. This is the ONE file that publishes a host port;
# `docker compose -f docker/docker-compose.yml up` on its own still exposes nothing.
#
# Apply:     docker compose -f docker/docker-compose.yml -f docker/listener-profile.yml up -d {service}
# Tear down: the same two -f flags plus `down`, or delete this file and recreate the service.
#
# A published port is NOT an open port — the host firewall can still drop inbound. If a
# callback does not land, check that before anything else.
#
# Generated {at} for engagement {eng}.
name: hackpit-cockpit

services:
  {service}:
"""


def render(profile: ListenerProfile, *, at: str) -> str:
    """Profile -> compose override text. PURE: builds a string, touches no disk.

    A wildcard or public bind renders a `hackpit-ack` line above the ports block. That is not
    decoration. test_exposure_safety is a STATIC TEXT SCAN, so without a marker in the file it
    has no way to tell a bind the operator consciously chose from one that slipped through, and
    simply teaching the scanner to accept wildcards would DELETE invariant 3 rather than relax
    it. With the marker, the one small file a reviewer reads states what is exposed AND that it
    was chosen deliberately, by whom and when.
    """
    ports = derive_ports(profile.kinds, profile.extra)
    eng = profile.engagement or "-"
    out = [_HEADER.format(service=profile.container, at=at, eng=eng)]

    kind = classify_ip(profile.ip)
    if kind in ("wildcard", "public"):
        out.append(f"    # hackpit-ack: {kind}  bind={profile.ip}  engagement={eng}  at={at}\n")
    out.append("    ports:\n")
    for port, proto in ports:
        out.append(f'      - "{profile.ip}:{port}:{port}/{proto}"\n')
    return "".join(out)


def compose_command(profile: ListenerProfile) -> list[str]:
    """The exact argv that applies this profile. PURE — builds a list, runs nothing.

    Both `-f` flags, always. Compose merges overrides onto the base file, so omitting the first
    would bring the service up with no image, and omitting the second is the whole exposure
    silently not happening. The same pair is needed on teardown.
    """
    return [
        "docker", "compose",
        "-f", str(DEFAULT_COMPOSE_PATH),
        "-f", str(PROFILE_PATH),
        "up", "-d", profile.container,
    ]


def write(profile: ListenerProfile, *, at: str) -> Path:
    """Validate, render, write. Raises ExposureRefused on any refusal.

    Warnings do NOT stop it — a dead bind address is a warning because Docker already fails
    loudly on one, and refusing would break the real case of writing a profile while off the
    VPN, intending to connect before applying it.
    """
    result = validate(profile)
    if not result.ok:
        raise ExposureRefused("; ".join(result.refusals))
    PROFILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    PROFILE_PATH.write_text(render(profile, at=at), encoding="utf-8")
    return PROFILE_PATH


def clear() -> bool:
    """Remove the profile. True if one was there.

    The CONTAINER keeps its bindings until it is recreated, so this does not close a port on
    its own — observe() reports that state as `drifted`, never as `none`.
    """
    if PROFILE_PATH.exists():
        PROFILE_PATH.unlink()
        return True
    return False
