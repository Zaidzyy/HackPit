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
import json
import re
import socket
import subprocess
from pathlib import Path
from typing import Any, Callable
from dataclasses import dataclass, field

from pydantic import BaseModel, Field, field_validator

from . import config
from . import redirector as _redirector
from .listener_ports import (
    CHISEL_DEFAULT_PORT,
    DNS_TUNNEL_PORT,
    LIGOLO_DEFAULT_PORT,
    SLIVER_DEFAULT_PORT,
)


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


# WHERE the ports are published. The field that makes part 4 an extension of this module
# rather than a second one beside it.
#
#   local  — an interface on THIS machine. Everything below behaves exactly as it did before
#            the field existed; the rendered override, the ack markers and the published-port
#            scanner are untouched. Regression-locked, because part 1's invariants may not be
#            softened by part 4.
#   remote — the ports are published on the CONFIGURED VPS (build #13 part 3's config store).
#            There is no local bind address at all, so `ip` is not read: the address is resolved
#            server-side, which is what keeps a remote profile host-locked the same way the
#            deploy is.
#
# The two are not one path with a flag. "Apply" means different operations — a local profile
# recreates a container and never touches SSH; a remote profile ships a file and never touches
# `docker compose` — and the validation rules genuinely differ (see :func:`validate`).
DESTINATIONS = ("local", "remote")


class ListenerProfile(BaseModel):
    """One published-port posture. Inert until rendered, written and applied."""

    ip: str = Field(
        "",
        description="Host bind address (local only). Ignored — and not read — when "
                    "destination='remote'.",
    )
    destination: str = Field("local", description="local (an interface here) | remote (the VPS).")
    container: str = Field("engage-sandbox", description="engage-sandbox | kali-open.")
    kinds: list[str] = Field(default_factory=list, description="Kinds to derive ports from.")
    extra: list[tuple[int, str]] = Field(default_factory=list, description="Explicit (port, proto).")
    engagement: str | None = Field(None, description="Recorded for audit. Scopes nothing.")
    ack_wildcard: bool = Field(False, description="Acknowledge binding EVERY interface.")
    ack_public: bool = Field(False, description="Acknowledge binding a publicly routable address.")

    @field_validator("destination")
    @classmethod
    def _known_destination(cls, v: str) -> str:
        if v not in DESTINATIONS:
            raise ValueError(f"destination must be one of {DESTINATIONS}, got {v!r}")
        return v

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
            # A public port that maps to its own reverse-tunnel port would produce a redirector
            # relaying to itself. `redirector.tunnel_port` refuses it outright; catching it HERE
            # turns that into a 422 naming the port the operator typed, rather than an exception
            # surfacing later from inside command rendering.
            try:
                _redirector.tunnel_port(int(port))
            except ValueError as exc:
                raise ValueError(str(exc)) from exc
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
    if profile.destination == "remote":
        return _validate_remote(profile)

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


def _validate_remote(profile: ListenerProfile) -> Validation:
    """The gates for a REMOTE profile — the ports land on a VPS, not on this machine.

    Deliberately its own function rather than the local rules with exceptions carved out,
    because almost every rule above is about a property a remote destination does not have:

      * **No bind address.** ``ip`` is not read at all. The address comes from the canary
        config store, resolved server-side — the same thing that makes the deploy host-locked.
        A profile that carried its own remote address would put the destination back into a
        request field, which is the mistake part 2 made and part 3 was built not to repeat.
      * **No liveness probe.** "Can something bind this address on this host" is meaningless
        for a port on someone else's machine, and answering it locally would produce a
        confident wrong answer.
      * **The public acknowledgement is UNCONDITIONAL.** Locally, `ack_public` distinguishes a
        deliberate public bind from a private one. There is no private case here: a port on a
        VPS is reachable by anyone who scans that address, always. So the acknowledgement is
        not conditional on classifying an address — there is no address to classify.
      * **No container.** Nothing is published locally, so `container` is not read either.
    """
    v = Validation()

    if not profile.ack_public:
        v.needs_ack.append("public")
        v.refusals.append(
            "a remote profile publishes ports on a PUBLIC address, reachable by anyone who "
            "scans it — not only by the target you are testing — and relays what arrives into "
            "this machine. Acknowledge with ack_public=true"
        )

    try:
        v.ports = derive_ports(profile.kinds, profile.extra)
    except ExposureRefused as exc:
        v.refusals.append(exc.reason)

    if not v.ports and not v.refusals:
        v.refusals.append("a profile with no ports publishes nothing — tick a kind or add a port")

    if profile.ip:
        v.warnings.append(
            f"the bind address {profile.ip!r} is ignored for a remote profile — the ports are "
            f"published on the configured VPS, whose address is resolved server-side"
        )

    return v


def _refuse_remote(profile: ListenerProfile, what: str) -> None:
    """Refuse to run a LOCAL-path operation on a remote profile.

    Every function below this line publishes a port on this machine by writing a compose
    override and recreating a container. None of that is what a remote profile means, and the
    failure of silently doing it anyway would be quiet and wrong in both directions: a compose
    file that publishes on `''`, and an operator believing a VPS is exposed when nothing was
    shipped to it. Refusing at the door keeps the two paths from ever half-mixing.
    """
    if profile.destination == "remote":
        raise ExposureRefused(
            f"a remote profile cannot be {what} — it publishes on the configured VPS, not on "
            f"this machine. Deploy it through the gated redirector path instead.",
            gate="destination",
        )


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
    _refuse_remote(profile, "rendered as a compose override")
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
    _refuse_remote(profile, "applied with docker compose")
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
    _refuse_remote(profile, "written as a compose override")
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


_PORTS_FMT = "{{json .NetworkSettings.Ports}}"


def _docker_ports(container: str) -> tuple[int, str, str]:
    try:
        p = subprocess.run(
            ["docker", "inspect", "-f", _PORTS_FMT, container],
            capture_output=True, text=True, timeout=10.0,
        )
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except FileNotFoundError:
        return 127, "", "docker CLI not found on PATH"
    except subprocess.TimeoutExpired:
        return 124, "", "docker inspect timed out"


def observe(
    profile: "ListenerProfile | None" = None,
    *,
    runner: "Callable[[list[str]], tuple[int, str, str]] | None" = None,
) -> dict[str, Any]:
    """What is ACTUALLY published, compared against what the profile asked for.

    Never reports a state it has not looked at — the rule lifecycle.py exists to enforce,
    applied to exposure instead of listener liveness. `status="listening"` assigned at Popen
    time was false for two of three binaries; `state="active"` assigned at write time would be
    false for every profile until the container is recreated. So: a container publishing
    something other than the profile is `drifted`, never `active`, and docker being unavailable
    is `unknown`, never `active`.
    """
    if profile is None:
        return {"state": "none", "published": {}, "expected": [], "note": "no profile written"}

    if profile.destination == "remote":
        # The same rule this function exists to enforce, applied to itself: never report a
        # state you have not looked at. `docker inspect` says nothing whatsoever about a
        # process on someone else's machine, and running it here would return "pending-restart"
        # for a redirector that is up, or "active" for one that is not.
        return {
            "state": "remote", "published": {},
            "expected": derive_ports(profile.kinds, profile.extra),
            "note": "published on the configured VPS — local docker inspect cannot observe it; "
                    "use the redirector's own status",
        }

    container = EXPOSABLE.get(profile.container, profile.container)
    call = runner or (lambda _argv: _docker_ports(container))
    rc, out, err = call(["docker", "inspect", "-f", _PORTS_FMT, container])
    if rc != 0:
        return {"state": "unknown", "published": {}, "expected": [],
                "note": err or f"docker inspect failed (rc {rc})"}

    try:
        published = json.loads(out or "{}") or {}
    except json.JSONDecodeError:
        return {"state": "unknown", "published": {}, "expected": [],
                "note": "could not parse docker inspect output"}

    expected = derive_ports(profile.kinds, profile.extra)
    want = {f"{port}/{proto}": (profile.ip, str(port)) for port, proto in expected}

    seen: dict[str, Any] = {}
    for key, bindings in published.items():
        for b in bindings or []:
            seen[key] = (b.get("HostIp"), b.get("HostPort"))

    if not seen:
        return {"state": "pending-restart", "published": {}, "expected": expected,
                "note": "profile written; recreate the container to apply it"}

    if len(seen) == len(want) and all(seen.get(k) == v for k, v in want.items()):
        return {
            "state": "active", "published": seen, "expected": expected,
            "note": "a published port is NOT an open port — if a callback does not land, "
                    "check the host firewall before anything else",
        }

    return {"state": "drifted", "published": seen, "expected": expected,
            "note": "the container publishes something other than this profile — recreate it"}


def _run(argv: list[str]) -> tuple[int, str, str]:
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=180.0)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except FileNotFoundError:
        return 127, "", "docker CLI not found on PATH"
    except subprocess.TimeoutExpired:
        return 124, "", "docker compose timed out"


def apply(
    profile: ListenerProfile,
    *,
    approved: bool,
    runner: "Callable[[list[str]], tuple[int, str, str]] | None" = None,
) -> dict[str, Any]:
    """Recreate the service so the profile takes effect. REQUIRES approval.

    A published port can only be set when a container is CREATED, so applying a profile
    recreates the service — which kills every listener, session and background job inside it.
    That is destructive to work in flight, so the operator is told before it happens rather
    than after. Same reason every other destructive action here carries a gate.

    A non-zero compose exit is raised with its real stderr rather than swallowed: the commonest
    failure is `bind: cannot assign requested address`, which names precisely what is wrong
    (the bind address is not on this host right now) and would be useless as "apply failed".
    """
    if not approved:
        raise ExposureRefused(
            "applying a listener profile recreates the container and kills every listener, "
            "session and background job inside it — set approved=true",
            gate="approval",
        )
    argv = compose_command(profile)
    call = runner or _run
    rc, out, err = call(argv)
    if rc != 0:
        raise ExposureRefused(f"compose failed (rc {rc}): {err or out}", gate="compose")
    return {"applied": True, "command": argv}


PRESETS: dict[str, ListenerProfile] = {
    # Build #10's hand-written case, expressed as a profile. The lab DC's subnet can reach
    # exactly one address on this machine — the VMware VMnet8 host adapter — and a DNS tunnel
    # needs exactly one port. Locked against the original by test_exposure, so the
    # generalisation stays provably faithful to the file it replaced.
    "vmnet8-dns": ListenerProfile(
        ip="192.168.13.1", container="engage-sandbox", kinds=["dns-tunnel"],
    ),
}

# --------------------------------------------------------------------------- #
# Remote profile persistence
# --------------------------------------------------------------------------- #
# A remote profile is not a compose override, so it cannot live in one. It gets its own
# gitignored file for the same reason the local one does: the FILE is the source of truth, it
# survives a backend restart, and a hand-edit is visible instead of masked by cached state.
#
# JSON rather than YAML because nothing consumes it but this module — there is no second tool
# on the other end whose format it has to match, which is the only reason the local one is YAML.
REMOTE_PROFILE_PATH = REPO_ROOT / "docker" / "redirector-profile.json"


def write_remote(profile: ListenerProfile, *, at: str) -> Path:
    """Validate and persist a remote profile. Raises ExposureRefused on any refusal.

    Writing it publishes NOTHING — exactly like the local path, where the rendered override is
    inert until it is applied. Nothing reaches the VPS until the gated deploy runs.
    """
    if profile.destination != "remote":
        raise ExposureRefused(
            "write_remote() takes a remote profile — a local one belongs in the compose override",
            gate="destination",
        )
    result = validate(profile)
    if not result.ok:
        raise ExposureRefused("; ".join(result.refusals), gate="exposure")
    REMOTE_PROFILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    REMOTE_PROFILE_PATH.write_text(
        json.dumps(
            {
                "_comment": "HackPit — GENERATED redirector profile. DO NOT COMMIT. "
                            "Writing this publishes nothing; the gated deploy does.",
                "at": at,
                "profile": profile.model_dump(),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return REMOTE_PROFILE_PATH


def live_remote_profile() -> "ListenerProfile | None":
    """The remote profile currently on disk, or None. Read back, never cached."""
    if not REMOTE_PROFILE_PATH.exists():
        return None
    try:
        raw = json.loads(REMOTE_PROFILE_PATH.read_text(encoding="utf-8"))
        return ListenerProfile(**raw["profile"])
    except (ValueError, KeyError, TypeError):
        # A hand-mangled file reads as "no profile" rather than crashing the panel that exists
        # to show what is exposed. It is visible as absent, which is the safe direction.
        return None


def clear_remote() -> bool:
    """Forget the remote profile. True if one was there.

    Removes HackPit's record of it. It does NOT stop a redirector already running on the VPS —
    the panel says so, because a delete that read as "the listener is down" would leave a
    public forwarder nobody is watching.
    """
    if REMOTE_PROFILE_PATH.exists():
        REMOTE_PROFILE_PATH.unlink()
        return True
    return False


_PORT_LINE = re.compile(
    r'^-\s*"(?P<ip>[^:]+):(?P<host>\d+):(?P<cont>\d+)/(?P<proto>tcp|udp)"$'
)


def live_profile() -> "ListenerProfile | None":
    """The profile currently on disk, reconstructed from the rendered file, or None.

    Read back rather than cached in memory: the file is the source of truth, it survives a
    backend restart, and a hand-edit is then visible instead of being masked by stale state.
    Ports come back as `extra` because the rendering is lossy about WHICH kind asked for a
    port — that only matters for the UI's tick-boxes, never for what is published.
    """
    if not PROFILE_PATH.exists():
        return None
    service = ""
    ip = ""
    extra: list[tuple[int, str]] = []
    for raw in PROFILE_PATH.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        m = _PORT_LINE.match(line)
        if m:
            ip = m.group("ip")
            extra.append((int(m.group("cont")), m.group("proto")))
        elif line.endswith(":") and line[:-1] in EXPOSABLE:
            service = line[:-1]
    if not ip or not service:
        return None
    kind = classify_ip(ip)
    return ListenerProfile(
        ip=ip, container=service, kinds=[], extra=extra,
        ack_wildcard=kind == "wildcard", ack_public=kind == "public",
    )
