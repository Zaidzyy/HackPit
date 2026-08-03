# Listener Profiles Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make "where does a callback land" a configurable, validated, observed property instead of one hand-written file hardcoded to one laptop's VMnet8 address.

**Architecture:** One new module, `backend/cockpit/exposure.py`, peer to `lifecycle.py`, owning the whole feature: validate → render → write → apply → observe. It renders a compose override that publishes exactly the ports the operator asked for, bound to an address they chose. The existing static published-port scanner keeps enforcing the invariants, extended with a `hackpit-ack` rule so a *deliberate* wildcard or public bind is distinguishable from one that slipped through.

**Tech Stack:** Python 3.14, FastAPI, pydantic v2, stdlib `ipaddress` + `socket`, Docker CLI (`docker inspect`, `docker compose`). No new third-party dependency.

## Global Constraints

- **No new third-party dependency.** The hermetic suite installs only `fastapi httpx pydantic pyyaml numpy`. Anything needing more is out.
- **Tests are plain scripts, not pytest.** Each file defines `test_*()` functions, prints a `  <description>: PASS` line per check, and ends with an `if __name__ == "__main__":` block calling them in order then `sys.exit(0)`. They run as `"$PY" test_file.py` from `backend/`.
- **Every test file must be added to `backend/run_safety_tests.sh`** with its own `run_test` line, or it never runs.
- **The lab sandbox is never exposable.** Structural, not policy — publishing to it breaks `assert_isolation_proven()`.
- **Chisel's SOCKS port 1080 is never publishable.** Proxychains reaches it from inside the sandbox.
- **Ports are individual. Ranges are refused.**
- **The generated file is never committed.**
- Commit messages end with: `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`. Branch: `main`.

## File Structure

| File | Responsibility |
|---|---|
| `backend/cockpit/exposure.py` | **Create.** The whole feature: model, classification, validation, render, write, apply, observe. |
| `backend/cockpit/obfuscation.py` | **Modify.** Name the DNS tunnel port as a constant so `exposure` imports it rather than repeating `53`. |
| `backend/cockpit/router.py` | **Modify.** Four endpoints. |
| `backend/test_exposure.py` | **Create.** The feature's own regression file. |
| `backend/test_exposure_safety.py` | **Modify.** Retarget invariant 2 at the generated file; add the `hackpit-ack` rule + its positive control. |
| `backend/test_support/c2-lab.golden.yml` | **Create** (moved from `docker/proof/c2-lab.yml`). Equivalence fixture. |
| `docker/proof/c2-lab.yml` | **Delete.** Replaced by the `vmnet8-dns` preset. |
| `docker/proof/c2_lab_proof.sh` | **Modify.** Generate the profile before bringing the stack up. |
| `.gitignore` | **Modify.** Ignore `docker/listener-profile.yml`. |
| `backend/run_safety_tests.sh` | **Modify.** Add `test_exposure.py`. |

---

### Task 1: Port derivation from listener kinds

**Files:**
- Create: `backend/cockpit/exposure.py`
- Modify: `backend/cockpit/obfuscation.py` (add `DNS_TUNNEL_PORT = 53` near the top-level constants)
- Test: `backend/test_exposure.py`

**Interfaces:**
- Consumes: `tunnels.CHISEL_DEFAULT_PORT`, `tunnels.LIGOLO_DEFAULT_PORT`, `sliver.SLIVER_DEFAULT_PORT`, `obfuscation.DNS_TUNNEL_PORT`
- Produces: `KIND_PORTS: dict[str, tuple[int, str]]`, `derive_ports(kinds: list[str], extra: list[tuple[int, str]]) -> list[tuple[int, str]]`, `ExposureRefused(reason, gate)`

Ports are **imported, never repeated**, so a change to a listener's default follows into the profile automatically. That is the same drift lock `server_argv_for` uses.

- [ ] **Step 1: Write the failing test**

```python
"""backend/test_exposure.py — listener profile regressions (build #13)."""
from __future__ import annotations

import sys

from cockpit import exposure


def test_ports_derive_from_kinds() -> None:
    assert exposure.derive_ports(["dns-tunnel"], []) == [(53, "udp")]
    assert exposure.derive_ports(["sliver", "dns-tunnel"], []) == [(53, "udp"), (31337, "tcp")]
    print("  ports derive from ticked kinds: PASS")


def test_chisel_socks_is_never_publishable() -> None:
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
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `cd backend && .venv/Scripts/python.exe test_exposure.py`
Expected: `ModuleNotFoundError: No module named 'cockpit.exposure'`

- [ ] **Step 3: Name the DNS port**

In `backend/cockpit/obfuscation.py`, beside the other module constants, add:

```python
# The port a DNS tunnel server binds. Named so cockpit/exposure.py imports it rather than
# repeating the literal — a profile must publish the port the listener actually uses.
DNS_TUNNEL_PORT = 53
```

Then replace the two `port=53` literals in the `observe(...)` calls with `port=DNS_TUNNEL_PORT`.

- [ ] **Step 4: Write the minimal implementation**

```python
"""Listener profiles — WHERE a callback lands (build #13, part 1).

HackPit reaches OUT to anything (Wall A is down). Being reached IN needs a container port
published on a host address the target can route to. Before this module, exactly one
hand-written file did that, hardcoded to one laptop's VMware VMnet8 address.

This module owns that surface end to end: validate -> render -> write -> apply -> observe.
It runs NO attack tooling; its only subprocess calls are `docker inspect` (read) and
`docker compose up -d` (apply, approval-gated).
"""
from __future__ import annotations

from .obfuscation import DNS_TUNNEL_PORT
from .sliver import SLIVER_DEFAULT_PORT
from .tunnels import CHISEL_DEFAULT_PORT, LIGOLO_DEFAULT_PORT


class ExposureRefused(RuntimeError):
    """A profile that will not be written. Carries the gate that refused it."""

    def __init__(self, reason: str, gate: str = "exposure") -> None:
        super().__init__(reason)
        self.reason = reason
        self.gate = gate


# The port each listener kind's REMOTE side dials. Imported, never repeated, so a change to a
# listener default follows into the profile instead of silently disagreeing with it.
#
# Chisel's SOCKS port (1080) is deliberately absent: proxychains reaches it from INSIDE the
# sandbox, so publishing it would widen the surface for nothing. Locked by test_exposure.
KIND_PORTS: dict[str, tuple[int, str]] = {
    "chisel": (CHISEL_DEFAULT_PORT, "tcp"),
    "ligolo": (LIGOLO_DEFAULT_PORT, "tcp"),
    "dns-tunnel": (DNS_TUNNEL_PORT, "udp"),
    "sliver": (SLIVER_DEFAULT_PORT, "tcp"),
}


def derive_ports(kinds: list[str], extra: list[tuple[int, str]]) -> list[tuple[int, str]]:
    """Ports for a profile: each ticked kind's default, plus explicit extras.

    Ticking a kind is a CONVENIENCE that fills in its port, not a restriction — the four kinds
    omit a plain reverse shell, which is the commonest callback there is, so `extra` carries
    whatever else the operator needs. Sorted and de-duplicated so the rendered file is stable.
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
```

- [ ] **Step 5: Run the tests and confirm they pass**

Run: `cd backend && .venv/Scripts/python.exe test_exposure.py`
Expected: four PASS lines, then `all listener-profile tests passed`

- [ ] **Step 6: Commit**

```bash
git add backend/cockpit/exposure.py backend/cockpit/obfuscation.py backend/test_exposure.py
git commit -m "exposure: derive publishable ports from listener kinds"
```

---

### Task 2: Bind-address classification and liveness

**Files:**
- Modify: `backend/cockpit/exposure.py`
- Test: `backend/test_exposure.py`

**Interfaces:**
- Produces: `WILDCARD_IPS: frozenset[str]`, `classify_ip(ip: str) -> str` returning `"wildcard" | "private" | "public" | "invalid"`, `address_is_live(ip: str) -> bool`

- [ ] **Step 1: Write the failing tests**

Add to `backend/test_exposure.py`:

```python
def test_ip_classification() -> None:
    assert exposure.classify_ip("192.168.13.1") == "private"
    assert exposure.classify_ip("10.10.14.7") == "private"
    assert exposure.classify_ip("100.101.5.2") == "private"   # CGNAT / Tailscale
    assert exposure.classify_ip("127.0.0.1") == "private"
    assert exposure.classify_ip("203.0.113.9") == "public"
    assert exposure.classify_ip("0.0.0.0") == "wildcard"
    assert exposure.classify_ip("::") == "wildcard"
    assert exposure.classify_ip("*") == "wildcard"
    assert exposure.classify_ip("hackpit-lab-target") == "invalid"
    assert exposure.classify_ip("10.10.14.300") == "invalid"
    print("  bind addresses classify private / public / wildcard / invalid: PASS")


def test_liveness_probe() -> None:
    # Loopback always exists; TEST-NET-3 never does.
    assert exposure.address_is_live("127.0.0.1") is True
    assert exposure.address_is_live("203.0.113.9") is False
    # A wildcard binds everything, so liveness is vacuously true.
    assert exposure.address_is_live("0.0.0.0") is True
    print("  the bind probe reports which addresses exist on this host: PASS")
```

and register both in `__main__`.

- [ ] **Step 2: Run and confirm failure**

Run: `cd backend && .venv/Scripts/python.exe test_exposure.py`
Expected: `AttributeError: module 'cockpit.exposure' has no attribute 'classify_ip'`

- [ ] **Step 3: Implement**

Append to `backend/cockpit/exposure.py`:

```python
import ipaddress
import socket

# The bindings that mean "every interface on this machine". Same set the published-port
# scanner recognises; kept in sync by test_exposure_safety.
WILDCARD_IPS: frozenset[str] = frozenset({"0.0.0.0", "::", "*"})

# 100.64.0.0/10 — carrier-grade NAT, which is what Tailscale and many mobile hotspots hand
# out. Checked explicitly rather than relying on `is_private`, whose membership for this
# range changed across Python versions.
_CGNAT = ipaddress.ip_network("100.64.0.0/10")


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
    forbids. Binding a throwaway UDP socket asks the operating system the question directly
    and answers the thing that actually matters — can a listener bind here — rather than
    inferring it from an interface table. Port 0 lets the OS pick, so nothing is occupied.
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
```

- [ ] **Step 4: Run and confirm pass**

Run: `cd backend && .venv/Scripts/python.exe test_exposure.py`
Expected: six PASS lines.

- [ ] **Step 5: Commit**

```bash
git add backend/cockpit/exposure.py backend/test_exposure.py
git commit -m "exposure: classify bind addresses and probe liveness without a new dependency"
```

---

### Task 3: The profile model and validation

**Files:**
- Modify: `backend/cockpit/exposure.py`
- Test: `backend/test_exposure.py`

**Interfaces:**
- Produces: `EXPOSABLE: dict[str, str]`, `ListenerProfile` (pydantic), `Validation` dataclass with `.refusals: list[str]`, `.warnings: list[str]`, `.needs_ack: list[str]`, `validate(profile) -> Validation`

- [ ] **Step 1: Write the failing tests**

Add to `backend/test_exposure.py`:

```python
def _profile(**kw):
    base = dict(ip="192.168.13.1", container="engage-sandbox", kinds=["dns-tunnel"],
                extra=[], engagement=None, ack_wildcard=False, ack_public=False)
    base.update(kw)
    return exposure.ListenerProfile(**base)


def test_private_live_address_needs_no_ack() -> None:
    v = exposure.validate(_profile(ip="127.0.0.1"))
    assert v.refusals == [], v.refusals
    assert v.needs_ack == [], v.needs_ack
    print("  a private, live address needs no acknowledgement: PASS")


def test_wildcard_needs_ack_both_directions() -> None:
    without = exposure.validate(_profile(ip="0.0.0.0"))
    assert any("wildcard" in r for r in without.refusals), without.refusals
    with_ack = exposure.validate(_profile(ip="0.0.0.0", ack_wildcard=True))
    assert with_ack.refusals == [], with_ack.refusals
    print("  a wildcard bind is refused without the ack and permitted with it: PASS")


def test_public_needs_ack_both_directions() -> None:
    without = exposure.validate(_profile(ip="203.0.113.9"))
    assert any("public" in r for r in without.refusals), without.refusals
    with_ack = exposure.validate(_profile(ip="203.0.113.9", ack_public=True))
    assert with_ack.refusals == [], with_ack.refusals
    print("  a public bind is refused without the ack and permitted with it: PASS")


def test_dead_address_warns_but_does_not_refuse() -> None:
    v = exposure.validate(_profile(ip="203.0.113.9", ack_public=True))
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
```

Register all six in `__main__`.

- [ ] **Step 2: Run and confirm failure**

Run: `cd backend && .venv/Scripts/python.exe test_exposure.py`
Expected: `AttributeError: module 'cockpit.exposure' has no attribute 'ListenerProfile'`

- [ ] **Step 3: Implement**

Append to `backend/cockpit/exposure.py`:

```python
from dataclasses import dataclass, field

from pydantic import BaseModel, Field, field_validator

from . import config

# Compose SERVICE names that may publish a port, mapped to the container they become.
#
# `kali-sandbox` is absent and must stay absent: its network is `internal: true`, so
# publishing a port would attach it to a non-internal network and assert_isolation_proven()
# would then refuse EVERY lab command. Exposure and lab isolation are mutually exclusive by
# construction — this is not a policy knob. Locked by test_exposure.
EXPOSABLE: dict[str, str] = {
    "engage-sandbox": config.ENGAGE_SANDBOX_CONTAINER,
    "kali-open": config.KALI_OPEN_CONTAINER,
}


class ListenerProfile(BaseModel):
    """One published-port posture. Inert until rendered, written and applied."""

    ip: str = Field(..., description="Host bind address, or a wildcard token with ack_wildcard.")
    container: str = Field("engage-sandbox", description="engage-sandbox | kali-open.")
    kinds: list[str] = Field(default_factory=list, description="Listener kinds to derive ports from.")
    extra: list[tuple[int, str]] = Field(default_factory=list, description="Explicit (port, proto).")
    engagement: str | None = Field(None, description="Recorded for audit. Scopes nothing.")
    ack_wildcard: bool = Field(False, description="Acknowledge binding EVERY interface.")
    ack_public: bool = Field(False, description="Acknowledge binding a publicly routable address.")

    @field_validator("extra")
    @classmethod
    def _no_ranges(cls, v: list[tuple[int, str]]) -> list[tuple[int, str]]:
        """Individual ports only. A range is how one typo publishes hundreds of ports, and it
        makes the exposure summary unreadable — which defeats the invariant that a reviewer can
        see the whole surface at a glance."""
        for port, proto in v:
            if isinstance(port, str) and ("-" in port or ":" in port):
                raise ValueError(f"port range {port!r} is not allowed — list ports individually")
            if proto not in ("tcp", "udp"):
                raise ValueError(f"protocol {proto!r} is not tcp or udp")
        return [(int(p), proto) for p, proto in v]


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

    Public and wildcard binds are RED-CONFIRMS, not refusals: this codebase's danger gate
    "NEVER blocks outright; requires the confirm — over-inclusive assist, human is the gate",
    and binding a broad address is exactly that shape. Inventing a second, stricter pattern
    here would be inconsistent for no gain, since a wildcard buys real things (a binding that
    survives a VPN or DHCP address change, and a fallback when a specific bind misbehaves
    under Docker Desktop's networking).
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
                f"unknown container {profile.container!r} — exposable: {', '.join(sorted(EXPOSABLE))}"
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
```

- [ ] **Step 4: Run and confirm pass**

Run: `cd backend && .venv/Scripts/python.exe test_exposure.py`
Expected: twelve PASS lines.

- [ ] **Step 5: Commit**

```bash
git add backend/cockpit/exposure.py backend/test_exposure.py
git commit -m "exposure: the profile model and its bind gates"
```

---

### Task 4: Render, including the acknowledgement line

**Files:**
- Modify: `backend/cockpit/exposure.py`
- Test: `backend/test_exposure.py`

**Interfaces:**
- Produces: `PROFILE_PATH: Path`, `ACK_RE: re.Pattern`, `render(profile: ListenerProfile, *, at: str) -> str`

The acknowledgement is rendered **into the file** because the scanner is a static text scan and otherwise cannot tell a deliberate wildcard from one that slipped through.

- [ ] **Step 1: Write the failing tests**

Add to `backend/test_exposure.py`:

```python
_AT = "2026-08-03T09:12:04Z"


def test_render_publishes_exactly_the_derived_ports() -> None:
    text = exposure.render(_profile(ip="10.10.14.7", kinds=["dns-tunnel", "sliver"]), at=_AT)
    assert '"10.10.14.7:53:53/udp"' in text, text
    assert '"10.10.14.7:31337:31337/tcp"' in text, text
    assert "engage-sandbox:" in text
    assert text.count('- "') == 2, text
    print("  render publishes exactly the derived ports: PASS")


def test_ack_line_is_rendered_only_when_needed() -> None:
    plain = exposure.render(_profile(ip="10.10.14.7"), at=_AT)
    assert "hackpit-ack" not in plain, plain
    wild = exposure.render(
        _profile(ip="0.0.0.0", ack_wildcard=True, engagement="e-4417"), at=_AT)
    assert "# hackpit-ack: wildcard  bind=0.0.0.0  engagement=e-4417" in wild, wild
    pub = exposure.render(_profile(ip="203.0.113.9", ack_public=True), at=_AT)
    assert "# hackpit-ack: public  bind=203.0.113.9  engagement=-" in pub, pub
    print("  the ack line is rendered only for a wildcard or public bind: PASS")


def test_render_is_deterministic() -> None:
    p = _profile(ip="10.10.14.7", kinds=["sliver", "dns-tunnel"])
    assert exposure.render(p, at=_AT) == exposure.render(p, at=_AT)
    print("  render is deterministic for a given profile and timestamp: PASS")
```

Register the three in `__main__`.

- [ ] **Step 2: Run and confirm failure**

Expected: `AttributeError: module 'cockpit.exposure' has no attribute 'render'`

- [ ] **Step 3: Implement**

Append to `backend/cockpit/exposure.py`:

```python
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PROFILE_PATH = REPO_ROOT / "docker" / "listener-profile.yml"
DEFAULT_COMPOSE_PATH = REPO_ROOT / "docker" / "docker-compose.yml"

# The marker that makes a broad bind auditable in the file itself. The scanner requires one
# of these covering EVERY wildcard or public binding it finds.
ACK_RE = re.compile(
    r"^#\s*hackpit-ack:\s*(?P<why>wildcard|public)\s+bind=(?P<ip>\S+)\s+engagement=(?P<eng>\S+)"
)

_HEADER = """\
# HackPit — GENERATED listener profile. DO NOT COMMIT.
#
# Written by backend/cockpit/exposure.py. This is the ONE file that publishes a host port;
# `docker compose -f docker/docker-compose.yml up` on its own still exposes nothing.
#
# Apply:    docker compose -f docker/docker-compose.yml -f docker/listener-profile.yml up -d {service}
# Tear down: the same two -f flags plus `down`, or delete this file and recreate the service.
#
# Generated {at} for engagement {eng}.
name: hackpit-cockpit

services:
  {service}:
"""


def render(profile: ListenerProfile, *, at: str) -> str:
    """Profile -> compose override text. PURE: builds a string, touches no disk.

    A wildcard or public bind renders a `hackpit-ack` line above the ports block. That is not
    decoration: test_exposure_safety is a static text scan, so without a marker in the file it
    has no way to tell a bind the operator consciously chose from one that slipped through.
    Simply teaching the scanner to accept wildcards would delete invariant 3 rather than relax
    it. With the marker, the one small file a reviewer reads states what is exposed AND that
    it was chosen deliberately, by whom and when.
    """
    ports = derive_ports(profile.kinds, profile.extra)
    eng = profile.engagement or "-"
    out = [_HEADER.format(service=profile.container, at=at, eng=eng)]

    kind = classify_ip(profile.ip)
    if kind in ("wildcard", "public"):
        out.append(
            f"    # hackpit-ack: {kind}  bind={profile.ip}  engagement={eng}  at={at}\n"
        )
    out.append("    ports:\n")
    for port, proto in ports:
        out.append(f'      - "{profile.ip}:{port}:{port}/{proto}"\n')
    return "".join(out)
```

- [ ] **Step 4: Run and confirm pass**

Expected: fifteen PASS lines.

- [ ] **Step 5: Commit**

```bash
git add backend/cockpit/exposure.py backend/test_exposure.py
git commit -m "exposure: render the override, with the ack written into the file"
```

---

### Task 5: The scanner learns the ack rule

**Files:**
- Modify: `backend/test_exposure_safety.py`
- Test: same file (it is both the guard and its own regression file)

**Interfaces:**
- Consumes: `published_ports(path)`, `_WILDCARD_IPS`, `_IP_BOUND` (all already in the file)
- Produces: `acks(path) -> list[tuple[str, str]]` returning `(why, ip)` pairs; `unacknowledged_broad_binds(path) -> list[tuple[int, str]]`

- [ ] **Step 1: Write the failing tests**

Add to `backend/test_exposure_safety.py`:

```python
def test_ack_marker_covers_a_wildcard_binding() -> None:
    """The four cases invariant 3 now rests on."""
    import tempfile

    def probe(text: str) -> list[tuple[int, str]]:
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "listener-profile.yml"
            p.write_text(text, encoding="utf-8")
            return unacknowledged_broad_binds(p)

    covered = (
        "services:\n  engage-sandbox:\n"
        "    # hackpit-ack: wildcard  bind=0.0.0.0  engagement=e-1  at=t\n"
        '    ports:\n      - "0.0.0.0:4444:4444/tcp"\n'
    )
    assert probe(covered) == [], probe(covered)

    missing = (
        "services:\n  engage-sandbox:\n"
        '    ports:\n      - "0.0.0.0:4444:4444/tcp"\n'
    )
    assert probe(missing), "an unacknowledged wildcard must fail"

    wrong_ip = (
        "services:\n  engage-sandbox:\n"
        "    # hackpit-ack: wildcard  bind=10.0.0.1  engagement=e-1  at=t\n"
        '    ports:\n      - "0.0.0.0:4444:4444/tcp"\n'
    )
    assert probe(wrong_ip), "an ack naming a different address must not cover this bind"

    public_covered = (
        "services:\n  engage-sandbox:\n"
        "    # hackpit-ack: public  bind=203.0.113.9  engagement=e-1  at=t\n"
        '    ports:\n      - "203.0.113.9:443:443/tcp"\n'
    )
    assert probe(public_covered) == [], probe(public_covered)

    print("  a broad bind must be covered by an ack naming that exact address: PASS")
```

Register it in `__main__` **before** the other tests, alongside the existing scanner control.

- [ ] **Step 2: Run and confirm failure**

Run: `cd backend && .venv/Scripts/python.exe test_exposure_safety.py`
Expected: `NameError: name 'unacknowledged_broad_binds' is not defined`

- [ ] **Step 3: Implement**

Add to `backend/test_exposure_safety.py`, below `published_ports`:

```python
# The marker that makes a deliberate broad bind auditable. Kept textually in step with
# cockpit/exposure.ACK_RE — both read the same line out of the same generated file.
_ACK = re.compile(
    r"^#\s*hackpit-ack:\s*(?P<why>wildcard|public)\s+bind=(?P<ip>\S+)\s+engagement=(?P<eng>\S+)"
)

# Addresses that are neither wildcard nor obviously private need the `public` ack. Private
# ranges are read from the literal quad rather than imported, so this file keeps its promise
# of depending on nothing outside the standard library.
_PRIVATE_PREFIXES = ("10.", "127.", "192.168.", "169.254.")


def _is_private_quad(ip: str) -> bool:
    if ip.startswith(_PRIVATE_PREFIXES):
        return True
    parts = ip.split(".")
    if len(parts) != 4 or not all(p.isdigit() for p in parts):
        return False
    first, second = int(parts[0]), int(parts[1])
    if first == 172 and 16 <= second <= 31:
        return True
    if first == 100 and 64 <= second <= 127:  # CGNAT / Tailscale
        return True
    return False


def acks(path: Path) -> list[tuple[str, str]]:
    """Every `hackpit-ack` marker in the file, as (why, bind_ip)."""
    if not path.exists():
        return []
    out = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        m = _ACK.match(raw.strip())
        if m:
            out.append((m.group("why"), m.group("ip")))
    return out


def unacknowledged_broad_binds(path: Path) -> list[tuple[int, str]]:
    """Published bindings that are wildcard or public and NOT covered by a matching ack.

    Build #10's invariant 3 refused every wildcard outright. Build #13 permits one behind an
    explicit acknowledgement — so the rule becomes "covered", not "absent". The ack must name
    the EXACT address published; a marker for some other address covers nothing.
    """
    acked = {ip for _why, ip in acks(path)}
    bad: list[tuple[int, str]] = []
    for lineno, entry in published_ports(path):
        m = _IP_BOUND.match(entry)
        ip = m.group("ip") if m else entry.split(":")[0]
        broad = (ip in _WILDCARD_IPS) or (m is not None and not _is_private_quad(ip))
        if not m and ip not in _WILDCARD_IPS:
            bad.append((lineno, entry))       # not IP-bound at all — invariant 3, unchanged
        elif broad and ip not in acked:
            bad.append((lineno, entry))
    return bad
```

- [ ] **Step 4: Run and confirm pass**

Run: `cd backend && .venv/Scripts/python.exe test_exposure_safety.py`
Expected: all existing PASS lines plus the new one.

- [ ] **Step 5: Retarget invariant 2 at the generated file**

Replace the module-level `EXPOSURE_OVERRIDE` constant and the body of
`test_exposure_override_is_ip_bound` so it reads the **generated** path when it exists and the
golden fixture otherwise:

```python
GENERATED_PROFILE = REPO / "docker" / "listener-profile.yml"
GOLDEN = REPO / "backend" / "test_support" / "c2-lab.golden.yml"
```

and inside the test, iterate `[p for p in (GENERATED_PROFILE, GOLDEN) if p.exists()]`, asserting
`unacknowledged_broad_binds(p) == []` for each. A checkout with no profile generated still
exercises the rule against the golden, so the check is never vacuous.

- [ ] **Step 6: Run, then commit**

```bash
cd backend && .venv/Scripts/python.exe test_exposure_safety.py
git add backend/test_exposure_safety.py
git commit -m "exposure: the scanner requires an ack covering every broad bind"
```

---

### Task 6: Write, gitignore, and audit

**Files:**
- Modify: `backend/cockpit/exposure.py`, `.gitignore`
- Test: `backend/test_exposure.py`

**Interfaces:**
- Produces: `write(profile: ListenerProfile, *, at: str) -> Path`, `clear() -> bool`, `compose_command(profile) -> list[str]`

- [ ] **Step 1: Write the failing tests**

```python
def test_generated_profile_is_gitignored() -> None:
    """The first profile generated on a client engagement holds THEIR internal address, and
    this repository is public."""
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
    assert "docker-compose.yml" in " ".join(argv)
    assert "listener-profile.yml" in " ".join(argv)
    assert argv[-3:] == ["up", "-d", "engage-sandbox"], argv
    print("  the compose command names both files and the one service: PASS")
```

- [ ] **Step 2: Run and confirm failure** — `AttributeError: ... 'compose_command'`

- [ ] **Step 3: Add the gitignore entry**

Append to `.gitignore`:

```
# Generated listener profile (build #13). Operator-local machine state, and on a client
# engagement it holds THEIR internal address — this repository is public.
docker/listener-profile.yml
```

- [ ] **Step 4: Implement**

```python
def compose_command(profile: ListenerProfile) -> list[str]:
    """The exact argv that applies this profile. PURE — builds a list, runs nothing."""
    return [
        "docker", "compose",
        "-f", str(DEFAULT_COMPOSE_PATH),
        "-f", str(PROFILE_PATH),
        "up", "-d", profile.container,
    ]


def write(profile: ListenerProfile, *, at: str) -> Path:
    """Validate, render, write. Raises ExposureRefused on any refusal — warnings do not stop it."""
    result = validate(profile)
    if not result.ok:
        raise ExposureRefused("; ".join(result.refusals))
    PROFILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    PROFILE_PATH.write_text(render(profile, at=at), encoding="utf-8")
    return PROFILE_PATH


def clear() -> bool:
    """Remove the profile. True if one was there. The container keeps its bindings until it is
    recreated — observe() reports that as `drifted`, not as `none`."""
    if PROFILE_PATH.exists():
        PROFILE_PATH.unlink()
        return True
    return False
```

- [ ] **Step 5: Run and confirm pass**, then commit

```bash
git add backend/cockpit/exposure.py backend/test_exposure.py .gitignore
git commit -m "exposure: write the profile, and keep it out of a public repo"
```

---

### Task 7: Observe — read the real bindings back

**Files:**
- Modify: `backend/cockpit/exposure.py`
- Test: `backend/test_exposure.py`

**Interfaces:**
- Produces: `observe(profile: ListenerProfile | None = None, *, runner=None) -> dict[str, Any]` with `state` in `{"active","pending-restart","drifted","none","unknown"}`

`runner` is an injection point so the test fakes `docker inspect` the way `test_kali` fakes `subprocess.run`.

- [ ] **Step 1: Write the failing tests**

```python
def _fake_docker(mapping):
    def run(argv):
        import json as _json
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

    def broken(argv):
        return 127, "", "docker CLI not found on PATH"
    assert exposure.observe(p, runner=broken)["state"] == "unknown"

    assert exposure.observe(None, runner=pending)["state"] == "none"
    print("  observe reports active / pending-restart / drifted / unknown / none: PASS")


def test_observe_never_claims_active_on_a_mismatch() -> None:
    p = _profile(ip="10.10.14.7", kinds=["dns-tunnel", "sliver"])
    half = _fake_docker({"53/udp": [{"HostIp": "10.10.14.7", "HostPort": "53"}]})
    assert exposure.observe(p, runner=half)["state"] == "drifted"
    print("  a partially-published profile is drifted, never active: PASS")


def test_observe_mentions_the_firewall_when_active() -> None:
    p = _profile(ip="10.10.14.7", kinds=["dns-tunnel"])
    active = _fake_docker({"53/udp": [{"HostIp": "10.10.14.7", "HostPort": "53"}]})
    note = exposure.observe(p, runner=active)["note"]
    assert "firewall" in note.lower(), note
    print("  an active profile says a published port is not an open port: PASS")
```

- [ ] **Step 2: Run and confirm failure**

- [ ] **Step 3: Implement**

```python
import json
import subprocess
from typing import Any, Callable

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
    profile: ListenerProfile | None = None,
    *,
    runner: Callable[[list[str]], tuple[int, str, str]] | None = None,
) -> dict[str, Any]:
    """What is ACTUALLY published, compared against what the profile asked for.

    Never assigns a state it has not looked at — the rule lifecycle.py exists to enforce,
    applied to exposure instead of listener liveness. A container publishing something other
    than the profile is `drifted`, never `active`; docker being unavailable is `unknown`,
    never `active`.
    """
    if profile is None:
        return {"state": "none", "published": {}, "expected": [], "note": "no profile written"}

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

    if all(seen.get(k) == v for k, v in want.items()) and len(seen) == len(want):
        return {
            "state": "active", "published": seen, "expected": expected,
            "note": "a published port is not an open port — if a callback does not land, "
                    "check the host firewall before anything else",
        }

    return {"state": "drifted", "published": seen, "expected": expected,
            "note": "the container publishes something other than this profile — recreate it"}
```

- [ ] **Step 4: Run and confirm pass**, then commit

```bash
git add backend/cockpit/exposure.py backend/test_exposure.py
git commit -m "exposure: observe the real bindings rather than assume them"
```

---

### Task 8: Apply, approval-gated

**Files:**
- Modify: `backend/cockpit/exposure.py`
- Test: `backend/test_exposure.py`

**Interfaces:**
- Produces: `apply(profile: ListenerProfile, *, approved: bool, runner=None) -> dict[str, Any]`

- [ ] **Step 1: Write the failing tests**

```python
def test_apply_requires_approval() -> None:
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


def test_apply_runs_the_compose_command() -> None:
    calls = []
    def runner(argv):
        calls.append(argv)
        return 0, "", ""
    exposure.apply(_profile(), approved=True, runner=runner)
    assert calls, "compose never ran"
    assert calls[0] == exposure.compose_command(_profile()), calls[0]
    print("  an approved apply runs exactly the compose command it showed: PASS")
```

- [ ] **Step 2: Run and confirm failure**

- [ ] **Step 3: Implement**

```python
def apply(
    profile: ListenerProfile,
    *,
    approved: bool,
    runner: Callable[[list[str]], tuple[int, str, str]] | None = None,
) -> dict[str, Any]:
    """Recreate the service so the profile takes effect. REQUIRES approval.

    Recreating a container kills every listener, session and background job inside it. That is
    destructive to work in flight, so the operator is told before it happens rather than after
    — the same reason every other destructive action here carries a gate.
    """
    if not approved:
        raise ExposureRefused(
            "applying a listener profile recreates the container and kills every listener, "
            "session and background job inside it — set approved=true",
            gate="approval",
        )
    argv = compose_command(profile)
    call = runner or (lambda a: _run(a))
    rc, out, err = call(argv)
    if rc != 0:
        raise ExposureRefused(f"compose failed (rc {rc}): {err or out}", gate="compose")
    return {"applied": True, "command": argv}


def _run(argv: list[str]) -> tuple[int, str, str]:
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=180.0)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except FileNotFoundError:
        return 127, "", "docker CLI not found on PATH"
    except subprocess.TimeoutExpired:
        return 124, "", "docker compose timed out"
```

- [ ] **Step 4: Run and confirm pass**, then commit

```bash
git add backend/cockpit/exposure.py backend/test_exposure.py
git commit -m "exposure: apply the profile behind an approval gate"
```

---

### Task 9: The preset, the golden fixture, and the endpoints

**Files:**
- Modify: `backend/cockpit/exposure.py`, `backend/cockpit/router.py`, `docker/proof/c2_lab_proof.sh`
- Create: `backend/test_support/c2-lab.golden.yml` (content copied verbatim from `docker/proof/c2-lab.yml`)
- Delete: `docker/proof/c2-lab.yml`
- Test: `backend/test_exposure.py`

**Interfaces:**
- Produces: `PRESETS: dict[str, ListenerProfile]` containing `vmnet8-dns`

- [ ] **Step 1: Write the failing equivalence test**

```python
def test_vmnet8_preset_matches_what_build10_hand_wrote() -> None:
    """The generalisation must expose exactly what the file it replaces exposed.

    Compared on PARSED exposure, not bytes: build #10's file opens with 27 lines of prose
    explaining why VMnet8 and why UDP/53, and no generator reproduces that. The guarantee
    wanted is 'same effective exposure', not 'same comments'.
    """
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.insert(0, str(_Path(__file__).resolve().parent))
    from test_exposure_safety import published_ports

    golden = exposure.REPO_ROOT / "backend" / "test_support" / "c2-lab.golden.yml"
    generated = _Path(exposure.render(exposure.PRESETS["vmnet8-dns"], at=_AT))
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        p = _Path(d) / "listener-profile.yml"
        p.write_text(exposure.render(exposure.PRESETS["vmnet8-dns"], at=_AT), encoding="utf-8")
        assert [e for _, e in published_ports(p)] == [e for _, e in published_ports(golden)], (
            published_ports(p), published_ports(golden))
    print("  the vmnet8-dns preset exposes exactly what c2-lab.yml exposed: PASS")
```

(Delete the unused `generated` line when implementing — it is shown here only to keep the
diff obvious; the temp-file form is the one that runs.)

- [ ] **Step 2: Move the golden fixture**

```bash
git mv docker/proof/c2-lab.yml backend/test_support/c2-lab.golden.yml
```

Add a line at the top of the moved file:

```
# MOVED from docker/proof/c2-lab.yml (build #13). No longer a live compose path — this is the
# fixture the vmnet8-dns preset is compared against, so the generalisation stays provably
# faithful to the hand-written file it replaced.
```

- [ ] **Step 3: Add the preset**

```python
PRESETS: dict[str, ListenerProfile] = {
    # Build #10's hand-written case, expressed as a profile. The lab DC's subnet can reach
    # exactly one address on this machine — the VMware VMnet8 host adapter — and a DNS tunnel
    # needs exactly one port. Locked against the original by test_exposure.
    "vmnet8-dns": ListenerProfile(
        ip="192.168.13.1", container="engage-sandbox", kinds=["dns-tunnel"],
    ),
}
```

- [ ] **Step 4: Add the endpoints**

In `backend/cockpit/router.py`, import `exposure` alongside the other cockpit modules and add:

```python
class ProfileRequest(BaseModel):
    ip: str
    container: str = "engage-sandbox"
    kinds: list[str] = Field(default_factory=list)
    extra: list[tuple[int, str]] = Field(default_factory=list)
    engagement: str | None = None
    ack_wildcard: bool = False
    ack_public: bool = False
    approved: bool = False


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@router.get("/exposure")
def get_exposure() -> dict[str, Any]:
    """The live profile and what is ACTUALLY published — never what was assumed."""
    return exposure.observe(exposure.live_profile())


@router.post("/exposure/profile")
def post_exposure_profile(req: ProfileRequest) -> dict[str, Any]:
    """Validate and write. 403 names the gate that refused; warnings are returned, not fatal."""
    profile = exposure.ListenerProfile(**req.model_dump(exclude={"approved"}))
    result = exposure.validate(profile)
    if not result.ok:
        raise HTTPException(status_code=403, detail={
            "gate": "exposure", "refusals": result.refusals,
            "needs_ack": result.needs_ack, "warnings": result.warnings,
        })
    path = exposure.write(profile, at=_now_iso())
    return {
        "written": str(path), "ports": result.ports, "warnings": result.warnings,
        "command": exposure.compose_command(profile),
    }


@router.post("/exposure/apply")
def post_exposure_apply(req: ProfileRequest) -> dict[str, Any]:
    profile = exposure.ListenerProfile(**req.model_dump(exclude={"approved"}))
    try:
        applied = exposure.apply(profile, approved=req.approved)
    except exposure.ExposureRefused as exc:
        raise HTTPException(status_code=403, detail={"gate": exc.gate, "reason": exc.reason})
    return {**applied, **exposure.observe(profile)}


@router.delete("/exposure/profile")
def delete_exposure_profile() -> dict[str, Any]:
    removed = exposure.clear()
    return {"removed": removed, "note": "the container keeps its bindings until it is recreated"}
```

Add `live_profile()` to `exposure.py`, returning the profile parsed back out of the written
file, or `None` when no file exists:

```python
def live_profile() -> ListenerProfile | None:
    """The profile currently on disk, reconstructed from the rendered file, or None."""
    if not PROFILE_PATH.exists():
        return None
    text = PROFILE_PATH.read_text(encoding="utf-8")
    service = ""
    ip = ""
    extra: list[tuple[int, str]] = []
    for raw in text.splitlines():
        line = raw.strip()
        m = re.match(r'^-\s*"(?P<ip>[^:]+):(?P<host>\d+):(?P<cont>\d+)/(?P<proto>tcp|udp)"$', line)
        if m:
            ip = m.group("ip")
            extra.append((int(m.group("cont")), m.group("proto")))
        elif line.endswith(":") and line[:-1] in EXPOSABLE:
            service = line[:-1]
    if not ip or not service:
        return None
    return ListenerProfile(
        ip=ip, container=service, kinds=[], extra=extra,
        ack_wildcard=classify_ip(ip) == "wildcard", ack_public=classify_ip(ip) == "public",
    )
```

- [ ] **Step 5: Update the proof script**

In `docker/proof/c2_lab_proof.sh`, replace every `-f docker/proof/c2-lab.yml` with
`-f docker/listener-profile.yml`, and add before the first compose invocation:

```sh
# Build #13: the exposure is generated from the vmnet8-dns preset rather than a checked-in
# file. Generate it first, or the compose call below has nothing to merge.
"$PY" -c "from cockpit import exposure; from datetime import datetime, timezone; \
exposure.write(exposure.PRESETS['vmnet8-dns'], at=datetime.now(timezone.utc).isoformat())"
```

- [ ] **Step 6: Run everything and commit**

```bash
cd backend && .venv/Scripts/python.exe test_exposure.py && .venv/Scripts/python.exe test_exposure_safety.py
git add -A
git commit -m "exposure: the vmnet8 preset, the golden fixture, and the endpoints"
```

---

### Task 10: Wire into the suite, assessment, and land

**Files:**
- Modify: `backend/run_safety_tests.sh`, `docs/ASSESSMENT-2026-07-26.md` (+ regenerated html/pdf)

- [ ] **Step 1: Add the test file to the suite**

In `backend/run_safety_tests.sh`, beside the other `run_test` lines:

```sh
run_test test_exposure.py "listener profiles (bind gates / ack rule / observed state / vmnet8 preset)"
```

- [ ] **Step 2: Run the whole suite**

Run: `sh backend/run_safety_tests.sh`
Expected: every file exits 0; the count rises from 56 to 57.

- [ ] **Step 3: Write the assessment section**

Add a build #13 section to `docs/ASSESSMENT-2026-07-26.md` covering: the four-part
decomposition and why 1a/1b are separate; what was built; and the three decisions that went
against the first draft — public and wildcard as red-confirms rather than refusals, arbitrary
ports allowed because the four kinds omit a plain reverse shell, and the correction that a
non-live bind address fails loudly rather than silently. Include the scanner hole found during
spec self-review and how the `hackpit-ack` marker closed it.

- [ ] **Step 4: Regenerate the document**

Run: `python docs/build-assessment.py`
Verify against the **HTML** and the page-count delta. Do **not** grep the PDF — Edge subsets
fonts to glyph IDs and a text search returns a false negative.

- [ ] **Step 5: Commit and push**

```bash
git add -A
git commit -m "build #13 part 1: listener profiles"
git push origin main
```

- [ ] **Step 6: Confirm CI green**

Run: `gh run list --limit 1`
Expected: `completed  success`. Do not treat the build as landed until it is.

---

## Self-Review

**Spec coverage** — §3.1 module → Tasks 1-8; §3.2 profile → Task 3; §3.3 one global profile →
Task 9 (`live_profile()`); §3.4 preset + golden → Task 9; §3.5 gitignore → Task 6; §3.6 observe
→ Task 7; §3.7 endpoints → Task 9; §4 guards 1-10 → Tasks 3, 5, 6, 8; §4.1 ack → Tasks 4-5;
§5 verification → every task's tests + Task 10; §6 assessment → Task 10; §7 commit → Task 10.
No gaps.

**Placeholders** — none. Every code step carries runnable code.

**Type consistency** — `ExposureRefused(reason, gate)` is raised in Tasks 1, 6, 8 and caught by
`.gate` in Task 9. `derive_ports` returns `list[tuple[int, str]]` throughout. `validate` returns
`Validation` with `.ok` used in Tasks 6 and 9. `render(profile, *, at)` keyword-only `at` is
consistent in Tasks 4, 6, 9. `observe(profile, *, runner)` matches Tasks 7 and 9.
