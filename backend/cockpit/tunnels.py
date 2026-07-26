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
* The rewritten command still runs through the NORMAL gated executor — approve-each, scope,
  the works. Wrapping adds a prefix; it introduces NO new execution capability and no new gate
  bypass. A proxychained command to an internal host is refused unless that subnet was added to
  scope by hand.

Live pivoting is inherently untested without a real compromised host to connect back; the
lifecycle, routing, one-liner generation and command rewriting are built and unit-tested, and
the actual agent connect-back is deferred to a real engagement.
"""

from __future__ import annotations

import ipaddress
import subprocess
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from pydantic import BaseModel, Field, field_validator

from . import config

# Bounds — a listener should not accumulate forever.
MAX_LIVE_TUNNELS = int(__import__("os").environ.get("HACKPIT_MAX_TUNNELS", "4"))

# Default ports. chisel: reverse SOCKS server; the agent's R:socks exposes a SOCKS5 on the
# SERVER at 127.0.0.1:1080, which proxychains then points at. ligolo: the proxy control port.
CHISEL_DEFAULT_PORT = 8080
CHISEL_SOCKS_PORT = 1080
LIGOLO_DEFAULT_PORT = 11601


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
    status: str = Field(description="starting | listening | down.")
    agent_command: str = Field(description="The one-liner to paste on the compromised host.")
    setup_note: str = ""
    started_at: str
    engagement_id: str | None = None


class TunnelRefused(RuntimeError):
    """The listener could not start / the request was invalid. Nothing runs."""


# --------------------------------------------------------------------------- #
# registry
# --------------------------------------------------------------------------- #
@dataclass
class _LiveTunnel:
    model: Tunnel
    proc: "subprocess.Popen[str] | None" = field(default=None)


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
        f"add the route(s) on this box: {routes}. Commands then run UNWRAPPED — no proxychains."
    )
    return server_argv, agent, note, None


# --------------------------------------------------------------------------- #
# lifecycle — HUMAN-ONLY
# --------------------------------------------------------------------------- #
def start_tunnel(req: TunnelStartRequest) -> Tunnel:
    """Start a pivot listener in the ENGAGE sandbox and return it + the agent one-liner.

    HUMAN-ONLY (route-driven). Runs the chisel/ligolo *server* inside the engage sandbox — a
    local listener, no target, so no target-scope gate applies to starting it. Refuses if the
    sandbox is down or the live cap is hit; nothing runs on refusal.
    """
    if not _container_running(config.ENGAGE_SANDBOX_CONTAINER):
        raise TunnelRefused(
            f"engage sandbox '{config.ENGAGE_SANDBOX_CONTAINER}' is not running — bring the "
            "stack up (docker compose -f docker/docker-compose.yml up -d)"
        )
    with _lock:
        live = sum(1 for t in _tunnels.values() if t.model.status != "down")
        if live >= MAX_LIVE_TUNNELS:
            raise TunnelRefused(f"too many live tunnels ({live}/{MAX_LIVE_TUNNELS}) — stop one first")

    if req.kind == "chisel":
        server_argv, agent, note, socks = _chisel_plan(req)
        routing, port = "socks", (req.listen_port or CHISEL_DEFAULT_PORT)
    else:
        server_argv, agent, note, socks = _ligolo_plan(req)
        routing, port = "interface", (req.listen_port or LIGOLO_DEFAULT_PORT)

    tid = uuid.uuid4().hex[:12]
    argv = ["docker", "exec", config.ENGAGE_SANDBOX_CONTAINER, *server_argv]
    try:
        proc = subprocess.Popen(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError:
        raise TunnelRefused("docker CLI not found on PATH")

    model = Tunnel(
        id=tid, kind=req.kind, routing=routing, lhost=req.lhost, listen_port=port,
        socks_port=socks, subnets=list(req.subnets), status="listening",
        agent_command=agent, setup_note=note, started_at=_now(), engagement_id=req.engagement_id,
    )
    with _lock:
        _tunnels[tid] = _LiveTunnel(model=model, proc=proc)
    return model


def list_tunnels() -> list[Tunnel]:
    """Every tunnel (starting/listening/down), refreshing liveness. Read-only."""
    with _lock:
        live = list(_tunnels.values())
    for lt in live:
        if lt.proc is not None and lt.proc.poll() is not None and lt.model.status != "down":
            lt.model.status = "down"
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
    if lt.proc is not None:
        try:
            lt.proc.kill()
        except Exception:
            pass
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
            if lt.proc is not None:
                try:
                    lt.proc.kill()
                except Exception:
                    pass
        _tunnels.clear()
