"""ZAP as a recording proxy inside a sandbox — GATED START, read-only history.

WHY THIS IS NOT THE THING BUILD #14 PART 1 REFUSED. Part 1 excluded a ZAP daemon because an HTTP
control channel bypasses :func:`executor.validate_request`, and because reaching one inside the
lab sandbox would mean opening the ``internal: true`` network that ``assert_isolation_proven()``
exists to deny.

Neither happens here, and it was MEASURED before it was designed (2026-08-03, ZAP 2.17.0):

    zaproxy -daemon -host 127.0.0.1 -port 8090     API answers after ~7s
    curl 127.0.0.1:8090/... FROM THE HOST          refused — unreachable
    the same call via `docker exec`                {"version":"2.17.0"}

The daemon binds loopback INSIDE the container. No port is published, so the backend has no
socket to it; the only way in is ``docker exec``, which is the one channel into a sandbox and the
thing the gates already classify. The API exists and is still unreachable from anywhere that
could bypass a gate.

WHAT IT CAPTURES: tools run inside the sandbox, pointed at the proxy (the executor's ``proxy``
flag). It RECORDS. It never scans — active scanning stays on part 1's gated command path
(``zaproxy -cmd -quickurl``), which carries its own red-confirm.
"""

from __future__ import annotations

import json
import subprocess
import threading
import time
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from . import config

#: ZAP's API and its proxy share one listener. Loopback-only, inside the container.
PROXY_HOST = "127.0.0.1"
DEFAULT_PROXY_PORT = 8090

#: The JVM needs this long before the API answers. MEASURED at ~7s; the headroom is for a loaded
#: host. lifecycle's default settle is far shorter, so both values are passed explicitly.
READY_TIMEOUT_SECONDS = 60
SETTLE_SECONDS = 8.0

#: THE ONLY URLS THIS MODULE ISSUES, all reads. No function here takes a path or endpoint
#: argument, so an ``action/`` call is not expressible without writing a visibly new function.
#: NOTHING ENFORCES THAT — the runtime allowlist and a static source test were both declined
#: (2026-08-03, Zaid), so it is a convention, and it is the only invariant in this build with
#: nothing behind it. It matters because :func:`history` is deliberately UNGATED (a panel that
#: refreshes cannot demand approval per refresh), so anything reaching ZAP from here reaches it
#: unapproved. Adding a URL parameter reopens that decision; see spec §7.3.
_VIEW_VERSION = "/JSON/core/view/version/"
_VIEW_COUNT = "/JSON/core/view/numberOfMessages/"
_VIEW_MSGS = "/JSON/core/view/messages/"

_lock = threading.Lock()
_models: dict[str, "Proxy"] = {}
_watched: dict[str, Any] = {}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------- #
# models
# --------------------------------------------------------------------------- #
class ProxyStartRequest(BaseModel):
    """Start the recording proxy in a sandbox."""

    port: int = Field(DEFAULT_PROXY_PORT, ge=1024, le=65535)
    engagement_id: str | None = Field(
        None,
        description="Engagement to attribute against. OMIT for LAB mode — unlike a pivot "
        "listener, this runs in whichever sandbox you are using, so lab mode is coherent and "
        "its isolation gate is about the very container the proxy occupies.",
    )
    # THE GATE FIELDS. Both default False, so a client that omits them is REFUSED rather than
    # allowed — a default of True would mean an omitted field silently grants exactly what the
    # field was added to require.
    approved: bool = Field(
        False, description="Explicit human approval for starting this proxy. Never defaulted true."
    )
    dangerous_ack: bool = Field(
        False,
        description="The explicit red-confirm. A recording proxy holds full request bodies — "
        "credentials, session tokens and payloads in cleartext — so this is always required.",
    )


class Proxy(BaseModel):
    """One live (or starting) recording proxy."""

    id: str
    container: str
    port: int
    status: str = Field(
        description="starting | listening | down — OBSERVED after the settle window, never "
        "assigned at spawn time. 'listening' means the port was confirmed bound inside the "
        "container; 'starting' means the process is up but the bind is unconfirmed."
    )
    liveness: str = Field("", description="What was actually observed about the process/port.")
    captured: int = 0
    started_at: str
    engagement_id: str | None = None


class CapturedHeader(BaseModel):
    name: str
    value: str


class CapturedRequest(BaseModel):
    method: str = "GET"
    url: str = ""
    headers: list[CapturedHeader] = Field(default_factory=list)
    #: RAW. Redaction happens in report.py and nowhere else — spec §6.
    body: str = ""


class CapturedResponse(BaseModel):
    status: int | None = None
    headers: list[CapturedHeader] = Field(default_factory=list)
    body: str = ""
    size_bytes: int = 0
    time_ms: int = 0


class CapturedExchange(BaseModel):
    """One recorded request/response pair.

    *** DELIBERATELY NOT `repeater.RepeaterExchange`, THOUGH THE SHAPE MATCHES. ***
    The first version of this module imported those models, and `test_repeater.py` refused it:
    the repeater is HUMAN-ONLY and its lock bans *any* import of the module, not just
    ``repeater.send`` — because a module that can import it is one line from calling it.

    The tempting fix was to add ``cockpit/proxy.py`` to that allow-list. That is the exact
    anti-pattern build #5 was about: widening a safety allow-list so new code fits, rather than
    working within it. The field NAMES match the repeater's on purpose, so the existing panel
    renders a captured exchange with no translation layer and a "replay in repeater" action can
    hand one straight over — the operator gets the reuse without the coupling.
    """

    id: str
    request: CapturedRequest
    response: CapturedResponse
    sent_at: str = ""
    container: str = ""


class ProxyRefused(RuntimeError):
    """The proxy could not start / the request was invalid. NOTHING ran.

    Carries the GATE that refused it so the route can map a safety refusal (403) apart from an
    availability problem (409), rather than collapsing both into one status.
    """

    def __init__(self, reason: str, gate: str = "unavailable",
                 dangerous_flags: list[str] | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.gate = gate
        self.dangerous_flags = dangerous_flags or []


# --------------------------------------------------------------------------- #
# the gate — approval + the heuristic red-confirm, before anything spawns
# --------------------------------------------------------------------------- #
def container_for(req: ProxyStartRequest) -> str:
    """Engagement runs use the engage sandbox; everything else the isolated lab one.

    Getting this wrong is not cosmetic: a real-target proxy in the egress-less lab box would
    capture nothing, and a lab proxy in the fully-open box would have reach it must not have.
    """
    return config.ENGAGE_SANDBOX_CONTAINER if req.engagement_id else config.SANDBOX_CONTAINER


def server_argv_for(req: ProxyStartRequest) -> list[str]:
    """The daemon argv this request will run. THE SINGLE DERIVATION.

    Both the gate and :func:`start_proxy` come through here, for the same reason the WinRM path
    funnels through one join: classifying a DIFFERENT argv than the one that executes reproduces
    Critical 2 in a new place. A test asserts the two are equal.

    ``-host 127.0.0.1`` IS THE ISOLATION PROPERTY. Do not widen it. The API is only safe to leave
    ungated on the read path because nothing outside this container can reach it at all.
    """
    return [
        "zaproxy", "-daemon",
        "-host", PROXY_HOST,
        "-port", str(req.port),
        "-config", "api.disablekey=true",
    ]


def _gate_request(req: ProxyStartRequest):
    """The ExecRequest the real gates run against.

    Surface: the daemon BINARY, the engagement, and — in LAB mode only — the lab target.

    THE REAL ARGV IS NOT THE SURFACE, and that is deliberate in both directions:

    * ``-host 127.0.0.1`` must NOT go in. The scope extractor reads any dotted token as a
      hostname, so passing it makes the gate refuse the operator's OWN SOCKET as an out-of-scope
      host — a refusal that teaches nothing and trains a workaround. tunnels.py keeps ``-laddr``
      out of its surface for exactly this reason, and this module's first test run reproduced it.

    * THE LAB TARGET must go in, in lab mode. A listener names no target, and lab mode refuses a
      target-less command ("the command must reference the lab") — a LOCKED invariant that
      test_cockpit.py guards and that this build does not touch. Declaring the lab is not a
      workaround around that rule; it is a true statement of scope. :func:`container_for` puts a
      lab proxy in the isolated sandbox, which sits on an ``internal: true`` network with no
      route off the bridge, so the lab target IS everything this listener can ever reach.
      (Decision 2026-08-03, Zaid; the alternatives were engagement-only — which would push
      practice traffic into the fully-open sandbox — and relaxing the locked rule for everyone.)

    In ENGAGEMENT mode the surface stays empty, as tunnels does: engagement mode already permits
    a target-less command, and the engagement's own scope governs what any run may reach.

    Nothing is weakened by the omission of the flags: the danger verdict comes from the BINARY
    plus ``-daemon`` (see ``allowlist._TOOL_ATTACK_FLAGS``), and the port is a bind on a
    container we already own rather than anything network-facing.
    """
    from .models import ExecRequest

    argv = server_argv_for(req)
    # ``-daemon`` IS IN THE SURFACE, and it has to be. The danger verdict for this binary is
    # argument-based (allowlist._TOOL_ATTACK_FLAGS: `-quickurl` attacks, `-daemon` records), so a
    # surface carrying only the binary name would make the red-confirm unfirable and
    # ``dangerous_ack`` decorative — gate-audit finding I2's exact shape. The surface therefore
    # carries the flag that DETERMINES DANGER while still omitting the bind address that would
    # make the scope extractor refuse our own socket.
    surface: list[str] = ["-daemon"]
    if not req.engagement_id:
        surface.append(config.LAB_TARGET_HOST)
    return ExecRequest(
        command=argv[0],
        args=surface,
        approved=req.approved,
        dangerous_ack=req.dangerous_ack,
        engagement_id=req.engagement_id,
    )


def validate_start(req: ProxyStartRequest):
    """The gate verdict for starting this proxy, spawning nothing. PURE.

    NO ENGAGEMENT PRECONDITION, and that is a deliberate divergence from tunnels.py rather than
    an omission. A pivot listener lives in the engage sandbox, so tunnels refuses lab mode rather
    than make the operator satisfy an isolation gate about a container the listener is not in —
    its docstring calls that "firing a gate on an unrelated condition".

    That reasoning INVERTS here. This proxy runs in whichever sandbox the operator is using, so
    in lab mode the isolation gate is asking about the very container the proxy occupies: the
    relevant condition, not an unrelated one. Requiring an engagement would also lock the proxy
    out of the lab, which is where most of its practice value is.
    """
    from . import executor

    return executor.validate_request(_gate_request(req))


# --------------------------------------------------------------------------- #
# lifecycle
# --------------------------------------------------------------------------- #
def _container_running(name: str) -> bool:
    try:
        out = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return name in out.stdout.split()


def _api_get(container: str, port: int, path: str, timeout: int = 10) -> str:
    """Read one of this module's fixed URLs, via ``docker exec``. NEVER a socket from the backend.

    ``path`` is only ever one of the module constants above; no caller passes a computed value.
    """
    url = f"http://{PROXY_HOST}:{port}{path}"
    try:
        out = subprocess.run(
            ["docker", "exec", container, "curl", "-s", "--max-time", str(timeout), url],
            capture_output=True, text=True, timeout=timeout + 5,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return out.stdout


def _wait_ready(container: str, port: int) -> bool:
    """Poll the version endpoint until the JVM answers.

    Polling beats sleeping a fixed time in both directions: a loaded host is slower than the ~7s
    measured, and a fast one should not be punished for it.
    """
    deadline = time.monotonic() + READY_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if '"version"' in _api_get(container, port, _VIEW_VERSION, timeout=3):
            return True
        time.sleep(1)
    return False


def start_proxy(req: ProxyStartRequest) -> Proxy:
    """Start the recording proxy in the sandbox. GATED — nothing spawns on a refusal."""
    from . import lifecycle

    rejected = validate_start(req)
    if rejected is not None:
        raise ProxyRefused(rejected.reason, gate=rejected.gate,
                           dangerous_flags=list(rejected.dangerous_flags))

    container = container_for(req)
    if not _container_running(container):
        raise ProxyRefused(
            f"sandbox '{container}' is not running — bring the stack up "
            "(docker compose -f docker/docker-compose.yml up -d)"
        )

    pid = f"zapproxy-{container}-{req.port}"
    with _lock:
        existing = _models.get(pid)
        if existing is not None and existing.status != "down":
            raise ProxyRefused(
                f"a proxy is already live on {container}:{req.port} — stop it first",
                gate="limit",
            )

    argv = server_argv_for(req)
    # interactive=False: a daemon needs no stdin, so it gets DEVNULL and proc.stdin is None.
    watched = lifecycle.spawn_watched(
        lifecycle.exec_argv(container, argv, interactive=False), interactive=False
    )
    ready = _wait_ready(container, req.port)
    live = lifecycle.observe(
        watched, container=container, port=req.port, proto="tcp", settle=SETTLE_SECONDS
    )

    detail = live.detail
    if not ready and live.status != "down":
        detail = (detail + " — the API did not answer within the ready window").strip()

    model = Proxy(
        id=pid, container=container, port=req.port,
        status=live.status, liveness=detail,
        captured=captured_count(container, req.port) if ready else 0,
        started_at=_now(), engagement_id=req.engagement_id,
    )
    with _lock:
        _models[pid] = model
        _watched[pid] = watched
    return model


def stop_proxy(pid: str) -> Proxy:
    """Stop a running proxy.

    NOT GATED, deliberately. Stopping a listener REMOVES capability; a gate that can refuse to
    stop one is a gate that makes the system less safe. Same position tunnels.py takes.
    """
    with _lock:
        model = _models.get(pid)
        watched = _watched.get(pid)
    if model is None:
        raise ProxyRefused(f"no proxy with id {pid!r}", gate="notfound")

    if watched is not None:
        try:
            watched.kill(container=model.container, server_argv=server_argv_for(
                ProxyStartRequest(port=model.port, approved=True, dangerous_ack=True)
            ))
        except Exception:  # noqa: BLE001 - a failed teardown must still mark it down
            pass

    stopped = model.model_copy(update={"status": "down", "liveness": "stopped by the operator"})
    with _lock:
        _models[pid] = stopped
        _watched.pop(pid, None)
    return stopped


def list_proxies() -> list[Proxy]:
    with _lock:
        return list(_models.values())


def status() -> dict[str, Any]:
    """Availability of both sandboxes + the live count — drives the UI banner."""
    with _lock:
        live = [p for p in _models.values() if p.status != "down"]
    return {
        "lab_sandbox": config.SANDBOX_CONTAINER,
        "lab_running": _container_running(config.SANDBOX_CONTAINER),
        "engage_sandbox": config.ENGAGE_SANDBOX_CONTAINER,
        "engage_running": _container_running(config.ENGAGE_SANDBOX_CONTAINER),
        "live": len(live),
        "default_port": DEFAULT_PROXY_PORT,
    }


# --------------------------------------------------------------------------- #
# history — READ-ONLY and UNGATED
# --------------------------------------------------------------------------- #
def _first_line(raw: Any) -> str:
    return str(raw or "").replace("\r\n", "\n").split("\n", 1)[0].strip()


def _headers_from(raw: Any) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for line in str(raw or "").replace("\r\n", "\n").split("\n")[1:]:
        if not line.strip() or ":" not in line:
            continue
        name, _, value = line.partition(":")
        out.append((name.strip(), value.strip()))
    return out


def parse_message(obj: Any, container: str):
    """One ZAP message -> a RepeaterExchange. NEVER raises; returns None if unusable.

    MEASURED shape (ZAP 2.17.0): ``id, requestHeader, requestBody, responseHeader, responseBody,
    rtt, timestamp, type, tags, note, cookieParams``. ``requestHeader``'s first line is
    ``METHOD URL HTTP/x``; ``responseHeader``'s is ``HTTP/x STATUS REASON``.

    A MALFORMED RESPONSE LINE DOES NOT DISCARD THE RECORD. ZAP logs exchanges that never
    completed (the fixture carries a real one reading ``HTTP/1.0 0``), and the request half is
    still worth having — so the status becomes None and everything else survives.

    Returns a :class:`CapturedExchange` — same field names as the repeater's model, but a local
    class, because the repeater is human-only and its lock bans importing it. See that class.
    """
    try:
        if not isinstance(obj, dict):
            return None
        parts = _first_line(obj.get("requestHeader")).split()
        if len(parts) < 2 or not parts[1].startswith("http"):
            return None
        method, url = parts[0], parts[1]

        status = None
        resp_parts = _first_line(obj.get("responseHeader")).split()
        if len(resp_parts) >= 2 and resp_parts[1].isdigit():
            code = int(resp_parts[1])
            # ZAP writes "HTTP/1.0 0" for an exchange that never got a response.
            status = code if 100 <= code <= 599 else None

        try:
            rtt = int(str(obj.get("rtt") or "0"))
        except (TypeError, ValueError):
            rtt = 0

        body = str(obj.get("responseBody") or "")
        mid = str(obj.get("id", ""))
        return CapturedExchange(
            id=f"zap-{mid}",
            request=CapturedRequest(
                method=method, url=url,
                headers=[CapturedHeader(name=n, value=v)
                         for n, v in _headers_from(obj.get("requestHeader"))],
                # RAW, deliberately. Redaction happens in report.py and nowhere else — spec §6.
                body=str(obj.get("requestBody") or ""),
            ),
            response=CapturedResponse(
                status=status,
                headers=[CapturedHeader(name=n, value=v)
                         for n, v in _headers_from(obj.get("responseHeader"))],
                body=body, size_bytes=len(body), time_ms=rtt,
            ),
            sent_at=str(obj.get("timestamp") or ""),
            container=container,
        )
    except Exception:  # noqa: BLE001 - a parser must never break a completed run
        return None


def endpoints_from(exchanges, session_id: str, run_id: str | None = None):
    """Captured requests -> Endpoint records. Existing model, no schema change."""
    from urllib.parse import parse_qs, urlparse

    from state.models import Endpoint

    out = []
    for ex in exchanges:
        if ex is None or not ex.request.url.startswith("http"):
            continue
        out.append(Endpoint(
            session_id=session_id, url=ex.request.url, method=ex.request.method,
            status=ex.response.status,
            params=sorted(parse_qs(urlparse(ex.request.url).query).keys()),
            source_run_id=run_id,
        ))
    return out


def captured_count(container: str, port: int) -> int:
    raw = _api_get(container, port, _VIEW_COUNT)
    try:
        return int(json.loads(raw).get("numberOfMessages", 0))
    except (ValueError, AttributeError, TypeError):
        return 0


def history(container: str, port: int, start: int = 0, count: int = 50):
    """Recent captured exchanges.

    READ-ONLY and UNGATED. A panel that refreshes cannot demand approval per refresh, and
    ``lifecycle.port_is_bound()`` sets the precedent by running ``ss`` the same way. See the
    note on the URL constants: this path reaching ZAP means reaching it unapproved, so it issues
    only the two fixed view URLs.
    """
    raw = _api_get(container, port, f"{_VIEW_MSGS}?start={int(start)}&count={int(count)}")
    try:
        msgs = json.loads(raw).get("messages") or []
    except (ValueError, AttributeError, TypeError):
        return []
    parsed = [parse_message(m, container) for m in msgs]
    return [e for e in parsed if e is not None]
