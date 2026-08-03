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
flag). It RECORDS.

*** BUILD #14 PART 3 ADDED A SECOND, GATED HALF: IT NOW ALSO SCANS. ***

The line "it never scans" was true of parts 1-2 and is no longer. This module drives ZAP's ACTIVE
SCANNER over the same ``docker exec`` transport, aimed at the endpoints the proxy already
captured — the thing neither earlier part could do, because part 1's ``-quickurl`` can only attack
what its own spider happens to crawl, and an API route reached by USING the app is not crawlable.

Two halves now live here, and the difference between them is the most important thing in the file:

    history / status / alerts   READ.   UNGATED. A panel refreshes; approval per refresh is not
                                        a thing that can work.
    start_scan                  ATTACK. GATED. Builds an ExecRequest, passes
                                        executor.validate_request, and only then execs — the
                                        tunnels.py shape. 376 real attack requests were measured
                                        against ONE endpoint, finding a live SQL injection.

THAT THEY SHARE A MODULE IS A DECISION, NOT AN OVERSIGHT (2026-08-04, Zaid). Part 2's spec §7.3
made "a URL parameter appears in this module" a review trigger; this build tripped it, the
decision was reopened, and Zaid chose ONE MODULE WITH NO GUARD over the structural split that
would have made an action URL unreachable from the read path. What was accepted is the RESIDUAL
risk — that nothing structural stops a future edit from calling an action URL from the ungated
read path. What was NOT accepted, and what no layout choice could grant, is ungated scan control:
every scan start goes through the real gates. See the constants below, and spec §6.

A THIRD BOUND, enforced by ZAP rather than by us: ``ascan/action/scan`` on a URL that is not
already in the Sites tree answers ``{"code":"url_not_found"}`` (measured). The active scanner's
reach is therefore bounded by what was proxied — a host never captured cannot be attacked through
this path even if every gate here were bypassed. A bound, not a control; the gates are the control.
"""

from __future__ import annotations

import json
import subprocess
import threading
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote, quote_plus

from pydantic import BaseModel, Field, field_validator

from . import config

#: ZAP's API and its proxy share one listener. Loopback-only, inside the container.
PROXY_HOST = "127.0.0.1"
DEFAULT_PROXY_PORT = 8090

#: The JVM needs this long before the API answers. MEASURED at ~7s; the headroom is for a loaded
#: host. lifecycle's default settle is far shorter, so both values are passed explicitly.
READY_TIMEOUT_SECONDS = 60
SETTLE_SECONDS = 8.0

# --------------------------------------------------------------------------- #
# THE URLS THIS MODULE ISSUES — SPLIT BY WHAT THEY DO, WHICH IS THE WHOLE POINT
#
# Until build #14 part 3 this list was "all reads", and the note here said an ``action/`` call
# was not expressible without writing a visibly new function. Part 3 wrote those functions. The
# review rule in part 2's spec §7.3 fired exactly as intended, the decision was reopened, and
# Zaid chose to keep one module and decline a guard (spec §6). So the boundary is now stated
# here instead of being implied by the absence of action URLs.
#
# *** THE RULE, FOR WHOEVER EDITS THIS NEXT ***
#   * The READ group is reachable from UNGATED code (:func:`history`, :func:`scan_status`,
#     :func:`scan_alerts`). A panel that refreshes cannot demand approval per refresh, and
#     ``lifecycle.port_is_bound()`` sets the precedent by running ``ss`` the same way.
#   * The ACTION group may be reached ONLY after :func:`executor.validate_request` has returned
#     None for that specific request. Today exactly one function does that: :func:`start_scan`.
#   * ``_ACTION_STOP`` is the deliberate exception: stopping an in-flight scan REMOVES attack
#     traffic, so gating it would make the system less safe (§5.4). It is an action URL that is
#     ungated ON PURPOSE, and it is the only one.
#
# NOTHING ENFORCES ANY OF THIS. Both candidate guards were declined (2026-08-03: a runtime
# allowlist and a static source test; 2026-08-04: the module split). It is a convention with a
# written boundary, and adding a URL to the ACTION group without a gate in front of it is the
# specific mistake this comment exists to make visible in review.
# --------------------------------------------------------------------------- #
# read, ungated
_VIEW_VERSION = "/JSON/core/view/version/"
_VIEW_COUNT = "/JSON/core/view/numberOfMessages/"
_VIEW_MSGS = "/JSON/core/view/messages/"
_VIEW_SCANS = "/JSON/ascan/view/scans/"
_VIEW_SCAN_STATUS = "/JSON/ascan/view/status/"
_VIEW_ALERTS = "/JSON/core/view/alerts/"

# action, GATED (except _ACTION_STOP — see above)
_ACTION_SCAN = "/JSON/ascan/action/scan/"
_ACTION_STOP = "/JSON/ascan/action/stop/"

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
def container_for(req: "ProxyStartRequest | ScanStartRequest") -> str:
    """Engagement runs use the engage sandbox; everything else the isolated lab one.

    Getting this wrong is not cosmetic: a real-target proxy in the egress-less lab box would
    capture nothing, and a lab proxy in the fully-open box would have reach it must not have.

    Shared by the proxy and the scanner deliberately: a scan drives the daemon that a start put
    in a particular container, so the two must agree on which one that is or the scan would talk
    to a port in the wrong box (and, in the lab case, to a box with reach the gate never scoped).
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


def kill_pattern_for(port: int) -> list[str]:
    """The ``pkill -f`` pattern that matches the RUNNING process, joined by lifecycle.kill.

    *** THE SPAWNED ARGV IS NOT THE RUNNING ARGV, AND THIS IS WHY. ***
    ``zaproxy`` is a wrapper script that exec's the JVM, so the process actually on the box is::

        java -Xmx2738m -jar /usr/share/zaproxy/zap-2.17.0.jar -daemon -host 127.0.0.1 -port 8090

    The literal string "zaproxy -daemon" never appears in that command line. Passing
    :func:`server_argv_for` to ``pkill -f`` therefore matched NOTHING and the daemon survived
    every stop — found by the proof's teardown check, not by any unit test, because a hermetic
    test has no process to fail to kill.

    The pattern matches on the install path and the PORT, so it is version-agnostic (no
    ``zap-2.17.0.jar`` to rot) and cannot reap a proxy running on a different port.

    *** THE ``[z]`` IS LOad-BEARING, NOT A TYPO. ***
    ``docker exec <c> pkill -f <pattern>`` runs pkill INSIDE the container, so the pattern is
    part of pkill's own command line and ``-f`` matches full command lines — a plain
    ``zaproxy...`` pattern matches the killer as well as the daemon, and pkill SIGTERMs itself.
    Observed directly: the probe shell exited 143 having killed nothing useful. ``[z]aproxy``
    matches the literal text "zaproxy" in the JVM's argv while the killer's own argv contains
    "[z]aproxy", which does not.
    """
    return [rf"[z]aproxy.*-daemon.*-port {int(port)}\b"]


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


def clash_refusal(container: str, port: int) -> ProxyRefused | None:
    """The refusal a new proxy in ``container`` would earn from one already there. PURE.

    *** ONE PROXY PER CONTAINER, NOT PER PORT — AND THE REASON IS ZAP'S, NOT OURS. ***

    ZAP takes an exclusive lock on its HOME DIRECTORY (``$HOME/.ZAP``), not on its port, so a
    second daemon in the same container dies at startup with "The home directory is already in
    use" whatever port it was given. This check was port-scoped until build #14 part 3's proof
    hit it: a leftover daemon on 8092 killed a fresh one on 8093, and the only evidence was a
    line in the JVM's log inside the container.

    Nothing was UNSAFE about the old behaviour — status is observed, so the dead proxy reported
    itself down rather than lying. It was unexplainable, which is its own kind of defect: the
    operator saw a proxy that would not start, and no reason anywhere in the UI.

    Split out of :func:`start_proxy` so it can be tested WITHOUT Docker. The first version of its
    test drove the whole of ``start_proxy`` and passed locally and failed in CI, where there is
    no Docker and the isolation gate refuses first — a test that silently depended on the
    developer's stack being up. A hermetic suite has to stay hermetic.
    """
    with _lock:
        clash = next(
            (p for p in _models.values() if p.container == container and p.status != "down"),
            None,
        )
    if clash is None:
        return None
    return ProxyRefused(
        f"a proxy is already live on {clash.container}:{clash.port} — stop it first"
        + ("" if clash.port == port else
           ". ZAP locks its home directory rather than its port, so a second daemon on "
           f":{port} in the same container would fail to start"),
        gate="limit",
    )


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
    clash = clash_refusal(container, req.port)
    if clash is not None:
        raise clash

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
            watched.kill(container=model.container, server_argv=kill_pattern_for(model.port))
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


# --------------------------------------------------------------------------- #
# THE SCANNER (build #14 part 3) — GATED start, OBSERVED status, UNGATED stop
#
# What this adds over part 1's `zaproxy -cmd -quickurl <url>`: an aim. `-quickurl` spiders the
# site and attacks whatever the crawl found, so an endpoint reached only by USING the app —
# `/rest/products/search?q=` behind a login, an API route nothing links to, the exact request a
# ffuf run just made — is not in its reach. Those are precisely what the proxy already recorded.
# MEASURED 2026-08-04: one captured endpoint, 376 attack requests, one live High SQL injection.
# --------------------------------------------------------------------------- #
#: ZAP's own words for how bad an alert is -> the severity vocabulary state.models.Finding uses.
#: NOT reusable from parsers._ZAP_RISK, which maps the REPORT's numeric `riskcode` ("0".."3").
#: The API says `risk: "High"`. Two shapes, two maps; see :func:`alerts_from` and spec §2.3.
_RISK_TO_SEVERITY = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
    "info": "info",
}


class ScanStartRequest(BaseModel):
    """Start an ACTIVE SCAN against one URL the proxy already captured."""

    target_url: str = Field(
        description="The URL to attack. It must already be in ZAP's Sites tree — i.e. something "
        "the proxy recorded. ZAP itself answers 'url_not_found' otherwise (measured), which is "
        "why this feature can only ever aim at traffic that already passed through the proxy."
    )
    port: int = Field(DEFAULT_PROXY_PORT, ge=1024, le=65535)
    recurse: bool = Field(
        False,
        description="Also attack everything below this URL in the tree. Same host either way — "
        "a subtree is same-origin — so this changes how MUCH attack traffic runs, not where it "
        "goes. The approved surface declares `-quickurl`, which means spider-then-scan, so it "
        "already describes more aggression than recursing over an existing tree.",
    )
    engagement_id: str | None = Field(
        None, description="Engagement to attribute against. OMIT for LAB mode."
    )
    # THE GATE FIELDS. Both default False so an omitted field is REFUSED, never granted.
    approved: bool = Field(False, description="Explicit human approval. Never defaulted true.")
    dangerous_ack: bool = Field(
        False,
        description="The explicit red-confirm. This sends real SQLi/XSS/command-injection "
        "payloads at every parameter of the target — 376 requests against a single endpoint in "
        "the measurement. Always required.",
    )

    @field_validator("target_url")
    @classmethod
    def _must_be_http(cls, v: str) -> str:
        """Refuse anything that is not an http(s) URL, before any gate runs.

        Not defence in depth for its own sake: the gate surface is ``-quickurl <target>`` and the
        scope extractor reads a HOST out of it. A ``file://`` or bare string has no host, so it
        would reach the target gate as a target-less command and be refused for a confusing
        reason — or, in engagement mode where target-less commands are permitted, be refused by
        nothing here at all and only bounce off ZAP. Refusing the shape up front means the
        surface the gate sees always contains a real host.
        """
        v = (v or "").strip()
        if not v.lower().startswith(("http://", "https://")):
            raise ValueError("target_url must be an http:// or https:// URL")
        return v


class Scan(BaseModel):
    """One active scan. Every count here is READ BACK FROM ZAP, never assigned at launch."""

    id: str
    container: str
    port: int
    target_url: str = ""
    recurse: bool = False
    state: str = Field(
        "", description="ZAP's own word: RUNNING | PAUSED | FINISHED | STOPPED. Observed."
    )
    progress: int = 0
    requests: int = Field(0, description="Attack requests ZAP has sent for this scan.")
    alerts: int = 0
    started_at: str = ""
    engagement_id: str | None = None


class ScanAlert(BaseModel):
    """One alert as the API reports it.

    *** NOT the shape `state/parsers.py::parse_zap` reads, and that is the trap of this build. ***
    That parser handles the `-quickurl` REPORT: nested under `site[].alerts[]`, severity in
    `riskcode` ("0".."3"), plugin in `pluginid`, the URL down in `instances[].uri`. The API
    returns a FLAT list with `risk: "High"`, `pluginId`, and `url` on the alert itself. Feeding an
    API response to `parse_zap` returns ZERO findings silently — `_zap_report()` requires a `site`
    key — which is part 1's headline trap (a parser matched against a string nobody measured)
    wearing new clothes. A test asserts the two are NOT interchangeable so this cannot be
    "simplified" into one function by someone who has not measured both.
    """

    id: str = ""
    name: str = ""
    risk: str = ""
    confidence: str = ""
    url: str = ""
    method: str = "GET"
    param: str = ""
    evidence: str = ""
    attack: str = ""
    plugin_id: str = ""
    cwe_id: str = ""
    description: str = ""
    solution: str = ""


# --------------------------------------------------------------------------- #
# the gate — the same four gates, given an honest surface
# --------------------------------------------------------------------------- #
def scan_target_for(req: ScanStartRequest) -> str:
    """*** THE SINGLE DERIVATION OF WHAT GETS ATTACKED. ***

    Part 2's lock was "the gated argv is the spawned argv". **That lock cannot be restated here**,
    because the gate classifies an ARGV and what executes is a URL — asserting string equality
    between the two would be theatre. The property underneath it still holds and is what matters:
    *the thing the gate scoped is the thing that gets attacked*.

    So both sides come through this one function: :func:`_gate_scan_request` puts its output in
    the surface the scope extractor reads, and :func:`scan_url_for` percent-encodes the SAME
    output into ZAP's ``url=`` parameter. A test asserts the host the gate scoped is the host the
    API attacks, for a target carrying a port, a path and a query string.
    """
    return req.target_url.strip()


def scan_argv_for(req: ScanStartRequest) -> list[str]:
    """The command this scan is EQUIVALENT TO, which is what the human approves.

    ``-quickurl`` is defined in ``allowlist._TOOL_ATTACK_FLAGS`` as "spider THEN ACTIVE SCAN —
    real SQLi/XSS/command-injection payloads at every parameter it discovered". An
    ``ascan/action/scan`` is that attack MINUS the spider, aimed at a tree the proxy already
    built. So the declared command describes strictly MORE than what runs.

    That direction is the whole argument. Declaring more aggression than you perform is safe;
    declaring less is the Critical 2 defect. This surface therefore needs none of the omissions
    the DAEMON surface needed (:func:`_gate_request` drops ``-host 127.0.0.1`` so the scope
    extractor does not refuse our own socket) — there is no bind address in it, so the whole argv
    goes to the gate exactly as written.
    """
    return ["zaproxy", "-quickurl", scan_target_for(req)]


def scan_url_for(req: ScanStartRequest) -> str:
    """The API path+query that launches the scan.

    *** WHY THE TARGET IS PERCENT-ENCODED, AND WHY THAT IS A SAFETY CONTROL ***

    The operator-supplied target is interpolated into a URL that carries THE SCAN'S OWN
    PARAMETERS. A target containing ``&recurse=true`` would append to ZAP's parameter list and
    turn recursion on — the human approves one scan and a broader one runs. That is Critical 2
    expressed in a query string rather than an argv, and nothing about a text field stops a ``&``.

    ``quote(safe="")`` encodes ``&``, ``=``, ``?`` and ``#``, so the target cannot escape its own
    parameter into ZAP's parser. A test asserts a target carrying ``&recurse=true`` does not
    enable recursion, with a control proving the parameter can still be set legitimately.

    (Shell injection is a separate and already-closed question: :func:`_api_get` hands argv to
    ``subprocess.run`` as a LIST with no shell, as part 2 established.)

    ``inScopeOnly=false`` because HackPit does not configure ZAP CONTEXTS — with none defined,
    ZAP considers nothing in scope and the parameter would refuse every scan. Scope is enforced
    where it belongs, at HackPit's own target gate (:func:`validate_scan`), which reads the real
    host out of the surface. Do not "tighten" this to true without first defining contexts; it
    would not add a control, it would remove the feature.
    """
    target = quote(scan_target_for(req), safe="")
    return (
        f"{_ACTION_SCAN}?url={target}"
        f"&recurse={'true' if req.recurse else 'false'}"
        f"&inScopeOnly=false"
    )


def _gate_scan_request(req: ScanStartRequest):
    """The ExecRequest the real gates run against. The FULL equivalent argv, nothing omitted."""
    from .models import ExecRequest

    argv = scan_argv_for(req)
    return ExecRequest(
        command=argv[0],
        args=argv[1:],
        approved=req.approved,
        dangerous_ack=req.dangerous_ack,
        engagement_id=req.engagement_id,
    )


def validate_scan(req: ScanStartRequest):
    """The gate verdict for this scan, attacking nothing. PURE.

    All four lab gates run, in the executor's order and unchanged. MEASURED against the real
    validator (spec §2.4): an unapproved scan is refused at ``approval``; one without the
    red-confirm at ``danger`` ("active web scan"); and a target outside the lab at ``target``
    ("'example.com' is not the lab") — so the existing scope extractor reads the host out of a
    full URL with a port and a query string, and no new gate is needed or added.
    """
    from . import executor

    return executor.validate_request(_gate_scan_request(req))


# --------------------------------------------------------------------------- #
# scan lifecycle
# --------------------------------------------------------------------------- #
_scans: dict[str, Scan] = {}


def _scan_key(container: str, port: int, scan_id: str) -> str:
    return f"{container}:{port}:{scan_id}"


def _json(raw: str) -> dict[str, Any]:
    try:
        obj = json.loads(raw)
    except (ValueError, TypeError):
        return {}
    return obj if isinstance(obj, dict) else {}


def observed_scans(container: str, port: int) -> list[Scan]:
    """Every scan ZAP knows about, as ZAP reports it. OBSERVED — nothing here is remembered.

    MEASURED row shape: ``{"reqCount","alertCount","progress","newAlertCount","id","state"}``.
    ``target_url`` and ``recurse`` are not in it — ZAP does not report what a scan was aimed at —
    so those are merged back in from :data:`_scans` when this process is the one that started it,
    and left empty when it is not. Empty is the honest answer after a backend restart; inventing
    a target would be worse than admitting we no longer know it.
    """
    rows = _json(_api_get(container, port, _VIEW_SCANS)).get("scans")
    if not isinstance(rows, list):
        return []
    out: list[Scan] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        sid = str(row.get("id", ""))
        if not sid:
            continue
        remembered = _scans.get(_scan_key(container, port, sid))
        out.append(Scan(
            id=sid, container=container, port=port,
            target_url=remembered.target_url if remembered else "",
            recurse=remembered.recurse if remembered else False,
            state=str(row.get("state") or ""),
            progress=_int(row.get("progress")),
            requests=_int(row.get("reqCount")),
            alerts=_int(row.get("alertCount")),
            started_at=remembered.started_at if remembered else "",
            engagement_id=remembered.engagement_id if remembered else None,
        ))
    return out


def _int(raw: Any) -> int:
    try:
        return int(str(raw or "0"))
    except (TypeError, ValueError):
        return 0


def is_running(scan: Scan) -> bool:
    """A scan that could still send attack traffic — i.e. one that must block a second scan.

    ``PAUSED`` counts as running. What is being bounded is CONCURRENT attack traffic, and a
    paused scan can be resumed at any moment, so treating it as finished would let a second scan
    start and then have the first one wake up underneath it.

    ``FINISHED`` and ``STOPPED`` never block, whatever ``progress`` says — a scan stopped at 40%
    is over, and refusing new work because of it would make :func:`stop_scan` a trap.

    The ``progress < 100`` clause exists for the converse: ZAP reports state and progress
    independently, so a row that has reached 100% but not yet flipped its state must not block.
    """
    return scan.state.upper() in {"RUNNING", "PAUSED"} and scan.progress < 100


def start_scan(req: ScanStartRequest) -> Scan:
    """Start an active scan. GATED — nothing is attacked on a refusal.

    Order is the point: validate, then check the world, then act. The gate runs FIRST and against
    the equivalent argv, so a refusal happens before ZAP is contacted at all.
    """
    rejected = validate_scan(req)
    if rejected is not None:
        raise ProxyRefused(rejected.reason, gate=rejected.gate,
                           dangerous_flags=list(rejected.dangerous_flags))

    container = container_for(req)
    if not _container_running(container):
        raise ProxyRefused(
            f"sandbox '{container}' is not running — bring the stack up "
            "(docker compose -f docker/docker-compose.yml up -d)"
        )

    # ONE SCAN AT A TIME, decided by OBSERVATION rather than by a local flag. A second concurrent
    # scan doubles the attack traffic against a target the operator approved once; a backend dict
    # would lose that fact across a restart, while ZAP always knows. Same principle as
    # lifecycle.observe: status is observed, never assigned.
    live = [s for s in observed_scans(container, req.port) if is_running(s)]
    if live:
        raise ProxyRefused(
            f"a scan is already running on {container}:{req.port} "
            f"(id {live[0].id}, {live[0].progress}%, {live[0].requests} requests sent) — "
            "stop it first, or wait for it to finish",
            gate="limit",
        )

    raw = _api_get(container, req.port, scan_url_for(req), timeout=30)
    body = _json(raw)

    if not body:
        raise ProxyRefused(
            f"the ZAP API on {container}:{req.port} did not answer — is the recording proxy "
            f"running on that port? (raw: {raw[:200]!r})"
        )
    if "code" in body:
        code = str(body.get("code"))
        if code == "url_not_found":
            raise ProxyRefused(
                f"ZAP has never seen {scan_target_for(req)} — the active scanner can only attack "
                "URLs already in its Sites tree. Proxy a request to it first (run a tool with "
                "proxy: true, or check the history panel for the exact URL that was captured).",
                gate="notfound",
            )
        raise ProxyRefused(f"ZAP refused the scan: {code} — {body.get('message', '')}")

    sid = str(body.get("scan", "")).strip()
    if not sid:
        raise ProxyRefused(f"ZAP returned no scan id: {raw[:200]!r}")

    model = Scan(
        id=sid, container=container, port=req.port,
        target_url=scan_target_for(req), recurse=req.recurse,
        state="RUNNING", progress=0, requests=0, alerts=0,
        started_at=_now(), engagement_id=req.engagement_id,
    )
    with _lock:
        _scans[_scan_key(container, req.port, sid)] = model
    # and immediately replace the assumed state with an observed one, so a scan that died on
    # arrival is never reported as RUNNING just because we launched it.
    return scan_status(container, req.port, sid) or model


def scan_status(container: str, port: int, scan_id: str) -> Scan | None:
    """One scan as ZAP currently reports it. READ-ONLY, UNGATED — a progress bar polls."""
    for scan in observed_scans(container, port):
        if scan.id == str(scan_id):
            return scan
    return None


def stop_scan(container: str, port: int, scan_id: str) -> Scan | None:
    """Stop an in-flight scan.

    NOT GATED, deliberately, and this is the strongest case in the codebase for that position:
    an active scan is sending hundreds of attack requests per endpoint right now, so this is the
    panic button. A gate that can refuse to press it is a gate that makes the system less safe —
    the same position tunnels.py and :func:`stop_proxy` take. It is the ONE action URL this
    module issues without approval, and the constant block says so.
    """
    _api_get(container, port, f"{_ACTION_STOP}?scanId={quote_plus(str(scan_id))}", timeout=20)
    return scan_status(container, port, scan_id)


# --------------------------------------------------------------------------- #
# alerts — READ-ONLY and UNGATED
# --------------------------------------------------------------------------- #
def parse_alert(obj: Any) -> ScanAlert | None:
    """One API alert -> :class:`ScanAlert`. NEVER raises; returns None if unusable.

    Tolerant on purpose, for the same reason :func:`parse_message` is: a parser must never break
    a run that already happened. An alert with a name is worth keeping even if every other field
    is missing, so only a missing name discards it.
    """
    try:
        if not isinstance(obj, dict):
            return None
        name = str(obj.get("name") or obj.get("alert") or "").strip()
        if not name:
            return None
        return ScanAlert(
            id=str(obj.get("id", "")),
            name=name,
            risk=str(obj.get("risk") or ""),
            confidence=str(obj.get("confidence") or ""),
            url=str(obj.get("url") or ""),
            method=str(obj.get("method") or "GET").upper(),
            param=str(obj.get("param") or ""),
            evidence=str(obj.get("evidence") or "")[:2000],
            attack=str(obj.get("attack") or "")[:2000],
            plugin_id=str(obj.get("pluginId") or obj.get("pluginid") or ""),
            cwe_id=str(obj.get("cweid") or ""),
            description=str(obj.get("description") or "")[:4000],
            solution=str(obj.get("solution") or "")[:4000],
        )
    except Exception:  # noqa: BLE001 - a parser must never break a completed scan
        return None


def scan_alerts(container: str, port: int, base_url: str = "",
                start: int = 0, count: int = 50) -> list[ScanAlert]:
    """Alerts ZAP is holding. READ-ONLY and UNGATED, like :func:`history`.

    NOT SCAN-SCOPED, and the caller should know it: ``core/view/alerts`` returns everything ZAP
    has, INCLUDING passive-scan alerts raised merely by traffic passing through the proxy (the
    committed fixture's Cross-Domain Misconfiguration came from ``sourceid: 3``, the passive
    scanner, with no active scan involved). Alerts also SURVIVE ``removeAllScans`` — both
    measured. ``base_url`` narrows by site, which is the only scoping the API offers.
    """
    query = f"?start={int(start)}&count={int(count)}"
    if base_url:
        query += f"&baseurl={quote_plus(base_url)}"
    rows = _json(_api_get(container, port, _VIEW_ALERTS + query, timeout=20)).get("alerts")
    if not isinstance(rows, list):
        return []
    parsed = [parse_alert(a) for a in rows]
    return [a for a in parsed if a is not None]


def findings_from(alerts, session_id: str, run_id: str | None = None):
    """Alerts -> Finding records. Existing model, no schema change.

    The severity map is :data:`_RISK_TO_SEVERITY` and NOT ``parsers._ZAP_RISK`` — see
    :class:`ScanAlert` for why those are two different vocabularies over the same concept.
    ``reference`` is the plugin id in the same ``pluginid:NNNNN`` spelling ``parse_zap`` writes,
    so an alert found by BOTH paths fingerprints to one finding instead of two.
    """
    from state.models import Finding

    out = []
    for a in alerts:
        if a is None or not a.name.strip():
            continue
        out.append(Finding(
            session_id=session_id,
            title=a.name,
            severity=_RISK_TO_SEVERITY.get(a.risk.strip().lower(), "info"),
            target=a.url,
            tool="zap",
            reference=f"pluginid:{a.plugin_id}" if a.plugin_id else "",
            evidence=(a.evidence or a.attack)[:2000],
            source_run_id=run_id,
        ))
    return out


def alert_endpoints_from(alerts, session_id: str, run_id: str | None = None):
    """Alerts -> Endpoint records: the parameter ZAP attacked is the one worth remembering."""
    from urllib.parse import parse_qs, urlparse

    from state.models import Endpoint

    out = []
    for a in alerts:
        if a is None or not a.url.startswith("http"):
            continue
        params = sorted(parse_qs(urlparse(a.url).query).keys())
        if a.param and a.param not in params:
            params = sorted([*params, a.param])
        out.append(Endpoint(
            session_id=session_id, url=a.url, method=a.method or "GET",
            params=params, source_run_id=run_id,
        ))
    return out
