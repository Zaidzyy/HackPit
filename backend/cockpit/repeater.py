"""The HTTP repeater — compose a request, send it, edit and replay (Phase 4 item 3).

The bug-bounty loop is: send a request, look at the response, tweak one header, send it
again. HackPit had no fast surface for that — you dropped to ``:kali`` and hand-wrote curl.
This is the structured version: a request object in, a parsed response out, and a history
you can replay and diff.

CONTAINMENT — the same model as ``:kali`` (cockpit/kali.py), which this deliberately mirrors,
plus a scope check ``:kali`` does not have:

1. HARDCODED CONTAINER. Every send runs inside ``config.KALI_OPEN_CONTAINER`` — the same
   full-reach, unprivileged, human-only sandbox ``:kali`` uses. The container is a code
   constant, NEVER a request field, so nothing in a request can redirect the egress. Using the
   existing open box means NO new egress capability is introduced (option 1, Zaid's decision):
   the alternative — sending from the backend process via httpx — would have created a new
   egress path originating from the Windows HOST, able to reach host-local services. It does
   not exist here.

2. ARGV-ONLY curl, never a shell. Unlike ``:kali``'s ``sh -c``, the request is turned into an
   explicit ``curl`` argv (method, headers, body) and run with ``docker exec … curl …`` — no
   shell parses it, so a header value or URL cannot break out into a second command. The body
   is fed on STDIN (``--data-binary @-``), so even a megabyte body with any bytes in it never
   touches the argv.

3. HUMAN-ONLY. A human clicking Send IS the approval (identical to typing in ``:kali``); there
   is no per-send gate prompt because a request the operator composed and sent needs no second
   confirmation. The flip side is the load-bearing rule: the orchestrator / agent / executor
   MUST have ZERO code path to :func:`send` — nothing in that path imports this module.
   Regression-locked by ``test_repeater_is_human_only`` (scans the source tree).

4. SCOPE-CHECKED. When the send names an active engagement, the URL host is checked against
   that engagement's PROGRAM SCOPE (``scope.py``) and an out-of-scope host is REFUSED — nothing
   is sent. Without an engagement it runs freely, exactly like ``:kali`` (Zaid runs ``:kali``
   unbounded by decision); the scope check is an addition for the bug-bounty case, never a
   loosening of anything.

5. AVAILABILITY + AUDIT + LIMITS. If the open sandbox is not up, the send refuses and nothing
   runs. Every send is recorded to the run store (audit) and kept in a per-session history for
   replay/diff, with a response-size cap and the shared timeout ceiling.

Callbacks note: a repeater cannot receive a blind out-of-band callback (SSRF/XXE/blind RCE)
because those come back to a PUBLICLY reachable listener, which a laptop behind NAT does not
have. That is the VPS-for-callbacks piece — its own decision (D2), still deferred until bounty
work needs it. The repeater sends and reads the direct response; it is not a collaborator.
"""

from __future__ import annotations

import subprocess
import threading
import uuid
from collections import OrderedDict, deque
from datetime import datetime, timezone
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from . import config, engagement, loot, runstore, scope as scope_mod
from .models import RunRecord

# Response-body cap (chars). A repeater response is meant to be read; a multi-MB download is
# truncated (marked) rather than held whole.
REPEATER_BODY_CAP = 500_000
# How many exchanges to keep per session for the history panel. Older ones fall off the end.
REPEATER_HISTORY_MAX = 200

# Methods the repeater will send. A conservative allowlist — this is an argv, not a shell, but
# an unknown method string as `-X` is refused rather than passed through.
_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"}

_DEFAULT_UA = "HackPit-Repeater/1.0"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------- #
# request / response models
# --------------------------------------------------------------------------- #
class RepeaterHeader(BaseModel):
    """One request header. A list of these (not a dict) so duplicate/ordered headers survive."""

    name: str = Field(..., min_length=1)
    value: str = ""


class RepeaterRequest(BaseModel):
    """A composed HTTP request. NO container/target field — the box is a constant (rule #1)."""

    method: str = Field("GET", description="HTTP method (GET/POST/…).")
    url: str = Field(..., min_length=1, description="Absolute URL, e.g. https://host/path.")
    headers: list[RepeaterHeader] = Field(default_factory=list)
    body: str = Field("", description="Request body (sent on stdin, so any content is safe).")
    follow_redirects: bool = Field(False, description="curl -L.")
    insecure: bool = Field(
        False, description="curl -k — accept a self-signed / invalid TLS cert (labs, staging)."
    )
    http2: bool = Field(False, description="Offer HTTP/2 (curl --http2).")
    timeout_seconds: int | None = Field(
        None, ge=1, description="Per-send timeout; omitted uses the 180s default, clamped to 3600."
    )
    engagement_id: str | None = Field(
        None, description="When set + active, the URL host is scope-checked; out-of-scope refused."
    )
    session_id: str | None = Field(None, description="Engagement to record + keep history against.")


class RepeaterResponseHeader(BaseModel):
    name: str
    value: str


class RepeaterResponse(BaseModel):
    status: int | None = Field(None, description="HTTP status code, or null if none was read.")
    http_version: str = ""
    reason: str = ""
    headers: list[RepeaterResponseHeader] = Field(default_factory=list)
    body: str = ""
    body_truncated: bool = False
    size_bytes: int = 0
    time_ms: int = 0
    final_url: str = ""
    error: str = ""


class RepeaterExchange(BaseModel):
    """One send: the request as sent, the parsed response, and its audit ids."""

    id: str
    run_id: str
    request: RepeaterRequest
    response: RepeaterResponse
    sent_at: str
    container: str
    session_id: str | None = None


class RepeaterRefused(RuntimeError):
    """The send was refused BEFORE anything ran — availability or scope. Nothing was sent."""


# --------------------------------------------------------------------------- #
# availability (mirrors kali._container_running — same open box)
# --------------------------------------------------------------------------- #
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
# scope
# --------------------------------------------------------------------------- #
def _scope_check(req: RepeaterRequest) -> None:
    """Refuse an out-of-scope host when the send names an active engagement. Fail closed.

    Mirrors the executor's model: scope binds ONLY in engagement mode. Without an active
    engagement, no scope applies (the repeater runs free, like :kali). With one, the URL host
    must be in the program scope — an out-of-scope send raises and nothing runs.
    """
    if not req.engagement_id:
        return
    eng = engagement.get_active(req.engagement_id)
    if eng is None:
        # An engagement id that names nothing active is fail-closed: do not silently run unbounded.
        raise RepeaterRefused(
            f"engagement {req.engagement_id!r} is not active — re-enter engagement mode, or omit "
            "the engagement id to send without a scope check"
        )
    host = scope_mod.bare_host(req.url)
    if not host:
        raise RepeaterRefused(f"could not read a host from the URL {req.url!r}")
    matcher = engagement.resolved_scope(eng)
    if not matcher.in_scope(host):
        raise RepeaterRefused(
            f"{host} is OUT OF SCOPE for engagement {req.engagement_id} "
            f"({matcher.describe()}) — refused, nothing was sent"
        )


# --------------------------------------------------------------------------- #
# curl argv (argv-only — no shell parses any request field)
# --------------------------------------------------------------------------- #
_SENTINEL_TMPL = "__HACKPIT_REPEATER_{}__"


def _build_curl(req: RepeaterRequest, sentinel: str) -> list[str]:
    """The curl argv for one request. Every request field is a discrete argv token."""
    method = req.method.strip().upper()
    argv = [
        "curl", "-sS",           # silent but show errors
        "-D", "-",               # dump response headers to stdout, ahead of the body
        "-o", "-",               # body to stdout too (explicit; the two interleave predictably)
        "--max-time", str(config.clamp_timeout(req.timeout_seconds)),
        "-X", method,
    ]
    if req.follow_redirects:
        argv.append("-L")
    if req.insecure:
        argv.append("-k")
    if req.http2:
        argv.append("--http2")

    has_ua = any(h.name.strip().lower() == "user-agent" for h in req.headers)
    if not has_ua:
        argv += ["-A", _DEFAULT_UA]
    for h in req.headers:
        name = h.name.strip()
        if not name:
            continue
        # `curl -H "Name: value"` — one token, no shell, so ':' / spaces / etc. are literal.
        argv += ["-H", f"{name}: {h.value}"]

    # Body on STDIN via @- so no request byte ever reaches the argv (or a shell).
    if req.body:
        argv += ["--data-binary", "@-"]

    # A metadata trailer curl appends AFTER the body — the reliable source of status + timing,
    # independent of how the header/body split parses.
    argv += ["-w", f"\n{sentinel} %{{http_code}} %{{time_total}} %{{size_download}} %{{url_effective}}\n"]
    argv.append(req.url)
    return argv


# --------------------------------------------------------------------------- #
# response parsing
# --------------------------------------------------------------------------- #
def _parse_response(raw: str, sentinel: str) -> RepeaterResponse:
    """Split curl's combined output into headers + body, reading status/timing from the trailer."""
    resp = RepeaterResponse()

    # 1) the -w trailer: "<sentinel> <code> <time_total> <size_download> <url>"
    idx = raw.rfind(sentinel)
    if idx != -1:
        trailer = raw[idx + len(sentinel):].strip()
        raw = raw[:idx].rstrip("\n")
        parts = trailer.split(" ", 3)
        if len(parts) >= 3:
            try:
                resp.status = int(parts[0])
            except ValueError:
                resp.status = None
            try:
                resp.time_ms = int(round(float(parts[1]) * 1000))
            except ValueError:
                pass
            try:
                resp.size_bytes = int(parts[2])
            except ValueError:
                pass
            if len(parts) == 4:
                resp.final_url = parts[3].strip()

    # 2) header block(s) then body. With -L there are several header blocks; the FINAL response's
    # headers are the last block that starts with "HTTP/". Segments are separated by a blank line.
    segments = raw.split("\r\n\r\n") if "\r\n\r\n" in raw else raw.split("\n\n")
    last_hdr = -1
    for i, seg in enumerate(segments):
        if seg.lstrip().startswith("HTTP/"):
            last_hdr = i
    if last_hdr == -1:
        # No header block parsed — treat everything as body (still capped).
        resp.body, resp.body_truncated = _cap_body(raw)
        return resp

    header_text = segments[last_hdr]
    body_text = ("\r\n\r\n" if "\r\n\r\n" in raw else "\n\n").join(segments[last_hdr + 1:])

    lines = [ln for ln in header_text.replace("\r\n", "\n").split("\n") if ln.strip()]
    if lines:
        status_line = lines[0]
        bits = status_line.split(" ", 2)
        resp.http_version = bits[0] if bits else ""
        if resp.status is None and len(bits) >= 2:
            try:
                resp.status = int(bits[1])
            except ValueError:
                pass
        if len(bits) == 3:
            resp.reason = bits[2].strip()
        for ln in lines[1:]:
            if ":" in ln:
                name, value = ln.split(":", 1)
                resp.headers.append(RepeaterResponseHeader(name=name.strip(), value=value.strip()))

    resp.body, resp.body_truncated = _cap_body(body_text)
    return resp


def _cap_body(text: str) -> tuple[str, bool]:
    if len(text) > REPEATER_BODY_CAP:
        return text[:REPEATER_BODY_CAP] + "\n…[response body truncated]…", True
    return text, False


# --------------------------------------------------------------------------- #
# history (per session, in-memory ring — the audit trail is the run store)
# --------------------------------------------------------------------------- #
_history: "OrderedDict[str, deque[RepeaterExchange]]" = OrderedDict()
_history_lock = threading.Lock()


def _record_history(exchange: RepeaterExchange) -> None:
    key = exchange.session_id or "_no_session"
    with _history_lock:
        dq = _history.get(key)
        if dq is None:
            dq = deque(maxlen=REPEATER_HISTORY_MAX)
            _history[key] = dq
        dq.appendleft(exchange)


def history(session_id: str | None) -> list[RepeaterExchange]:
    """Most-recent-first exchanges for a session (for the history / replay / diff panel)."""
    key = session_id or "_no_session"
    with _history_lock:
        dq = _history.get(key)
        return list(dq) if dq else []


# --------------------------------------------------------------------------- #
# send
# --------------------------------------------------------------------------- #
def send(req: RepeaterRequest) -> RepeaterExchange:
    """Send one request from inside the open sandbox and return the parsed exchange.

    HUMAN-ONLY — called only from the HTTP route. Refuses (nothing sent) if the open sandbox is
    down or the host is out of scope for a named engagement. Otherwise runs curl argv-only, caps
    and parses the response, records the run for audit and keeps it in the session history.
    """
    method = req.method.strip().upper()
    if method not in _METHODS:
        raise RepeaterRefused(f"unsupported method {req.method!r}")
    parsed = urlparse(req.url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise RepeaterRefused(f"URL must be an absolute http(s) URL — got {req.url!r}")

    # Scope FIRST (fail closed), then availability. Neither runs anything.
    _scope_check(req)
    if not _container_running(config.KALI_OPEN_CONTAINER):
        raise RepeaterRefused(
            f"open sandbox '{config.KALI_OPEN_CONTAINER}' is not running — bring the stack up "
            "(docker compose -f docker/docker-compose.yml up -d)"
        )

    run_id = uuid.uuid4().hex[:12]
    sent_at = _now()
    sentinel = _SENTINEL_TMPL.format(uuid.uuid4().hex)
    workdir = loot.kali_workdir()
    argv = ["docker", "exec", "-i", *loot.exec_flags(workdir),
            config.KALI_OPEN_CONTAINER, *_build_curl(req, sentinel)]

    resp = RepeaterResponse()
    timeout = config.clamp_timeout(req.timeout_seconds) + 15  # curl enforces --max-time; this is a backstop
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout,
            input=req.body if req.body else None,
        )
        resp = _parse_response(proc.stdout, sentinel)
        if proc.returncode != 0 and resp.status is None:
            # curl failed before any response (DNS, refused, TLS) — stderr carries the reason.
            resp.error = (proc.stderr or f"curl exited {proc.returncode}").strip()[:2000]
    except subprocess.TimeoutExpired:
        resp.error = f"send exceeded {timeout}s and was killed"
    except FileNotFoundError:
        resp.error = "docker CLI not found on PATH"

    exchange = RepeaterExchange(
        id=uuid.uuid4().hex[:12], run_id=run_id, request=req, response=resp,
        sent_at=sent_at, container=config.KALI_OPEN_CONTAINER, session_id=req.session_id,
    )

    # Audit — recorded like every other run. command="http" keeps the log honest about what this
    # is (an HTTP send, not a shell), target = the host reached.
    try:
        runstore.save_run(RunRecord(
            run_id=run_id, command="http", args=[method, req.url],
            target=scope_mod.bare_host(req.url) or req.url,
            approved=True,  # a human composing + sending IS the approval
            exit_code=resp.status if resp.status is not None else None,
            stdout=resp.body[:REPEATER_BODY_CAP], stderr=resp.error,
            started_at=sent_at, finished_at=_now(),
            session_id=req.session_id, step_id=None,
        ))
    except Exception:
        pass

    _record_history(exchange)
    return exchange


def status() -> dict:
    """Availability of the repeater's sandbox — drives the UI banner."""
    up = _container_running(config.KALI_OPEN_CONTAINER)
    return {
        "container": config.KALI_OPEN_CONTAINER,
        "up": up,
        "ready": up,
        "detail": "" if up else "open sandbox container is not running",
    }
