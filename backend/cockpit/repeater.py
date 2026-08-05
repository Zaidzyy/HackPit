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
have. That listener shipped as the OOB canary (build #13 part 3) and now has two backends — a
self-hosted VPS canary and interact.sh. The repeater still only sends and reads the direct
response; it is not a collaborator, and nothing here imports the OOB modules. A payload minted
by the canary panel reaches this surface as pre-filled text the operator sends by hand.
"""

from __future__ import annotations

import subprocess
import threading
import uuid
from collections import OrderedDict, deque
from datetime import datetime, timezone
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from . import config, cookiejar, engagement, loot, runstore, scope as scope_mod
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
    # *** THE COOKIE JAR (build #19 item 2) — ON BY DEFAULT, AND DISCLOSED ON EVERY SEND. ***
    # Defaulting this False would have left the feature switched off for everyone who did not
    # know it existed, and the thing it fixes — every authenticated flow breaking on the SECOND
    # request — is the common case rather than the exotic one. What pays for the default is that
    # the exchange REPORTS every attached cookie, where it came from and what it suppressed, so
    # the state cannot change a request invisibly. See cockpit/cookiejar.py.
    use_cookie_jar: bool = Field(
        True,
        description="Attach stored cookies matching this URL, and store any Set-Cookie from the "
        "response. Set false to send with NO session — testing what an unauthenticated caller "
        "sees is a real test, and it must not need the jar to be emptied first.",
    )
    # *** PAYLOAD SHAPING (build #18 item 4) — AN OPTION, NOT A GATE. ***
    # No confirm, no acknowledgement and no refusal if unset. The repeater is human-only by
    # construction and a human clicking Send IS the approval; this changes the bytes of a request
    # that human already composed. See cockpit/shaping.py for why it lives here and NOT in the
    # active scanner (short version: ZAP's API exposes no arbitrary payload transform, so a knob
    # there would have been a switch with nothing behind it).
    shapes: list[str] = Field(
        default_factory=list,
        description="Transforms to apply to every [[…]] span in the URL and body, in order — "
        "e.g. ['sql-comment', 'url-encode']. Plus the request-level 'param-pollution' and "
        "'chunked'. An unknown name is REPORTED and skipped, never refused. With no shapes the "
        "markers are simply stripped, which is the control half of any shaped-vs-unshaped "
        "measurement: the two requests then differ in the shaping and in nothing else.",
    )


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
    #: *** THE REQUEST AS SHAPED — WHAT ACTUALLY WENT ON THE WIRE. ***
    #: `request` above is what the operator composed, markers and all. These two are the result,
    #: and they are reported rather than left to be inferred: a shaped request that comes back 200
    #: is only evidence if you can see the bytes that produced it. This is the same rule as
    #: reading the browser id back out of ZAP instead of echoing what was set.
    sent_url: str = ""
    sent_body: str = ""
    shapes_applied: list[str] = Field(default_factory=list)
    shape_warnings: list[str] = Field(
        default_factory=list,
        description="Shapes that did nothing, and why — an unknown name, or a request-level "
        "shape with nothing to act on. WARN AND CONTINUE: the request was still sent.",
    )
    #: *** THE JAR'S DISCLOSURE. A HEADER THE OPERATOR DID NOT TYPE HAS TO EXPLAIN ITSELF. ***
    #: `cookies` carries NO VALUES — only the name, the domain and path it was stored under, and
    #: the response that set it. See cookiejar.CookieAttachment for why there is no value field:
    #: this object is serialised into an API response and a run record renders into a REPORT, and
    #: never handing a credential over cannot regress.
    cookies_attached: list["cookiejar.CookieAttachment"] = Field(default_factory=list)
    cookies_stored: list["cookiejar.CookieAttachment"] = Field(
        default_factory=list,
        description="Cookies this response's Set-Cookie headers put INTO the jar. Names only.",
    )
    cookie_warnings: list[str] = Field(
        default_factory=list,
        description="Cookies the operator's own Cookie: header suppressed, Secure cookies "
        "withheld from an http URL, and anything unparseable. WARN AND CONTINUE throughout.",
    )
    cookie_jar_used: bool = Field(
        True, description="False when the send deliberately went WITHOUT the jar."
    )


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
def _scope_check(req: RepeaterRequest, url: str) -> None:
    """Refuse an out-of-scope host when the send names an active engagement. Fail closed.

    Mirrors the executor's model: scope binds ONLY in engagement mode. Without an active
    engagement, no scope applies (the repeater runs free, like :kali). With one, the URL host
    must be in the program scope — an out-of-scope send raises and nothing runs.

    *** ``url`` IS THE SHAPED URL, NOT ``req.url``, AND THAT IS LOAD-BEARING (build #18). ***
    Shaping rewrites ``[[…]]`` spans, and nothing stops an operator from marking a span inside
    the HOST. Checking the composed URL and sending a different one would be the same defect the
    proxy module calls "the gated argv is not the spawned argv" and the scanner calls "the thing
    the gate scoped is the thing that gets attacked" — a scope check on bytes that never went on
    the wire. So the check runs on the outgoing URL, which is also why :func:`shape_request` is
    pure and runs before this.
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
    host = scope_mod.bare_host(url)
    if not host:
        raise RepeaterRefused(f"could not read a host from the URL {url!r}")
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


def shape_request(req: RepeaterRequest) -> tuple[str, str, list[str], list[str]]:
    """``(url, body, shapes_applied, warnings)`` — the request as it will go on the wire. PURE.

    Split out of :func:`send` so a UI can PREVIEW the shaped bytes without sending anything, and
    so the property "the thing you were shown is the thing that was sent" is one function rather
    than two implementations. It spawns nothing.

    WARN AND CONTINUE everywhere. An unknown shape name, a ``param-pollution`` on a URL with no
    query string, a ``chunked`` on a request with no body — each is reported and the request goes
    anyway. A refusal here would be a prohibition invented by the tooling, which is exactly what
    build #17 had to strip three of.
    """
    from . import shaping

    warnings: list[str] = []
    url, unknown_url = shaping.apply_shapes(req.url, req.shapes)
    body, unknown_body = shaping.apply_shapes(req.body, req.shapes)
    for name in dict.fromkeys(unknown_url + unknown_body):
        warnings.append(
            f"unknown shape {name!r} — skipped. Known: {', '.join(sorted(shaping.known_shapes()))}"
        )

    applied = [s for s in req.shapes if s in shaping.VALUE_TRANSFORMS]
    marked = shaping.has_marker(req.url) or shaping.has_marker(req.body)
    if applied and not marked:
        warnings.append(
            f"no {shaping.SHAPE_OPEN}…{shaping.SHAPE_CLOSE} span in the URL or body, so the "
            "value transforms had nothing to act on — mark the payload and send again"
        )

    if "param-pollution" in req.shapes:
        polluted = shaping.pollute_query(url)
        if polluted == url:
            warnings.append(
                "'param-pollution' had no effect — the URL carries no query string to duplicate"
            )
        else:
            url = polluted
            applied.append("param-pollution")
    if "chunked" in req.shapes:
        if body:
            applied.append("chunked")
        else:
            warnings.append("'chunked' had no effect — this request has no body")
    return url, body, applied, warnings


#: A `Cookie:` header the operator typed. Split on ';' and read the names to the left of '='.
def typed_cookie_names(req: RepeaterRequest) -> frozenset[str]:
    """Cookie NAMES already present in a composed `Cookie:` header. Those beat the jar's copies.

    Duplicate `Cookie:` headers are read as well as one — curl sends them all, so pretending only
    the first exists would make the jar suppress the wrong set.
    """
    names: set[str] = set()
    for h in req.headers:
        if h.name.strip().lower() != "cookie":
            continue
        for pair in (h.value or "").split(";"):
            name, sep, _ = pair.strip().partition("=")
            if sep and name.strip():
                names.add(name.strip())
    return frozenset(names)


def _build_curl(req: RepeaterRequest, sentinel: str, *, url: str, has_body: bool,
                chunked: bool = False, cookie_header: str = "") -> list[str]:
    """The curl argv for one request. Every request field is a discrete argv token.

    ``url`` and ``has_body`` are PASSED IN rather than read off ``req``, because after build #18
    they are the SHAPED values and the request object still holds what the operator typed. One
    derivation, one thing on the wire — the same reason ``server_argv_for`` in proxy.py is the
    single source for the daemon's argv.
    """
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
    # *** ONE `Cookie:` HEADER, NEVER TWO, AND THAT IS NOT A STYLE CHOICE. ***
    # RFC 6265 §5.4 is explicit that a user agent MUST NOT attach more than one Cookie header,
    # and servers disagree about what to do when one arrives: some concatenate, some read the
    # first and drop the rest. Emitting the jar as a second `-H "Cookie: …"` would therefore
    # produce a request whose meaning depends on the target's parser — a silent wrong answer of
    # exactly the shape this repo keeps finding. So when the jar contributes, the operator's
    # typed cookies and the jar's are joined into a single header, operator's first.
    #
    # WHEN THE JAR CONTRIBUTES NOTHING THE HEADERS GO OUT EXACTLY AS TYPED — duplicates included.
    # Two Cookie headers may be precisely what an operator is testing, and this must not be the
    # code that quietly decides they may not.
    typed_cookie_values = [h.value for h in req.headers if h.name.strip().lower() == "cookie"]
    for h in req.headers:
        name = h.name.strip()
        if not name:
            continue
        if cookie_header and name.lower() == "cookie":
            continue                       # folded into the single header emitted below
        # `curl -H "Name: value"` — one token, no shell, so ':' / spaces / etc. are literal.
        argv += ["-H", f"{name}: {h.value}"]
    if cookie_header:
        merged = "; ".join([v.strip().rstrip(";") for v in typed_cookie_values if v.strip()]
                           + [cookie_header])
        argv += ["-H", f"Cookie: {merged}"]

    # Body on STDIN via @- so no request byte ever reaches the argv (or a shell).
    if has_body:
        argv += ["--data-binary", "@-"]
        if chunked:
            # curl chunks the body when Content-Length is suppressed and the header is asked for.
            # A `-H "Transfer-Encoding: chunked"` alone makes curl send BOTH framings on some
            # versions, which is request smuggling by accident rather than a shaped payload; the
            # explicit `Content-Length:` removal is what makes it one framing.
            argv += ["-H", "Transfer-Encoding: chunked", "-H", "Content-Length:"]

    # A metadata trailer curl appends AFTER the body — the reliable source of status + timing,
    # independent of how the header/body split parses.
    argv += ["-w", f"\n{sentinel} %{{http_code}} %{{time_total}} %{{size_download}} %{{url_effective}}\n"]
    argv.append(url)
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

    *** THE COOKIE JAR IS APPLIED HERE AND DISCLOSED ON THE EXCHANGE (build #19 item 2). ***
    Cookies matching the SHAPED url are attached, this response's `Set-Cookie` headers are stored
    against the FINAL url, and both are reported by name on the returned exchange. No cookie
    VALUE reaches the exchange, the run record or anything downstream of them — see
    cockpit/cookiejar.py, and note that the run record below still carries only the method, the
    URL and the shapes, because `report.py` renders a run record's argv verbatim into a report.
    """
    method = req.method.strip().upper()
    if method not in _METHODS:
        raise RepeaterRefused(f"unsupported method {req.method!r}")
    # SHAPE FIRST — everything after this point, including the scope check, reasons about the
    # bytes that will actually go on the wire. :func:`shape_request` is pure and sends nothing.
    sent_url, sent_body, shapes_applied, shape_warnings = shape_request(req)

    parsed = urlparse(sent_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise RepeaterRefused(f"URL must be an absolute http(s) URL — got {sent_url!r}")

    # Scope FIRST (fail closed), then availability. Neither runs anything.
    _scope_check(req, sent_url)
    if not _container_running(config.KALI_OPEN_CONTAINER):
        raise RepeaterRefused(
            f"open sandbox '{config.KALI_OPEN_CONTAINER}' is not running — bring the stack up "
            "(docker compose -f docker/docker-compose.yml up -d)"
        )

    # THE JAR, on the way out. Selection happens on the SHAPED url for the same reason the scope
    # check does: the cookies attached must be the ones matching the host that is actually
    # reached, and nothing stops an operator marking a [[…]] span inside the host.
    jar = cookiejar.jar_for(req.session_id)
    if req.use_cookie_jar:
        selection = jar.select(sent_url, typed_cookie_names(req))
    else:
        selection = cookiejar.CookieSelection()
    cookie_warnings: list[str] = []
    for name in selection.suppressed:
        cookie_warnings.append(
            f"cookie {name!r} is in the jar but you typed it yourself — YOUR value was sent"
        )
    for name in selection.skipped_secure:
        cookie_warnings.append(
            f"cookie {name!r} is marked Secure and this URL is plain http — not attached"
        )

    run_id = uuid.uuid4().hex[:12]
    sent_at = _now()
    sentinel = _SENTINEL_TMPL.format(uuid.uuid4().hex)
    workdir = loot.kali_workdir()
    argv = ["docker", "exec", "-i", *loot.exec_flags(workdir),
            config.KALI_OPEN_CONTAINER,
            *_build_curl(req, sentinel, url=sent_url, has_body=bool(sent_body),
                         chunked="chunked" in shapes_applied,
                         cookie_header=selection.header)]

    resp = RepeaterResponse()
    timeout = config.clamp_timeout(req.timeout_seconds) + 15  # curl enforces --max-time; this is a backstop
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout,
            input=sent_body if sent_body else None,
        )
        resp = _parse_response(proc.stdout, sentinel)
        if proc.returncode != 0 and resp.status is None:
            # curl failed before any response (DNS, refused, TLS) — stderr carries the reason.
            resp.error = (proc.stderr or f"curl exited {proc.returncode}").strip()[:2000]
    except subprocess.TimeoutExpired:
        resp.error = f"send exceeded {timeout}s and was killed"
    except FileNotFoundError:
        resp.error = "docker CLI not found on PATH"

    # ...and on the way back in. `final_url` is preferred over the sent URL because with `-L` the
    # Set-Cookie may have come from the LAST hop, and storing it against the first host would
    # file the session cookie under a domain that never issued it.
    stored: list[cookiejar.CookieAttachment] = []
    if req.use_cookie_jar:
        set_cookies = [h.value for h in resp.headers if h.name.lower() == "set-cookie"]
        if set_cookies:
            origin = resp.final_url or sent_url
            before = {(c.domain, c.path, c.name) for c in jar.cookies()}
            cookie_warnings.extend(jar.ingest(set_cookies, origin))
            stored = [
                cookiejar.CookieAttachment(name=c.name, domain=c.domain, path=c.path,
                                           set_by_url=c.set_by_url, set_at=c.set_at)
                for c in jar.cookies()
                if (c.domain, c.path, c.name) not in before or c.set_by_url == origin
            ]

    exchange = RepeaterExchange(
        id=uuid.uuid4().hex[:12], run_id=run_id, request=req, response=resp,
        sent_at=sent_at, container=config.KALI_OPEN_CONTAINER, session_id=req.session_id,
        sent_url=sent_url, sent_body=sent_body,
        shapes_applied=shapes_applied, shape_warnings=shape_warnings,
        cookies_attached=selection.attached, cookies_stored=stored,
        cookie_warnings=cookie_warnings, cookie_jar_used=req.use_cookie_jar,
    )

    # Audit — recorded like every other run. command="http" keeps the log honest about what this
    # is (an HTTP send, not a shell), target = the host reached. THE SHAPED URL IS WHAT IS
    # RECORDED, because the record has to say what was sent rather than what was typed — an audit
    # trail showing the unshaped request would misdescribe every shaped send.
    try:
        runstore.save_run(RunRecord(
            run_id=run_id, command="http", args=[method, sent_url, *shapes_applied],
            target=scope_mod.bare_host(sent_url) or sent_url,
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
