"""A per-session cookie jar for the repeater (build #19 item 2).

THE PROBLEM IT SOLVES. The repeater sends one request and reads one response. Every
authenticated flow therefore broke on the SECOND request: the login returned a `Set-Cookie`,
nothing kept it, and the follow-up went out anonymous. The operator's workaround was to copy the
value out of the response pane and paste it into a `Cookie:` header by hand, once per send.

*** THE JAR IS STATE, AND STATE THAT SILENTLY CHANGES A REQUEST IS A TRAP. ***
Everything in this module's design follows from that one sentence:

* :func:`select` returns the ATTACHMENTS, not a header string — each carries the cookie name, the
  domain and path it was stored under, and the URL of the response that set it. The repeater puts
  that list on the exchange, so an operator reading a send can always answer "why is that header
  there" without reading this file.
* **A cookie the operator typed WINS, and the suppression is reported.** An explicit
  `Cookie: session=x` in the composed request is the operator testing a specific value; a jar
  that silently overwrote it would make the request under test unreachable. The jar's copy is
  dropped and :class:`CookieSelection` names it in ``suppressed``.
* **VALUES NEVER LEAVE THIS MODULE except onto the wire.** :class:`CookieAttachment` carries no
  value field at all. That is build #18's rule restated: never handing a secret over cannot
  regress, while redacting it afterwards depends on a redactor being correct forever — and the
  redactor that would have had to be correct here, ``report.py::redact_captured_body``, is not
  called on a run record at all (measured; see the test).

*** WHAT THIS IS NOT. *** It is not a browser. `HttpOnly` is parsed and ignored on purpose: that
flag exists to hide a cookie from *scripts in a page*, and there is no page and no script here.
`SameSite` is parsed and ignored for the same reason — there is no originating navigation to
compare against, so honouring it would mean inventing one.

NOTHING HERE REFUSES ANYTHING. A malformed `Set-Cookie`, a `Domain` the response had no right to
set, an expiry that will not parse — each is skipped or clamped and REPORTED in ``warnings``, and
the send goes anyway. A cookie jar that could refuse a send would be a prohibition invented by
the tooling.
"""

from __future__ import annotations

import re
import threading
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlsplit

from pydantic import BaseModel, Field

#: How many cookies to keep per jar. RFC 6265 §6.1 suggests at least 3000 total / 50 per domain;
#: this is a manual testing tool, not a browser, and an unbounded dict fed by a fuzzing target is
#: a memory leak with a plausible cover story. Oldest-stored falls off first.
JAR_MAX_COOKIES = 500


def _now() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------- #
# models
# --------------------------------------------------------------------------- #
class Cookie(BaseModel):
    """One stored cookie. ``value`` lives here and is never copied into a disclosure model."""

    name: str
    value: str
    domain: str = Field(description="Lower-cased, no leading dot. See :func:`_domain_match`.")
    path: str = "/"
    secure: bool = False
    http_only: bool = Field(False, description="Parsed and IGNORED — we are not a browser.")
    same_site: str = Field("", description="Parsed and IGNORED — there is no navigation to judge.")
    host_only: bool = Field(
        True,
        description="True when the response sent no `Domain` attribute, which per RFC 6265 §5.3 "
        "means the cookie is for THAT EXACT HOST and no subdomain of it.",
    )
    expires: datetime | None = Field(
        None, description="None means a session cookie — kept until the jar is cleared."
    )
    set_at: str = ""
    set_by_url: str = Field("", description="The response that set it. Shown to the operator.")

    def is_expired(self, at: datetime | None = None) -> bool:
        return self.expires is not None and self.expires <= (at or _now())


class CookieAttachment(BaseModel):
    """WHY a `Cookie:` header appeared on a request the operator did not type it on.

    *** THERE IS DELIBERATELY NO ``value`` FIELD. *** This model is what goes on the exchange,
    into the API response and onto the screen. A value here would be a session token in a JSON
    body that anything downstream may log, and the whole point of the disclosure is to explain a
    header rather than to reprint a credential.
    """

    name: str
    domain: str
    path: str
    set_by_url: str = ""
    set_at: str = ""


class CookieSelection(BaseModel):
    """The result of matching a jar against one outgoing URL."""

    header: str = Field("", description="The `Cookie:` header value, or '' for nothing to send.")
    attached: list[CookieAttachment] = Field(default_factory=list)
    suppressed: list[str] = Field(
        default_factory=list,
        description="Cookie NAMES the jar held and did NOT send because the operator typed that "
        "name explicitly. The operator's value wins; this says which ones.",
    )
    skipped_secure: list[str] = Field(
        default_factory=list,
        description="Names held for this host but withheld because they are `Secure` and the "
        "request is plain http. Reported rather than silently dropped.",
    )


# --------------------------------------------------------------------------- #
# parsing
# --------------------------------------------------------------------------- #
#: Attribute names RFC 6265 §5.2 defines. Anything else is ignored (and reported).
_KNOWN_ATTRS = {"expires", "max-age", "domain", "path", "secure", "httponly", "samesite"}

_TOKEN_RE = re.compile(r"^[^=;,\s]+$")


def _parse_expiry(attrs: dict[str, str], warnings: list[str], name: str) -> datetime | None:
    """`Max-Age` beats `Expires` (RFC 6265 §5.3 step 3). A value that will not parse is REPORTED
    and the cookie becomes a session cookie rather than being thrown away."""
    if "max-age" in attrs:
        raw = attrs["max-age"].strip()
        try:
            secs = int(raw)
        except ValueError:
            warnings.append(f"cookie {name!r}: Max-Age {raw!r} is not an integer — kept as a "
                            "session cookie")
        else:
            # A zero or negative Max-Age means "delete now" — an expiry in the past does that
            # through the ordinary expiry path, so there is no second deletion rule to get wrong.
            return _now() + timedelta(seconds=secs)
    if "expires" in attrs:
        raw = attrs["expires"].strip()
        try:
            dt = parsedate_to_datetime(raw)
        except (TypeError, ValueError, IndexError):
            warnings.append(f"cookie {name!r}: Expires {raw!r} is not a date we can read — kept "
                            "as a session cookie")
            return None
        if dt is None:
            return None
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    return None


def _default_path(url: str) -> str:
    """RFC 6265 §5.1.4. The default path is the request path up to (not including) the LAST '/',
    which is NOT the same as the request path — `/a/b` defaults to `/a`, not `/a/b`."""
    path = urlsplit(url).path
    if not path.startswith("/"):
        return "/"
    idx = path.rfind("/")
    return path[:idx] if idx > 0 else "/"


def parse_set_cookie(header_value: str, request_url: str,
                     warnings: list[str] | None = None) -> Cookie | None:
    """One `Set-Cookie` header value -> a :class:`Cookie`, or None if there is nothing usable.

    NEVER RAISES. A header this cannot read is reported in ``warnings`` and skipped; a response
    with one broken cookie among five must still contribute the other four.
    """
    warn = warnings if warnings is not None else []
    raw = str(header_value or "").strip()
    if not raw:
        return None
    parts = raw.split(";")
    nv = parts[0]
    if "=" not in nv:
        warn.append(f"Set-Cookie {raw[:60]!r}: no name=value pair — skipped")
        return None
    name, _, value = nv.partition("=")
    name = name.strip()
    value = value.strip()
    if not name or not _TOKEN_RE.match(name):
        warn.append(f"Set-Cookie {raw[:60]!r}: unusable cookie name — skipped")
        return None

    attrs: dict[str, str] = {}
    for chunk in parts[1:]:
        key, _, val = chunk.partition("=")
        key = key.strip().lower()
        if not key:
            continue
        if key not in _KNOWN_ATTRS:
            warn.append(f"cookie {name!r}: unknown attribute {key!r} — ignored, cookie kept")
            continue
        attrs[key] = val.strip()

    req_host = (urlsplit(request_url).hostname or "").lower()
    domain_attr = attrs.get("domain", "").strip().lstrip(".").lower()
    host_only = not domain_attr
    domain = req_host if host_only else domain_attr

    # *** RFC 6265 §5.3 step 6, AND IT IS A REAL CONTROL RATHER THAN PEDANTRY. ***
    # `evil.example.com` may not set a cookie for `example.com`, and a jar that let it would
    # forward the operator's session for one host onto every request to another. This is the ONE
    # place the jar declines to store something — and it still does not refuse the SEND. It warns,
    # drops that one cookie, and everything else about the exchange proceeds.
    if not host_only and req_host and not _domain_match(req_host, domain):
        warn.append(
            f"cookie {name!r}: {req_host} tried to set Domain={domain!r}, which is not a suffix "
            "of it — not stored (the response is still yours to read)"
        )
        return None

    return Cookie(
        name=name, value=value, domain=domain,
        path=attrs.get("path") or _default_path(request_url),
        secure="secure" in attrs,
        http_only="httponly" in attrs,
        same_site=attrs.get("samesite", ""),
        host_only=host_only,
        expires=_parse_expiry(attrs, warn, name),
        set_at=_now().isoformat(),
        set_by_url=request_url,
    )


# --------------------------------------------------------------------------- #
# matching
# --------------------------------------------------------------------------- #
def _domain_match(host: str, domain: str) -> bool:
    """RFC 6265 §5.1.3. DOT-ANCHORED, for the reason build #18's fronting module records:
    `notexample.com` ends with `example.com` as a string and is a different registrable domain."""
    host = (host or "").lower().rstrip(".")
    domain = (domain or "").lower().lstrip(".").rstrip(".")
    if not host or not domain:
        return False
    return host == domain or host.endswith("." + domain)


def _path_match(req_path: str, cookie_path: str) -> bool:
    """RFC 6265 §5.1.4. `/foo` matches `/foo`, `/foo/bar` and `/foo/`, but NOT `/foobar`."""
    req = req_path or "/"
    cookie = cookie_path or "/"
    if req == cookie:
        return True
    if not req.startswith(cookie):
        return False
    return cookie.endswith("/") or req[len(cookie):].startswith("/")


class CookieJar:
    """A per-session store. Thread-safe; the repeater's routes run on a thread pool."""

    def __init__(self, max_cookies: int = JAR_MAX_COOKIES) -> None:
        self._lock = threading.Lock()
        self._max = max_cookies
        # keyed (domain, path, name) — RFC 6265 §5.3 step 11's identity for "the same cookie"
        self._store: dict[tuple[str, str, str], Cookie] = {}

    # -- write ------------------------------------------------------------- #
    def store(self, cookie: Cookie) -> None:
        key = (cookie.domain, cookie.path, cookie.name)
        with self._lock:
            # An expired cookie DELETES rather than stores — that is how a server logs you out,
            # and a jar that kept it would silently re-authenticate the next request.
            if cookie.is_expired():
                self._store.pop(key, None)
                return
            self._store[key] = cookie
            while len(self._store) > self._max:
                self._store.pop(next(iter(self._store)))

    def ingest(self, set_cookie_values: list[str], request_url: str) -> list[str]:
        """Apply every `Set-Cookie` from one response. Returns the warnings, never raises."""
        warnings: list[str] = []
        for value in set_cookie_values:
            cookie = parse_set_cookie(value, request_url, warnings)
            if cookie is not None:
                self.store(cookie)
        return warnings

    # -- read -------------------------------------------------------------- #
    def cookies(self) -> list[Cookie]:
        with self._lock:
            return list(self._store.values())

    def disclosure(self) -> list[CookieAttachment]:
        """Everything held, WITHOUT VALUES — what the "what is in my jar" panel reads."""
        return [
            CookieAttachment(name=c.name, domain=c.domain, path=c.path,
                             set_by_url=c.set_by_url, set_at=c.set_at)
            for c in sorted(self.cookies(), key=lambda c: (c.domain, c.path, c.name))
        ]

    def select(self, url: str, typed_names: frozenset[str] = frozenset()) -> CookieSelection:
        """The cookies to attach to ``url``, and everything the operator needs to explain them.

        ``typed_names`` are cookie names already present in a `Cookie:` header the operator
        composed. Those WIN — see the module docstring.
        """
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        path = parts.path or "/"
        https = parts.scheme.lower() == "https"
        now = _now()

        sel = CookieSelection()
        if not host:
            return sel

        matched: list[Cookie] = []
        for c in self.cookies():
            if c.is_expired(now):
                continue
            ok_domain = (host == c.domain) if c.host_only else _domain_match(host, c.domain)
            if not ok_domain or not _path_match(path, c.path):
                continue
            if c.secure and not https:
                sel.skipped_secure.append(c.name)
                continue
            if c.name in typed_names:
                sel.suppressed.append(c.name)
                continue
            matched.append(c)

        # RFC 6265 §5.4: longer paths first, then earliest-set first. Servers that read only the
        # first occurrence of a name then get the more specific one, which is the intended reading.
        matched.sort(key=lambda c: (-len(c.path), c.set_at))
        sel.header = "; ".join(f"{c.name}={c.value}" for c in matched)
        sel.attached = [
            CookieAttachment(name=c.name, domain=c.domain, path=c.path,
                             set_by_url=c.set_by_url, set_at=c.set_at)
            for c in matched
        ]
        sel.suppressed.sort()
        sel.skipped_secure.sort()
        return sel

    # -- clear ------------------------------------------------------------- #
    def clear(self) -> int:
        with self._lock:
            n = len(self._store)
            self._store.clear()
            return n


# --------------------------------------------------------------------------- #
# the per-session registry
# --------------------------------------------------------------------------- #
_jars: dict[str, CookieJar] = {}
_jars_lock = threading.Lock()

#: Sends with no ``session_id`` share one jar, under the same key the repeater's history uses.
#: Deliberately NOT a fresh jar per send: an operator poking at a target before entering an
#: engagement still expects the second request to carry the first response's session.
NO_SESSION_KEY = "_no_session"


def jar_for(session_id: str | None) -> CookieJar:
    key = session_id or NO_SESSION_KEY
    with _jars_lock:
        jar = _jars.get(key)
        if jar is None:
            jar = CookieJar()
            _jars[key] = jar
        return jar


def clear_jar(session_id: str | None) -> int:
    """Empty one session's jar; returns how many cookies were dropped."""
    return jar_for(session_id).clear()


def reset_all() -> None:
    """Every jar, gone. For tests and for exiting an engagement — a session cookie for one
    program has no business surviving into the next, which is the same argument the bypass-header
    module makes about the Replacer rule."""
    with _jars_lock:
        _jars.clear()
