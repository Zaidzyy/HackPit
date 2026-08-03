#!/usr/bin/env python3
"""HackPit out-of-band canary — the deployable (build #13 part 3, spec §3.1).

A canary answers the question a blind vulnerability cannot: did anything actually come back
out. Blind SSRF, blind XXE, blind RCE with no output, DNS-exfil SQLi, JNDI callbacks — for
all of them the hit IS the proof, and there is no proof at all without a listener the target
can reach. This file is that listener.

It is ONE FILE and it imports nothing outside the standard library, because it is deployed
by copying it to a VPS you already own. No pip, no venv, no wheel that moves under you a
year later on a box you SSH into once.

DNS MATTERS MORE THAN HTTP
--------------------------
Plenty of targets block outbound HTTP from application servers while DNS still resolves
through their internal resolver, so a DNS canary lands where an HTTP one never will. That is
why the zone is NS-delegated to this server rather than pointed at it with an A record, and
why the DNS half is authoritative rather than a stub.

Every query is answered with a real A record, never NXDOMAIN. That is deliberate: the answer
is what lets a chained proof work — the target resolves `<token>.<zone>`, gets an address,
and the HTTP follow-up lands on the same box and correlates to the same token.

WHY IT IS SAFE TO EXPOSE
------------------------
This is the first HackPit component that faces the internet, and it does so from a machine
holding a client's evidence. The safety argument is not a control, it is an absence:

  * it **records**, and that is all — no execution, no eval, no deserialisation;
  * it **never forwards** — no outbound connection exists in this file, so it cannot be
    turned into a redirector (that is part 4, and a different thing);
  * it **never reflects** request content into a response — the body is a constant;
  * the log is **append-only JSONL** — nothing here can rewrite what was recorded;
  * **reads are authenticated**, because the log holds a target's internal hostnames and
    source addresses. That is the client's information, and an open read endpoint would
    publish it to anyone who guessed the host.

The correlation is not done here. This file records the candidate token it saw; only
HackPit knows which tokens were ever minted, and for which engagement. A canary that knew
would be a canary worth stealing.

Deploy:
    HACKPIT_OOB_TOKEN=<32+ char shared secret> \\
    python3 server.py --zone oob.example.net --answer-ip <this VPS public IP>

Read (from HackPit):
    curl -H "Authorization: Bearer $HACKPIT_OOB_TOKEN" \\
         "http://<host>/_hp/hits?after=0&limit=100"
"""

from __future__ import annotations

import argparse
import hmac
import json
import os
import socket
import struct
import sys
import threading
import time
from collections import namedtuple
from dataclasses import dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# --------------------------------------------------------------------------- #
# constants
# --------------------------------------------------------------------------- #
ENV_READ_SECRET = "HACKPIT_OOB_TOKEN"

DEFAULT_DNS_PORT = 53
DEFAULT_HTTP_PORT = 80
DEFAULT_TTL = 60
DEFAULT_HITS_PATH = "hits.jsonl"

# The read API's prefix. Requests under it are SERVED, never recorded as canary hits: it is
# the operator's own traffic. Nothing minted can collide with it — `_` is not in the token
# alphabet — and no payload template ever renders it.
API_PREFIX = "/_hp/"

TYPE_A, TYPE_NS, TYPE_ANY, CLASS_IN = 1, 2, 255, 1
_QTYPE_NAMES = {1: "A", 2: "NS", 5: "CNAME", 15: "MX", 16: "TXT", 28: "AAAA", 255: "ANY"}

# A UDP DNS response over 512 bytes forces the resolver to retry over TCP, which this server
# does not speak. Nothing built here comes close, and the test proves it for a maximal name.
MAX_DATAGRAM = 512

# Caps. Every one of these bounds attacker-controlled storage: an uncapped canary on a small
# VPS is a disk-fill anyone on the internet can trigger. The body cap is also policy — a
# canary records that something arrived and from where, not a copy of the target's traffic.
MAX_BODY = 512
MAX_BODY_READ = 8192
MAX_HEADERS = 32
MAX_HEADER_NAME = 64
MAX_HEADER_VALUE = 256
MAX_PATH = 1024
MAX_HOST = 256
MAX_METHOD = 16

# Headers whose VALUE is never written down. A blind SSRF routinely arrives carrying the
# target's own credentials — an internal service token, a session cookie, a proxy
# authorisation. The finding needs "an authenticated internal client reached out"; it does
# not need the secret it used, and storing that would make the canary worth breaking into.
REDACTED = "[redacted]"
REDACTED_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "api-key",
        "x-auth-token",
        "x-amz-security-token",
    }
)

# The only thing a canary ever says back. A constant, so no request can steer it.
CANARY_BODY = b"ok\n"

# Read-API paging and rate limiting.
READ_LIMIT_DEFAULT = 100
READ_LIMIT_MAX = 500
RATE_LIMIT = 60
RATE_WINDOW = 60.0
MAX_TRACKED_SOURCES = 4096

# The shared read secret has to be long enough that an internet-facing bearer check is not
# a weekend of guessing. 16 is the floor; the deploy panel generates far more.
MIN_SECRET = 16


class ConfigError(Exception):
    """Refusing to start. Always preferred over starting with a control missing."""


# --------------------------------------------------------------------------- #
# tokens, as this file sees them
# --------------------------------------------------------------------------- #
# The token grammar, duplicated from backend/oob/tokens.py ON PURPOSE: this file is copied
# to a VPS on its own and may not import from the repository. test_oob_server.py holds the
# two together against a real minted population, because the failure mode of drift is
# silent — hits still land, they just stop correlating.
_TOKEN_CHARS = frozenset("abcdefghijkmnpqrstuvwxyz23456789")
_LABEL_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789")


def is_token(value: str) -> bool:
    """True if `value` has the exact shape of a HackPit-minted canary token.

    Strict: 12-63 characters, letter-first, drawn from the minting alphabet. Used where
    POSITION carries no meaning — the first segment of a URL path could be anything, so the
    grammar has to do all the work of telling a canary from a page.
    """
    if not isinstance(value, str) or not 12 <= len(value) <= 63:
        return False
    if value[0] not in _TOKEN_CHARS or value[0].isdigit():
        return False
    return all(c in _TOKEN_CHARS for c in value)


def _is_label(value: str) -> bool:
    """True if `value` is a plain lowercase DNS label — looser than :func:`is_token`.

    Used only for the label sitting immediately left of the authoritative zone, where the
    position already carries the meaning: nothing else can be there. Recording the candidate
    and letting HackPit decide whether it was ever minted keeps every hit in the log,
    including the ones from a token this file has never heard of.
    """
    return bool(value) and len(value) <= 63 and all(c in _LABEL_CHARS for c in value)


def token_from_qname(qname: str, zone: str) -> str | None:
    """The token is the label immediately LEFT OF THE ZONE, not the leftmost label.

    `data.<token>.<zone>` has to correlate, because blind-RCE and DNS-exfil one-liners
    prepend command output to the name. Reading the leftmost label instead would work for
    the bare case and silently fail for every payload that carries data.
    """
    name = (qname or "").strip().rstrip(".").lower()
    root = (zone or "").strip().rstrip(".").lower()
    if not name or not root:
        return None
    suffix = "." + root
    if not name.endswith(suffix):
        return None
    prefix = name[: -len(suffix)]
    if not prefix:
        return None
    label = prefix.split(".")[-1]
    return label if _is_label(label) else None


def token_from_http(host: str, path: str, zone: str) -> str | None:
    """Read the token from the Host subdomain, falling back to the first path segment.

    Some payload sinks take a hostname and some take a URL. The host is tried first because
    a subdomain can only have come from a canary URL; the path fallback is held to the
    strict token grammar because `/anything` is not evidence of anything.
    """
    hostname = (host or "").strip().lower().split(":")[0]
    root = (zone or "").strip().rstrip(".").lower()
    from_host = token_from_qname(hostname, root)
    if from_host:
        return from_host

    first = (path or "").lstrip("/").split("/")[0].split("?")[0]
    in_zone = bool(root) and (hostname == root or hostname.endswith("." + root))
    if not in_zone and not is_token(first):
        # Reached by raw IP with a path that is not a token: recorded, but not attributed.
        return None
    return first if is_token(first) else None


# --------------------------------------------------------------------------- #
# DNS wire format (RFC 1035)
# --------------------------------------------------------------------------- #
Query = namedtuple("Query", "txid rd qname qtype qclass qbytes")


def parse_query(packet: bytes) -> Query | None:
    """Parse a standard DNS question, or return None.

    An open UDP/53 receives malformed and hostile datagrams as its normal traffic, so this
    refuses rather than repairs. Compression pointers are rejected outright: a QUESTION is
    never compressed in practice, so a pointer here is either a broken client or an attempt
    to walk the parser into a loop, and there is no third case worth supporting.

    `qbytes` keeps the question EXACTLY as it arrived so the response can echo it verbatim.
    Resolvers randomise the case of a query as an anti-spoofing measure (DNS 0x20) and
    compare the echo; a re-encoded, lowercased question would be discarded as a spoof.
    """
    if not isinstance(packet, (bytes, bytearray)) or len(packet) < 12:
        return None
    txid, flags, qdcount = struct.unpack(">HHH", bytes(packet[:6]))
    if flags & 0x8000:  # QR set: this is a response, not a question
        return None
    if (flags >> 11) & 0x0F:  # opcode != QUERY (IQUERY, STATUS, NOTIFY, UPDATE)
        return None
    if qdcount != 1:
        return None

    labels: list[bytes] = []
    off = 12
    while True:
        if off >= len(packet):
            return None
        length = packet[off]
        if length == 0:
            off += 1
            break
        if length & 0xC0:  # compression pointer, or a reserved length prefix
            return None
        off += 1
        if off + length > len(packet):
            return None
        labels.append(bytes(packet[off : off + length]))
        off += length
        if len(labels) > 127:
            return None
    if off + 4 > len(packet):
        return None

    qtype, qclass = struct.unpack(">HH", bytes(packet[off : off + 4]))
    qname = ".".join(label.decode("ascii", "replace") for label in labels).lower()
    return Query(txid, bool(flags & 0x0100), qname, qtype, qclass, bytes(packet[12 : off + 4]))


def _pack_ip(address: str) -> bytes:
    parts = (address or "").split(".")
    if len(parts) != 4:
        raise ConfigError(f"--answer-ip must be a dotted-quad IPv4 address, got {address!r}")
    out = bytearray()
    for part in parts:
        if not part.isdigit() or not 0 <= int(part) <= 255:
            raise ConfigError(f"--answer-ip must be a dotted-quad IPv4 address, got {address!r}")
        out.append(int(part))
    return bytes(out)


def build_response(query: Query, answer_ip: str, ttl: int = DEFAULT_TTL) -> bytes:
    """Answer authoritatively with an A record — never NXDOMAIN.

    A refusal would record the DNS half of a chained proof and kill the HTTP half. An
    address is what keeps the second request coming, so the answer is the feature.

    A query for another type (AAAA, TXT, MX) gets NOERROR with no answer rather than a
    refusal, for the same reason: the name stays alive and the client retries for A.
    """
    flags = 0x8400 | (0x0100 if query.rd else 0x0000)  # QR=1, AA=1, RD echoed, RA=0, rcode=0
    answering = query.qtype in (TYPE_A, TYPE_ANY) and query.qclass == CLASS_IN
    out = struct.pack(">HHHHHH", query.txid, flags, 1, 1 if answering else 0, 0, 0)
    out += query.qbytes
    if answering:
        out += b"\xc0\x0c"  # the answer's name points back at the question's
        out += struct.pack(">HHIH", TYPE_A, CLASS_IN, ttl, 4)
        out += _pack_ip(answer_ip)
    return out


# --------------------------------------------------------------------------- #
# what a hit records
# --------------------------------------------------------------------------- #
def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def excerpt(body: bytes) -> tuple[str, bool]:
    """A capped, always-serialisable excerpt of a request body, and whether it was cut.

    Capping is spec §7 made mechanical: a canary records that something arrived and from
    where, not a copy of the target's traffic. The truncation flag matters because an
    excerpt that does not say it is one reads as the whole body in a report.
    """
    if not body:
        return ("", False)
    raw = bytes(body)
    return (raw[:MAX_BODY].decode("utf-8", "replace"), len(raw) > MAX_BODY)


def clean_headers(items) -> dict[str, str]:
    """Record which headers arrived, with credential values dropped and everything capped."""
    out: dict[str, str] = {}
    for name, value in items:
        if len(out) >= MAX_HEADERS:
            break
        key = str(name).strip().lower()[:MAX_HEADER_NAME]
        if not key:
            continue
        out[key] = REDACTED if key in REDACTED_HEADERS else str(value)[:MAX_HEADER_VALUE]
    return out


def hit_from_dns(qname: str, qtype: int, source_ip: str, zone: str, at: str | None = None) -> dict:
    """A DNS hit. An out-of-zone query is still recorded — with no token, never dropped.

    The stray queries matter: they are how you notice the zone is delegated and being
    crawled, and how a misconfigured payload shows up as "arrived at the wrong name" rather
    than as silence.
    """
    return {
        "kind": "dns",
        "token": token_from_qname(qname, zone),
        "qname": qname[:MAX_HOST],
        "qtype": _QTYPE_NAMES.get(qtype, str(qtype)),
        "source_ip": source_ip,
        "at": at or _now(),
    }


def hit_from_http(
    method: str,
    path: str,
    host: str,
    headers,
    body: bytes,
    source_ip: str,
    zone: str,
    at: str | None = None,
) -> dict:
    """An HTTP hit: what was asked for, by whom, and a capped excerpt of what it carried."""
    text, truncated = excerpt(body)
    return {
        "kind": "http",
        "token": token_from_http(host, path, zone),
        "method": str(method)[:MAX_METHOD],
        "path": str(path)[:MAX_PATH],
        "host": str(host)[:MAX_HOST],
        "headers": clean_headers(headers),
        "body": text,
        "body_truncated": truncated,
        "source_ip": source_ip,
        "at": at or _now(),
    }


def canary_response() -> bytes:
    """The entire HTTP response body, for every canary request ever made.

    A constant. Reflecting any part of the request would hand the internet a free
    open-reflection oracle on a host that is, by design, allowed to be reached by the
    targets you are testing.
    """
    return CANARY_BODY


# --------------------------------------------------------------------------- #
# the hit log: append-only
# --------------------------------------------------------------------------- #
class HitLog:
    """Append-only JSONL. No database, no rewrite path, no delete.

    Held in memory as well as on disk because the volume is tiny (a canary that sees a
    thousand hits has had a busy month) and because a poll must not re-read the file on
    every request. The file is the record; memory is the index.
    """

    def __init__(self, path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self._hits: list[dict] = []
        self._load()

    def _load(self) -> None:
        """Resume from the file. A restart that lost the cursor would re-deliver every
        historical hit to the poll client as if it were new."""
        if not self.path.exists():
            return
        with open(self.path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    hit = json.loads(line)
                except ValueError:
                    continue  # a torn final line from a hard kill is skipped, never repaired
                if isinstance(hit, dict):
                    self._hits.append(hit)

    @property
    def cursor(self) -> int:
        return int(self._hits[-1].get("seq", len(self._hits))) if self._hits else 0

    def append(self, hit: dict) -> int:
        with self._lock:
            record = dict(hit)
            record["seq"] = self.cursor + 1
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
                handle.flush()
            self._hits.append(record)
            return record["seq"]

    def read(self, after: int = 0, limit: int = READ_LIMIT_DEFAULT) -> dict:
        """Everything newer than `after`, NEWEST FIRST, bounded by a maximum page.

        Newest-first so that a poll arriving after a burst sees the recent hits first, and
        bounded so one request can never pull the whole log.
        """
        try:
            after = int(after)
            limit = max(1, min(int(limit), READ_LIMIT_MAX))
        except (TypeError, ValueError):
            after, limit = 0, READ_LIMIT_DEFAULT
        with self._lock:
            fresh = [h for h in self._hits if int(h.get("seq", 0)) > after]
            return {"hits": list(reversed(fresh))[:limit], "cursor": self.cursor}


class RateLimiter:
    """Per-source fixed window over the read API.

    Per SOURCE rather than per endpoint on purpose: a global limit would let anyone on the
    internet lock the operator's own poll client out of its data by spending the budget.
    """

    def __init__(self, limit: int = RATE_LIMIT, window: float = RATE_WINDOW) -> None:
        self.limit = limit
        self.window = window
        self._seen: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def allow(self, source: str, now: float | None = None) -> bool:
        moment = time.time() if now is None else now
        with self._lock:
            stamps = [t for t in self._seen.get(source, ()) if moment - t < self.window]
            allowed = len(stamps) < self.limit
            if allowed:
                stamps.append(moment)
            self._seen[source] = stamps
            if len(self._seen) > MAX_TRACKED_SOURCES:
                # A spray of forged source addresses must not grow the table without bound.
                self._seen = {k: v for k, v in self._seen.items() if v and moment - v[-1] < self.window}
            return allowed


# --------------------------------------------------------------------------- #
# configuration
# --------------------------------------------------------------------------- #
def load_read_secret(env) -> str:
    """Read the shared bearer secret, or refuse to start.

    Fail closed. A canary that came up with no secret would look identical to a working
    one — listeners bound, hits landing — while the client's internal hostnames sat behind
    an open endpoint. There is no "warn and continue" reading of that.
    """
    raw = (env.get(ENV_READ_SECRET) or "").strip()
    if not raw:
        raise ConfigError(
            f"{ENV_READ_SECRET} is not set. The hit log holds a target's internal hostnames "
            f"and source addresses; it is never served unauthenticated."
        )
    if len(raw) < MIN_SECRET:
        raise ConfigError(
            f"{ENV_READ_SECRET} is {len(raw)} characters; the minimum is {MIN_SECRET}. This "
            f"endpoint is on the public internet."
        )
    return raw


def authorized(header_value: str | None, secret: str) -> bool:
    """Constant-time bearer check.

    `hmac.compare_digest` rather than `==`: a byte-at-a-time comparison exposed to the
    internet leaks the secret to anyone patient enough to measure it, and nothing about the
    two spellings looks different in review.
    """
    if not header_value or not secret:
        return False
    prefix = "Bearer "
    if not header_value.startswith(prefix):
        return False
    presented = header_value[len(prefix) :]
    return hmac.compare_digest(presented.encode("utf-8", "ignore"), secret.encode("utf-8"))


@dataclass
class Config:
    zone: str
    answer_ip: str
    read_secret: str
    hits_path: Path
    bind: str = "0.0.0.0"
    dns_port: int = DEFAULT_DNS_PORT
    http_port: int = DEFAULT_HTTP_PORT
    ttl: int = DEFAULT_TTL


# --------------------------------------------------------------------------- #
# the listeners
# --------------------------------------------------------------------------- #
class DNSListener(threading.Thread):
    """Authoritative for `*.<zone>`: record the query, answer with the address."""

    daemon = True

    def __init__(self, config: Config, hits: HitLog) -> None:
        super().__init__(name="oob-dns")
        self.config = config
        self.hits = hits
        self._stop = threading.Event()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((config.bind, config.dns_port))
        self._sock.settimeout(0.5)
        self.port = self._sock.getsockname()[1]

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(MAX_DATAGRAM)
            except socket.timeout:
                continue
            except OSError:
                break  # the socket was closed under us by stop()
            query = parse_query(data)
            if query is None:
                continue
            try:
                self.hits.append(
                    hit_from_dns(query.qname, query.qtype, addr[0], self.config.zone)
                )
                self._sock.sendto(
                    build_response(query, self.config.answer_ip, self.config.ttl), addr
                )
            except OSError:
                # One unanswerable datagram never takes the listener down with it: an
                # internet-facing daemon that dies on a malformed packet is a canary that
                # silently stops being evidence.
                continue

    def stop(self) -> None:
        self._stop.set()
        self._sock.close()


class _CanaryHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, handler, config: Config, hits: HitLog) -> None:
        super().__init__(address, handler)
        self.config = config
        self.hits = hits
        self.limiter = RateLimiter()


class CanaryHandler(BaseHTTPRequestHandler):
    """Records anything that arrives; serves only the authenticated read API."""

    server_version = "hackpit-oob"
    sys_version = ""

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003 - base class name
        """Log the fact, never the request line.

        The path, the method and every header are attacker-controlled, and this daemon's
        stdout is read in an operator's terminal. Echoing arbitrary bytes there is how a
        log line becomes an escape sequence.
        """
        sys.stderr.write(f"[{_now()}] {self.client_address[0]} request handled\n")

    # -- the two paths ------------------------------------------------------ #
    def _handle(self) -> None:
        path = self.path or "/"
        if path.startswith(API_PREFIX):
            self._serve_api(path)
            return
        self._record()
        self._respond(200, "text/plain; charset=utf-8", canary_response())

    def _record(self) -> None:
        try:
            declared = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            declared = 0
        body = self.rfile.read(min(max(declared, 0), MAX_BODY_READ)) if declared > 0 else b""
        self.server.hits.append(
            hit_from_http(
                self.command,
                self.path,
                self.headers.get("Host") or "",
                self.headers.items(),
                body,
                self.client_address[0],
                self.server.config.zone,
            )
        )

    def _serve_api(self, path: str) -> None:
        source = self.client_address[0]
        if not self.server.limiter.allow(source):
            self._respond(429, "application/json", b'{"error":"rate limited"}')
            return
        if not authorized(self.headers.get("Authorization"), self.server.config.read_secret):
            self._respond(401, "application/json", b'{"error":"unauthorized"}')
            return

        route, _, query = path.partition("?")
        if route == API_PREFIX + "hits":
            page = self.server.hits.read(
                after=_int_param(query, "after", 0),
                limit=_int_param(query, "limit", READ_LIMIT_DEFAULT),
            )
            self._respond(200, "application/json", json.dumps(page).encode("utf-8"))
        elif route == API_PREFIX + "health":
            payload = {"ok": True, "zone": self.server.config.zone, "cursor": self.server.hits.cursor}
            self._respond(200, "application/json", json.dumps(payload).encode("utf-8"))
        else:
            self._respond(404, "application/json", b'{"error":"no such endpoint"}')

    def _respond(self, status: int, content_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)


# Every method a target's HTTP client might use lands on the same recorder. Bound by name
# because BaseHTTPRequestHandler dispatches on `do_<METHOD>`; anything not listed gets the
# base class's 501, which is still a response and still tells the operator nothing.
for _method in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
    setattr(CanaryHandler, f"do_{_method}", CanaryHandler._handle)


def _int_param(query: str, name: str, default: int) -> int:
    """Pull one integer parameter out of a query string.

    Parsed by hand rather than with `urllib.parse` so this file can ban the whole `urllib`
    root — the module that would let a canary fetch a URL lives one dotted name away from
    the one that parses them, and only two integers are ever read here.
    """
    for part in (query or "").split("&"):
        key, _, value = part.partition("=")
        if key == name:
            try:
                return int(value)
            except ValueError:
                return default
    return default


class Canary:
    """Both listeners and the log, started and stopped together."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.hits = HitLog(config.hits_path)
        self.dns = DNSListener(config, self.hits)
        self.http = _CanaryHTTPServer(
            (config.bind, config.http_port), CanaryHandler, config, self.hits
        )
        self.http_port = self.http.server_address[1]
        self.dns_port = self.dns.port
        self._http_thread = threading.Thread(target=self.http.serve_forever, name="oob-http")
        self._http_thread.daemon = True

    def start(self) -> None:
        self.dns.start()
        self._http_thread.start()

    def stop(self) -> None:
        self.dns.stop()
        self.http.shutdown()
        self.http.server_close()
        self._http_thread.join(timeout=5)
        self.dns.join(timeout=5)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="HackPit out-of-band canary listener")
    parser.add_argument("--zone", required=True, help="the NS-delegated zone, e.g. oob.example.net")
    parser.add_argument("--answer-ip", required=True, help="the address every A query answers with")
    parser.add_argument("--hits", default=DEFAULT_HITS_PATH, help="append-only JSONL hit log")
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--dns-port", type=int, default=DEFAULT_DNS_PORT)
    parser.add_argument("--http-port", type=int, default=DEFAULT_HTTP_PORT)
    parser.add_argument("--ttl", type=int, default=DEFAULT_TTL)
    args = parser.parse_args(argv)

    try:
        config = Config(
            zone=args.zone.strip().rstrip(".").lower(),
            answer_ip=args.answer_ip,
            read_secret=load_read_secret(os.environ),
            hits_path=Path(args.hits),
            bind=args.bind,
            dns_port=args.dns_port,
            http_port=args.http_port,
            ttl=args.ttl,
        )
        _pack_ip(config.answer_ip)  # fail at startup, not on the first query
    except ConfigError as exc:
        sys.stderr.write(f"refusing to start: {exc}\n")
        return 2

    canary = Canary(config)
    canary.start()
    sys.stderr.write(
        f"[{_now()}] canary up: zone={config.zone} dns={config.bind}:{canary.dns_port} "
        f"http={config.bind}:{canary.http_port} log={config.hits_path}\n"
    )
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        canary.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
