"""Engagement PROGRAM SCOPE — a multi-pattern, bug-bounty-shaped scope model.

An engagement is no longer locked to ONE exact host. The operator names a *program scope* at
entry — the same shape a real bug-bounty/pentest scope takes:

    *   |   scanme.nmap.org, *.example.com, 10.10.10.0/24, !admin.example.com

* ``*``         — EVERYTHING: every name, every address. The deliberate opt-out — with it
                  the target check passes every host, which is the same behaviour as having
                  no scope model at all. It must be TYPED (an empty scope is still refused),
                  so the record shows ``scope: *`` and the report reads as an unbounded run
                  by choice rather than by omission.
* ``host``      — an exact host or IP (``scanme.nmap.org``, ``10.10.10.5``). A URL form is
                  accepted and reduced to its bare host.
* ``*.domain``  — a WILDCARD: every SUBdomain of ``domain``, AND the apex itself (a real
                  program that scopes ``*.example.com`` means ``example.com`` too).
* ``CIDR``      — a network range (``10.10.10.0/24``), matched against IP tokens.
* ``!pattern``  — an EXCLUSION (any of the forms). Exclusions always win — including over
                  ``*``, so ``*, !prod.example.com`` is "everything except that one host".

Matching is deliberately LEXICAL/NUMERIC and does no DNS at match time: a *name* is judged
against the host + wildcard patterns, an *IP* against the CIDR patterns and the addresses the
exact-host patterns resolved to at entry. That makes ``in_scope`` deterministic, testable, and
free of "resolve an out-of-scope name to decide if it's out of scope" DNS leaks.

FAIL-CLOSED: an empty spec, a malformed pattern, a spec with no include patterns, or a spec
whose ONLY includes are exact hosts that all fail to resolve → :class:`ValueError`. Engagement
mode cannot be entered without a scope that means something.

This module enforces NOTHING by itself. On this branch (Wall A DOWN) there is no firewall: the
scope drives (a) the best-effort argv target-lock, (b) what the proposer is told it may target,
and (c) which recon-discovered hosts may be added to the live allowed set. The ACTUAL bound on
a real-target run remains HUMAN APPROVAL OF EVERY COMMAND.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field

# Separators accepted between patterns in a scope spec (comma / whitespace / newline).
_SPLIT = re.compile(r"[\s,;]+")

# A dotted name that could be a host in recon output (used by extract_hosts).
_HOST_RE = re.compile(r"\b(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)+[A-Za-z]{2,63}\b")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Dotted tokens in tool output that are files/versions, not hosts. Best-effort — a
# false positive here only means a host is NOT auto-added (fail-closed direction).
_NOT_HOST_TLDS = frozenset({
    "txt", "json", "xml", "csv", "html", "htm", "js", "css", "py", "php", "asp", "aspx",
    "conf", "cfg", "ini", "list", "lst", "dic", "gz", "zip", "tar", "log", "md", "yaml",
    "yml", "bak", "pem", "key", "crt", "db", "sqlite", "pdf", "png", "jpg", "jpeg", "gif",
    "svg", "so", "exe", "dll", "sh", "jar", "war", "class", "map", "woff", "woff2", "ico",
})


def bare_host(token: str) -> str:
    """Strip scheme / userinfo / path / port from a token → bare host (or IP literal)."""
    t = (token or "").strip()
    if not t:
        return ""
    if "://" in t:
        t = t.split("://", 1)[1]
    for sep in ("/", "?", "#"):
        if sep in t:
            t = t.split(sep, 1)[0]
    t = t.split("@")[-1]
    if t.startswith("["):  # [v6]:port
        return t[1:].split("]", 1)[0]
    if t.count(":") == 1:  # host:port (a lone ':' — not a v6 literal)
        t = t.split(":", 1)[0]
    return t.strip().rstrip(".")


@dataclass(frozen=True)
class ScopePattern:
    """One parsed scope pattern. ``kind`` is 'any' | 'host' | 'wildcard' | 'cidr'."""

    raw: str
    kind: str
    value: str          # host: bare host lowercased | wildcard: '.suffix' | cidr: network str
    exclude: bool = False

    def matches(self, host: str, ip: ipaddress._BaseAddress | None) -> bool:
        if self.kind == "any":
            return True  # '*' — every name and every address
        if self.kind == "cidr":
            if ip is None:
                return False
            try:
                return ip in ipaddress.ip_network(self.value)
            except ValueError:  # pragma: no cover - validated at parse time
                return False
        if self.kind == "wildcard":
            # The APEX counts: a real program that scopes '*.example.com' means
            # example.com too, and refusing the apex only ever refused a command
            # the operator was authorized to run.
            return host == self.value[1:] or (
                host.endswith(self.value) and len(host) > len(self.value)
            )
        # exact host (name or IP literal)
        return host == self.value

    def label(self) -> str:
        return ("!" if self.exclude else "") + self.raw


@dataclass(frozen=True)
class ResolvedScope:
    """A parsed + resolved program scope. ``in_scope`` is the matcher everything else uses."""

    raw: str                                                   # the spec exactly as typed
    include: tuple[ScopePattern, ...] = ()
    exclude: tuple[ScopePattern, ...] = ()
    seed_hosts: tuple[str, ...] = ()                           # exact-host includes (names/IPs)
    seed_ips: tuple[str, ...] = field(default_factory=tuple)   # what those hosts resolved to

    # -- matching ---------------------------------------------------------- #
    def in_scope(self, token: str) -> bool:
        """True if ``token`` (a host, IP, host:port or URL) is IN scope and NOT excluded."""
        host = bare_host(token).lower()
        if not host:
            return False
        try:
            ip: ipaddress._BaseAddress | None = ipaddress.ip_address(host)
            host = str(ip)  # canonical form, so the seed-IP compare is apples-to-apples
        except ValueError:
            ip = None
        # An IP also matches when an exact-host include resolved to it.
        in_by_seed = ip is not None and host in self.seed_ips
        for pat in self.exclude:
            if pat.matches(host, ip):
                return False
        if in_by_seed:
            return True
        return any(pat.matches(host, ip) for pat in self.include)

    # -- description (prompt + UI) ------------------------------------------ #
    def includes(self) -> list[str]:
        return [p.raw for p in self.include]

    def excludes(self) -> list[str]:
        return [p.raw for p in self.exclude]

    def unbounded(self) -> bool:
        """True when the scope is '*' — the operator declared everything authorized, so the
        target check passes every host. Surfaced in the UI banner and the report: an
        unbounded run is a deliberate choice and should read as one."""
        return any(p.kind == "any" for p in self.include)

    def describe(self) -> str:
        """One-line human/LLM-readable summary of the scope."""
        inc = ", ".join(self.includes()) or "(none)"
        if self.unbounded():
            inc = "* (everything — no target check)"
        exc = ", ".join(self.excludes())
        return f"IN SCOPE: {inc}" + (f" | OUT OF SCOPE: {exc}" if exc else "")


def _parse_one(token: str) -> ScopePattern:
    raw = token.strip()
    exclude = False
    if raw.startswith("!"):
        exclude, raw = True, raw[1:].strip()
    if not raw:
        raise ValueError("empty scope pattern")

    # '*' — EVERYTHING. The deliberate opt-out of the target check: with it in the
    # scope, every host passes and the argv lock stops refusing anything. Typed, not
    # defaulted (an empty scope is still refused), so the engagement record shows
    # 'scope: *' and the report says plainly that the run was unbounded.
    if raw == "*":
        return ScopePattern(raw="*", kind="any", value="*", exclude=exclude)

    if raw.startswith("*."):
        suffix = bare_host(raw[1:]).lower()  # '*.example.com' -> '.example.com'
        if not suffix.startswith(".") or "." not in suffix[1:]:
            raise ValueError(f"invalid wildcard scope '{token}' — use *.example.com")
        return ScopePattern(raw=raw, kind="wildcard", value=suffix, exclude=exclude)

    if "/" in raw and "://" not in raw:
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError as exc:
            raise ValueError(f"invalid CIDR scope '{token}': {exc}")
        return ScopePattern(raw=raw, kind="cidr", value=str(net), exclude=exclude)

    host = bare_host(raw).lower()
    if not host:
        raise ValueError(f"could not parse a host from scope pattern '{token}'")
    if "*" in host:
        raise ValueError(f"invalid wildcard scope '{token}' — only a leading '*.' is supported")
    try:
        host = str(ipaddress.ip_address(host))  # normalise an IP literal
    except ValueError:
        pass
    return ScopePattern(raw=raw, kind="host", value=host, exclude=exclude)


def _resolve(host: str) -> list[str]:
    """Best-effort forward resolution of an exact-host include (v4 + v6). [] on failure."""
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return []
    out: list[str] = []
    for info in infos:
        addr = info[4][0]
        if addr not in out:
            out.append(addr)
    return out


def parse_scope(spec: str, resolve: bool = True) -> ResolvedScope:
    """Parse (and, by default, resolve) a program-scope spec. FAIL-CLOSED — raises ValueError
    on an empty spec, a malformed pattern, a spec with no includes, or a spec whose only
    includes are exact hosts that ALL failed to resolve."""
    text = (spec or "").strip()
    if not text:
        raise ValueError(
            "a scope is required — name at least one in-scope host, *.wildcard or CIDR"
        )
    include: list[ScopePattern] = []
    exclude: list[ScopePattern] = []
    for token in _SPLIT.split(text):
        if not token:
            continue
        pat = _parse_one(token)
        (exclude if pat.exclude else include).append(pat)
    if not include:
        raise ValueError("scope has no IN-SCOPE pattern — an exclusion-only scope allows nothing")

    hosts = tuple(p.value for p in include if p.kind == "host")
    ips: list[str] = []
    if resolve:
        for h in hosts:
            for addr in _resolve(h):
                if addr not in ips:
                    ips.append(addr)
        wide = any(p.kind in ("any", "wildcard", "cidr") for p in include)
        if hosts and not ips and not wide:
            raise ValueError(
                "could not resolve any in-scope host — check the scope (DNS failed for: "
                + ", ".join(hosts)
                + ")"
            )
    return ResolvedScope(
        raw=text,
        include=tuple(include),
        exclude=tuple(exclude),
        seed_hosts=hosts,
        seed_ips=tuple(ips),
    )


# --------------------------------------------------------------------------- #
# recon-driven expansion: pull candidate hosts out of a run's output
# --------------------------------------------------------------------------- #
def extract_hosts(text: str, cap: int = 400) -> list[str]:
    """Candidate hosts/IPs found in a run's output, de-duplicated, order-preserved.

    Best-effort text mining (nmap/subfinder/curl/dig output all differ): dotted names whose
    last label looks like a TLD, plus IPv4 literals. Anything that looks like a filename or a
    version string is dropped. A candidate is only ever a CANDIDATE — the caller validates it
    against the scope before it can be added to anything.
    """
    seen: list[str] = []
    if not text:
        return seen

    def _add(h: str) -> None:
        h = h.strip().strip(".").lower()
        if h and h not in seen and len(seen) < cap:
            seen.append(h)

    for m in _IPV4_RE.finditer(text):
        octets = m.group(0).split(".")
        if all(o.isdigit() and int(o) <= 255 for o in octets):
            _add(m.group(0))
    for m in _HOST_RE.finditer(text):
        host = m.group(0).lower()
        tld = host.rsplit(".", 1)[-1]
        if tld in _NOT_HOST_TLDS:
            continue
        _add(host)
    return seen
