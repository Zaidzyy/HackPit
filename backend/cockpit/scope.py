"""Engagement SCOPE resolution — turn the operator's named scope into the concrete
firewall allow-tokens the scope-lock enforces, plus the /etc/hosts mapping tools use to
resolve the scope name locally (so no general DNS egress hole is opened).

A scope is EITHER a single host (``scanme.nmap.org`` / ``http://scanme.nmap.org``, or a bare
IP) OR a CIDR range (``10.10.10.0/24`` for internal/AD work):

* host  -> resolve to its IP(s) (v4 + v6); the firewall allows EXACTLY those, and the sandbox
           gets an ``/etc/hosts`` entry ``<ip> <host>`` so tools resolve the name with no DNS.
* CIDR  -> validate the network; the firewall allows THAT range only.

Fail-closed: an empty / malformed / unresolvable scope raises :class:`ValueError` — engagement
mode cannot be entered without a valid, concrete network floor. This module does NO networking
enforcement itself (that is the firewall sidecar); it only computes what to allow.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field


@dataclass(frozen=True)
class ResolvedScope:
    raw: str                                # exactly what the operator typed
    kind: str                               # 'host' | 'cidr'
    allow_tokens: tuple[str, ...]           # firewall allow-list (resolved IPs, or [cidr])
    host: str | None = None                 # bare hostname (kind == 'host'), for /etc/hosts
    hosts_ips: tuple[str, ...] = field(default_factory=tuple)  # v4 IP(s) for /etc/hosts


def _bare_host(target: str) -> str:
    """Strip scheme / userinfo / path / port from a target -> bare host (or IP literal)."""
    t = target.strip()
    if "://" in t:
        t = t.split("://", 1)[1]
    t = t.split("/", 1)[0]          # drop any path
    t = t.split("@")[-1]            # drop any userinfo
    if t.startswith("["):          # [v6]:port
        return t[1:].split("]", 1)[0]
    if t.count(":") == 1:          # host:port (a lone ':' — not a v6 literal)
        t = t.split(":", 1)[0]
    return t


def resolve_scope(target: str) -> ResolvedScope:
    """Resolve the operator's named scope into a :class:`ResolvedScope`. Raises ValueError
    (fail-closed) on an empty / malformed / unresolvable scope."""
    raw = (target or "").strip()
    if not raw or any(c.isspace() for c in raw):
        raise ValueError("scope must be a single non-empty host or CIDR (no spaces)")

    # CIDR range (has a '/', and is not a URL) -> validate the network, allow it only.
    if "/" in raw and "://" not in raw:
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError as exc:
            raise ValueError(f"invalid CIDR scope '{raw}': {exc}")
        return ResolvedScope(raw=raw, kind="cidr", allow_tokens=(str(net),))

    host = _bare_host(raw)
    if not host:
        raise ValueError(f"could not parse a host from scope '{raw}'")

    # bare IP literal -> allow exactly that address.
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        return ResolvedScope(
            raw=raw, kind="host", allow_tokens=(str(ip),), host=host,
            hosts_ips=(str(ip),) if ip.version == 4 else (),
        )

    # hostname -> resolve to v4 + v6 addresses.
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError as exc:
        raise ValueError(f"could not resolve scope host '{host}': {exc}")
    ips: list[str] = []
    for _fam, _t, _p, _c, sockaddr in infos:
        addr = sockaddr[0]
        if addr not in ips:
            ips.append(addr)
    if not ips:
        raise ValueError(f"scope host '{host}' resolved to no addresses")
    v4 = tuple(i for i in ips if ":" not in i)
    return ResolvedScope(
        raw=raw, kind="host", allow_tokens=tuple(ips), host=host, hosts_ips=v4,
    )


def hosts_line(scope: ResolvedScope) -> str | None:
    """The ``/etc/hosts`` line to inject into the sandbox so the scope name resolves locally
    (no DNS). None for a CIDR scope (no hostname) or a bare-IP host."""
    if scope.kind != "host" or not scope.host or not scope.hosts_ips:
        return None
    if scope.host == scope.hosts_ips[0]:  # the host WAS an IP literal — nothing to map
        return None
    return f"{scope.hosts_ips[0]} {scope.host}"
