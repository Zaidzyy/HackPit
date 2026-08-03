#!/usr/bin/env python3
"""HackPit C2 redirector — the deployable (build #13 part 4, spec §3.2).

A laptop behind NAT has no address an internet-facing target can dial, so an implant running
inside a real target has nowhere to call. This file is the thing it calls: it runs on a VPS you
already own, accepts a connection on a public port, and relays it to a loopback port where a
reverse tunnel — dialled OUTWARD by the operator — is waiting. The implant talks to the VPS; the
VPS talks down a tunnel that was established from the inside. Nothing is traversed inbound.

It is ONE FILE importing nothing outside the standard library, for the same reason
``oob/server.py`` is: it is deployed by copying it to a bare box you SSH into once.

THIS ONE FORWARDS, AND THAT CHANGES THE SAFETY ARGUMENT
------------------------------------------------------
The canary in part 3 is safe to expose because of an absence — it records, never executes,
never forwards, and answers a constant. This file is the exact thing that canary has an
AST-asserted ban against becoming, so that argument is not available and it would be dishonest
to reuse its shape. What is here instead is BOUNDED FORWARDING, and the bounds are structural:

  * **One destination, and it is loopback.** :data:`TARGET_HOST` is a module constant. Nothing
    in this file resolves a hostname, reads a destination from the network, or takes one from a
    connection. There is no expressible way to relay anywhere else — which matters because an
    open forwarder on a public IP is precisely what a stranger scanning that address wants to
    find.
  * **A declared port set.** Ports are named individually on the command line. No ranges, no
    dynamically-opened listeners.
  * **It relays nothing when nobody is attached.** With no reverse tunnel up, the loopback
    target is a closed port: a client is accepted and immediately dropped. That is the right
    failure direction — a redirector nobody is attached to relays nothing, rather than relaying
    somewhere unexpected.
  * **Bounded concurrency and bounded time.** Connection count and idle time are capped, so a
    stranger cannot hold the box's file descriptors open indefinitely.

It does not log traffic CONTENT. A redirector that recorded what passed through it would be a
copy of a client's session data sitting on a rented server, which is the same line part 3's
canary draws at a capped body excerpt — only here there is no reason to keep any of it.

Deploy:
    python3 forward.py --tcp 443 --udp 53

Take it down:
    pkill -f hackpit-oob-redirector/forward.py
"""

from __future__ import annotations

import argparse
import select
import socket
import sys
import threading
import time
from datetime import datetime, timezone

# THE destination. A constant, and the whole containment argument (spec §2.1): there is no
# argument, no header and no handshake that can point this file at another address. Everything
# it relays goes to a loopback port on the machine it is running on, where the operator's
# reverse tunnel terminates.
TARGET_HOST = "127.0.0.1"

# Public port -> the loopback port its tunnel terminates on. Derived by a fixed offset rather
# than configured, so the two ends agree without a shared file that could drift; the operator's
# `ssh -R` command is rendered from the same arithmetic (backend/cockpit/redirector.py).
TUNNEL_PORT_BASE = 40000

# Caps. Every one of these bounds what a stranger on the internet can consume, because this
# port is reachable by anyone who scans the address — not only by the target under test.
MAX_CONNECTIONS = 64
IDLE_TIMEOUT = 300.0
CONNECT_TIMEOUT = 5.0
BUFFER = 65536
ACCEPT_TIMEOUT = 0.5

# UDP associations expire, or a long engagement accumulates one entry per source address that
# ever sent a datagram — an unbounded table anyone can grow.
UDP_ASSOCIATION_TTL = 120.0
MAX_UDP_ASSOCIATIONS = 256


def tunnel_port(public_port: int) -> int:
    """The loopback port a given public port's reverse tunnel terminates on.

    Shared arithmetic, deliberately trivial and deliberately not configurable: the operator's
    ``ssh -R`` command and this forwarder have to agree, and a mismatch produces a redirector
    that accepts connections and drops every one of them — which looks exactly like a target
    that never called back.

    *** THE SELF-MAPPING RANGE IS REFUSED, NOT SILENTLY RETURNED. ***
    ``BASE + (p % 10000)`` lands in [40000, 49999], so for a public port already in that range
    the tunnel port IS the public port. The forwarder would then bind the public listener and
    the reverse tunnel on one socket and relay to itself, and the rendered ``ssh -R`` would
    collide with the listener it is meant to feed. 10,000 ports do this, and they sit inside
    Linux's default ephemeral range (32768-60999), which is how the redirector tests hit it as
    an intermittent EADDRINUSE on CI and never on a Windows box.

    Refusing is the whole fix and it costs nothing real: every port outside 40000-49999 —
    including every conventional C2 port, 80/443/53/8080/4444 — keeps the exact tunnel port it
    had before, so no already-rendered command changes. Raising here rather than at the call
    sites means no caller, present or future, can compute a self-mapping pair.
    """
    port = int(public_port)
    mapped = TUNNEL_PORT_BASE + (port % 10000)
    if mapped == port:
        raise ValueError(
            f"public port {port} maps to itself ({mapped}): a redirector on any port in "
            f"{TUNNEL_PORT_BASE}-{TUNNEL_PORT_BASE + 9999} would forward to its own listener. "
            "Pick a public port outside that range."
        )
    return mapped


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _log(message: str) -> None:
    """Facts only — never the bytes that passed through.

    The traffic is a client's session data and this is a rented box; there is no reason to keep
    any of it. Addresses and counts are what an operator needs to answer "is it working".
    """
    sys.stderr.write(f"[{_now()}] {message}\n")
    sys.stderr.flush()


class _Pump(threading.Thread):
    """One accepted TCP connection, relayed to the loopback target until either side closes."""

    daemon = True

    def __init__(self, client: socket.socket, peer: str, target_port: int, done) -> None:
        super().__init__(name=f"relay-{peer}")
        self.client = client
        self.peer = peer
        self.target_port = target_port
        self.done = done

    def run(self) -> None:
        upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        upstream.settimeout(CONNECT_TIMEOUT)
        try:
            # TARGET_HOST, never a value from the connection. See the module docstring.
            upstream.connect((TARGET_HOST, self.target_port))
        except OSError:
            # No tunnel attached. Drop the client rather than holding it open: a redirector
            # nobody is listening behind should relay nothing, visibly and immediately.
            _log(f"{self.peer} dropped — no tunnel on {TARGET_HOST}:{self.target_port}")
            self._close(upstream)
            return
        upstream.settimeout(None)
        self.client.settimeout(None)
        _log(f"{self.peer} relayed to {TARGET_HOST}:{self.target_port}")

        last = time.monotonic()
        try:
            while True:
                readable, _, errored = select.select([self.client, upstream], [], [self.client, upstream], 1.0)
                if errored:
                    break
                if not readable:
                    if time.monotonic() - last > IDLE_TIMEOUT:
                        _log(f"{self.peer} idle-closed after {IDLE_TIMEOUT:.0f}s")
                        break
                    continue
                last = time.monotonic()
                for source in readable:
                    sink = upstream if source is self.client else self.client
                    try:
                        chunk = source.recv(BUFFER)
                    except OSError:
                        chunk = b""
                    if not chunk:
                        return
                    try:
                        sink.sendall(chunk)
                    except OSError:
                        return
        finally:
            self._close(upstream)

    def _close(self, upstream: socket.socket) -> None:
        for sock in (self.client, upstream):
            try:
                sock.close()
            except OSError:
                pass
        self.done()


class TCPRedirector(threading.Thread):
    """Accept on a public TCP port; relay each connection to the loopback tunnel port."""

    daemon = True

    def __init__(self, public_port: int, bind: str = "0.0.0.0") -> None:
        super().__init__(name=f"tcp-{public_port}")
        self.public_port = public_port
        self.target_port = tunnel_port(public_port)
        self._stop = threading.Event()
        self._live = 0
        self._lock = threading.Lock()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((bind, public_port))
        self._sock.listen(16)
        self._sock.settimeout(ACCEPT_TIMEOUT)
        self.port = self._sock.getsockname()[1]

    def _release(self) -> None:
        with self._lock:
            self._live = max(0, self._live - 1)

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                client, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break  # closed under us by stop()
            peer = f"{addr[0]}:{addr[1]}"
            with self._lock:
                if self._live >= MAX_CONNECTIONS:
                    _log(f"{peer} refused — {MAX_CONNECTIONS} connections already live")
                    try:
                        client.close()
                    except OSError:
                        pass
                    continue
                self._live += 1
            _Pump(client, peer, self.target_port, self._release).start()

    def stop(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass


class UDPRedirector(threading.Thread):
    """Relay datagrams both ways for a public UDP port (the DNS-tunnel shape).

    UDP has no connection, so a reply has to be matched back to whoever sent the request. One
    upstream socket per source address does that; the table is capped and entries expire,
    because otherwise anyone on the internet can grow it one spoofed source at a time.
    """

    daemon = True

    def __init__(self, public_port: int, bind: str = "0.0.0.0") -> None:
        super().__init__(name=f"udp-{public_port}")
        self.public_port = public_port
        self.target_port = tunnel_port(public_port)
        self._stop = threading.Event()
        self._assoc: dict[tuple, tuple[socket.socket, float]] = {}
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((bind, public_port))
        self._sock.settimeout(ACCEPT_TIMEOUT)
        self.port = self._sock.getsockname()[1]

    def _expire(self, now: float) -> None:
        for key in [k for k, (_s, seen) in self._assoc.items() if now - seen > UDP_ASSOCIATION_TTL]:
            sock, _ = self._assoc.pop(key)
            try:
                sock.close()
            except OSError:
                pass

    def _upstream_for(self, source: tuple) -> socket.socket | None:
        now = time.monotonic()
        self._expire(now)
        existing = self._assoc.get(source)
        if existing is not None:
            self._assoc[source] = (existing[0], now)
            return existing[0]
        if len(self._assoc) >= MAX_UDP_ASSOCIATIONS:
            return None
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.2)
        self._assoc[source] = (sock, now)
        return sock

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                data, source = self._sock.recvfrom(BUFFER)
            except socket.timeout:
                self._expire(time.monotonic())
                continue
            except OSError:
                break
            upstream = self._upstream_for(source)
            if upstream is None:
                continue
            try:
                # TARGET_HOST again — the destination is never taken from the datagram.
                upstream.sendto(data, (TARGET_HOST, self.target_port))
                reply, _ = upstream.recvfrom(BUFFER)
                self._sock.sendto(reply, source)
            except OSError:
                continue

    def stop(self) -> None:
        self._stop.set()
        for sock, _ in list(self._assoc.values()):
            try:
                sock.close()
            except OSError:
                pass
        self._assoc.clear()
        try:
            self._sock.close()
        except OSError:
            pass


class Redirector:
    """Every declared port, started and stopped together."""

    def __init__(self, tcp_ports: list[int], udp_ports: list[int], bind: str = "0.0.0.0") -> None:
        self.listeners = [TCPRedirector(p, bind) for p in tcp_ports]
        self.listeners += [UDPRedirector(p, bind) for p in udp_ports]

    def start(self) -> None:
        for listener in self.listeners:
            listener.start()

    def stop(self) -> None:
        for listener in self.listeners:
            listener.stop()
        for listener in self.listeners:
            listener.join(timeout=5)

    def describe(self) -> list[str]:
        return [
            f"{type(l).__name__[:3].lower()}/{l.public_port} -> {TARGET_HOST}:{l.target_port}"
            for l in self.listeners
        ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="HackPit C2 redirector")
    parser.add_argument("--tcp", type=int, action="append", default=[],
                        help="public TCP port to relay (repeatable)")
    parser.add_argument("--udp", type=int, action="append", default=[],
                        help="public UDP port to relay (repeatable)")
    parser.add_argument("--bind", default="0.0.0.0")
    args = parser.parse_args(argv)

    if not args.tcp and not args.udp:
        sys.stderr.write("refusing to start: no ports declared (--tcp / --udp)\n")
        return 2

    redirector = Redirector(args.tcp, args.udp, args.bind)
    redirector.start()
    _log("redirector up: " + ", ".join(redirector.describe()))
    _log("this is a PUBLIC listener that relays into the operator's machine — take it down "
         "when the engagement ends")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        redirector.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
