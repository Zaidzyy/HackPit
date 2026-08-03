#!/usr/bin/env python3
"""LIVE proof: the C2 redirector, end to end on loopback (build #13 part 4, spec §4).

A redirector relaying `127.0.0.1:A -> 127.0.0.1:B` is the ENTIRE mechanism. The only thing a
public IP adds is that a stranger can reach A — which is precisely the part that cannot be
stood in for locally, and precisely the part reported NOT-RUN below. Everything else is real
here: a real forwarder process, a real listener standing in for the far end of the operator's
reverse tunnel, a real client standing in for an implant, and real bytes in both directions.

What this demonstrates that the hermetic tests cannot:

  * the forwarder relays a full request/response exchange over real sockets, TCP and UDP;
  * with no tunnel attached it accepts and DROPS, promptly — the failure direction that
    matters, because a redirector nobody is behind must relay nothing rather than relaying
    somewhere unexpected;
  * it survives a client that disappears mid-stream, which is what an implant on a flaky link
    actually does;
  * the rendered reverse-tunnel command and the running forwarder agree on the tunnel port —
    the two carry that arithmetic in separate files by design, and a drift produces a
    redirector that accepts everything and forwards nothing.

Binds real loopback sockets, so it is a proof rather than a hermetic test — the same reason
the OOB canary's loopback proof lives here. No Docker, no VPS, nothing beyond 127.0.0.1.

Run:  python docker/proof/redirector_loopback_proof.py
      sh backend/run_safety_tests.sh --with-proof   # runs it alongside the others
"""
from __future__ import annotations

import importlib.util
import socket
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from cockpit import redirector as render  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "hackpit_redirector_forward", ROOT / "redirector" / "forward.py"
)
assert _spec and _spec.loader
F = importlib.util.module_from_spec(_spec)
sys.modules["hackpit_redirector_forward"] = F
_spec.loader.exec_module(F)

_tally = {"pass": 0, "fail": 0, "notrun": 0}
_notes: list[str] = []


def result(name: str, status: str, detail: str) -> None:
    """One line in the harness's RESULT protocol (PASS / FAIL / NOTRUN), folded into the tally."""
    print(f"RESULT {name} {status} {detail}", flush=True)
    _tally[status.lower()] += 1
    if status == "NOTRUN":
        _notes.append(f"{name} — {detail}")


def check(name: str, condition: bool, detail: str) -> bool:
    result(name, "PASS" if condition else "FAIL", detail)
    return condition


class _Target:
    """Stands in for oob.config.DeployTarget — only the fields the renderer reads."""

    host = "203.0.113.10"
    user = "root"
    port = 22
    key_path = ""


def _free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def run() -> int:
    print("== HackPit C2 redirector — LOOPBACK END-TO-END PROOF ==")
    print("   nothing leaves 127.0.0.1; no VPS and no Docker are involved")

    public = _free_port()
    target = F.tunnel_port(public)
    print(f"   public=127.0.0.1:{public}  ->  tunnel=127.0.0.1:{target}")

    listeners: list[object] = []
    try:
        # -- 1. nothing attached: accept and drop ---------------------------- #
        #
        # First, deliberately, and before any listener exists on the tunnel port. This is the
        # state a redirector spends most of its life in — deployed, tunnel not yet dialled —
        # and the wrong behaviour here (hanging) would hold file descriptors open on a public
        # port for anyone who connects.
        idle = F.TCPRedirector(public, bind="127.0.0.1")
        idle.start()
        listeners.append(idle)
        started = time.monotonic()
        client = socket.create_connection(("127.0.0.1", public), timeout=5)
        client.settimeout(5)
        client.sendall(b"is anyone home")
        try:
            leftover = client.recv(1024)
        except ConnectionResetError:
            leftover = b""      # an abrupt reset IS the drop; Windows reports it this way
        elapsed = time.monotonic() - started
        client.close()
        check(
            "idle.accepts_and_drops",
            leftover == b"" and elapsed < 10,
            f"with no tunnel on :{target} the client was dropped in {elapsed:.2f}s and got "
            f"{leftover!r} — a redirector nobody is behind relays nothing",
        )
        idle.stop()
        idle.join(timeout=5)
        listeners.remove(idle)

        # -- 2. a full exchange, both directions ----------------------------- #
        backend = socket.socket()
        backend.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        backend.bind(("127.0.0.1", target))
        backend.listen(4)
        received: list[bytes] = []

        def _serve() -> None:
            conn, _ = backend.accept()
            received.append(conn.recv(4096))
            conn.sendall(b"TASKING-FROM-THE-OPERATOR")
            conn.close()

        server = threading.Thread(target=_serve, daemon=True)
        server.start()

        live = F.TCPRedirector(public, bind="127.0.0.1")
        live.start()
        listeners.append(live)

        client = socket.create_connection(("127.0.0.1", public), timeout=5)
        client.sendall(b"CHECKIN-FROM-THE-IMPLANT")
        reply = client.recv(4096)
        client.close()
        server.join(timeout=5)

        check(
            "tcp.relays_both_ways",
            received and received[0] == b"CHECKIN-FROM-THE-IMPLANT"
            and reply == b"TASKING-FROM-THE-OPERATOR",
            f"the far end received {received[0] if received else None!r} and the client got "
            f"{reply!r} — a full exchange across the forwarder over real sockets",
        )

        # -- 3. a client that vanishes mid-stream ---------------------------- #
        #
        # What an implant on a flaky link actually does. A forwarder that leaked a thread or a
        # descriptor per abandoned connection would degrade over an engagement rather than
        # failing visibly.
        def _accept_and_wait() -> None:
            try:
                conn, _ = backend.accept()
                conn.recv(16)
                time.sleep(0.2)
                conn.close()
            except OSError:
                pass

        waiter = threading.Thread(target=_accept_and_wait, daemon=True)
        waiter.start()
        rude = socket.create_connection(("127.0.0.1", public), timeout=5)
        rude.sendall(b"half a mess")
        rude.close()          # gone, mid-stream, no shutdown
        waiter.join(timeout=5)
        time.sleep(0.3)

        survivor = socket.create_connection(("127.0.0.1", public), timeout=5)
        survivor.close()
        check(
            "tcp.survives_an_abandoned_client",
            live.is_alive(),
            "a client that vanished mid-stream did not take the listener down, and the next "
            "connection was still accepted",
        )
        live.stop()
        live.join(timeout=5)
        listeners.remove(live)
        backend.close()

        # -- 4. UDP, the DNS-tunnel shape ------------------------------------ #
        udp_public = _free_port()
        udp_target = F.tunnel_port(udp_public)
        udp_backend = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_backend.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        udp_backend.bind(("127.0.0.1", udp_target))
        udp_backend.settimeout(5)
        seen: list[bytes] = []

        def _serve_udp() -> None:
            data, source = udp_backend.recvfrom(4096)
            seen.append(data)
            udp_backend.sendto(b"udp-tasking", source)

        udp_server = threading.Thread(target=_serve_udp, daemon=True)
        udp_server.start()

        udp_listener = F.UDPRedirector(udp_public, bind="127.0.0.1")
        udp_listener.start()
        listeners.append(udp_listener)

        udp_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_client.settimeout(5)
        udp_client.sendto(b"udp-checkin", ("127.0.0.1", udp_public))
        udp_reply, _ = udp_client.recvfrom(4096)
        udp_client.close()
        udp_server.join(timeout=5)

        check(
            "udp.relays_both_ways",
            seen and seen[0] == b"udp-checkin" and udp_reply == b"udp-tasking",
            f"a datagram crossed :{udp_public} -> :{udp_target} and the reply was matched back "
            f"to its source",
        )
        udp_listener.stop()
        udp_listener.join(timeout=5)
        listeners.remove(udp_listener)
        udp_backend.close()

        # -- 5. the two ends agree ------------------------------------------- #
        rendered = render.reverse_tunnel_command(_Target(), [(public, "tcp")])
        expected = f"127.0.0.1:{target}:127.0.0.1:{public}"
        check(
            "tunnel.the_two_ends_agree",
            expected in rendered,
            f"the rendered ssh command forwards {expected}, which is exactly the loopback port "
            f"the running forwarder relayed to — the arithmetic lives in two files and matches",
        )
        check(
            "tunnel.terminates_on_loopback",
            "0.0.0.0" not in " ".join(rendered),
            "the rendered tunnel binds 127.0.0.1 on the VPS, not a public interface — the "
            "forwarder is the only thing reachable from outside, and it has one destination",
        )

        # -- 6. what loopback CANNOT show ------------------------------------ #
        result(
            "public.inbound_reachability",
            "NOTRUN",
            "needs the VPS: that a connection from the internet reaches the forwarder on its "
            "public address. HackPit does not provision servers (spec §5); this is the one "
            "property loopback cannot stand in for.",
        )
        result(
            "public.live_implant_session",
            "NOTRUN",
            "needs one real engagement: an implant inside a target checking in through the "
            "full chain — public port, forwarder, reverse tunnel, operator's listener.",
        )
        result(
            "public.ssh_deploy",
            "NOTRUN",
            "needs the VPS: shipping forward.py over SSH and starting it. The GATES are "
            "covered hermetically (test_oob_deploy_safety.py — no wrapper takes a destination, "
            "an unapproved deploy sends nothing); what is missing is a remote box to reach.",
        )
    finally:
        for listener in listeners:
            try:
                listener.stop()          # type: ignore[attr-defined]
            except Exception:            # noqa: BLE001 - cleanup must not mask a real failure
                pass

    print()
    print("==========================================================================")
    print(f"== redirector loopback proof: {_tally['pass']} passed, {_tally['fail']} failed, "
          f"{_tally['notrun']} not-run ==")
    print("==========================================================================")
    if _notes:
        print()
        print("NOT RUN (reported as not-run, never as passed):")
        for note in _notes:
            print(f"  * {note}")
    print()
    if _tally["fail"] == 0:
        print("No assertion FAILED. The forwarding mechanism was exercised over real sockets in")
        print("both protocols and both directions; only public reachability is outstanding.")
        return 0
    print("FAILURES PRESENT — do not deploy this to a public address until they are understood.")
    return 1


if __name__ == "__main__":
    raise SystemExit(run())
