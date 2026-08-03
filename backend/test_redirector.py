"""Build #13 part 4 — the redirector: the live forward, and what gets rendered.

The forwarder is exercised FOR REAL. A redirector relaying `127.0.0.1:A -> 127.0.0.1:B` is the
entire mechanism — the only thing a public IP adds is that a stranger can reach A. So a real
listener is started on B, a real client connects to A, and the bytes are asserted in both
directions over real sockets. Nothing here is mocked.

What is locked:

  * **Bytes cross, both ways.** The whole point.
  * **With nothing attached, a client is accepted and DROPPED**, not left hanging. That is the
    failure direction that matters: a redirector nobody is behind must relay nothing, promptly
    and visibly, rather than holding connections open on a public port.
  * **The two ends agree on the tunnel port.** `redirector/forward.py` and
    `backend/cockpit/redirector.py` carry the same arithmetic in two files by design — the
    deployable may not import from the repo — and a drift there produces a forwarder that
    accepts every connection and drops every one, which looks exactly like an implant that
    never called home.
  * **UDP is not silently claimed to work over ssh -R.** It cannot. The renderer emits a socat
    pair and says so, instead of an `ssh -R` line that would run cleanly and carry nothing.

Binds real loopback sockets on ephemeral ports, which is why the live half is short and
bounded; the fuller end-to-end lives in docker/proof/redirector_loopback_proof.py.

Run: python test_redirector.py
"""

from __future__ import annotations

import importlib.util
import socket
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from cockpit import redirector as render  # noqa: E402

BACKEND = Path(__file__).resolve().parent
FORWARD_PATH = BACKEND.parent / "redirector" / "forward.py"

# Loaded by path, like the canary's deployable: it is a standalone file copied to a VPS, not a
# package member, and importing it as `forward` would squat a very common module name.
_spec = importlib.util.spec_from_file_location("hackpit_redirector_forward", FORWARD_PATH)
assert _spec and _spec.loader, f"cannot load {FORWARD_PATH}"
F = importlib.util.module_from_spec(_spec)
sys.modules["hackpit_redirector_forward"] = F
_spec.loader.exec_module(F)


class _Target:
    """A stand-in for oob.config.DeployTarget — only the fields the renderer reads."""

    host = "203.0.113.10"
    user = "root"
    port = 22
    key_path = "/home/op/.ssh/id_ed25519"


def _free_port() -> int:
    """A free loopback port whose tunnel port is a DIFFERENT port.

    *** THIS SKIPS A RANGE, AND THE RANGE IS A REAL DEFECT. ***
    `tunnel_port(p) == TUNNEL_PORT_BASE + (p % 10000)` with a base of 40000, so for every port
    in 40000-49999 the tunnel port IS the public port. That is 10,000 ports on which a
    redirector forwards to itself, and they sit inside Linux's default ephemeral range
    (32768-60999) — which is why CI hit `EADDRINUSE` here and a Windows dev box never did: the
    test bound the stand-in backend on the target port, then the redirector tried to bind the
    same number.

    Skipping the range keeps these tests testing the intended topology (public != tunnel)
    instead of the collision. It does NOT fix the underlying defect: an operator who picks a
    public port in 40000-49999 still gets a redirector whose `ssh -R` port collides with its own
    listener. That is logged for build #13 to settle, because changing the arithmetic changes
    every rendered reverse-tunnel command.
    """
    for _ in range(50):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        try:
            F.tunnel_port(port)          # RAISES on a self-mapping port; that is the signal
        except ValueError:
            continue
        return port
    raise AssertionError("could not find a free port outside the self-mapping range")


# --------------------------------------------------------------------------- #
# the live forward
# --------------------------------------------------------------------------- #
def test_bytes_cross_the_forwarder_in_both_directions() -> None:
    """Real sockets. A listener stands in for the far end of the operator's reverse tunnel."""
    public = _free_port()
    target = F.tunnel_port(public)

    # The "operator's listener" — what the reverse tunnel would terminate on.
    backend = socket.socket()
    backend.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    backend.bind(("127.0.0.1", target))
    backend.listen(4)

    received: list[bytes] = []

    def _serve() -> None:
        conn, _ = backend.accept()
        received.append(conn.recv(1024))
        conn.sendall(b"PONG-from-the-operator")
        conn.close()

    server = threading.Thread(target=_serve, daemon=True)
    server.start()

    listener = F.TCPRedirector(public, bind="127.0.0.1")
    listener.start()
    try:
        client = socket.create_connection(("127.0.0.1", public), timeout=5)
        client.sendall(b"PING-from-the-implant")
        reply = client.recv(1024)
        client.close()
        server.join(timeout=5)
    finally:
        listener.stop()
        backend.close()

    assert received and received[0] == b"PING-from-the-implant", received
    assert reply == b"PONG-from-the-operator", reply
    print(f"  a real client on :{public} reached a real listener on :{target}, both ways: PASS")


def test_with_no_tunnel_attached_a_client_is_dropped_not_hung() -> None:
    """A redirector nobody is behind must relay NOTHING — promptly, and visibly.

    Hanging would be the bad outcome twice over: it holds file descriptors on a public port for
    anyone who connects, and it makes "the tunnel is down" look like "the target is slow".
    """
    public = _free_port()
    listener = F.TCPRedirector(public, bind="127.0.0.1")
    listener.start()
    started = time.monotonic()
    try:
        client = socket.create_connection(("127.0.0.1", public), timeout=5)
        client.settimeout(5)
        client.sendall(b"anyone there?")
        # A dropped connection surfaces as a clean EOF (b"") on some platforms and as an
        # abrupt reset on others — Windows gives ECONNRESET here. Both ARE the drop; the
        # property under test is that the client learns immediately, so accept either and
        # assert on the timing, which is the part that would actually regress.
        try:
            leftover = client.recv(1024)
        except ConnectionResetError:
            leftover = b""
        assert leftover == b"", f"the forwarder returned data with nothing behind it: {leftover!r}"
        client.close()
    finally:
        listener.stop()
    elapsed = time.monotonic() - started
    assert elapsed < F.IDLE_TIMEOUT, (
        f"the client was held for {elapsed:.1f}s — a redirector with nothing behind it must "
        f"drop, not hold a file descriptor open on a public port"
    )
    print(f"  with no tunnel on the loopback target, a client is dropped in {elapsed:.2f}s: PASS")


def test_the_forwarder_stops_cleanly_and_releases_its_port() -> None:
    """A redirector you cannot take down is worse than one you never started."""
    public = _free_port()
    listener = F.TCPRedirector(public, bind="127.0.0.1")
    listener.start()
    listener.stop()
    listener.join(timeout=5)
    assert not listener.is_alive(), "the listener thread outlived stop()"

    rebind = socket.socket()
    rebind.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        rebind.bind(("127.0.0.1", public))
    finally:
        rebind.close()
    print("  stop() ends the thread and frees the port for a rebind: PASS")


def test_a_udp_datagram_crosses_the_forwarder() -> None:
    """The DNS-tunnel shape: a datagram out, a reply matched back to its source."""
    public = _free_port()
    target = F.tunnel_port(public)

    backend = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    backend.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    backend.bind(("127.0.0.1", target))
    backend.settimeout(0.5)
    seen: list[bytes] = []
    serving = threading.Event()
    done = threading.Event()

    # *** WHY THIS RETRIES, AND WHY THAT IS NOT PAPERING OVER A BUG. ***
    # The forwarder gives each upstream socket 200ms to answer (forward.py: sock.settimeout(0.2))
    # and DROPS the datagram if it does not, which is correct: a relay loop must not block on a
    # dead upstream. UDP has no retransmit, so a single send racing a backend thread that has not
    # been scheduled yet is lost silently — and the client then sits until its own timeout. This
    # test failed roughly two runs in three, locally and in CI, for exactly that reason.
    # A real DNS client retries; so does this one. What is under test is that a datagram CROSSES
    # the forwarder and the reply is matched back to its source — not that UDP is reliable.
    def _serve() -> None:
        serving.set()
        while not done.is_set():
            try:
                data, source = backend.recvfrom(1024)
            except OSError:            # socket.timeout is an OSError subclass
                continue
            seen.append(data)
            try:
                backend.sendto(b"udp-reply", source)
            except OSError:
                return

    server = threading.Thread(target=_serve, daemon=True)
    server.start()
    assert serving.wait(timeout=5), "the stand-in backend thread never started"

    listener = F.UDPRedirector(public, bind="127.0.0.1")
    listener.start()
    reply = b""
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(1)
        deadline = time.monotonic() + 20
        attempts = 0
        while time.monotonic() < deadline:
            attempts += 1
            client.sendto(b"udp-query", ("127.0.0.1", public))
            try:
                reply, _ = client.recvfrom(1024)
                break
            except OSError:
                continue
        client.close()
        assert reply, (
            f"no reply after {attempts} datagram(s) over 20s — this is no longer the "
            "scheduling race the retry exists for; the forwarder is not relaying UDP"
        )
    finally:
        done.set()
        listener.stop()
        backend.close()
        server.join(timeout=5)

    assert seen and seen[0] == b"udp-query", seen
    assert reply == b"udp-reply", reply
    print(f"  a UDP datagram crossed :{public} -> :{target} and the reply came back: PASS")


# --------------------------------------------------------------------------- #
# the two ends agree
# --------------------------------------------------------------------------- #
def test_both_sides_derive_the_same_tunnel_port() -> None:
    """Duplicated arithmetic, held together — the token-grammar lesson from part 3.

    Drift here is silent: the forwarder would relay to a loopback port the tunnel does not
    terminate on, every connection would be dropped, and it would look exactly like a target
    that never called back.
    """
    for port in (22, 80, 443, 4444, 8080, 8888, 53, 1, 65535, 10000, 10001):
        assert F.tunnel_port(port) == render.tunnel_port(port), (
            f"the deployable and the renderer disagree on the tunnel port for {port}: "
            f"{F.tunnel_port(port)} vs {render.tunnel_port(port)}"
        )
    assert F.TUNNEL_PORT_BASE == render.TUNNEL_PORT_BASE
    assert F.TARGET_HOST == render.TARGET_HOST == "127.0.0.1"

    # THE SELF-MAPPING RANGE. The sweep above is all conventional ports and never touched
    # 40000-49999, which is exactly why this defect survived: every port in that range mapped
    # to ITSELF, so the forwarder would bind the public listener and the tunnel on one socket.
    # Both sides must refuse, and refuse identically — a renderer that emitted an `ssh -R` the
    # forwarder would reject is the drift this whole test exists to prevent.
    for port in (40000, 44444, 45000, 49999):
        for name, fn in (("deployable", F.tunnel_port), ("renderer", render.tunnel_port)):
            try:
                got = fn(port)
            except ValueError:
                continue
            raise AssertionError(
                f"the {name} returned {got} for public port {port} instead of refusing: that is "
                "a redirector forwarding to its own listener"
            )
    # ...and the ports either side of the range are still perfectly legal, so the guard is a
    # scalpel and not a blanket
    for port in (39999, 50000):
        assert F.tunnel_port(port) == render.tunnel_port(port) != port
    print("  the two sides agree on 11 ports, both refuse all 4 self-mapping ports, "
          "and the boundaries either side still work: PASS")


# --------------------------------------------------------------------------- #
# what gets rendered
# --------------------------------------------------------------------------- #
def test_the_reverse_tunnel_binds_loopback_on_the_vps() -> None:
    """`-R 0.0.0.0:` would put the tunnel endpoint itself on a public interface with no
    forwarder in front of it — an unbounded relay straight into the operator's machine."""
    argv = render.reverse_tunnel_command(_Target(), [(443, "tcp"), (8888, "tcp")])
    joined = " ".join(argv)
    assert argv[0] == "ssh" and "-N" in argv, argv
    assert "0.0.0.0" not in joined, f"the tunnel binds a public interface on the VPS: {joined}"
    for port in (443, 8888):
        expected = f"127.0.0.1:{render.tunnel_port(port)}:127.0.0.1:{port}"
        assert expected in argv, f"missing forward for {port}: {argv}"
    assert "ExitOnForwardFailure=yes" in joined, (
        "without it ssh reports success and forwards nothing when the remote port is taken"
    )
    assert f"{_Target.user}@{_Target.host}" in argv, argv
    assert _Target.key_path in argv, argv
    print("  the rendered tunnel terminates on loopback, with ExitOnForwardFailure: PASS")


def test_udp_gets_a_socat_bridge_and_never_a_bogus_ssh_forward() -> None:
    """ssh -R carries TCP only. An `-R` line for a UDP port would run cleanly and move nothing."""
    ports = [(443, "tcp"), (53, "udp")]
    argv = render.reverse_tunnel_command(_Target(), ports)
    joined = " ".join(argv)
    assert f":{render.tunnel_port(443)}:" in joined, joined
    assert f":{render.tunnel_port(53)}:" not in joined, (
        "a UDP port was rendered as an ssh -R forward, which carries nothing"
    )
    bridges = render.udp_bridge_commands(_Target(), ports)
    assert len(bridges) == 2, bridges
    assert {b["where"] for b in bridges} == {"on the VPS", "on this machine"}, bridges
    assert all("socat" in b["command"] for b in bridges), bridges
    # ...and with no UDP port there is no bridge noise at all.
    assert render.udp_bridge_commands(_Target(), [(443, "tcp")]) == []
    print("  UDP renders a socat pair with each end labelled; no bogus ssh -R forward: PASS")


def test_the_forwarder_argv_enumerates_every_port() -> None:
    argv = render.forwarder_argv([(443, "tcp"), (8888, "tcp"), (53, "udp")])
    assert argv[:2] == ["python3", f"{render.REMOTE_DIR}/forward.py"], argv
    assert argv.count("--tcp") == 2 and argv.count("--udp") == 1, argv
    assert "443" in argv and "8888" in argv and "53" in argv, argv
    assert not any("-" in a and a.count("-") == 1 and a[0].isdigit() for a in argv), (
        f"a port range was rendered: {argv}"
    )
    print("  the forwarder argv names every port individually, no ranges: PASS")


def test_the_description_states_the_exposure_plainly() -> None:
    """A panel that rendered this as a row of green ticks would be describing something else."""
    described = render.describe(_Target(), [(443, "tcp"), (53, "udp")])
    assert described["tcp_ports"] == [443] and described["udp_ports"] == [53], described
    for field in ("exposure", "aup", "not_authenticated", "teardown"):
        assert described[field].strip(), f"{field} is empty"
    assert "ANYONE who scans" in described["exposure"], described["exposure"]
    assert "not only the target you are testing" in described["exposure"], described["exposure"]
    assert "abuse complaint" in described["aup"], described["aup"]
    assert "does not authenticate" in described["not_authenticated"], described["not_authenticated"]
    assert described["teardown"].startswith("pkill"), described["teardown"]
    # No secret can appear in any of it — nothing here is handed a secret to begin with.
    assert "key_path" not in str(described) or _Target.key_path in str(described["reverse_tunnel"])
    print("  describe() states the public exposure, the AUP position and the teardown: PASS")


def test_no_ports_means_the_forwarder_refuses_to_start() -> None:
    """A redirector with no declared ports listens on nothing; starting it would be a lie."""
    assert F.main(["--bind", "127.0.0.1"]) == 2, "the forwarder started with no ports declared"
    print("  the forwarder refuses to start with no declared ports: PASS")


if __name__ == "__main__":
    print("== C2 redirector: the live forward + what gets rendered (spec §3.2, §3.3) ==")
    test_bytes_cross_the_forwarder_in_both_directions()
    test_with_no_tunnel_attached_a_client_is_dropped_not_hung()
    test_the_forwarder_stops_cleanly_and_releases_its_port()
    test_a_udp_datagram_crosses_the_forwarder()
    test_both_sides_derive_the_same_tunnel_port()
    test_the_reverse_tunnel_binds_loopback_on_the_vps()
    test_udp_gets_a_socat_bridge_and_never_a_bogus_ssh_forward()
    test_the_forwarder_argv_enumerates_every_port()
    test_the_description_states_the_exposure_plainly()
    test_no_ports_means_the_forwarder_refuses_to_start()
    print("ALL C2 redirector rendering + live-forward tests pass")
