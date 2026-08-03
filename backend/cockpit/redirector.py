"""Redirector rendering — the commands, and what they expose (build #13 part 4, spec §3.3).

PURE. This module builds strings and lists. It opens no socket, runs no subprocess and ships
no file: the deployable is ``redirector/forward.py``, the transfer is the executor's gated
path, and the reverse tunnel is a command the OPERATOR runs on their own machine.

WHY THE TUNNEL IS RENDERED AND NOT RUN
--------------------------------------
It is a long-lived outbound SSH process on the operator's laptop, and starting it deliberately
is the approval — the same boundary the DNS-tunnel client one-liner draws. Growing a managed
process surface for it is a separate decision with its own lifecycle, status and failure modes,
and it is not taken here. HackPit renders the command and stops.

THE ONE AWKWARD FACT, STATED RATHER THAN PAPERED OVER
-----------------------------------------------------
**SSH reverse tunnels carry TCP only.** A Sliver implant or a reverse shell rides ``ssh -R``
end to end and needs nothing else. A DNS tunnel does not: UDP/53 has to be bridged across the
TCP tunnel with a wrapper at each end. So the UDP case renders an extra `socat` pair and says
plainly that it needs one, rather than emitting an ``ssh -R`` line for UDP that would look
correct, run without error, and silently carry nothing — which is indistinguishable from a
target that never called back, and is exactly the class of silent failure part 3 was built to
remove.
"""

from __future__ import annotations

from typing import Any

# --------------------------------------------------------------------------- #
# The shared arithmetic
# --------------------------------------------------------------------------- #
# DUPLICATED FROM redirector/forward.py ON PURPOSE, exactly as the canary's token grammar is
# duplicated in oob/server.py: the deployable is copied to a VPS on its own and may not import
# from this repository. test_redirector.py holds the two together, because drift here is the
# silent kind — the forwarder would relay to a loopback port the tunnel does not terminate on,
# every connection would be accepted and dropped, and it would look exactly like an implant
# that never called home.
TUNNEL_PORT_BASE = 40000
TARGET_HOST = "127.0.0.1"

# Where the artifact lands on the VPS. A constant for the same reason the canary's is: a
# caller-supplied remote path is an arbitrary-write primitive wearing a deploy button.
REMOTE_DIR = "/opt/hackpit-redirector"

# The SSH options the rendered tunnel command carries. `ExitOnForwardFailure` is the one that
# matters: without it ssh reports success and sits there when the remote port is already bound,
# leaving a tunnel that is up and forwards nothing.
TUNNEL_SSH_OPTIONS = (
    "-N",
    "-o", "ExitOnForwardFailure=yes",
    "-o", "ServerAliveInterval=30",
    "-o", "StrictHostKeyChecking=accept-new",
)


def tunnel_port(public_port: int) -> int:
    """The loopback port a given public port's reverse tunnel terminates on.

    *** MUST STAY BYTE-EQUIVALENT TO redirector/forward.py::tunnel_port, GUARD INCLUDED. ***
    The two are duplicated because the forwarder is deployed standalone to the VPS and cannot
    import the backend; `test_redirector.py::test_both_sides_derive_the_same_tunnel_port` holds
    them together, and now checks the refusal as well as the arithmetic.

    A public port already inside [40000, 49999] maps to ITSELF, which would render an `ssh -R`
    whose loopback port is the public listener's own port. Refused rather than returned — see
    the long note in redirector/forward.py. Every port outside that range is unaffected, so no
    previously-rendered command changes.
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


def split_ports(ports: list[tuple[int, str]]) -> tuple[list[int], list[int]]:
    """(tcp, udp) port numbers, sorted — the two halves are carried differently."""
    tcp = sorted({int(p) for p, proto in ports if proto == "tcp"})
    udp = sorted({int(p) for p, proto in ports if proto == "udp"})
    return tcp, udp


# --------------------------------------------------------------------------- #
# What runs on the VPS
# --------------------------------------------------------------------------- #
def forwarder_argv(ports: list[tuple[int, str]]) -> list[str]:
    """The argv that starts the forwarder on the VPS. PURE — builds a list, runs nothing.

    Every port is named individually. There is no range form to render because there is no
    range form to accept: an enumerated set is what lets a reviewer read the whole exposed
    surface at a glance, which is the same rule part 1 applies to published ports.
    """
    tcp, udp = split_ports(ports)
    argv = ["python3", f"{REMOTE_DIR}/forward.py"]
    for port in tcp:
        argv += ["--tcp", str(port)]
    for port in udp:
        argv += ["--udp", str(port)]
    return argv


# --------------------------------------------------------------------------- #
# What the operator runs, on their own machine
# --------------------------------------------------------------------------- #
def reverse_tunnel_command(target: Any, ports: list[tuple[int, str]]) -> list[str]:
    """``ssh -N -R …`` — the outbound dial that makes the whole thing work behind NAT.

    Bound to ``127.0.0.1`` on the VPS side deliberately. The alternative, ``-R 0.0.0.0:…``,
    needs ``GatewayPorts yes`` in the remote sshd config AND would put the tunnel endpoint
    itself on a public interface with no forwarder in front of it — an unbounded relay straight
    into the operator's machine. Terminating on loopback means the only thing reachable from
    outside is the forwarder, which has exactly one destination.

    Carries no secret: authentication is the operator's key file, named by path.
    """
    tcp, _udp = split_ports(ports)
    argv = ["ssh", *TUNNEL_SSH_OPTIONS]
    if target.key_path:
        argv += ["-i", target.key_path, "-o", "IdentitiesOnly=yes"]
    argv += ["-p", str(target.port)]
    for port in tcp:
        argv += ["-R", f"{TARGET_HOST}:{tunnel_port(port)}:{TARGET_HOST}:{port}"]
    argv += [f"{target.user}@{target.host}"]
    return argv


def udp_bridge_commands(target: Any, ports: list[tuple[int, str]]) -> list[dict[str, str]]:
    """The `socat` pair a UDP port needs, because ssh -R cannot carry UDP.

    Empty when no UDP port is declared. Each entry says WHERE it runs, because getting the two
    ends the wrong way round produces a bridge that starts cleanly and moves nothing.
    """
    _tcp, udp = split_ports(ports)
    out: list[dict[str, str]] = []
    for port in udp:
        bridge = tunnel_port(port) + 1  # a TCP port beside the UDP tunnel port, not on top of it
        out.append({
            "port": str(port),
            "where": "on the VPS",
            "command": f"socat TCP4-LISTEN:{tunnel_port(port)},fork,reuseaddr "
                       f"UDP4:{TARGET_HOST}:{port}",
            "why": "accepts the tunnelled TCP stream and re-emits it as UDP to the forwarder",
        })
        out.append({
            "port": str(port),
            "where": "on this machine",
            "command": f"socat UDP4-RECVFROM:{bridge},fork TCP4:{TARGET_HOST}:{bridge}",
            "why": "wraps your local UDP listener so the TCP tunnel can carry it",
        })
    return out


# --------------------------------------------------------------------------- #
# What the operator is told
# --------------------------------------------------------------------------- #
def describe(target: Any, ports: list[tuple[int, str]]) -> dict[str, Any]:
    """Everything a remote profile means, in the words it needs to be said in.

    The exposure sentence is not decoration and is not softened. What is being stood up is a
    public listener that relays into the operator's own machine; a panel that renders that as a
    row of green ticks would be describing something else.
    """
    tcp, udp = split_ports(ports)
    return {
        "host": target.host,
        "remote_dir": REMOTE_DIR,
        "tcp_ports": tcp,
        "udp_ports": udp,
        "tunnel_map": [
            {"public": port, "tunnel": tunnel_port(port), "proto": proto}
            for port, proto in sorted(ports)
        ],
        "forwarder": forwarder_argv(ports),
        "reverse_tunnel": reverse_tunnel_command(target, ports),
        "udp_bridges": udp_bridge_commands(target, ports),
        "exposure": (
            f"{len(tcp) + len(udp)} port(s) become reachable on {target.host} by ANYONE who "
            f"scans that address — not only the target you are testing. Traffic that arrives is "
            f"relayed down your reverse tunnel into this machine. Take it down when the "
            f"engagement ends."
        ),
        "aup": (
            "The VPS is yours, so the account, the address and any abuse complaint are yours. "
            "A redirector used for authorized testing is a normal tool; the provider's AUP "
            "almost certainly does not cover anything else."
        ),
        "not_authenticated": (
            "The redirector does not authenticate callers, and deliberately does not pretend "
            "to: a shared secret would have to live inside the implant, which is a binary the "
            "target holds. The real control is that it forwards to exactly one loopback port "
            "and nowhere else."
        ),
        "teardown": f"pkill -f {REMOTE_DIR}/forward.py",
    }
