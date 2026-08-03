"""Build #13 part 4 — SAFETY invariants for the C2 redirector (spec §2).

Part 3's canary is safe to expose because of an ABSENCE: it records, never executes, never
forwards, and answers a constant. That argument does not survive here and reusing its shape
would be dishonest — this file **forwards by design**, and it is the exact thing
`test_oob_server.py` has an AST-asserted ban against the canary becoming.

So the claim is different, and these are the checks that make it true rather than aspirational:

  1. **ONE destination, and it is loopback.** Every outbound call in the deployable addresses
     the `TARGET_HOST` constant. Nothing resolves a hostname, and no destination is ever taken
     from a connection or a datagram. An open forwarder on a public IP is precisely what a
     stranger scanning that address wants to find, so "it cannot be pointed anywhere else" has
     to be a property of the code, not a promise in a docstring.
  2. **The port set is enumerated.** No ranges, and a remote profile is refused without an
     explicit acknowledgement — unconditionally, because there is no private case: a port on a
     VPS is reachable by anyone.
  3. **The two paths never half-mix.** A remote profile cannot be rendered, written or applied
     as a compose override, and a local one cannot be shipped over SSH.
  4. **The deployable is stdlib-only and inert apart from forwarding.** It is copied to a bare
     VPS; a third-party import is an install step on a box reached once, and an `eval` or a
     shell in a file on a public port is a different category of thing entirely.

Each carries a positive control. Hermetic — no socket is bound here (the live forward is
`test_redirector.py`).

Run: python test_redirector_safety.py
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from cockpit import exposure, redirector  # noqa: E402

BACKEND = Path(__file__).resolve().parent
FORWARD_PATH = BACKEND.parent / "redirector" / "forward.py"
RENDER_PATH = BACKEND / "cockpit" / "redirector.py"

# Calls that address a destination, and WHICH argument carries it. `sendto` is the one that
# would have been read wrong: its signature is (data, address), so scanning `args[0]` inspects
# the payload and reports every relay as an unknown destination. Getting this wrong in the
# other direction — scanning a call shape that never appears — is how a guard passes vacuously.
_OUTBOUND = {"connect": 0, "connect_ex": 0, "create_connection": 0, "sendto": 1}

# Sockets that only ever ANSWER a peer they already heard from. Replying to the source of a
# datagram is not choosing a destination — it is the UDP analogue of writing back on an accepted
# connection — so those calls are held to a different (and still non-empty) rule below: the
# address must have come off the wire, never from a literal.
_ANSWERING_SOCKETS = {"self._sock", "self.client"}

# Anything that turns a name into an address. A forwarder that resolves has, by definition, a
# destination it did not have at startup.
_RESOLVERS = {"getaddrinfo", "gethostbyname", "gethostbyname_ex", "getnameinfo", "getfqdn"}


def _tree(path: Path) -> ast.AST:
    return ast.parse(path.read_text(encoding="utf-8"))


def _dotted(node: ast.AST) -> str:
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return ".".join(reversed(parts))


def _outbound_destinations(tree: ast.AST) -> list[tuple[int, str, str]]:
    """(line, receiver, how the destination was built) for every addressing call."""
    found: list[tuple[int, str, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        index = _OUTBOUND.get(node.func.attr)
        if index is None or len(node.args) <= index:
            continue
        receiver = _dotted(node.func.value)
        address = node.args[index]
        if isinstance(address, ast.Tuple) and address.elts:
            host = address.elts[0]
            if isinstance(host, ast.Name):
                how = f"name:{host.id}"
            elif isinstance(host, ast.Constant):
                how = f"literal:{host.value!r}"
            else:
                how = f"expression:{type(host).__name__}"
        elif isinstance(address, ast.Name):
            how = f"name:{address.id}"          # a whole address tuple held in one variable
        elif isinstance(address, ast.Constant):
            how = f"literal:{address.value!r}"
        else:
            how = f"expression:{type(address).__name__}"
        found.append((node.lineno, receiver, how))
    return found


# --------------------------------------------------------------------------- #
# 1. one destination, and it is loopback
# --------------------------------------------------------------------------- #
def test_every_outbound_call_addresses_the_loopback_constant() -> None:
    """THE containment claim for a component whose whole job is to relay."""
    tree = _tree(FORWARD_PATH)
    destinations = _outbound_destinations(tree)
    assert destinations, (
        "no outbound call found in the forwarder — either it stopped forwarding or this scan "
        "stopped seeing it; either way the check below is vacuous"
    )

    # The relay half: any socket that CHOOSES where to go must choose the constant.
    chooses = [d for d in destinations if d[1] not in _ANSWERING_SOCKETS]
    assert chooses, "no relay call found — the destination check would be vacuous"
    offenders = [(line, recv, how) for line, recv, how in chooses if how != "name:TARGET_HOST"]
    assert not offenders, (
        f"the forwarder addresses something other than the TARGET_HOST constant: {offenders}. "
        f"A destination that can come from a connection is an open proxy."
    )

    # The answering half: a reply goes back to a peer that was heard from, so its address must
    # be a value off the wire — never a literal, which would mean the forwarder emits traffic
    # to somewhere it chose.
    answering = [d for d in destinations if d[1] in _ANSWERING_SOCKETS]
    literal_replies = [(line, recv, how) for line, recv, how in answering if how.startswith("literal:")]
    assert not literal_replies, (
        f"a reply on a listening socket addresses a literal: {literal_replies} — a listener "
        f"should only ever answer whoever just sent to it"
    )

    # TARGET_HOST is what it says it is, and is a constant assignment — not something rebound
    # from argv at startup.
    assert redirector.TARGET_HOST == "127.0.0.1"
    assigned = [
        node.value.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "TARGET_HOST" for t in node.targets)
        and isinstance(node.value, ast.Constant)
    ]
    assert assigned == ["127.0.0.1"], f"TARGET_HOST is not a single loopback constant: {assigned}"
    print(f"  all {len(chooses)} relay calls address TARGET_HOST; {len(answering)} replies "
          "answer the wire: PASS")


def test_the_forwarder_resolves_no_names() -> None:
    """A resolver is how a fixed destination quietly becomes a variable one."""
    tree = _tree(FORWARD_PATH)
    hits = [
        f"line {n.lineno}: {n.func.attr}()"
        for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
        and n.func.attr in _RESOLVERS
    ]
    assert not hits, f"the forwarder resolves hostnames: {hits}"
    print("  the forwarder performs no name resolution: PASS")


def test_the_destination_scan_can_fail() -> None:
    """Control: the two checks above print the same line working and broken."""
    planted = {
        "a destination from the request": (
            "import socket\n"
            "def relay(where):\n"
            "    s = socket.socket()\n"
            "    s.connect((where, 80))\n"
        ),
        "a literal that is not loopback": (
            "import socket\n"
            "s = socket.socket()\n"
            "s.connect(('evil.example.com', 80))\n"
        ),
        "a datagram-supplied destination": (
            "import socket\n"
            "def go(sock, addr):\n"
            "    sock.sendto(b'x', (addr[0], 53))\n"
        ),
    }
    for label, source in planted.items():
        found = _outbound_destinations(ast.parse(source))
        assert found, f"the scan saw no outbound call in the planted {label}"
        assert any(how != "name:TARGET_HOST" for _line, _recv, how in found), (
            f"the destination scan missed a planted {label} — it cannot fail"
        )

    # And specifically that `sendto`'s ADDRESS is read, not its payload. Scanning args[0] there
    # was the real bug in this file's first draft: it reported every legitimate relay as an
    # unknown destination, which is the kind of false alarm that gets a guard loosened.
    (only,) = _outbound_destinations(
        ast.parse("def go(s, TARGET_HOST):\n    s.sendto(payload, (TARGET_HOST, 53))\n")
    )
    assert only[2] == "name:TARGET_HOST", (
        f"sendto's address argument is not being read — got {only[2]!r} from the payload slot"
    )

    resolving = "import socket\nsocket.getaddrinfo('x', 80)\n"
    assert [
        n for n in ast.walk(ast.parse(resolving))
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
        and n.func.attr in _RESOLVERS
    ], "the resolver scan cannot fail"
    print(f"  control: {len(planted)} planted destinations + a planted resolver all caught: PASS")


# --------------------------------------------------------------------------- #
# 2. the exposed surface is enumerated and acknowledged
# --------------------------------------------------------------------------- #
def test_a_remote_profile_always_needs_the_public_acknowledgement() -> None:
    """Unconditionally — there is no private case. A port on a VPS is reachable by anyone.

    Locally, `ack_public` distinguishes a deliberate public bind from a private one. Here there
    is no address to classify, so the acknowledgement cannot be conditional on classifying one.
    """
    unacked = exposure.ListenerProfile(destination="remote", kinds=["sliver"])
    result = exposure.validate(unacked)
    assert not result.ok, "a remote profile was accepted with no acknowledgement"
    assert "public" in result.needs_ack, result.needs_ack
    assert any("anyone who scans" in r for r in result.refusals), result.refusals

    acked = exposure.ListenerProfile(destination="remote", kinds=["sliver"], ack_public=True)
    assert exposure.validate(acked).ok, exposure.validate(acked).refusals

    # ...and a remote profile with no ports publishes nothing, so it is refused like a local one.
    empty = exposure.ListenerProfile(destination="remote", ack_public=True)
    assert not exposure.validate(empty).ok, "a portless remote profile was accepted"
    print("  a remote profile needs the public ack unconditionally, and needs ports: PASS")


def test_port_ranges_are_refused_on_the_remote_path_too() -> None:
    """An enumerated set is what lets a reviewer read the exposed surface at a glance."""
    try:
        exposure.ListenerProfile(destination="remote", extra=[("4000-4100", "tcp")],
                                 ack_public=True)
    except Exception as exc:
        assert "range" in str(exc), exc
    else:
        raise AssertionError("a port range was accepted on a remote profile")

    # The rendered argv names each port individually — no range form exists to emit.
    argv = redirector.forwarder_argv([(443, "tcp"), (8888, "tcp")])
    assert argv.count("--tcp") == 2, argv
    print("  port ranges are refused and the forwarder argv enumerates every port: PASS")


def test_the_bind_address_of_a_remote_profile_is_ignored_and_said_so() -> None:
    """Silently ignoring it would let an operator believe they had narrowed the exposure."""
    profile = exposure.ListenerProfile(
        destination="remote", ip="192.168.1.5", kinds=["sliver"], ack_public=True
    )
    result = exposure.validate(profile)
    assert result.ok, result.refusals
    assert any("ignored" in w for w in result.warnings), result.warnings
    print("  a bind address on a remote profile is ignored, and the profile says so: PASS")


# --------------------------------------------------------------------------- #
# 3. the two paths never half-mix
# --------------------------------------------------------------------------- #
def test_a_remote_profile_cannot_take_the_local_path() -> None:
    """A compose override that published on `''`, or an operator believing a VPS is exposed
    when nothing was shipped to it — both quiet, both wrong, both avoided at the door."""
    remote = exposure.ListenerProfile(destination="remote", kinds=["sliver"], ack_public=True)
    for label, call in (
        ("render", lambda: exposure.render(remote, at="x")),
        ("compose_command", lambda: exposure.compose_command(remote)),
        ("write", lambda: exposure.write(remote, at="x")),
        ("apply", lambda: exposure.apply(remote, approved=True, runner=lambda a: (0, "", ""))),
    ):
        try:
            call()
        except exposure.ExposureRefused as exc:
            assert exc.gate == "destination", f"{label} refused at gate {exc.gate!r}"
            continue
        raise AssertionError(f"a remote profile was accepted by the local path's {label}()")

    # ...and the mirror: a local profile is not a redirector profile.
    local = exposure.ListenerProfile(ip="127.0.0.1", kinds=["sliver"])
    try:
        exposure.write_remote(local, at="x")
    except exposure.ExposureRefused as exc:
        assert exc.gate == "destination", exc.gate
    else:
        raise AssertionError("a local profile was written as a remote one")
    print("  neither destination can be processed by the other's path (5 entry points): PASS")


def test_observe_never_claims_to_have_looked_at_the_vps() -> None:
    """`docker inspect` says nothing about a process on someone else's machine.

    The same rule this function already enforces for local state, applied to itself — reporting
    `pending-restart` for a redirector that is up, or `active` for one that is not, would be the
    exact defect lifecycle.py exists to prevent.
    """
    remote = exposure.ListenerProfile(destination="remote", kinds=["sliver"], ack_public=True)
    state = exposure.observe(remote)
    assert state["state"] == "remote", state
    assert state["published"] == {}, state
    assert "cannot observe" in state["note"], state
    print("  observe() reports `remote` and never guesses at the VPS's state: PASS")


# --------------------------------------------------------------------------- #
# 4. the deployable is inert apart from forwarding
# --------------------------------------------------------------------------- #
_BANNED_ROOTS = {
    "subprocess", "pickle", "marshal", "shelve", "requests", "httpx", "urllib", "ftplib",
    "smtplib", "ctypes", "importlib", "shutil", "os",
}
_BANNED_CALLS = {"eval", "exec", "compile", "__import__", "system", "popen", "Popen"}


def test_the_forwarder_executes_nothing() -> None:
    """It sits on a public port. A shell or an eval in it is a different category of thing."""
    tree = _tree(FORWARD_PATH)
    offences: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            offences += [f"line {node.lineno}: import {a.name}"
                         for a in node.names if a.name.split(".")[0] in _BANNED_ROOTS]
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] in _BANNED_ROOTS:
                offences.append(f"line {node.lineno}: from {node.module} import ...")
        elif isinstance(node, ast.Call):
            name = ""
            if isinstance(node.func, ast.Name):
                name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                name = node.func.attr
            if name in _BANNED_CALLS:
                offences.append(f"line {node.lineno}: {name}()")
    assert not offences, "the forwarder is not inert:\n  " + "\n  ".join(offences)

    for planted in ("import subprocess\n", "def f(x):\n    return eval(x)\n", "import os\n"):
        found = False
        for node in ast.walk(ast.parse(planted)):
            if isinstance(node, ast.Import):
                found |= any(a.name.split(".")[0] in _BANNED_ROOTS for a in node.names)
            elif isinstance(node, ast.Call):
                fn = node.func
                found |= isinstance(fn, ast.Name) and fn.id in _BANNED_CALLS
        assert found, f"the inertness scan missed a planted {planted!r}"
    print("  the forwarder imports no shell and makes no execution call (3 controls): PASS")


def test_the_deployable_is_standard_library_only() -> None:
    """It is copied to a bare VPS. A wheel is an install step on a box reached once."""
    stdlib = set(sys.stdlib_module_names)
    tree = _tree(FORWARD_PATH)
    roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])
    outside = sorted(r for r in roots if r not in stdlib)
    assert not outside, f"forward.py imports non-stdlib modules: {outside}"
    assert not any(isinstance(n, ast.ImportFrom) and n.level for n in ast.walk(tree)), (
        "a relative import means the file is not standalone"
    )
    print(f"  the deployable imports {len(roots)} modules, all standard library: PASS")


def test_the_renderer_has_no_transport() -> None:
    """`cockpit/redirector.py` builds strings. The tunnel is rendered and never run."""
    tree = _tree(RENDER_PATH)
    banned = _BANNED_ROOTS | {"socket", "select", "threading"}
    offences = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            offences += [a.name for a in node.names if a.name.split(".")[0] in banned]
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] in banned:
                offences.append(node.module or "")
    assert not offences, f"the renderer can run what it renders: {offences}"
    print("  the renderer imports no transport — it builds strings and stops: PASS")


def test_the_forwarder_never_logs_traffic_content() -> None:
    """A record of what passed through would be a copy of a client's session data on a rented
    box. Nothing needs it, so nothing keeps it."""
    tree = _tree(FORWARD_PATH)
    log_args: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "_log":
            for arg in node.args:
                log_args.append(ast.dump(arg))
    assert log_args, "no _log() call found — this check would be vacuous"
    for dumped in log_args:
        for payload in ("chunk", "data", "reply", "buf", "body"):
            assert f"id='{payload}'" not in dumped, (
                f"a _log() call carries {payload!r} — that is traffic content"
            )
    print(f"  none of the {len(log_args)} log calls carries traffic content: PASS")


if __name__ == "__main__":
    print("== C2 redirector SAFETY invariants (spec §2) ==")
    test_every_outbound_call_addresses_the_loopback_constant()
    test_the_forwarder_resolves_no_names()
    test_the_destination_scan_can_fail()
    test_a_remote_profile_always_needs_the_public_acknowledgement()
    test_port_ranges_are_refused_on_the_remote_path_too()
    test_the_bind_address_of_a_remote_profile_is_ignored_and_said_so()
    test_a_remote_profile_cannot_take_the_local_path()
    test_observe_never_claims_to_have_looked_at_the_vps()
    test_the_forwarder_executes_nothing()
    test_the_deployable_is_standard_library_only()
    test_the_renderer_has_no_transport()
    test_the_forwarder_never_logs_traffic_content()
    print("ALL C2 redirector safety invariants hold")
