"""The default port each listener binds — one place, imported by everything that needs it.

WHY THIS MODULE EXISTS (build #13). `cockpit/exposure.py` has to know which port a listener
binds, because a profile that publishes a different one publishes nothing useful. The obvious
way to get that is to import it from the module that owns the listener:

    from .tunnels import CHISEL_DEFAULT_PORT      # <- trips the human-only tunnel scan

That is refused, and correctly. `test_tunnels.test_tunnels_lifecycle_is_human_only` scans the
whole tree for ANY reference to the tunnel module and allows exactly two files, so that no
agent or automation path can raise a pivot listener. The pattern matches the import, not the
call, precisely so a module cannot get within reach of `start_tunnel` and be trusted not to use
it. `sliver` and `obfuscation` carry the same guard.

Adding `exposure.py` to those allow-lists would have been the wrong fix twice over: it narrows
the file set instead of fixing the predicate (the mistake build #5 records), and it would have
left this module free to call `start_tunnel` with nothing watching.

So the CONSTANTS move somewhere neutral and the dependency disappears. Nothing here imports a
listener module; the listener modules import this. A port is configuration, not behaviour, and
the drift lock is stronger than before — there is now exactly one definition rather than one
per owner.

Chisel's SOCKS port is here for completeness and is deliberately NOT publishable: proxychains
reaches it from inside the sandbox, so exposing it would widen the surface for nothing.
"""

from __future__ import annotations

# chisel: the reverse SOCKS server the agent dials.
CHISEL_DEFAULT_PORT = 8080

# chisel: the SOCKS5 the agent's `R:socks` exposes ON THE SERVER, which proxychains points at.
# Container-internal by design — never published. See cockpit/exposure.KIND_PORTS.
CHISEL_SOCKS_PORT = 1080

# ligolo: the proxy control port.
LIGOLO_DEFAULT_PORT = 11601

# sliver: the C2 daemon's listener.
SLIVER_DEFAULT_PORT = 31337

# dnscat2 / iodine: both DNS tunnel servers bind UDP/53 inside the sandbox.
DNS_TUNNEL_PORT = 53
