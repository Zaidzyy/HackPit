# Public C2 redirector — design spec

**Date:** 2026-08-03
**Branch:** `main`
**Build:** #13, part 4 of 4
**Pattern:** the last piece of "where a callback lands". Part 1 solved it for targets that can
route to your laptop. Part 3 solved *confirmation* for targets that cannot. This solves
*sessions* for targets that cannot — a shell that dials a public address and reaches you behind
NAT.

## 1. What this unblocks, and what it is not

Part 1 made the callback destination configurable, but every destination it can express is an
interface **on this machine**. That is the whole limit: a laptop behind NAT has no address an
internet-facing target can dial, so a reverse shell, a Sliver implant or a DNS-tunnel client
running inside a real target has nowhere to call. Part 3 made the *proof* of a blind
vulnerability reachable; it deliberately does not carry a session, and its server is
forbidden from forwarding anything.

This part adds the remaining shape: a **redirector** on a VPS you already own, which accepts an
inbound connection on a public port and relays it, through a reverse tunnel the operator dialled
outward, to a listener on the operator's machine. The implant talks to the VPS; the VPS talks
down a tunnel that was established from the inside; NAT is never traversed inbound.

**What it is not.** Not a C2 framework — Sliver already is one and is already wired. Not
multi-hop, not domain fronting, not a CDN front, not a fleet. One VPS, one tunnel, one set of
declared ports.

## 2. This one carries real AUP weight, and that is not a formality

Part 3's canary is safe to expose because of an *absence*: it records, never executes, never
forwards, and answers a constant. That argument does not survive contact with this part, and
pretending otherwise would be the dishonest move.

A redirector **forwards by design**. It is the thing part 3's server has an AST-asserted ban
against becoming. Concretely, what is being stood up here is:

* an **always-on listener on a public IP**, reachable by anyone who scans that address, not only
  by the target under test;
* which **relays traffic it did not authenticate** — an implant callback cannot present a bearer
  token the way part 3's read API can, so "authenticate the client" is not available as a
  control the way it was there;
* **into the operator's own machine**, which is the direction that actually matters. A
  misconfigured redirector is an inbound path from the internet to a laptop, not just an exposed
  service on a rented box.

So the honest safety story is not "there is nothing in it worth attacking" — it is **bounded
forwarding**, and the bounds have to be structural rather than advisory:

1. **One destination, and it is loopback.** The forwarder relays to `127.0.0.1:<tunnel port>` on
   the VPS and nowhere else. The destination is a constant in the shipped file, not a runtime
   argument, so a compromised or confused forwarder has no expressible way to relay somewhere
   new. It cannot be turned into an open proxy, which is exactly what an attacker who finds an
   open forwarder wants.
2. **A declared, enumerated port set.** No ranges, no dynamic listeners. The same rule part 1
   already enforces on published ports, and for the same reason: a reviewer has to be able to
   read the whole exposed surface at a glance.
3. **It is off unless the tunnel is up.** With no reverse tunnel established, the forwarder's
   only destination is a closed loopback port, so it accepts and immediately drops. That is the
   desired failure direction — a redirector nobody is attached to relays nothing rather than
   relaying somewhere else.
4. **Deploying it is a per-call human approval**, on the same gated path part 3's deploy uses,
   host-locked to the same configured VPS, with a `stop` that is as easy to reach as `start`.
5. **The operator is told, in the panel and in the generated file, in plain words**: this is a
   public listener that forwards into your machine; take it down when the engagement ends.

The provider's acceptable-use policy almost certainly permits a redirector used for authorized
testing and almost certainly does not permit it used for anything else — and the account, the
address and the abuse complaints are the operator's. That belongs on the screen, not only in a
document.

**Deliberately not built:** any form of authentication on the redirector. It would be
theatre — the implant is a binary the operator generated, so a shared secret in it is
recoverable by anyone who has the implant, which is precisely the target. Bounded forwarding is
the real control; a fake one alongside it would be worse than none.

## 3. Components

### 3.1 `ListenerProfile` gains a destination (extends part 1)

Today `ListenerProfile.ip` is a host interface. It gains a sibling notion:

* `destination="local"` — today's behaviour, **byte-identical**. The rendered compose override,
  the `hackpit-ack` markers and the published-port scanner all keep working unchanged. This is a
  hard requirement: part 1's invariants are regression-locked and part 4 may not soften one.
* `destination="remote"` — the ports are published **on the configured VPS** instead of on a
  local interface. There is no local bind address at all, so `ip` is not read; the address comes
  from the part-3 config store, which is what keeps this host-locked.

The validation rules genuinely differ rather than being reused with a flag:

| | local | remote |
|---|---|---|
| bind address | an interface on this host | none — the VPS, resolved server-side |
| "is the address live" check | yes (bind a throwaway socket) | meaningless; skipped |
| public bind | needs `ack_public` | **always** public; needs an acknowledgement unconditionally |
| what applying does | recreates a container | ships a file and starts a forwarder |

The last row is why this is a real abstraction change and not a field: "apply" means two
different operations. A remote profile never touches `docker compose`, and a local profile never
touches SSH.

### 3.2 `redirector/forward.py` — the deployable

Stdlib-only, one file, shipped by copying — the same constraints and the same reasoning as
`oob/server.py`, because it lands on the same bare VPS.

A TCP forwarder: accept on `0.0.0.0:<public port>`, connect to `127.0.0.1:<tunnel port>`, pump
bytes both ways until either side closes. UDP for the DNS-tunnel kind, which is datagram-shaped
and needs a per-source association rather than a stream.

It reads nothing from the network to decide anything: the destination is fixed at startup from
argv and is a loopback port. It has no read API, no log of traffic content, and no configuration
protocol — a redirector that could be reconfigured over the wire is an open proxy with a
handshake.

### 3.3 `backend/cockpit/redirector.py` — rendering

Pure. Turns a remote profile into:

* the **forwarder invocation** for each declared port;
* the **reverse-tunnel command** the operator runs on their own machine
  (`ssh -N -R 127.0.0.1:<tunnel>:127.0.0.1:<local> …`), rendered with the configured VPS, user,
  port and key;
* a **plain-language exposure summary** — what is now reachable on a public address, from where,
  and how to take it down.

The reverse tunnel is rendered and **not run**. HackPit prints the command and stops, the same
boundary the DNS-tunnel client one-liner draws: it is a long-lived outbound process on the
operator's own machine, and the operator starting it deliberately is the approval. Adding a
managed-process surface for it is a separate decision and is not taken here.

### 3.4 Deploy — the SAME path as part 3, generalised once

Part 3's `executor.deploy_oob_canary` ships one file to the configured VPS behind an approval,
taking no destination. Part 4 needs to ship a different file to the same box. The wrong answer
is a second deploy function with its own transport; the wrong answer is also a `path` parameter,
which would turn a deploy button into an arbitrary-write primitive.

So the transport, the target resolution, the SSH options, the stdin-not-argv secret discipline
and the step orchestration become **one private engine**, and each artifact is a module-level
constant naming a file inside the repository. The public surface stays two thin wrappers that
take an approval and nothing addressable. `test_oob_deploy_safety.py`'s signature assertion
extends to cover both.

### 3.5 The panel

Part 1's four `/cockpit/exposure` endpoints **have no frontend caller at all** — they shipped
without one. That is the same gap build #12 existed to close, so this part builds the exposure
panel and adds the remote-destination option to it, rather than adding a second orphan surface.

## 4. Verification

**On loopback, for real, the same way §3.1 of part 3 was.** A redirector forwarding
`127.0.0.1:A → 127.0.0.1:B` is the entire mechanism: a real listener is started on B, a real
client connects to A, and the test asserts the bytes arrive both ways, that the forwarder relays
to nowhere but B, and that with nothing on B the connection is accepted and dropped rather than
hanging. Public reachability is the only thing loopback cannot show.

**Reported NOT-RUN, named individually, never folded into a pass:** that the VPS's public
address accepts an inbound connection from the internet, and one real implant session through
the full chain. The SSH transfer remains NOT-RUN for the same reason it is in part 3.

## 5. Not in scope

Domain fronting, CDN or cloud fronting, multiple redirectors, traffic shaping or malleable
profiles, mTLS, and any authentication on the redirector (see §2 for why the last one is
deliberate rather than pending). No provisioning: HackPit still does not create servers or buy
domains.
