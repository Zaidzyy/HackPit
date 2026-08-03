# Listener profiles — where a callback lands — design spec

**Date:** 2026-08-03
**Branch:** `main` (single-branch as of 2026-08-03)
**Build:** #13, part 1 of 4
**Pattern:** generalise the one thing build #10 hand-wrote (`docker/proof/c2-lab.yml`) into a
first-class, validated, observed surface — the way `lifecycle.py` generalised three copies of
the same listener spawn.

## 1. Intent and boundaries

HackPit can reach **out** to anything — the engage sandbox is fully open by decision (Wall A
down). What it cannot do is be reached **in**. A callback is the target dialling *you*, and for
that to land a container port must be published on a host address the target can route to.
Today exactly one file does that, it is hand-written, and it is hardcoded to the VMware VMnet8
address of one laptop.

This build makes "where do callbacks land" a configurable, validated, **observed** property.

### Scope of this spec

This is **part 1 of a 4-part program**, and the other three are deliberately out of scope:

| Part | What | Infra needed | Status |
|---|---|---|---|
| **1c — this spec** | Local IP-bound listener profiles | none | now |
| Evasion gated deploy | D16-style reversal of generate-only | none | own spec, next |
| 1a — OOB canary | Remote DNS/HTTP hit recorder | VPS + domain | own spec, blocked on infra |
| 1b — public C2 listener | Public redirector for beacons | VPS | own spec, blocked on infra |

1c is first because it is free, verifiable today, and it is where the **callback-destination**
abstraction gets designed — so 1a and 1b slot into an existing shape rather than being bolted on.

### Fixed boundaries

- **No host-side listening process.** Everything published goes through Docker, so the existing
  published-port scanner can see the entire exposure surface by reading compose files. A relay
  bound on the host outside Docker would be invisible to it.
- **The lab sandbox is never exposable.** Its network is `internal: true`; publishing a port
  would attach it to a non-internal network and `assert_isolation_proven()` would then refuse
  every lab command. Exposure and lab isolation are mutually exclusive by construction, not by
  policy — this is not a knob.
- **No new C2, no new listener kinds.** This build changes *where* existing listeners are
  reachable, never *what* they are.
- **Nothing here is remote.** No VPS, no domain, no internet-facing anything. A profile can only
  ever name an address on the operator's own machine.

## 2. What exists today (audited before adding anything)

`docker/docker-compose.yml` publishes **nothing** — four services, zero `ports:` keys.

`docker/proof/c2-lab.yml` is the sole exposure, opt-in by requiring a second `-f`, and adds one
line: `"192.168.13.1:53:53/udp"`.

`backend/test_exposure_safety.py` fences it with three invariants:

1. the default posture publishes nothing;
2. exposure is opt-in and lives in its own small reviewable file;
3. every published port is bound to one literal host IP — `"53:53/udp"` and `"0.0.0.0:53:53/udp"`
   are both rejected, because binding every interface means binding whatever Wi-Fi the laptop
   is on.

It is a **text scan, not a YAML parse**, so the hermetic suite needs no third-party dependency.

Listener ports in the code today: chisel `8080/tcp` (`CHISEL_DEFAULT_PORT`), ligolo `11601/tcp`
(`LIGOLO_DEFAULT_PORT`), Sliver `31337/tcp` (`SLIVER_DEFAULT_PORT`), DNS tunnel `53/udp`
(`obfuscation.py`). Chisel's SOCKS `1080` is **not** publishable and must not be offered —
proxychains reaches it from inside the sandbox, so only the port a remote agent dials needs to
be exposed.

## 3. What gets built

### 3.1 `backend/cockpit/exposure.py` — the whole feature

A new module, peer to `lifecycle.py`, for the same reason that one exists: all four listener
kinds need this, so it cannot live inside any one of them. It **executes no attack tooling**;
its only subprocess calls are `docker inspect` (read) and `docker compose up -d` (apply).

Five responsibilities:

- `validate(profile)` — the bind rules in §4, returning refusals and warnings separately.
- `render(profile)` — profile → compose YAML text. Pure; no I/O.
- `write(profile)` — render, write `docker/listener-profile.yml`, record to the run store.
- `apply(profile)` — run `docker compose -f docker-compose.yml -f listener-profile.yml up -d
  <container>`. **Requires `approved=true`**, because recreating a container kills every live
  listener, session and background job inside it, and the operator must be told that before it
  happens rather than after.
- `observe()` — read the **actual** published bindings back from `docker inspect` and report
  what is true.

### 3.2 The profile

```
ip          str    literal dotted quad, or a wildcard token behind a red-confirm
container   str    "engage-sandbox" | "kali-open"        (never the lab sandbox)
kinds       list   subset of {chisel, ligolo, dns-tunnel, sliver}  -> derives ports
extra       list   explicit individual host ports, e.g. [(4444,"tcp"), (443,"tcp")]
engagement  str?   recorded for audit only; does not scope anything
```

Ticking a kind is a **convenience that derives its default port**, not a cage. `extra` exists
because the four kinds omit the single most common callback there is — a plain reverse shell on
443 or 4444 caught with netcat, pwncat or an msfconsole handler. Restricting to known kinds
would have hit that wall on first use.

**Ports are individual; ranges are refused.** A range is how a single typo publishes hundreds of
ports, and it makes the exposure summary unreadable — which defeats invariant 2's whole point,
that a reviewer can see the entire surface at a glance.

### 3.3 One active profile, globally

`engage-sandbox` is one shared container and recreating it is a global act, so two engagements
physically cannot have different bindings. The data model says so rather than pretending
otherwise: **one profile is live at a time.** The engagement it was generated for is recorded on
the profile and in the run store for audit and reporting, and scopes nothing. Generating a new
profile replaces the live one and says that it does.

This is `lifecycle.py`'s rule applied to state instead of status: do not model something the
system cannot deliver.

### 3.4 `c2-lab.yml` is replaced by a preset

The VMnet8 lab case *is* a profile — `192.168.13.1` + `dns-tunnel` → `53/udp`. It ships as a
named preset `vmnet8-dns`, `docker/proof/c2-lab.yml` is deleted, and `c2_lab_proof.sh` generates
its profile before bringing the stack up.

**A test asserts the preset renders the same EFFECTIVE EXPOSURE as the file build #10 hand-wrote:**
`published_ports()` over the generated file equals `published_ports()` over the original, attached
to the same compose service. That file moves from `docker/proof/c2-lab.yml` to
`backend/test_support/c2-lab.golden.yml`, where it is no longer a live compose path but the
fixture the equivalence test compares against.

*Byte-equivalence was the first claim here and it was wrong* — build #10's file opens with 27
lines of hand-written prose explaining why VMnet8 and why UDP/53, and no generator will reproduce
that. Comparing the parsed exposure is the honest comparison and it is also the one that matters:
the guarantee wanted is "this preset exposes exactly what the hand-written file exposed", not
"this preset reproduces its comments". The generalisation is therefore *proven* faithful to the
thing it replaces rather than assumed to be. One live exposure file, ever.

### 3.5 The generated file is gitignored

`docker/listener-profile.yml` is operator-local machine state, not source. `192.168.13.1` is
already public in the repo so nothing is lost today — but the first profile generated on a client
engagement holds **that client's internal address**, and this repository is public. That is client
data leakage, and it is the same class of mistake as the hardcoded `C:\Users\zaid_\…` path
parameterised out of `fix-vmnet8.ps1` before it was tracked.

A test asserts the path is ignored. Presets live in code; the live file never gets committed.

### 3.6 Observed, never assigned

`observe()` reads the real bindings from `docker inspect` and reports one of:

| State | Meaning |
|---|---|
| `active` | published bindings match the live profile |
| `pending-restart` | profile written, container not yet recreated |
| `drifted` | container publishes something other than the profile |
| `none` | no profile written |
| `unknown` | docker unavailable — reported as unknown, never as active |

A published port is **not** an open port: the host firewall can still drop inbound. When a
profile is `active`, `observe()` says so explicitly, because "check Windows Firewall" is the
first thing to check when a callback does not land and the surface should say it rather than
leave the operator guessing.

### 3.7 Endpoints

Pure cockpit concern, so these live on `cockpit/router.py`, not `main.py` (the decoupling rule
sends only cross-cutting endpoints to `main.py`).

- `GET /cockpit/exposure` — live profile + `observe()` state + the firewall note.
- `POST /cockpit/exposure/profile` — validate + write. Returns refusals, warnings, the rendered
  ports and the exact compose command.
- `POST /cockpit/exposure/apply` — `approved=true` required; runs compose, then `observe()`.
- `DELETE /cockpit/exposure/profile` — remove the file, return the teardown command.

## 4. The guards

| # | Rule | Enforcement |
|---|---|---|
| 1 | Default compose publishes nothing | Refusal (unchanged) |
| 2 | Exposure lives in one small reviewable file | Refusal (retargeted at the generated file) |
| 3 | Every published port names a host IP | Refusal, **except** an acknowledged wildcard (§4.1) |
| 4 | Wildcard bind (`0.0.0.0`, `::`, `*`) | **Red-confirm** — allowed, must be acknowledged **in the file** |
| 5 | Public bind address | **Red-confirm** — allowed, must be acknowledged **in the file** |
| 6 | Address not currently live on this host | **Warning** — not refused |
| 7 | Port ranges | Refusal |
| 8 | Container is the lab sandbox | Refusal (structural) |
| 9 | Generated file committed | Refusal |
| 10 | `apply()` without approval | Refusal |

### 4.1 The acknowledgement is written into the file, or the scanner cannot see it

Allowing an acknowledged wildcard breaks the static scanner as it stands: `test_exposure_safety`
reads compose text and has no way to tell a wildcard the operator consciously chose from one that
slipped through. Making the scanner simply stop rejecting wildcards would delete invariant 3
rather than relax it.

So the acknowledgement is **part of the rendered file**. A profile carrying a wildcard or public
bind renders a provenance line immediately above the `ports:` block:

```yaml
# hackpit-ack: wildcard  bind=0.0.0.0  engagement=e-4417  at=2026-08-03T09:12:04Z
ports:
  - "0.0.0.0:4444:4444/tcp"
```

The scanner's rule becomes: **every wildcard or public binding must be covered by a matching
`hackpit-ack` line naming that exact bind address.** An unacknowledged one still fails, exactly as
before. A hand-edited file that adds `0.0.0.0` without the marker fails too.

This makes invariant 2 stronger rather than weaker: the one small file a reviewer reads now states
not only *what* is exposed but that it was consciously chosen, by whom, when, and for which
engagement.

**Why 4 and 5 are confirms and not refusals.** This codebase already has the right pattern and it
would be wrong to invent a second one: the danger gate *never blocks outright*, it requires an
explicit second acknowledgement on top of approval — "over-inclusive assist — human is the gate."
Binding a public or wildcard address is exactly that shape. A wildcard genuinely earns its place
twice: it survives an address change (VPN reconnect, DHCP, Ethernet→Wi-Fi) where a named bind
leaves a container that will not restart, and it is the fallback when a specific bind misbehaves
under Docker Desktop's vpnkit/WSL networking. It costs precision exactly where precision matters
most — a wildcard `4444` on a client site is an unauthenticated listening service on the client's
LAN — so the acknowledgement is the operator saying they meant it.

**Why 6 is a warning.** An address that is not live is not a silent failure: Docker refuses to
start the container with `bind: cannot assign requested address`. The check buys a better error,
earlier — not safety. And refusing would be actively wrong in the real case of writing a profile
while off the VPN, intending to connect before running compose.

**Interface liveness without a dependency.** Enumerating interfaces portably needs a third-party
package, which the hermetic suite forbids. Instead: open a UDP socket and attempt to `bind()` the
address — success means it is live here, `EADDRNOTAVAIL` means it is not. Stdlib-only, works on
Windows and Linux, and it tests the thing that actually matters rather than inferring it.

## 5. Verification

New `backend/test_exposure.py`, plus extensions to `test_exposure_safety.py`. Both hermetic —
no Docker, no network — with `docker inspect` faked the way `test_kali` fakes `subprocess.run`.

**Faithfulness**
- The `vmnet8-dns` preset renders byte-equivalent to build #10's committed file.

**Refusals** — one case each: port range; lab sandbox as target; unknown listener kind; a
committed generated file; `apply()` without approval.

**Confirms** — each in **both** directions, so the gate is proven live rather than merely present:
- wildcard refused without the ack, permitted with it;
- public address refused without the ack, permitted with it;
- a private, live address needs no ack at all (the control that proves the confirm is not
  firing on everything).

**Warnings** — a non-live address warns and still writes; a live one warns not at all.

**Observation** — `observe()` returns each of `active`, `pending-restart`, `drifted`, `none`,
`unknown` against a faked docker, including the case that matters most: a container publishing
bindings that do not match the profile must report `drifted`, never `active`.

**The ack marker** (§4.1) — four cases, because this is where invariant 3 now rests:
- a wildcard binding **with** its matching `hackpit-ack` line passes the scanner;
- the same binding with the marker deleted fails;
- a marker naming a *different* bind address than the one published fails (the marker must cover
  that exact address, not merely exist);
- a public binding follows the same three.

**Positive control**, in the `test_scans` idiom: a deliberately broken renderer that emits
`0.0.0.0` unacknowledged is caught by the published-port scanner. Without this the scanner could
silently stop matching and every test above would still pass.

**Ports** — chisel's SOCKS `1080` is asserted absent from every rendered profile.

The full suite (`sh backend/run_safety_tests.sh`) stays green, and `run_safety_tests.sh` gains
the new file with its own `run_test()` line and exit-code gate.

## 6. Assessment doc + PDF

Per the standing rule, in the same commit as the code: a build #13 section in
`docs/ASSESSMENT-2026-07-26.md` covering what was built, the four-part decomposition and why the
other three are separate, and the design decisions that went **against** the first instinct —
public and wildcard as confirms rather than refusals, arbitrary ports allowed, and the correction
that a non-live bind address fails loudly rather than silently. Regenerate with
`python docs/build-assessment.py`; verify against the HTML and the page-count delta, never by
grepping the PDF.

## 7. Commit + push

Single branch. Commit the code, tests, deleted `c2-lab.yml`, updated `c2_lab_proof.sh`, gitignore
entry and regenerated assessment together; `git push origin main`; confirm CI green before
treating it as landed.

## 8. Reused traps (carried forward)

- **`| tee` eats the exit code.** Read `PIPESTATUS`. Cost a disarmed safety runner in build #10
  and a mute drift job this week.
- **Fix the predicate, never narrow the file set** (build #5). If the published-port scanner
  misses a shape, widen the scanner.
- **A guard that has never fired is not a guard.** Every refusal and every confirm gets a
  positive control.
- **Defender may delete files under `data/`** after a write. Verify after generating.
- **`docker compose` needs both `-f` flags on teardown too**, or the override silently stays
  applied.
