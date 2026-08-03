# Out-of-band canary — design spec

**Date:** 2026-08-03
**Branch:** `main`
**Build:** #13, part 3 of 4
**Pattern:** the second half of "where a callback lands". Part 1 solved it for targets that can
route to your laptop. This solves it for targets that cannot — which is every internet-facing
bug bounty target.

## 1. What this unblocks

Whole vulnerability classes are **unconfirmable** without an internet-reachable listener,
because the hit *is* the entire proof: blind SSRF, blind XXE, blind RCE with no returned output,
blind SQLi via DNS (`xp_dirtree`, `UTL_HTTP`), JNDI/deserialization callbacks, and async SSRF
where the app calls your URL minutes later through a queue. Without this, a promising blind
injection has to be written up as "unconfirmed", which most programs reject and which this
project's own report discipline already bans.

**DNS matters more than HTTP.** Plenty of targets block outbound HTTP from app servers while DNS
still resolves through their internal resolver, so DNS-based OOB works where HTTP does not. That
is why this needs a real domain with **NS delegation** — and why part 1 can never do this job:
a target's resolver will never route to a private address.

## 2. Scope

**In:** the OOB server, token minting and correlation, the poll client, the cockpit panel, payload
templates, and the configure/deploy/verify panel.

**Out:** provisioning. HackPit does **not** create servers or buy domains. A credential that can
create one droplet can create a hundred, and it would sit in an app that has no route auth; the
ROI is bad for a one-time task; and domain registration needs a funded registrar account and
ICANN verification regardless. A tool that *spins up* C2 infrastructure is also a materially
different thing from one pointed at infrastructure you already own — the same concern that ended
build #11. You create the droplet and buy the domain yourself, once. Everything after is buttons.

**Also out:** the public C2 redirector (part 4). This server records hits; it never forwards
traffic and never becomes a redirector.

## 3. Components

### 3.1 `oob/server.py` — the deployable

A single file, **stdlib only**, so it runs on a bare VPS with no install step and can be shipped
by copying one file. Two listeners:

* **DNS/53** — authoritative for `*.<zone>`. Any query is recorded and answered with a benign A
  record (not NXDOMAIN: an answer lets an HTTP follow-up land, which is how a chained SSRF proof
  works). Records `(token, qname, source_ip, at)`.
* **HTTP/80** — any request recorded with path, method, headers, source IP. The token comes from
  the subdomain or the first path segment.

**Storage is append-only JSONL.** No database, no eval, no execution, no reflection of request
content into a response. This is the first HackPit component that is internet-facing and its
entire job is to *write down what arrived*.

**The read API is authenticated.** The hit log contains a target's internal hostnames and source
addresses — it is engagement data, and an unauthenticated read endpoint would publish the
client's information to anyone who guessed the host. A shared bearer token, stored on the
HackPit side exactly like the WinRM secrets: gitignored, never returned by any endpoint.
Rate-limited, and hits are served newest-first with a cursor.

### 3.2 `backend/oob/tokens.py` — minting and correlation

A token is short, unguessable, and DNS-label-safe. Minting records `(token, engagement_id,
step_id, note, at)` so a hit that lands ten minutes later resolves back to *which test* caused
it — the correlation is the product, not the hit.

### 3.3 The poll client + state ingest

HackPit polls the read API on a cursor and ingests hits into the engagement state, so an OOB
confirmation becomes a finding like any other rather than a thing you screenshot.

### 3.4 Payload templates

Per class — SSRF, XXE, blind RCE, blind SQLi, JNDI — each rendering a **minted token** into the
one-liner you paste. Templates only: HackPit renders the string and stops, the same boundary
`obfuscation.operator_oneliner` draws.

### 3.5 The configure / deploy / verify panel

* **Configure** — VPS address, SSH key, zone. Stored like the WinRM profiles: gitignored, never
  returned, secret redacted in every record.
* **NS records** — generated as exact copy-paste text for the registrar. This is the step people
  get wrong; naming it precisely is most of the value.
* **Deploy** — ship `server.py` to the VPS over SSH and start it.
* **Verify** — mint a throwaway token, resolve it against the public zone, and assert the hit
  landed. This is the valuable button: it turns "is my canary working" from an assumption into a
  re-runnable check.

## 4. The new capability, and how it is gated

**SSH deploy is a new remote-execution path**, and this build's own lesson applies: part 2's
`deliver` first reached *around* the gated execution point and a whole-tree guard caught it. So
deploy does not grow its own transport. It goes through the executor the way
`executor.send_windows_scripts` does, host-locked to the **configured VPS address** — never a
request field — with per-call approval. A scan asserts no agent, orchestrator or loop module can
reach the deploy path, matching the locks on `:kali`, tunnels, Sliver and evasion.

The OOB server itself is deliberately dumb: append-only, no execution, no forwarding. The
strongest guarantee available for an internet-facing component is that there is nothing in it
worth attacking.

## 5. Verification

**End to end, on loopback, for real** — this is the point worth stating plainly, because the
first assumption was that nothing here could be verified without infrastructure. It can. The
server runs on `127.0.0.1` with DNS on `5353`; a resolver query carrying a minted token is sent
against it; the test asserts the hit was recorded, correlated to the right engagement and
step, and surfaced through the read API with the wrong bearer token refused. That exercises
every code path except public reachability.

**Hermetic suite:** the poll client, token minting, correlation, template rendering and the
config store are all unit-tested with no network. The loopback end-to-end runs as a proof
alongside the Docker isolation proof, not in the hermetic suite, since it binds sockets.

**Reported NOT-RUN until the VPS and domain exist** — exactly two things, never folded into a
pass: that NS delegation resolves publicly to the server, and one live hit from a real target.
The verify button converts both into real checks the moment the infrastructure is configured.

## 6. Assessment doc + PDF

Same commit. Must record that this is the first internet-facing HackPit component, what makes it
safe to expose (append-only, no execution, authenticated reads), and that provisioning was
deliberately declined with the reasons. Regenerate with `python docs/build-assessment.py`;
verify against the HTML and page-count delta, never by grepping the PDF.

## 7. Not in scope

Part 4's redirector. No provisioning, billing or registrar integration. No forwarding of any
kind. No storage of request bodies beyond a capped excerpt — a canary records that something
arrived and from where, not a copy of the target's traffic.
