# Out-of-band canary — interact.sh second backend

**Date:** 2026-08-06
**Branch:** `main`
**Build:** follow-on to #13 part 3 (the OOB canary)
**Pattern:** a second transport under an unchanged correlation pipeline. Build #13 part 3 built the
self-hosted canary (own VPS, own NS-delegated zone). This adds interact.sh as a **parallel** backend
so OOB capability exists with zero infrastructure — while keeping the owned, private backend.

## 1. What this unblocks

The self-hosted canary is the private, owned option, but it costs a VPS + a domain + one-time NS
delegation before a single hit can land. interact.sh (ProjectDiscovery's public OOB service, the
same shape as Burp Collaborator) needs none of that: register, generate a payload host, poll, get
the callback. The cost is that callbacks **transit a third party** — which is exactly why this is an
*addition*, not a replacement. The operator picks per test which backend to paste, or pastes both.

The valuable half — correlating a callback back to the step that caused it and filing it as a finding
— is **identical for both backends and reused unchanged**. Only the transport differs.

## 2. Scope

**In:**
* `backend/oob/interactsh.py` — the interact.sh protocol client (register / generate / poll /
  deregister), the crypto, its own session store, and its correlation map.
* `poll.py` extension — `poll_all()` that sweeps both backends and files through the existing ingest.
* `templates.py` extension — an interact.sh callback shape; the per-class catalog is reused verbatim.
* `router.py` extension — interact.sh register/deregister/status, auto-poll toggle, backend-aware
  mint/poll/verify.
* **Auto-poll** — a background timer that sweeps both backends and files findings on an interval.
* **Send-to-repeater** — a frontend-only convenience that pre-fills a rendered payload into the
  repeater editor.
* Frontend: interact.sh config/status, auto-poll toggle, send-to-repeater in `OOBCanaryScreen.tsx`.
* Tests (hermetic) + a live network proof against `oast.fun`.
* Assessment md + html + pdf, same commit.

**Out:**
* Provisioning of any kind (unchanged from part 3). interact.sh *needs* none.
* Auto-injection / autonomous delivery. Delivery stays a human action through the repeater — the
  propose-only invariant is untouched (operator decision: **L1**, 2026-08-06).
* Per-engagement interact.sh registrations. One global session with per-mint suffixes, matching the
  single-canary model.
* Self-hosted config/deploy changes. The SSH deploy gate is not touched — interact.sh has no VPS.
* Forwarding of any kind. This records callbacks; it never forwards.

## 3. The core asymmetry (why interact.sh is not just "another VPS")

| | Self-hosted (built) | interact.sh (this build) |
|---|---|---|
| Correlation id | **HackPit** mints `<token>` | **interact.sh** assigns a correlation-id; each payload is `<suffix><corr-id>.<server>` |
| Payload host | `<token>.<zone>` | the full interact.sh-generated host |
| Callback transport | VPS read API `/_hp/hits`, bearer auth | interact.sh `/poll`, RSA-OAEP + AES-CFB encrypted |
| Poll destination | one fixed host from config | one fixed interact.sh server from config |
| Correlate → findings → state | reused | **reused unchanged** |

Both backends converge on **the same correlated-hit dict** that `poll.findings_for()` already
consumes, and `poll.ingest()` files them identically.

## 4. Components

### 4.1 `backend/oob/interactsh.py` (new)

Self-contained like `tokens.py` — logic plus its own table. Contains:

* **Protocol client** over HTTP: `register`, `deregister`, and `poll`. Payload-host generation is a
  local string operation (correlation-id + a fresh per-mint suffix), no network.
* **Crypto** (via the already-present `cryptography` lib): RSA-2048 keygen at register; each poll
  returns an RSA-OAEP-SHA256-wrapped AES key and AES-256-CFB-encrypted interaction blobs, decrypted
  here. `secrets`, never `random`, for the correlation-id and secret-key (asserted structurally by
  the test, matching `tokens.py`).
* **Session store** — a new `oob_interactsh` table in the gitignored `sessions.db`:
  `server`, `correlation_id`, `secret_key`, `private_key` (PEM), `auth_token`, `registered_at`, and a
  `seen` set of interaction ids for dedup. `secret_key`, `private_key`, and `auth_token` are
  **write-only** — never returned by any view (the `has_secret` pattern from `config.py`), because
  anyone holding them can read a client's callbacks.
* **Correlation map** — a per-mint `suffix -> (engagement_id, step_id, note, at)` table, mirroring
  `tokens.py`. At generate time a fresh suffix is minted and stored; at poll time the suffix is
  extracted from each interaction's full host and looked up.
* **Normalizer** — turns each decrypted interaction into the exact hit dict `findings_for` consumes:
  `kind` (`dns`/`http`), `qname`/`host`, `qtype`/`method`/`path`, `source_ip`, `at`, `body`
  (capped), and the correlation fields.

**Default server** `oast.fun`, overridable, with an optional `auth_token` so a self-hosted
interactsh-server also works (operator decision, 2026-08-06).

### 4.2 `poll.py` — `poll_all()` (extend, do not muddy the self-hosted client)

The self-hosted `poll()` stays exactly as is. A new `poll_all(sessions, after=None)`:

1. self-hosted (if configured): `fetch → correlate` → correlated dicts.
2. interact.sh (if a session exists): `interactsh.poll_correlated()` → correlated dicts.
3. merge, call the existing `ingest()` once, advance **each backend's cursor independently**.

A failure in one backend must not stop the other or advance the failed one's cursor — the part 3
rule (re-reading is free, missing a hit is not) holds per-backend.

### 4.3 `templates.py` (tiny)

`Callback` gains a way to carry an interact.sh full host in the same slots the payloads already read
(`fqdn`, etc.). The per-class SSRF/XXE/blind-RCE/blind-SQLi/JNDI catalog is otherwise **unchanged** —
a payload differs only in the callback host. The render-a-string-and-stop boundary is unchanged and
still asserted by `test_oob_templates.py`.

### 4.4 Auto-poll (new)

A background timer started in the app lifespan that calls `poll_all()` on an interval when at least
one backend is configured.

* **Read-only automation.** It reaches `poll_all → ingest → state` and **nothing else** — no
  execution surface, no delivery, no offensive action. It reads the operator's own callbacks. This
  does not cross the propose-only invariant and is stated as such in the assessment.
* **Toggle + interval** stored in an `oob_settings` row; default **enabled when a backend is
  configured** (the "callbacks just appear" the operator asked for), with a visible off switch.
* Errors are logged and swallowed — a slow or rate-limited backend must never crash the app or the
  other backend's sweep. Interval floored so it cannot hammer interact.sh.

### 4.5 Send-to-repeater (new, frontend-only)

A button in the OOB panel hands a rendered payload to the repeater screen, where it appears pre-filled
in the request editor and the operator clicks Send.

* **No backend coupling.** `backend/oob` does **not** import `cockpit/repeater`. The repeater's
  load-bearing rule (orchestrator/agent/executor have zero code path to `send()`,
  `test_repeater_is_human_only`) is untouched, and the human-sends invariant holds: the payload
  arrives in the editor, a human sends it.

### 4.6 `router.py` (extend)

* `GET /oob` — also returns interact.sh status (masked: server, correlation-id **prefix only**,
  generated count, registered_at, last poll) and the auto-poll setting. Never a secret.
* `POST /oob/interactsh/register` — start or rotate a session (a new outbound call, contained per §5).
* `DELETE /oob/interactsh` — deregister on the server and forget locally.
* `POST /oob/autopoll` — set the toggle/interval.
* `POST /oob/mint` — renders payloads for **every configured backend** in one call, all tied to the
  same engagement/step/note; response labels payloads by backend.
* `POST /oob/poll` — calls `poll_all()`.
* `POST /oob/verify` — adds the interact.sh live check.
* Self-hosted `/oob/config`, `/oob/deploy` unchanged.

## 5. Safety & containment (load-bearing)

interact.sh polling is a **new backend outbound egress**, so it inherits `poll.py`'s exact
containment, asserted by tests:

* **Destination resolved server-side from the store**, never a request field. No argument can change
  where it connects.
* **No redirects followed** (a tampered/proxied endpoint answering `302 http://169.254.169.254/…`
  must be an error, not an SSRF from the backend host), **no ambient proxy**, **capped response**,
  JSON parsed and **never executed**. Decrypted interaction data is treated as untrusted — capped and
  validated before it becomes a record.
* **Secrets** (`secret_key`, `private_key`, `auth_token`) are bearer secrets: gitignored in
  `sessions.db`, write-only, never serialized by any view.
* **No agent/orchestrator/loop reach.** `interactsh.py` and the auto-poll task open outbound network,
  so the existing whole-tree safety scans (no-execution, no unapproved egress from an agent path)
  must cover them; neither contains an execution primitive nor a delivery surface.
* **No new gated command.** register/poll/deregister are contained backend calls like the existing
  self-hosted poll, not executor commands. The SSH deploy gate is untouched.

## 6. Verification

* **Hermetic (in the suite):** mock interact.sh's register/poll with canned encrypted payloads —
  generate a keypair in-test, encrypt a fake interaction with the same RSA-OAEP + AES-CFB scheme,
  and assert the client **decrypts → correlates → files**. Cover: the crypto round-trip; the
  containment (no-redirect refused, response cap, secret-never-serialized); the suffix correlation
  map; `poll_all()` merging self-hosted + interact.sh; and dedup via the `seen` set.
* **Proof (network, non-hermetic, alongside the loopback proof):** a real round-trip against
  `oast.fun` — register, DNS-resolve a generated host, poll, assert the hit came back, decrypted, and
  correlated. **This can run live without owning infrastructure** — interact.sh's whole appeal — so
  unlike the self-hosted backend it is not reported NOT-RUN.

## 7. Docs

Assessment md + regenerated html + pdf, **same commit**. Must record: OOB now has two backends; the
interact.sh backend **transits a third party** (the privacy tradeoff, stated plainly); the new
outbound poll's containment matches the self-hosted poll; and auto-poll is read-only automation that
does not cross the propose-only invariant. Regenerate with `python docs/build-assessment.py`; verify
against the HTML and page-count delta, never by grepping the PDF.

Also fix the stale note in `cockpit/repeater.py` (lines ~41-44) that calls the VPS-for-callbacks
piece "deferred" — it shipped in build #13 part 3.

## 8. Not in scope

Auto-injection / autonomous delivery (L1 decision). Per-engagement interact.sh sessions. Any
provisioning, billing, or registrar work. Any forwarding. Storage of request bodies beyond a capped
excerpt.
