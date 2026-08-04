# Browser interception + browser-driven crawl — design spec

**Date:** 2026-08-04
**Branch:** `main`
**Build:** #15, in two parts
**Pattern:** build #14 part 2 made a daemon safe by changing the TRANSPORT so nothing was published.
This publishes one — deliberately, for the first time in the project — because a **measurement
that build relied on turned out to be wrong**, and because without it HackPit cannot get a single
HTTP response out of nine of the eleven assets in a real bug bounty program.

---

## 1. Why this stopped being optional

On 2026-08-04 a passive sweep of the Majid Al Futtaim Lifestyle program (Bugcrowd, in scope, one
`HEAD` per host) returned **nothing at all** from every host. Not rate-limited — refused:

| protocol | result |
|---|---|
| HTTP/2 | instant stream reset, `INTERNAL_ERROR` |
| HTTP/1.1 | total timeout, 0 bytes in 15s |

Two *different* failure modes on two protocols is an edge actively refusing the client, not a
protocol quirk. Nine of the eleven assets sit behind **Akamai**, which these brands run with Bot
Manager. HackPit's egress is fine — it reached Akamai and Akamai said no.

**So the honest state of the product is: against WAF/bot-managed targets it does not reach rate
limiting, it does not reach request one.** The audit's answer to "can it run a full bug bounty"
was *"partly — breaks at volume"*. Volume is a problem you would like to have.

A real browser is what passes: correct TLS fingerprint, real headers, JS execution, a real
profile. That is the whole of this build.

---

## 2. The measurement that unblocked it — and the one that was wrong

Build #14 part 2 recorded, as a MEASURED finding, that ZAP's `api.key` *"enforces NOTHING"*, and
that finding blocked browser interception for a day. **It is wrong.** Re-measured 2026-08-04
against ZAP 2.17.0 in the sandbox, started with `-config api.disablekey=false -config
api.key=<secret>`:

| check | result |
|---|---|
| `core/view/version` **without** key | refused (empty) |
| same **with** key | `{"version":"2.17.0"}` |
| **`ascan/action/stop` without key** | **refused (empty)** |
| same with key | answers normally |
| wrong key | refused |
| **the PROXY, meanwhile** | `HTTP 200` — serves normally |

**Why the original was wrong, and it is the reusable part: ZAP persists `-config` values into
`$HOME/.ZAP/config.xml`.** `cockpit/proxy.py::server_argv_for` passes `-config
api.disablekey=true` on *every* proxy start. The original test ran `-config api.key=…` with no
explicit `disablekey`, inherited `true` from a previous HackPit run, and concluded ZAP was
broken. **HackPit was disabling its own lock and we blamed the tool.**

Generalise, and add it to the trap list beside "the container is not the image": **a daemon that
persists its configuration makes every measurement conditional on what a previous run wrote.**
State the flag explicitly, or you are measuring history.

### 2.1 What else was measured

| fact | result |
|---|---|
| Chromium in the sandbox image | **present**, `150.0.7871.124` |
| `chromedriver` / `geckodriver` | **absent** |
| ZAP `ajaxSpider` component | **present** (`{"status":"stopped"}`) |
| ZAP Selenium addon | **installed** (`selenium-release-15.43.0.zap`) |
| configured browser id | `firefox-headless` — **and Firefox is not in the image** |
| `setOptionBrowserId` validation | **NONE — it accepted `not-a-browser` with `{"Result":"OK"}`** |
| crawl knobs | `MaxCrawlDepth: 10`, `MaxDuration: 60` |
| apt repository lists in the container | **zero files** — so package availability is UNVERIFIED |
| lab network `hackpit-isolated` | `internal: true`, no gateway |

---

## 3. Scope

**Part 1 (B) — publish the proxy so a real browser can use it.** Engagement sandbox only.
**Part 2 (A′) — drive ZAP's AJAX spider with a real browser**, so the crawl continues from the
session the human established by hand.

**Out, stated so it is not assumed:**

- **The lab.** `hackpit-isolated` is `internal: true` — Docker attaches no gateway, so a published
  port has no route. This is engagement-only **by physics, not by preference**, which happens to
  match Zaid's standing rule: if the lab constrains a feature, build it for engagements.
- **Our own headless-Chromium driver.** Considered and rejected in favour of A′ — see §6.
- **Mobile.** Decided against separately (audit §3.1a).
- **Bot-detection evasion.** This build uses a real browser because that is what a real user has.
  It does not spoof TLS fingerprints, rotate identities, or defeat a CAPTCHA. If a target refuses
  a genuine browser, that is a result and it gets recorded, not worked around.

---

## 4. Part 1 — publishing the port

### 4.1 What changes

- `docker/docker-compose.yml`: the **engage** sandbox publishes `127.0.0.1:8090:8090`.
- `cockpit/proxy.py::server_argv_for` stops passing `api.disablekey=true` and instead passes
  `api.disablekey=false` plus `api.key=<per-start random>`.
- The operator points Firefox/Chrome at `127.0.0.1:8090` and browses. ZAP records it exactly as
  it records a tool run today; the history panel, the endpoint ingest and part 3's scanner all
  work unchanged, because nothing downstream cares how a request arrived.

### 4.2 The safety argument, restated — because part 2's no longer applies

Part 2's argument was *"no port is published, so the API is unreachable, so the only channel is
`docker exec`, which the gates classify."* **Half of that is now deliberately false.** The
replacement is not weaker, but it is different and it must be stated in full:

1. **Bound to host loopback, not `0.0.0.0`.** `127.0.0.1:8090:8090` — reachable from processes on
   Zaid's machine, never from the LAN. The compose file must not use the short `8090:8090` form,
   which binds all interfaces.
2. **The API requires a key, and the key is enforced** (§2 — measured on views *and* actions).
   What is published unauthenticated is an HTTP **proxy**, which is the entire point; the control
   channel behind the same listener refuses everything without a secret HackPit alone holds.
3. **Engagement sandbox only.** The lab's `internal: true` isolation and
   `docker/proof/isolation_proof.sh` are untouched.
4. The key is **random per start**, so it does not persist between sessions and there is no
   long-lived secret to leak.

**Residual risk, accepted and written down:** any local process on the machine can use the proxy
(it cannot scan — that needs the key). Impact is that traffic gets recorded that the operator did
not intend. That is a privacy annoyance on a single-user machine, not a control failure.

### 4.3 *** THE KEY MUST NOT REACH A RUN RECORD ***

`-config api.key=<secret>` on the command line puts the secret in the spawned argv — and HackPit
**records argv** into run records, which feed the state store, the LLM prompt and rendered
reports. Build #13 part 3 already learned this shape (*"the read secret rides stdin into a 0700
file rather than a command line, because `ps` is world-readable"*).

The mechanism already exists: `cockpit/secretargs.py` redacts secrets from recorded argv. **The
key must be registered with it**, and a test must assert a started proxy's recorded argv contains
the redaction marker and not the key — with a positive control proving the check can fail. This is
the single easiest way for this build to leak a credential and it must be closed by test, not by
care.

### 4.4 `isolation_proof.sh` must be rewritten, not relaxed

Its load-bearing check today is *"the ZAP API is UNREACHABLE from this host"*. That assertion is
about to become false **for the engage sandbox and only for it**. The proof must therefore split:

- **lab sandbox** — unchanged. Still unreachable. Any failure here is still a stop-everything.
- **engage sandbox** — reachable, **and refuses an API call without the key**, **and answers with
  it**, **and still serves as a proxy**. Three assertions replacing one, plus a control.

Deleting the assertion, or weakening it to "reachable", would throw away the check that made part
2 defensible. The property being proven changes from *"nothing can reach the control channel"* to
*"the control channel refuses everyone who does"* — and the second needs more assertions, not
fewer.

---

## 5. Part 2 — the AJAX spider

### 5.1 Why it is worth having, given part 1

Part 1 gives manual browsing. Part 2 gives scale — **and the reason to prefer ZAP's spider over
our own browser driver exists only because part 1 lands first**: manual browsing establishes an
**authenticated session inside ZAP**, and the AJAX spider runs through that same ZAP, so it
inherits those cookies and crawls the logged-in application.

A separate headless Chromium would start cold and need scripted authentication per target — an
auth-automation problem this build would then own forever. Log in once by hand, let the spider
expand from there, let part 3's scanner attack what both produced. Three stages, one pipeline,
no glue code, because stage 3 already exists and stage 2 is one more gated API action in the
shape `start_scan` already established.

### 5.2 What it needs

- **A webdriver in the image.** `chromedriver` is absent. The likely package is `chromium-driver`,
  **but this is UNVERIFIED**: the container has zero apt list files, so `apt-cache` cannot see any
  uninstalled package and the check performed proved nothing. **The Dockerfile must `apt-get
  update` and then install it, and the build must FAIL LOUDLY if the package does not exist.**
  This is exactly how build #14 part 1 was written against `zap-baseline.py`, which Kali does not
  ship — caught only by the image build. Do not design around a package name until the image says
  it exists.
- **`optionBrowserId` set to a Chromium-backed value** — and **verified**, because
  `setOptionBrowserId` **does not validate**: it accepted `not-a-browser` and answered
  `{"Result":"OK"}`. Setting it proves nothing. The proof must start a crawl and confirm a browser
  actually launched and messages were captured. *An OK is not a result*, in the same family as
  *an exit code is not a result*.

### 5.3 Gating — and why the red-confirm is required for a *different* reason

The crawl is gated like every other action: build an `ExecRequest`, pass
`executor.validate_request`, then act. The equivalent-command surface is
`zaproxy -zapit <target>` — part 1 defined that as *"reconnaissance: crawl + fingerprint, no
attack traffic"*, which is what a crawler is.

**But it still requires `dangerous_ack`, and the reason must be stated because it is not the
scanner's reason.** The active scanner earns its confirm by sending injection payloads. An AJAX
spider earns one because **it drives a real browser that clicks things**. On a production
e-commerce site — which is exactly what is in scope here — clicking everything reachable can
delete a basket, submit a form, trigger an email, or place an order. That is a different hazard
from SQLi and arguably a more embarrassing one.

**`MaxCrawlDepth` and `MaxDuration` go in the approved surface**, for the same reason `-autorun`
was excluded in part 1: a crawler that decides its own depth means the command the human approved
has stopped describing what runs.

---

## 6. Alternatives considered and rejected

| option | why not |
|---|---|
| **Our own headless Chromium**, driven by `docker exec` | Duplicates a crawler ZAP already ships, needs Playwright or a hand-written CDP client, and starts from a cold session so it owns authentication forever (§5.1). Chromium's presence in the image makes a *one-off* `--dump-dom` command cheap later if wanted; it is not a crawler. |
| **Filtering reverse proxy** in front of ZAP, dropping `/JSON/` | Was the leading candidate while the key was believed useless. Now unnecessary: it would be a hand-written security predicate standing in for one ZAP enforces itself, and a bypass in it would be the whole hole. |
| **Second ZAP with the API disabled**, chained upstream | Two instances need `-dir` (ZAP locks its home directory, not its port — build #14 part 3), and the browsing instance would have no API, so its captures could not be read back. |
| **noVNC / interactive desktop in the container** | Publishes a remote-desktop control channel instead of a keyed proxy — strictly more exposure for less benefit. |

---

## 7. Safety invariants this build must not weaken

1. **The lab sandbox publishes nothing** and stays `internal: true`. `isolation_proof.sh`'s lab
   half is untouched.
2. **The published port binds host loopback only.** Never the short `8090:8090` form.
3. **The API key is enforced** (`api.disablekey=false`) and **random per start**.
4. **The key never reaches a run record, a report or a prompt** — via `secretargs`, asserted.
5. **Every crawl passes `executor.validate_request`** with the real target in the surface, and
   carries approval + red-confirm.
6. **Depth and duration are in the approved surface.**
7. **Stop stays ungated** for both proxy and crawl — stopping removes capability.
8. `cockpit` and `arsenal` still do not reference each other.

---

## 8. Testing

Hermetic:

- the compose file publishes **loopback-only**, asserted on the file, with a control that the
  short form would fail the check
- the daemon argv carries `api.disablekey=false` and a key, and **the recorded argv is redacted**
  — with a positive control proving the redaction check can fail
- the key is different on two consecutive starts
- crawl gating: unapproved → `approval`; no `dangerous_ack` → `danger`; off-scope target →
  `target`; each with a control in the same test
- the scoped host is the crawled host — one derivation, the part-3 lock restated for this action
- depth/duration appear in the gate surface
- stop is not gated (source-level)

Proof (`docker/proof/browser_intercept_proof.sh`), for what no hermetic test can assert:

- the engage sandbox's port **is** reachable from the host
- **an API call from the host without the key is REFUSED**; with the key it answers — the check
  the whole build rests on
- the proxy serves a real request from the host, and it appears in ZAP's history
- the **lab** sandbox's API is still **unreachable** from the host
- the AJAX spider actually launches a browser and captures messages — not merely that
  `setOptionBrowserId` returned OK
- teardown leaves nothing listening

Part 1/2/3 proof conventions apply unchanged: compare image IDs first, `MSYS_NO_PATHCONV=1` on
container paths, pipe into python rather than staging through a host file, and decide on the
artefact.

---

## 9. Definition of done

- `sh backend/run_safety_tests.sh` green with the new files.
- `sh docker/proof/browser_intercept_proof.sh` green, including the without-key refusal and the
  lab's continued unreachability.
- A browser on Windows, pointed at `127.0.0.1:8090`, browses a target and the traffic appears in
  `:proxy` — and part 3's scanner can then attack a URL captured that way.
- The AJAX spider crawls from a manually-authenticated session and its finds appear in the same
  history.
- **Verified against a real Akamai-fronted in-scope host that a bare `curl` cannot reach** — that
  is the acceptance test for this entire build, and if a real browser is refused too, that is the
  finding and it gets written down rather than worked around.
- `:proxy` ships the new controls with their endpoints — no orphaned routes, and the screen is
  **looked at in a browser**, not merely typechecked.
- `docs/ASSESSMENT-2026-07-26.md` updated and regenerated in the **same commit**, verified against
  the HTML.
- The corrected `api.key` finding is written into `zap-api-unauthenticated-finding.md` — that
  memory currently states the opposite of what is true and will mislead the next session.
- CI green, every verification gated on a captured `$?`.
