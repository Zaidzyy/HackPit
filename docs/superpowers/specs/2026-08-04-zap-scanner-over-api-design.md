# ZAP scanner-over-API — design spec

**Date:** 2026-08-04
**Branch:** `main`
**Build:** #14, part 3 of 3 (part 1 = the gated `-quickurl` scanner, part 2 = the recording proxy)
**Pattern:** part 2 built the daemon by making the transport a command. This drives the daemon's
**scanner** the same way — and gets something neither earlier part could: an active scan aimed at
**the exact endpoints the proxy already captured**, instead of re-spidering the target from scratch.

## 1. What this unblocks

Part 1 can scan a URL: `zaproxy -cmd -quickurl <url>` spiders the site and then attacks whatever
the spider found. That is the only aim it has. It cannot attack:

- an endpoint reached only after a login the spider cannot perform,
- an API route that no page links to (`/rest/products/search?q=` is discovered by *using* the app,
  not by crawling it),
- the specific request a `ffuf` or `nuclei` run just made.

Part 2 captures all of those into ZAP's Sites tree as a side effect of recording. **Nothing yet
attacks them.** This joins the two halves: the proxy records what you actually touched, and the
scanner attacks precisely that.

## 2. The measurements

Measured 2026-08-04 against ZAP 2.17.0 in `hackpit-kali-sandbox`, driven the part-2 way
(`docker exec` → `curl` → `127.0.0.1:<port>`). Not inferred.

### 2.1 The scan lifecycle

| Call | Result |
|---|---|
| `/JSON/ascan/action/scan/?url=<captured url>&recurse=false` | `{"scan":"0"}` — launched |
| `/JSON/ascan/view/status/?scanId=0` | `{"status":"100"}` |
| `/JSON/ascan/view/scans/` | `[{"reqCount":"376","alertCount":"1","progress":"100","id":"0","state":"FINISHED"}]` |
| `/JSON/ascan/action/stop/?scanId=0` | `{"Result":"OK"}` |
| `/JSON/ascan/view/status/?scanId=999` | `{"code":"does_not_exist","message":"Does Not Exist"}` |

**376 real attack requests against one captured endpoint**, and it found a **High SQL injection**
(`pluginId 40018`, param `q`, attack `measure'`) that part 1's spider-first path had no reliable
route to.

### 2.2 *** ZAP REFUSES TO SCAN WHAT IT HAS NOT SEEN *** — the containment property

| Call | Result |
|---|---|
| `ascan/action/scan?url=http://hackpit-lab-target:3000/never-visited-xyz` | `{"code":"url_not_found","message":"URL Not Found in the Scan Tree"}` |
| `ascan/action/scan?url=http://10.99.99.99/` | `{"code":"url_not_found",…}` |

This is not merely the feature's selling point. It is a **second containment property, enforced by
ZAP itself and independent of HackPit's gates**: the active scanner's reachable set is bounded by
what already passed through the proxy. A target that was never proxied cannot be attacked through
this path at all, even if every HackPit gate were bypassed.

It is a bound, not a control — HackPit's own gates remain the control (§5). But it means the
worst case of a defect in this build is "it attacked something you already proxied", not "it
attacked an arbitrary host".

### 2.3 The alert shape — **NOT the shape `parse_zap` expects**

`/JSON/core/view/alerts/?start=0&count=99` returns a **flat** list:

```
alerts[] : name, alert, risk, url, method, param, evidence, attack,
           pluginId, alertRef, confidence, cweid, wascid,
           description, solution, reference, messageId, inputVector, tags{}
```

Part 1's `state/parsers.py::parse_zap` parses the `-quickurl` **report**, which is nested and
differently keyed:

| | `-quickurl` report (part 1) | API view (this build) |
|---|---|---|
| shape | `{"site":[{"alerts":[…]}]}` | `{"alerts":[…]}` flat |
| severity | `riskcode` — `"0"`–`"3"` | `risk` — `"High"`/`"Medium"`/`"Low"`/`"Informational"` |
| plugin | `pluginid` (lowercase) | `pluginId` (camelCase) |
| where | `instances[].uri` | `url` on the alert itself |

`_zap_report()` returns `None` unless the object has a `site` key, so **feeding an API response to
`parse_zap` yields exactly zero findings, silently, forever.** That is the part-1 headline trap in
a new place — a parser matching a string nobody checked against reality. This build therefore adds
a separate mapper, and tests it against a **real captured response** committed as a fixture
(`backend/test_support/zap_api_alerts_fixture.json`, the two alerts from §2.1), never a
hand-written one.

Also measured: `core/view/alerts` is **not scan-scoped** — it returns passive-scan alerts too (the
`Cross-Domain Misconfiguration` in the fixture came from `sourceid:3`, the passive scanner), and
alerts **survive `removeAllScans`**. Scoping is by `baseurl=`, which was measured to filter
correctly (2 alerts for the lab host, `{"alerts":[]}` for another).

### 2.4 The gate accepts a full URL and scopes on its host

Measured against the real `executor.validate_request`, surface `zaproxy -quickurl <url>`:

| Request | Verdict |
|---|---|
| lab URL, `approved=True`, `dangerous_ack=True` | **allowed** |
| lab URL, no `dangerous_ack` | refused at **danger** — *"active web scan"* |
| lab URL, not approved | refused at **approval** |
| `http://example.com/x`, both set | refused at **target** — *"'example.com' is not the lab"* |

So the existing scope extractor reads the host out of a full URL with a port and a query string,
and the target-lock refuses an off-lab one. No new gate is needed, and none is added.

## 3. Scope

**In:** gated scan start, scan status/stop, alert read-back, alerts → `Finding` + `Endpoint`
mapping, the `/cockpit/proxy/scan*` routes, the scan panel on `:proxy`, tests, a proof, the
assessment.

**Out, stated so it is not assumed:**

- **Browser interception.** Still blocked on [[zap-api-unauthenticated-finding]]: publishing the
  port for a browser also publishes an unauthenticated scan trigger to the host. This build does
  not change that and does not publish anything.
- **Spidering via the API** (`spider/action/scan`). The whole point here is to attack the captured
  tree; adding a spider re-introduces "attack whatever it happened to crawl", which is part 1's
  job and carries part 1's confirm.
- **Scan policies / attack strength / alert threshold tuning.** The default policy is used. A
  policy that decides its own aggression is the `-autorun` shape part 1 excluded for the same
  reason: the approved command would stop describing what runs.
- **Authenticated scanning** (`scanAsUser`, contexts, session management). Its own build.

## 4. Components

| # | Component | File |
|---|---|---|
| 1 | scan lifecycle + alert read + mapping | `backend/cockpit/proxy.py` (extended — §6) |
| 2 | routes: start / status / stop / alerts | `backend/cockpit/router.py` |
| 3 | scan panel | `frontend/src/app/proxy/page.tsx`, `frontend/src/lib/api.ts` |
| 4 | tests | `backend/test_zap_scan.py`, `backend/test_zap_scan_safety.py` |
| 5 | proof | `docker/proof/zap_scan_proof.sh` |

## 5. Gating — and the invariant that replaces "gated argv == spawned argv"

**Start requires approval + red-confirm**, through the real `executor.validate_request`. Nothing
new is added; the existing gates are given an honest surface:

```python
ExecRequest(command="zaproxy", args=["-quickurl", target_url], …)
```

**Why that surface is honest rather than a fudge.** `-quickurl` is defined in
`allowlist._TOOL_ATTACK_FLAGS` as *"spider THEN ACTIVE SCAN — real SQLi/XSS/command-injection
payloads at every parameter it discovered"*. An `ascan/action/scan` is that attack **minus the
spider**. So the declared command describes strictly **more** aggression than what runs, and it
carries the real target through the real scope extractor (§2.4). Declaring more than you do is
safe in a way declaring less never is.

### 5.1 The new Critical-2 shape, and the lock for it

Part 2's lock was *the gated argv is the spawned argv*. **That lock cannot be restated here**,
because the two artefacts are in different languages: the gate classifies an **argv**, and what
executes is a **URL**. Asserting string equality would be meaningless.

The property that actually matters is the one underneath it — **the thing the gate scoped is the
thing that gets attacked** — so the lock becomes:

> `scan_target_for(req)` is the **single derivation**. `_gate_scan_request()` puts its output in
> the gate surface, and `scan_url_for()` percent-encodes the *same* output into the API URL. A
> test asserts the host the gate scoped is the host the API attacks, for a target with a port, a
> path, a query string and an encoded character.

### 5.2 Query-parameter injection into the API URL — a defect class that did not exist before

The scan target is operator-supplied and is interpolated into a URL that carries **the scan's own
parameters**:

```
/JSON/ascan/action/scan/?url=<TARGET>&recurse=false
```

A target containing `&recurse=true&…` would append or override ZAP's parameters — the operator
approves one scan and a different one runs. This is the Critical-2 failure mode expressed in a
query string, and it is **not** hypothetical: nothing about a URL field stops a `&`.

`scan_url_for()` therefore percent-encodes the target with `quote(safe="")`, so `&`, `=`, `#` and
`?` cannot survive into ZAP's parameter parser. A test asserts that a target carrying
`&recurse=true` cannot turn recursion on.

(The transport itself is already safe from *shell* injection: `_api_get` passes argv as a list to
`subprocess.run` with no shell, as part 2 established. This is about ZAP's parser, not the shell.)

### 5.3 Concurrency is bounded by OBSERVATION, not by local state

A second concurrent scan doubles the attack traffic against a target the operator approved once.
`start_scan` therefore refuses when ZAP reports a scan already running — read from
`ascan/view/scans`, i.e. **observed from ZAP**, not tracked in a backend dict that a restart would
lose. Same principle as part 2's `lifecycle.observe`: status is observed, never assigned.

### 5.4 Stop is not gated

Stopping an active scan REMOVES attack traffic. A gate that can refuse to stop one is a gate that
makes the system less safe — the position `tunnels.py` and part 2 both take. `stop_scan` is
reachable with no approval, deliberately, and is the panic button while 376 requests/endpoint are
in flight.

## 6. Module layout — the reopened decision, ASKED AND ANSWERED

Part 2's spec §7.3 set a review rule: *any change to `cockpit/proxy.py` that introduces a URL
parameter, or any URL other than the two view constants, reopens the read-only decision.* This
build introduces `action/` URLs, so the decision was reopened and put to Zaid with three options.

**Zaid chose: one module, no guard** — the scanner lives in `cockpit/proxy.py` alongside the
ungated history reader, and the proposed structural split (a separate module so the ungated reader
could never gain an action URL) was declined. That is his call and it is not to be re-litigated or
quietly "fixed" later.

**What that decision is and is not:**

- It is a decision about **module layout**, and a decision to decline a guard on that layout.
- It is **not** a decision to leave scan control ungated. Scan control IS gated: build an
  `ExecRequest`, pass `executor.validate_request`, then exec — the `tunnels.py` shape, unaffected
  by where the code lives.
- What is accepted is the **residual risk**: the ungated history reader and the gated scan control
  share one module, with nothing structural stopping a future edit from calling an action URL from
  the read path.

The module docstring and the URL-constant block carry this distinction so the next reader inherits
the reasoning rather than the ambiguity. The constants are split into a `read, ungated` group and
an `action, GATED` group, and the comment states which functions may touch which.

## 7. Safety invariants this build must not weaken

1. **No published port.** Unchanged — nothing here publishes anything; the proof re-asserts
   host-unreachability because this build adds the first *action* URLs behind that boundary.
2. **`docker exec` remains the only channel.** No socket from backend to container.
3. **Every scan start passes `executor.validate_request`** — approval, danger, target/scope,
   isolation — with the real target in the surface.
4. **The scoped host is the attacked host** (§5.1), one derivation, asserted.
5. **The target cannot inject ZAP API parameters** (§5.2), asserted.
6. **Nothing starts on a refusal** — the gate runs before any exec.
7. **Stop stays ungated** (§5.4).
8. **The history read path stays read-only** — now a *convention with a stated boundary* rather
   than an unqualified one (§6). Restated in the module.
9. **`cockpit` and `arsenal` still do not reference each other.**

## 8. Testing

Hermetic (`test_zap_scan.py`, `test_zap_scan_safety.py`):

- unapproved start refused at **approval**; no-`dangerous_ack` refused at **danger**; each with a
  control in the same test
- an **off-lab target refused at the target gate** — the scope extractor sees the real host
- the scoped host == the attacked host, for a URL with port + path + query
- **`&recurse=true` in the target cannot turn recursion on** (§5.2), with a control proving the
  parameter *can* be set legitimately
- nothing execs on a refusal (source-order, as part 2 does)
- stop is not gated (source-level)
- alerts → `Finding`/`Endpoint` **against the real committed fixture**: the High SQLi maps to
  severity `high` with its plugin id and the exact URL
- a malformed/partial alert yields a partial record and never raises
- **the part-1 report parser and this mapper are not interchangeable**: `parse_zap` on the API
  fixture yields zero findings, and that is asserted so the shape difference in §2.3 can never be
  "simplified" into one function by someone who did not measure both

Proof (`docker/proof/zap_scan_proof.sh`) — what no hermetic test can assert:

- the daemon is up and the API is **unreachable from the host** (inherited, re-run because this
  build puts action URLs behind that boundary)
- **a URL never proxied is refused by ZAP** (`url_not_found`) — §2.2 containment, measured live
- a captured endpoint scans to completion and the alert count rises
- the REAL alert response maps to `Finding`s with the real mapper — the fixture and reality agree
- stop works and teardown leaves nothing listening

Part 1/2 proof conventions apply unchanged: compare image IDs first, `MSYS_NO_PATHCONV=1` on
container paths, pipe into python rather than staging through a host file, and decide on the
artefact because **an exit code is not a result**.

## 9. Definition of done

- `sh backend/run_safety_tests.sh` green with the new files (68 → 70).
- `sh docker/proof/zap_scan_proof.sh` green, including `url_not_found` and host-unreachability.
- A scan without `dangerous_ack` is refused with nothing started; with it, a captured endpoint is
  scanned and its findings appear in engagement state.
- `:proxy` ships the scan panel **with** its endpoints — no orphaned routes.
- `docs/ASSESSMENT-2026-07-26.md` updated and regenerated in the **same commit**, verified against
  the HTML (the PDF cannot be grepped).
- CI green, and every verification gated on a captured `$?` — never `cmd | tail && git commit`.
