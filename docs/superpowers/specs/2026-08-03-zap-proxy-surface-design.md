# ZAP proxy surface — design spec

**Date:** 2026-08-03
**Branch:** `main`
**Build:** #14, part 2 of 2 (part 1 = the gated scanner, landed `206cc01..d3722ae`)
**Pattern:** the deferred half of build #14. Part 1 excluded the daemon because an HTTP control
channel bypasses `validate_request`. This builds the daemon anyway — by making the transport a
command, so nothing bypasses anything.

## 1. What this unblocks

HackPit parses a run's **findings** and throws its **raw HTTP away**. After a `ffuf` run you have
a list of paths; you cannot see the request that produced one, the response headers, or the body.
The repeater can send a request you type by hand, but nothing feeds it what a tool actually sent.

This captures the traffic of every tool run inside the sandbox into one searchable place, and
turns each captured request into an `Endpoint` in engagement state.

## 2. The finding that makes this safe

**ZAP's API can be bound to `127.0.0.1` inside the container and driven with `docker exec`.**
Measured against the running sandbox on 2026-08-03, not assumed:

| Check | Result |
|---|---|
| `zaproxy -daemon -host 127.0.0.1 -port 8090` starts | yes, API answering after **7 s** |
| `curl 127.0.0.1:8090/JSON/core/view/version/` **from the host** | **refused — unreachable** |
| same call via `docker exec` | `{"version":"2.17.0"}` |
| request proxied from inside the sandbox is recorded | yes — `{"numberOfMessages":"5"}` |
| recorded message carries full request + response | yes, bodies included |

So the daemon exists, and **no socket reaches it from the backend**:

```
backend ──docker exec──> curl 127.0.0.1:8090/JSON/… ──> ZAP
                ▲
        the ONE channel into a sandbox, unchanged since M1
```

Part 1 §3 objected to an **ungated** control channel and to opening the isolated network. Neither
happens here. No port is published, so `assert_isolation_proven()` and
`docker/proof/isolation_proof.sh` still hold; and the transport is a command, so the executor's
gates apply to anything that runs.

## 3. Scope

**In:** the gated daemon lifecycle (start / stop / observed status), history read-back, mapping
captured requests into `Endpoint` records, an opt-in `proxy` flag on an exec request that points a
tool at the proxy, the `/cockpit/proxy/*` routes, the `:proxy` frontend, tests, a proof, and the
assessment.

**Out, and stated so it is not assumed:**

- **Browser interception.** Proxying a browser on the host requires publishing a container port,
  which breaks the lab sandbox's `internal: true` isolation. That is its own exposure decision
  with its own spec — the same "both, X first" split part 1 used.
- **Driving ZAP's scanner through the API.** Scanning stays on part 1's gated command path
  (`zaproxy -cmd -quickurl`). This surface records; it does not attack.
- **Any enforcement that the history reader stays read-only.** Both candidates were declined
  (2026-08-03, Zaid): a runtime allowlist validating URLs against ZAP's API surface, and a
  three-line static test grepping the module for `action/`. The reader is still *written* to be
  read-only — two module-level URL constants, no endpoint parameter anywhere — but that is a
  convention with nothing behind it. §7.3 records the consequence and the review rule.

## 4. Components

One new module, mirroring `cockpit/tunnels.py`, which already solves the "gate a POST-driven
listener" problem.

| # | Component | File |
|---|---|---|
| 1 | daemon lifecycle + history read | `backend/cockpit/proxy.py` (new) |
| 2 | routes: start / stop / status / history | `backend/cockpit/router.py` |
| 3 | `proxy` flag that points a tool at the listener | `backend/cockpit/models.py`, `executor.py` |
| 4 | captured request → `Endpoint` | `backend/state/parsers.py` |
| 5 | report-boundary redaction | `backend/report.py` |
| 6 | `:proxy` screen | `frontend/src/app/proxy/page.tsx` |
| 7 | tests + proof + assessment | `backend/test_zap_proxy*.py`, `docker/proof/zap_proxy_proof.sh` |

### 4.1 Lifecycle (`cockpit/proxy.py`)

Reuses `cockpit/lifecycle.py` rather than reimplementing spawn-and-hope:

- `lifecycle.spawn_watched(argv, interactive=False)` — a daemon needs no stdin, so it gets
  `DEVNULL` and `proc.stdin is None`. The no-writer invariant
  (`test_lifecycle_safety.py::test_watched_listeners_expose_no_stdin_writer`) covers it already.
- `lifecycle.observe(...)` — status is **observed** (`ss` inside the container), never assigned.
  **The settle window must accommodate a measured ~7 s JVM start**; the module's default is
  shorter, so `proxy.py` passes an explicit `settle` and a bounded readiness poll against
  `core/view/version` rather than sleeping a fixed time and hoping.
- One live proxy at a time, per container. A second start is refused, not silently stacked.

### 4.2 History read-back

`docker exec <container> curl -s http://127.0.0.1:<port>/JSON/core/view/messages/?start=&count=`

Ungated on purpose: a panel that refreshes cannot demand approval per refresh, and there is
precedent — `lifecycle.port_is_bound()` runs `ss` read-only and ungated for the same reason.

**Measured message shape** (`/JSON/core/view/messages/`, ZAP 2.17.0):

```
id, requestHeader, requestBody, responseHeader, responseBody,
rtt, timestamp, type, tags, note, cookieParams
```

`requestHeader` is the raw request — its first line gives method and URL. `responseHeader`'s
first line gives the status. Both are parsed with a small tolerant splitter that returns partial
records rather than raising, matching the "a parser must never break a completed run" invariant.

Records are shaped as `RepeaterExchange` (already defined in `cockpit/repeater.py`) rather than a
new model, so the existing repeater UI can render them and a captured request can be replayed.

### 4.3 Pointing tools at the proxy

`ExecRequest` gains `proxy: bool = False`. When set and a proxy is live, the executor prepends the
proxy flag **for that specific binary**, because the spelling differs per tool:

| tool | flag |
|---|---|
| `curl`, `ffuf`, `wget` | `-x http://127.0.0.1:<port>` (curl/wget), `-x` (ffuf) |
| `nuclei` | `-proxy http://127.0.0.1:<port>` |
| `sqlmap` | `--proxy=http://127.0.0.1:<port>` |

A tool with no known flag is run **unchanged**, and the response says so — silently dropping the
proxy flag would produce a run the operator believes was captured and was not.

**This introduces no new execution capability.** It rewrites arguments on a request that still
passes every gate, exactly as `tunnels.py` wraps a command with `proxychains` and says so:
*"Wrapping adds a prefix; it introduces NO new execution capability and no new gate."* The gated
argv and the executed argv are derived from **one** function, and a test asserts they are equal —
the Critical 2 invariant.

### 4.4 State ingest

Each captured request becomes an `Endpoint`: `url`, `method`, `status` from the response line,
`params` from the query string. Existing `upsert_endpoints`; no schema change.

## 5. Gating

**Start requires approval + red-confirm**, like the three existing listeners (gate audit finding
I2). A proxy earns the red-confirm at least as much as a pivot listener: it holds full request
bodies, so it sees credentials, session tokens and payloads in cleartext.

**But it runs in BOTH modes, and that is a deliberate divergence from `tunnels.py`.**
`tunnels.validate_start` refuses a request with no `engagement_id`, and its docstring explains
why: a pivot listener lives in the *engage* sandbox, so making the operator satisfy lab mode's
isolation gate would be "firing a gate on an unrelated condition… the operator would be told to
prove the lab is isolated in order to start a pivot into a client network."

That reasoning does not transfer — it inverts. The ZAP proxy runs in **whichever sandbox the
operator is working in**, so in lab mode the isolation gate is asking about the very container
the proxy occupies. It is the relevant condition, not an unrelated one. Copying the
engagement-only rule would also block the proxy from the lab, which is where most of its
practice value is (capturing a `ffuf` run against Juice Shop).

So `validate_start` here is simply `executor.validate_request(_gate_request(req))` with no
engagement precondition: lab mode gets its four gates including isolation, engagement mode gets
its three. Same function, same order, no new gate.

The gate is built the `tunnels.py` way: `server_argv_for(req)` is **the single derivation**, and
both `_gate_request()` and the spawn come through it. `validate_request` runs FIRST; on refusal
**nothing spawns**.

**Stop is not gated.** Stopping a listener removes capability; refusing to stop one would be a
gate that makes the system less safe. Same position `tunnels.py` takes.

## 6. Secrets

**Decision (2026-08-03, Zaid): store raw, redact only at the report boundary.**

Captured bodies contain passwords, `Authorization` headers, cookies and API keys. Redacting on
ingest was considered and rejected: it defeats the feature, because the request that matters is
usually the one carrying the token, and this is the operator's own engagement data on their own
disk.

So:

- **The panel and the store hold raw bodies.** Nothing is hidden from the operator.
- **`report.py` redacts.** A report is the artefact handed to a client or a grader, and a session
  token pasted into an OSCP report is an easy and real mistake. The redaction reuses the existing
  credential-vault masking rather than inventing a second one.
- **A test asserts a known secret in a captured body does not survive into a rendered report**,
  with a positive control proving the check can fail — the build #9 secret-in-record lesson.

## 7. Safety invariants this build must not weaken

1. **No published port.** The daemon binds `127.0.0.1` inside the container. `isolation_proof.sh`
   must still pass, and the proof in §9 asserts host-unreachability directly.
2. **`docker exec` remains the only channel** into a sandbox. No socket from backend to container.
3. **The history reader cannot act — by construction, and NOTHING CHECKS THIS.**

   The reader issues two fixed URLs, held as module-level constants:

   ```python
   _VIEW_COUNT = "/JSON/core/view/numberOfMessages/"
   _VIEW_MSGS  = "/JSON/core/view/messages/"
   ```

   No function in the module takes a path, endpoint or URL argument, so an `action/` call is not
   expressible without writing a visibly new function.

   **BOTH enforcement options were considered and BOTH declined (2026-08-03, Zaid):** the runtime
   allowlist (§3) and a static source test. This is therefore a *convention*, not a guarded
   invariant — the only one in this build with nothing behind it.

   **Why that placement matters, stated plainly rather than buried:** the history read is
   deliberately ungated (§4.2), so it is the one path here with no human approval step. Anything
   that reaches ZAP from it reaches ZAP unapproved. Today that is two read URLs and the risk is
   zero. The exposure is entirely to a *future* edit adding an action call to this module.

   **So the rule is a review rule:** any change to `cockpit/proxy.py` that introduces a URL
   parameter, or any URL other than the two constants above, reopens this decision. It does not
   get to be satisfied quietly.
4. **The gated argv is the executed argv** — one derivation, asserted.
5. **No new execution capability.** The `proxy` flag rewrites arguments on an already-gated
   request.
6. **`cockpit` and `arsenal` still do not reference each other** in either direction.

## 8. Testing

Hermetic (`test_zap_proxy.py`, `test_zap_proxy_safety.py`):

- gate order, with a positive control in the same test: an unapproved start and a start without
  `dangerous_ack` are both refused with nothing spawned
- gated argv == spawned argv, asserted on the source
- `requestHeader`/`responseHeader` parsing against a **real captured message**, committed as a
  fixture from the measurement in §2 — not hand-written
- malformed/partial messages yield partial records and never raise
- the per-tool proxy flag: correct spelling per binary, and an **unknown tool is left unchanged
  and reported**, with a control
- a known secret in a captured body does not survive into a rendered report, with a control

Proof (`docker/proof/zap_proxy_proof.sh`), for what no hermetic test can assert:

- the daemon starts and reports its version via `docker exec`
- **the API is unreachable from the host** — the load-bearing isolation check
- a request proxied from inside the sandbox is captured and reads back
- the captured message parses into a `RepeaterExchange` and an `Endpoint`

It reuses part 1's proof conventions, which cost three rounds to get right: compare the running
container's image ID against the built image before exec'ing into it, use `MSYS_NO_PATHCONV=1` on
container paths, pipe rather than staging through a host file, and never treat an exit code as a
result.

## 9. Definition of done

- `sh backend/run_safety_tests.sh` passes with the new files.
- `sh docker/proof/zap_proxy_proof.sh` passes, including host-unreachability.
- A start without `dangerous_ack` is refused with nothing spawned; with it, the proxy comes up and
  status is **observed**, not assumed.
- A `ffuf` or `curl` run with `proxy: true` appears in the history panel and its URL appears as an
  `Endpoint` in engagement state.
- `:proxy` ships **with** its endpoints — no orphaned routes (the build #13 part 1 lesson).
- `docs/ASSESSMENT-2026-07-26.md` updated and regenerated in the **same commit**, verified against
  the HTML (the PDF cannot be grepped — Edge subsets fonts to glyph IDs).
- CI green.
