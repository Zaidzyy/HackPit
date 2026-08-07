# Build spec — HTTP request-smuggling detector (web core)

**Status:** ready to execute in a fresh session. **Author:** planning session, 2026-08-07.
**One line:** a gated surface that probes a target for **request smuggling / desync** — CL.TE, TE.CL, CL.CL, TE.TE and the modern **CL.0 / H2 desync (H2.CL, H2.TE, H2.0)** — using safe timing-differential detection first, socket-poisoning confirmation only on explicit approval. Today HackPit has smuggling KB + the bypass/fronting work from build #18, but no tester.

---

## 0. Guiding constraint (read first, do not weaken)

Adds **NO new gate.** Per-command human approval is the only bound. Keep it **maximally open / offensive**: real desync probes against a real front-end/back-end pair — through the gated executor (approve-each), **scope-checked on the wire**, **stop ungated**, hardcoded container (mirror the intruder/nuclei containment). A smuggling probe can affect co-tenant requests, so **default to timing-differential detection** (self-contained, safe) and gate the **confirmation/exploit** stage behind its own explicit approval + a clear operator warning — but never behind a *new gate class*, just an approve-each with an honest description.

## 1. Read-first

- `backend/cockpit/nuclei.py` — the **gated detection-job** template (one approval, many requests, findings out). The smuggling detector is that shape.
- `backend/cockpit/repeater.py` + `intruder.py` — raw request handling, hardcoded container, per-request scope check, ungated stop.
- `backend/cockpit/proxy.py` — the front-end/back-end story build #18 already reasons about (Akamai edge nodes etc.) — smuggling is about the FE/BE parsing split; reuse any host/edge context.
- `backend/state/store.py` (`upsert_findings`) — a confirmed desync → a `Finding`.
- `backend/cockpit/router.py` — register `/smuggle/*`.
- Memory: build #18's **"check the bytes that go on the wire"**; **six ZAP API shape traps** (not used here, but the "an exit code is not a result" discipline is).

## 2. What to build

### 2a. Tooling
Add **`smuggler.py`** (defparam — the standard CL/TE mutation prober) and **`h2csmuggler`** (h2c-upgrade smuggling) to `backend/arsenal/tools.json` + `docker/Dockerfile.sandbox` + a `docker/proof/smuggle_install_proof.sh`. Respect `kali-sandbox-image-traps` (real binary names, setcap/no-new-privs). Image rebuild is the operator's step — flag it.

### 2b. The detection job (`backend/cockpit/smuggle.py`, mirrors `nuclei.py`)
- ONE gated job: given a target URL + a chosen mutation set (CL.TE / TE.CL / CL.CL / TE.TE / CL.0 / H2.CL / H2.TE / H2.0), run `smuggler.py`/`h2csmuggler` (or a small in-module raw-socket prober for the H2 variants) inside `KALI_OPEN_CONTAINER`.
- **Timing-differential detection** is the default and safe path: send a request whose ambiguous framing makes the back-end wait for bytes that never come → a measurable delay ⇒ desync-susceptible. No other user's request is touched.
- **Scope-checked** on the wire; **stop ungated**.
- A susceptibility hit → a `Finding` with the mutation type + timing evidence.

### 2c. Confirmation stage (separate approve-each)
A distinct, explicitly-approved step that attempts the classic **socket-poisoning confirmation** (smuggle a partial request, then a normal request returns the poisoned response). This is the one that can affect other traffic — surface a plain-language warning in the approval description ("this may affect co-tenant requests"). Still just approve-each; no new gate class.

### 2d. Frontend — `/smuggle`
A panel: target + a checklist of mutation types → run (detection) → a matrix of per-mutation verdicts (timing deltas) → an explicit "attempt confirmation" button per susceptible mutation. `hp-tn-*`; **look at the screen**.

## 3. Tests
- `backend/test_smuggle.py` — the job builds the right argv per mutation type; scope-checked on the wire (out-of-scope refused); the confirmation stage is a **separate** approval with the warning present; stop ungated; verdict parsing turns a fixture `smuggler.py` output + timing set into per-mutation verdicts + a Finding.
- Extend the safety runner: no new gate; runs only in the hardcoded container; the confirmation stage cannot run without its own approval. Add to `run_safety_tests.sh`.

## 4. Acceptance criteria
- Operator points `/smuggle` at an in-scope target, picks mutations, approves → detection runs, per-mutation timing verdicts render; susceptible mutations offer an explicit confirmation step; a confirmed desync → Finding.
- Detection is safe-by-default (timing); confirmation is separately approved with a co-tenant warning; containment identical to nuclei/intruder; no new gate.
- `run_safety_tests.sh` green; `next build` exits 0; screen looked at; assessment + README updated (same commit). `smuggler.py`/`h2csmuggler` added to arsenal + Dockerfile + proof (rebuild flagged).

## 5. Assumptions (flip any)
- CL.TE / TE.CL / CL.0 / H2.* are the must-haves (most prevalent today). If a session can't finish the H2 desync variants, ship the CL/TE + CL.0 set and stub H2 — say so in the PR.
- Detection via timing-differential is default; confirmation is opt-in per-mutation. If you'd rather gate confirmation harder, note it — but the standing rule is human-approval-only, no new gate class.

---

## 6. README + screenshot + assessment (do exactly like prior sessions)

**Not done until README + a real screenshot ship.** Screen route: **`/smuggle`**.
- Headless-Edge screenshot (`headless-edge-screenshots`), app running, **synthetic**/fixture verdict matrix (no real target host in the shot):
  ```
  EDGE="/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"
  "$EDGE" --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=1 \
    --user-data-dir=<tmp-profile> --window-size=1440,950 --virtual-time-budget=8000 \
    --screenshot=out.png "http://localhost:3000/smuggle"
  ```
  **View it** — the mutation matrix + verdicts render (not blank/error).
- Add screenshot to `assets/screenshots/`; README feature section + "at a glance" row (request smuggling / desync).
- Update `docs/ASSESSMENT-2026-07-26.md` + regen html/pdf same commit (`keep-assessment-current`; verify vs html).
- **Look at the screen** (`frontend-class-vocabulary`): `hp-tn-*`, never a bare `hp-card`.
