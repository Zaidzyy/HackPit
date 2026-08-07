# Build spec — Single-packet / last-byte-sync race tester (web core)

**Status:** ready to execute in a fresh session. **Author:** planning session, 2026-08-07.
**One line:** add the race-condition primitive the intruder can't do — fire N requests so they arrive in the **same instant** (HTTP/2 single-packet, or HTTP/1.1 last-byte synchronization) to hit limit-overrun / TOCTOU / coupon-reuse / one-time-token races. Modeled exactly on the intruder: ONE gated job, same four gates, no new ones.

---

## 0. Guiding constraint (read first, do not weaken)

Adds **NO new gate.** Per-command human approval is the only bound. Keep it **maximally open / offensive**: real concurrent requests to a real endpoint — through the **same containment the intruder inherits** (hardcoded `config.KALI_OPEN_CONTAINER`, argv-only, **scope-checked per request on the substituted URL / wire bytes**, **stop ungated**). It is ONE approval that buys many requests (the intruder's own justification) — the full request template + concurrency count are part of the approved surface. No autonomy.

## 1. Read-first (this is the intruder, with a synchronized engine)

- `backend/cockpit/intruder.py` — **the template.** Read its containment contract in full (hardcoded container, argv-only curl body-on-stdin, per-request scope check on the substituted URL, ungated stop, the whole payload/positions set is in the gate surface — nothing truncated). The race tester is the same job shape with a different transport.
- `backend/cockpit/repeater.py` — how one raw request is represented/sent (the race job sends the same request N times, synchronized).
- `frontend/src/components/IntruderScreen.tsx` + `/intruder/page.tsx` — clone for a `RaceScreen` / `/race` page.
- `backend/cockpit/router.py` — register `/race/*` (start = gated job, status, stop = ungated).
- `backend/test_intruder.py` — the test template (gate surface completeness, scope-per-request, stop).
- Memory: **listener-lifecycle / jobs** — the run+stop pattern (a worker whose stop kills the Popen), same as the intruder/credentials worker.

## 2. What to build

### 2a. The race engine (the only genuinely new piece)
Turbo Intruder is a Burp extension (not headless), so build a **minimal single-packet client** invoked as the job's argv (a small vetted script in the sandbox, added to the arsenal + `docker/Dockerfile.sandbox` + a `docker/proof/` check). Two modes, operator-selected:
- **HTTP/2 single-packet attack**: open one H2 connection, queue N requests, withhold the final frame of each, then release all final frames together — all N complete-in-one-packet (PortSwigger's technique; a small Python using the `h2`/`httpx[http2]` lib, or a Go client). This is the reliable modern mode.
- **HTTP/1.1 last-byte sync**: N connections, send all bytes except the last of each request, then release the last byte on all connections together.
Carry the mode + concurrency N + the raw request in the gate surface.

### 2b. The job (`backend/cockpit/race.py`, mirrors `intruder.py`)
- ONE gated job: given a captured/pasted request + N + mode, run the engine inside `KALI_OPEN_CONTAINER`.
- **Scope-check per request** on the substituted URL (build #18's rule — check the bytes on the wire), same as the intruder.
- Collect per-request status/length/timing; **stop is ungated** (kills the Popen).
- **Verdict**: the race-window signal — e.g. `>1` request that should have been singular succeeded (2× "coupon applied", 2× "withdrawal ok"), or a status/length cluster that differs from the serial baseline. Surface a clear "N/K requests won the race" result.

### 2c. Findings + frontend
- A confirmed race → a `Finding` in engagement state (severity by impact).
- `RaceScreen` (clone IntruderScreen): paste request, mark what to vary (usually nothing — same request N times), set N, pick mode, fire → results table + the win-count verdict. `hp-tn-*`; **look at the screen**.

## 3. Tests
- `backend/test_race.py` — the job builds the correct argv/surface for both modes; **scope is checked per request** on the substituted URL (an out-of-scope host in the request is refused); the whole request + N are in the gate surface (nothing truncated — the intruder's Critical-2 lesson); stop is ungated; verdict logic flags a >1-winner cluster from a fixture result set.
- Extend the safety runner: the job adds **no new gate** (same four), executes only inside the hardcoded container. Add to `run_safety_tests.sh`.

## 4. Acceptance criteria
- Operator pastes a request, sets N and mode, approves once → the engine fires N synchronized requests; the results table + "won the race" verdict render; a confirmed race becomes a Finding.
- Containment identical to the intruder (hardcoded container, per-request scope check, ungated stop); no new gate.
- `run_safety_tests.sh` green; `next build` exits 0; screen looked at; assessment + README updated (same commit). Engine added to arsenal + Dockerfile + proof (image rebuild flagged for the operator).

## 5. Assumptions (flip any)
- Ship the **HTTP/2 single-packet** mode first (most reliable, most used); H1 last-byte-sync second — say so in the PR if only one lands.
- The engine is a small in-repo client (no headless Turbo Intruder). If a suitable CLI is found in the image, use it instead and note it.
- Same-request-×N is the default; per-request variation reuses the intruder's positions model if wanted.

---

## 6. README + screenshot + assessment (do exactly like prior sessions)

**Not done until README + a real screenshot ship.** Screen route: **`/race`**.
- Headless-Edge screenshot (`headless-edge-screenshots`), app running, **synthetic** result set (a local demo endpoint or a fixture-rendered view — never a real target):
  ```
  EDGE="/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"
  "$EDGE" --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=1 \
    --user-data-dir=<tmp-profile> --window-size=1440,950 --virtual-time-budget=8000 \
    --screenshot=out.png "http://localhost:3000/race"
  ```
  **View it** — the request box + results/verdict render (not blank/error).
- Add screenshot to `assets/screenshots/`; README feature section + "at a glance" row (single-packet race).
- Update `docs/ASSESSMENT-2026-07-26.md` + regen html/pdf same commit (`keep-assessment-current`; verify vs html).
- **Look at the screen** (`frontend-class-vocabulary`): `hp-tn-*`, never a bare `hp-card`.
