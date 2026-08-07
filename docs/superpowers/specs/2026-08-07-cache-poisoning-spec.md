# Build spec — Web cache poisoning / cache deception (web core)

**Status:** ready to execute in a fresh session. **Author:** planning session, 2026-08-07.
**One line:** a gated surface that finds **unkeyed inputs** and proves they can poison a shared cache (inject a marker via a header/param the cache ignores in its key, then confirm it's served to a *different* request), plus **cache deception** (a sensitive dynamic page cached under a static-looking path). Zero surface today.

---

## 0. Guiding constraint (read first, do not weaken)

Adds **NO new gate.** Per-command human approval is the only bound. Keep it **maximally open / offensive**: real poisoning probes against a real cache — through the gated executor (approve-each), **scope-checked on the wire**, **stop ungated**, hardcoded container. Poisoning a shared cache affects other users, so **the poison-confirmation step is its own explicit approve-each with a plain-language warning** ("this may serve a poisoned response to other users of this cache") — but never a *new gate class*; the standing rule is human-approval-only.

## 1. Read-first

- `backend/cockpit/nuclei.py` — the gated detection-job template (one approval, many requests, findings out).
- `backend/cockpit/repeater.py` / `intruder.py` — raw request handling, hardcoded container, per-request scope check, ungated stop; the unkeyed-input sweep is intruder-shaped (many header/param probes, one approval, full probe set in the gate surface — nothing truncated).
- `backend/cockpit/proxy.py` + build #18 edge/CDN reasoning — cache behavior is a CDN/edge property; reuse host/edge context.
- `backend/state/store.py` (`upsert_findings`) — a confirmed poisoning → `Finding`.
- Memory: build #18 **"check the bytes on the wire"**; the open-redirect/bypass tables (unkeyed `X-Forwarded-Host` chains into open-redirect/XSS).

## 2. What to build

### 2a. Tooling
Add **`wcvs`** (Hackmanit `web-cache-vulnerability-scanner`, Go) to `backend/arsenal/tools.json` + `docker/Dockerfile.sandbox` + `docker/proof/wcvs_install_proof.sh`. (`ffuf`/`arjun` already present help enumerate candidate params.) Respect `kali-sandbox-image-traps`; image rebuild is the operator's step — flag it.

### 2b. Detection job (`backend/cockpit/cache.py`, mirrors `nuclei.py` + intruder sweep)
- **Cache-key reflection sweep**: send a request with a unique marker in each candidate **unkeyed input** (`X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Forwarded-Proto`, `X-Host`, `X-Forwarded-Port`, `X-Original-URL`, `X-Rewrite-URL`, param cloaking, fat-GET body, etc.), one input at a time; detect (a) the marker **reflected** in the response, and (b) the response is **cacheable** (`Cache-Control`/`Age`/`X-Cache`/`CF-Cache-Status` hit). Reflected + cacheable + unkeyed ⇒ candidate.
- **Verdict**: for each candidate, run `wcvs` (or the in-module confirmation) to show the marker persists across a *fresh* request that didn't send it (proof the cache served the poison).
- **Cache deception**: request `/account/settings/foo.css` (or `;.css`, `%2f..`, path-confusion variants) → if the framework serves the dynamic page AND the cache stores it under the static extension, sensitive content is now cacheable → Finding.
- Scope-checked on the wire; **stop ungated**.

### 2c. Confirmation stage (separate approve-each)
The step that actually **plants** a poisoned entry to prove exploitability is its own explicit approval with the co-user warning. Detection (reflection + cacheability) is safe and default.

### 2d. Frontend — `/cache`
Panel: target + candidate-input checklist → run (detection) → table of unkeyed inputs with reflected/cacheable flags → "confirm poisoning" per candidate + a cache-deception result. `hp-tn-*`; **look at the screen**.

## 3. Tests
- `backend/test_cache.py` — the sweep builds the right per-input probes (full set in the gate surface, nothing truncated); scope-checked on the wire; reflected+cacheable verdict logic from fixtures; cache-deception path-confusion detection; the poison-confirmation is a **separate** approval with the warning; stop ungated.
- Extend the safety runner: no new gate; hardcoded container; confirmation cannot run without its own approval. Add to `run_safety_tests.sh`.

## 4. Acceptance criteria
- Operator points `/cache` at an in-scope target → detection surfaces unkeyed inputs with reflected/cacheable flags and any cache-deception hit; a confirmed poisoning (separately approved) → Finding.
- Detection safe-by-default; confirmation separately approved with a co-user warning; containment identical to nuclei/intruder; no new gate.
- `run_safety_tests.sh` green; `next build` exits 0; screen looked at; assessment + README updated (same commit). `wcvs` added to arsenal + Dockerfile + proof (rebuild flagged).

## 5. Assumptions (flip any)
- Cache **poisoning** (unkeyed input) is the must-have; **deception** is the secondary — if a session can't do both, ship poisoning and stub deception, say so in the PR.
- `wcvs` drives confirmation; the reflection/cacheability sweep can be in-module (intruder-shaped) so detection works even without the tool.

---

## 6. README + screenshot + assessment (do exactly like prior sessions)

**Not done until README + a real screenshot ship.** Screen route: **`/cache`**.
- Headless-Edge screenshot (`headless-edge-screenshots`), app running, **synthetic**/fixture table (no real target in the shot):
  ```
  EDGE="/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"
  "$EDGE" --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=1 \
    --user-data-dir=<tmp-profile> --window-size=1440,950 --virtual-time-budget=8000 \
    --screenshot=out.png "http://localhost:3000/cache"
  ```
  **View it** — the unkeyed-input table + verdicts render (not blank/error).
- Add screenshot to `assets/screenshots/`; README feature section + "at a glance" row (cache poisoning / deception).
- Update `docs/ASSESSMENT-2026-07-26.md` + regen html/pdf same commit (`keep-assessment-current`; verify vs html).
- **Look at the screen** (`frontend-class-vocabulary`): `hp-tn-*`, never a bare `hp-card`.
