# Build spec — JS recon → secret / endpoint mining (`:recon` extension)

**Status:** ready to execute in a fresh session. **Author:** planning session, 2026-08-07.
**One line:** pull a target's JavaScript (bundles + source maps), **mine endpoints, parameters, and secrets/API keys out of it**, and feed the results into the ranked `:recon` attack surface. Today the S3→bundle→secret chain is conceptual + a `secrets-hunt` skill; nothing mines a live target's JS as a surface.

---

## 0. Guiding constraint (read first, do not weaken)

Adds **NO new gate.** Per-command human approval is the only bound. Keep it **maximally open / offensive** — but **engagement-bound** exactly like `:recon`: it needs egress + a scope, and **scope-safety is by construction, not a gate** (only in-scope hosts' JS is fetched; every mined URL/host is scope-filtered before it reaches the ranked surface or loot). ONE approval runs the fetch+mine job (crack-worker/recon shape). No autonomy.

## 1. Read-first (this is a `:recon` sibling)

- `backend/cockpit/recon.py` — the guided-recon job (gated, egress+scope-bound, one approval → several execs). The JS-mine job is the same shape.
- `backend/state/parsers.py` — **the ranked-surface parsers.** Mined endpoints/params become surface records here. **TRAP (measured):** `test_state.py` **bans `urllib`** in `state/parsers.py` — hand-parse URLs/params, do not import `urllib`.
- The ranked `:recon` surface + its `?session=` deep-link (exists so the headless screenshot renders the ranked view) — reuse for the shot.
- `backend/state/store.py` (`upsert_findings`) — a found secret/API key → a `Finding` (secret → loot file, **not** finding text; mirror `:credentials`).
- `backend/arsenal/tools.json` — check what's catalogued; add what's missing (below).
- Memory: `:recon` **scope-safety by construction**; the `state/parsers.py` urllib ban; secrets→loot.

## 2. What to build

### 2a. Tooling
Add the JS-recon toolchain to `arsenal/tools.json` (+ `docker/Dockerfile.sandbox` + a `docker/proof/` check for any not present): **`getjs`/`subjs`** (collect JS URLs), **`LinkFinder`** (endpoints/paths from JS), **`SecretFinder`** (regex secrets in JS), **`trufflehog`** / **`gitleaks`** (high-signal secret detection incl. verified keys), and a **source-map unpacker** (`sourcemapper` / unpack `.map` → original `src/`). Respect `kali-sandbox-image-traps`; rebuild is the operator's step — flag it.

### 2b. The fetch+mine job (`backend/cockpit/jsrecon.py`, mirrors `recon.py`)
Given in-scope hosts (from the engagement/`:recon` surface or operator input), ONE gated job that:
1. collects JS URLs (`getjs`/from proxy history/from the crawl) — **scope-filtered**,
2. fetches each in-scope JS (through the container),
3. mines: **endpoints/paths** (LinkFinder), **parameter names** (regex + AST-ish extraction), **secrets/API keys** (SecretFinder + trufflehog/gitleaks; mark trufflehog-*verified* keys High), **source maps** → recover original source paths/comments,
4. **scope-filters every mined URL/host** before it lands anywhere,
5. writes mined endpoints/params into the **ranked surface** (`state/parsers.py`) and secrets → **loot** + a `Finding`.

### 2c. Frontend — extend `/recon`
Mined endpoints/params appear as ranked-surface rows (tagged source: `js`), with a "secrets found" panel (names/verified-flag, values in loot). Reuse the `?session=` deep-link for the screenshot. `hp-tn-*`; **look at the screen**.

## 3. Tests
- `backend/test_jsrecon.py` — mining fixtures: a JS blob → correct endpoints/params/secrets; a `.map` → recovered source paths; **every mined host is scope-filtered** (an out-of-scope URL in the JS never reaches the surface/loot); a verified secret → High Finding with the value in loot, **not** in finding text.
- `backend/test_state.py` must still pass — **no `urllib` in `state/parsers.py`** (hand-parse).
- Safety: the job adds **no new gate**; runs in the container; scope-safety is by construction. Add to `run_safety_tests.sh`.

## 4. Acceptance criteria
- Given in-scope hosts, one approval fetches + mines their JS; endpoints/params appear in the ranked `:recon` surface tagged `js`; secrets/API keys → loot + Findings (verified keys High); source maps recovered.
- Only in-scope JS is fetched and only in-scope mined hosts reach the surface — by construction, not a gate.
- `run_safety_tests.sh` green; `next build` exits 0; screen looked at; assessment + README updated (same commit). Toolchain added to arsenal + Dockerfile + proof (rebuild flagged).

## 5. Assumptions (flip any)
- Endpoints/params + secrets are the must-haves; source-map unpacking is the bonus — if a session can't do the maps, ship the rest, say so in the PR.
- JS URL collection accepts the engagement's crawl/proxy history or operator-provided hosts; no fetching outside scope, ever.
- Secrets → loot, never finding text (mirror `:credentials`).

---

## 6. README + screenshot + assessment (do exactly like prior sessions)

**Not done until README + a real screenshot ship.** Screen route: **`/recon`** (with `?session=` to render the mined view).
- Headless-Edge screenshot (`headless-edge-screenshots`), app running, **synthetic** mined data (fake endpoints/keys — never a real target's secrets):
  ```
  EDGE="/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"
  "$EDGE" --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=1 \
    --user-data-dir=<tmp-profile> --window-size=1440,950 --virtual-time-budget=8000 \
    --screenshot=out.png "http://localhost:3000/recon?session=<demo>"
  ```
  **View it** — mined endpoints + secrets panel render (not blank/error).
- Add screenshot to `assets/screenshots/`; README feature section + "at a glance" row (JS recon → secrets/endpoints).
- Update `docs/ASSESSMENT-2026-07-26.md` + regen html/pdf same commit (`keep-assessment-current`; verify vs html).
- **Look at the screen** (`frontend-class-vocabulary`): `hp-tn-*`, never a bare `hp-card`.
