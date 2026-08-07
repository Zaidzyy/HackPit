# Build spec — Parameter / content discovery as a first-class step (`:recon` extension)

**Status:** ready to execute in a fresh session. **Author:** planning session, 2026-08-07.
**One line:** wire `arjun` / `x8` / `ffuf` / `paramspider` into a **discover hidden params + endpoints → hand to intruder/nuclei/repeater** workflow, feeding the ranked `:recon` surface. The tools are all catalogued; today the step is manual.

---

## 0. Guiding constraint (read first, do not weaken)

Adds **NO new gate.** Per-command human approval is the only bound. Keep it **maximally open / offensive**, **engagement-bound** like `:recon` (egress + scope; **scope-safety by construction** — every discovered URL/param is scope-filtered before it lands). ONE approval runs a discovery job that buys many requests (the intruder/nuclei justification). Discovered items are **suggestions handed to other surfaces**, never auto-fired. No autonomy.

## 1. Read-first (a `:recon` sibling that feeds the manual surfaces)

- `backend/cockpit/recon.py` — the gated recon-job shape (one approval → several execs).
- `backend/cockpit/intruder.py` / `nuclei.py` — the **destinations**: a discovered param/endpoint becomes a pre-filled intruder position / nuclei target / repeater request. Reuse their request models.
- `backend/state/parsers.py` — discovered endpoints/params → ranked-surface rows. **TRAP:** no `urllib` here (`test_state.py` bans it) — hand-parse.
- The `:recon` ranked surface + `?session=` deep-link — reuse for the shot.
- `backend/arsenal/tools.json` — `arjun`, `x8`, `ffuf`, `paramspider` are catalogued; confirm the invocations the catalog templates hardcode actually work in the image (the `zap_install_proof` discipline).
- Memory: `:recon` scope-by-construction; the `state/parsers.py` urllib ban; **arsenal never names a placeholder `<lhost>`** style — keep templates substitutable.

## 2. What to build — `backend/cockpit/discover.py` (mirrors `recon.py`)

- ONE gated job, operator picks the mode(s):
  - **Parameter discovery**: `arjun` (+ `x8`) against an in-scope URL → hidden GET/POST/JSON params (by reflection/length/status differential).
  - **Historical params**: `paramspider` (wayback/gau) → params seen historically — **scope-filtered**.
  - **Content/endpoint discovery**: `ffuf`/`feroxbuster` with a wordlist → hidden paths/dirs (full wordlist in the gate surface, intruder-style — nothing truncated).
- **Scope-filter** every discovered URL/param before it reaches the surface or loot.
- Write discovered params/endpoints into the ranked `:recon` surface (tagged `discovery`), each with a **"send to intruder / nuclei / repeater"** action that pre-fills that surface (the actual attack is still approve-each there).
- Discoveries of interest (e.g. an admin endpoint, a debug param) → a `Finding`.

## 3. Tests
- `backend/test_discover.py` — the job builds correct argv per mode; the **full wordlist/param set is in the gate surface** (not truncated — the intruder Critical-2 lesson); every discovered host is **scope-filtered**; a discovered param produces a valid pre-filled intruder position; parsing `arjun`/`ffuf` fixture output → surface rows.
- `backend/test_state.py` still green — no `urllib` in `state/parsers.py`.
- Safety: no new gate; scope-by-construction; discoveries are suggestions, never auto-fired. Add to `run_safety_tests.sh`.

## 4. Acceptance criteria
- Operator points `/recon` (discovery mode) at an in-scope target, one approval → hidden params + endpoints appear in the ranked surface tagged `discovery`, each with a "send to intruder/nuclei/repeater" action that pre-fills — the attack itself still approve-each.
- Only in-scope items reach the surface — by construction.
- `run_safety_tests.sh` green; `next build` exits 0; screen looked at; assessment + README updated (same commit).

## 5. Assumptions (flip any)
- Parameter discovery (arjun/x8) is the must-have; content discovery (ffuf) and historical (paramspider) are the round-out — if a session can't do all, ship param discovery + the hand-off, say so in the PR.
- The hand-off pre-fills the target surface but never fires it; the discovery job itself is the only thing approved.
- No new tools — all four are catalogued (verify the image invocations).

---

## 6. README + screenshot + assessment (do exactly like prior sessions)

**Not done until README + a real screenshot ship.** Screen route: **`/recon`** (discovery view, `?session=` deep-link).
- Headless-Edge screenshot (`headless-edge-screenshots`), app running, **synthetic** discovered data (fake params/paths — never a real target):
  ```
  EDGE="/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"
  "$EDGE" --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=1 \
    --user-data-dir=<tmp-profile> --window-size=1440,950 --virtual-time-budget=8000 \
    --screenshot=out.png "http://localhost:3000/recon?session=<demo>"
  ```
  **View it** — discovered params/endpoints + hand-off actions render (not blank/error).
- Add screenshot to `assets/screenshots/`; README feature section + "at a glance" row (parameter / content discovery).
- Update `docs/ASSESSMENT-2026-07-26.md` + regen html/pdf same commit (`keep-assessment-current`; verify vs html).
- **Look at the screen** (`frontend-class-vocabulary`): `hp-tn-*`, never a bare `hp-card`.
