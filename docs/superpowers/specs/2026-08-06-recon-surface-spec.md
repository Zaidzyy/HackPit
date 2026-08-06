# Build spec — Guided recon → ranked attack surface (`:recon`)

**Status:** ready to execute in a fresh session. **Author:** planning session, 2026-08-06.
**One line:** the front door a bounty/pentest actually starts from — give it a domain (or CIDR), it runs recon as approved jobs, auto-seeds engagement state (hosts/services/endpoints), and ranks the surface by likely-exploitable so you know what to hit first.

---

## 0. Guiding constraint (read first)

Adds **NO new gate.** Each recon tool runs as **one approved job** (`cockpit/jobs.py`) with the ungated stop button; a "run the whole passive sweep" action chains several jobs but is still one human approval per tool invocation (or one approval for the sweep that you can stop) — pick the sweep model that matches `jobs.py`, don't invent a batch auto-runner. No autonomy. Ranking is advisory text, never an auto-action.

**Scope discipline is the one thing to respect here:** recon can only *widen the allowed set within* the declared scope, exactly like the existing recon-driven expansion (`extract_hosts` → in-scope join the live set, out-of-scope surfaced read-only, never silently added). Do not weaken that — it is a correctness property (don't scan out of scope), not an extra gate.

## 1. Read-first
- `backend/cockpit/scope.py` — `parse_scope`, `ResolvedScope.in_scope`, **`extract_hosts(text)`** (mines hosts from tool output; the recon-expansion primitive to build on).
- The existing **recon-driven expansion** path (assessment §2 "Recon-driven expansion") — this feature is its guided, first-class front end. Find where run output currently feeds host discovery and reuse it.
- `backend/cockpit/jobs.py` + `router.py` — job engine + stop.
- `backend/state/models.py` (`Host`, `Service`, `Endpoint`) + `state/parsers.py` + `state/ingest.py` — recon output must upsert these (nmap→services, httpx→endpoints, etc.). Parsers for the recon tools go in `state/parsers.py`.
- Fingerprinting from build #21 (`backend/test_fingerprint_*` point to the module) — reuse service/stack fingerprinting to enrich `Endpoint.tech` and drive ranking.
- `backend/arsenal/tools.json` — present: `subfinder`, `dnsx`, `httpx`, `naabu`, `nmap`, `katana`, `gau`, `waybackurls`. Use these.
- Frontend: `CockpitState.tsx` (state panel), `CockpitADGraph.tsx`/attack-map for a visual, and `/engagements` flow (recon should seed a session).

## 2. What to build

### Backend — `backend/cockpit/recon.py` (new)
1. **Passive sweep** (bug-bounty safe, default): `subfinder`→`dnsx`→`httpx` (live hosts + tech), `gau`/`waybackurls`/`katana` (URLs/params). Each a gated job; output parsed to `Host`/`Endpoint` via `state/parsers.py` and `upsert`ed. Every discovered host is scope-checked (`ResolvedScope`) before it joins the live allowed set; out-of-scope names are surfaced read-only, never scanned.
2. **Active sweep** (opt-in, one more approval): `naabu`/`nmap` service scan on in-scope live hosts → `Service` rows + `nmap` script output → `Finding`s where relevant.
3. **Ranking** (`recon.rank_surface(session_id)`): a deterministic score per host/endpoint from signals already in state — open service count, tech/version (CVE-worthy stacks via the `:exploits` index), parameter-rich endpoints (IDOR/injection surface), auth surfaces, and (optionally) a nuclei-info pass. Output an ordered "hit these first" list with the *why* for each. **Advisory only** — it proposes an order; it runs nothing.

### Backend — routes (`cockpit/router.py`)
`POST /cockpit/recon/passive` and `/cockpit/recon/active` (gated jobs → state), `GET /cockpit/recon/surface?session_id=...` (the ranked view; executes nothing). Cross-cutting wiring in `main.py` (cockpit/arsenal decoupling).

### Frontend — `/recon` + `ReconScreen.tsx`
A domain/CIDR input that (creating or attaching to an engagement) kicks off the passive sweep, shows live discovery counts, then renders the **ranked attack surface** (host → services → endpoints, each with its rank + reason, and a one-click "compose an attack path for this host" / "nuclei-scan these endpoints" handoff into the existing surfaces). `hp-tn-*`; look at the screen before done.

## 3. Tests
- `backend/test_recon.py` — parser correctness (subfinder/httpx/naabu/nmap output → Host/Service/Endpoint), scope gating of discovered hosts (out-of-scope stays read-only), `rank_surface` ordering/determinism.
- `backend/test_recon_safety.py` — module parses + ranks only, executes nothing (AST); jobs go through `validate_request`; **recon can never widen beyond the declared scope** (assert an out-of-scope discovered host does not enter the allowed set). Add both to `run_safety_tests.sh`.

## 4. Acceptance criteria
- Given a scoped domain, the passive sweep runs as approved jobs and seeds hosts/services/endpoints into engagement state; the active sweep adds services/findings; the ranked surface lists targets with reasons and hands off cleanly to `:attack-paths` / `:nuclei`.
- Out-of-scope discoveries are surfaced read-only, never scanned — proven by a test.
- `run_safety_tests.sh` green; `next build` exits 0; screen looked at; assessment + README updated (same commit).

## 5. Assumptions (flip any)
- Passive sweep is the default (safe for live bug-bounty targets); active port/service scanning is a separate, explicit approval.
- Recon seeds/attaches to an engagement session so downstream surfaces (attack-path, nuclei, cred-attack) share the same state.
- Ranking is heuristic and advisory; it never triggers a scan or command on its own.

---

## 6. README + screenshot — do this exactly like the 2026-08-06 README session

**Not done until the README and a real screenshot ship with it.** New screen route: **`/recon`**.

- **Capture a real lab-state screenshot** with headless Edge (the `headless-edge-screenshots` method). With the app running:
  ```
  EDGE="/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"
  "$EDGE" --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=1 \
    --user-data-dir=<tmp-profile> --window-size=1440,950 --virtual-time-budget=8000 \
    --screenshot=out.png "http://localhost:3000/recon"
  ```
  **View it** to confirm it rendered (the ranked-surface view against a lab domain reads best), not a blank/error page.
- **Never a real target in a public screenshot.** Recon a lab domain / example.com only — do NOT screenshot a run against a real scoped bounty target.
- **Add the screenshot** to `assets/screenshots/` with the next free number and commit it.
- **Add a concise README feature section** in the existing voice + a row in the "What you get, at a glance" table.
- **Update `docs/ASSESSMENT-2026-07-26.md`** + regenerate html/pdf in the **same commit** (`keep-assessment-current`).
- **Look at the screen** (`frontend-class-vocabulary`): use `hp-tn-*`, never a bare `hp-card`.
