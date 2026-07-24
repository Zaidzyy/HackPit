# Cockpit — Session Log

*Running log of the unsupervised Cockpit build session(s). Newest entries at the bottom
of each section. Zaid reviews this + docs/cockpit-plan.md on return.*

---

## Session 2026-07-24 (unsupervised, Hardening & QA night)

Goal: lock the safety invariants behind real tests, sweep the app for broken states, resolve the two
M3 open questions, and tidy up. **No new features, no new execution** — this HARDENS what exists.

### llm_config.json + stack state (unchanged this session)
- `llm_config.json` was **never touched** — it stayed `{provider: claude-agent-sdk, model: opus}`
  throughout (confirmed at start + end). All new tests are **hermetic** (no live LLM: the report
  test asserts report.py's code-built Evidence/prompt, which the LLM only writes prose around), so
  no Ollama gen was needed. A real Ollama end-to-end report gen was already verified in the M3 session.
- **No production backend module changed** — the four Part-A/B commits added only test + doc files
  (`test_cockpit.py`, `test_engagement.py`, `run_safety_tests.sh`, `backend/README.md`). So there is
  no stale-code risk and no backend restart was required; the running server serves current prod code.
- Stack left running: Docker isolated stack (ready+isolated), backend `:8000`, frontend dev `:3000`.

### Part A — regression-lock the SAFETY invariants ✅ (commit QA-A)
Extended `backend/test_cockpit.py` from 3 tests to 9 so the four-gate model **fails loudly** if weakened:
- **allowlist**: non-allowlisted rejected; EVERY shell metachar (`; | & $ ` \n \r < > \ ! *`) rejected;
  per-command arg rules (nmap `--script`/`-sC`/`-A`/file-output blocked; curl ceiling 12; whatweb
  ceiling 8); and the allowlist is asserted to be EXACTLY `{nmap, curl, whatweb}` so a regression that
  adds a weaponised tool trips the test.
- **target-lock**: non-lab hosts (incl. `169.254.169.254` metadata, loopback) rejected.
- **approval**: default/`False` rejected.
- **isolation**: `assert_isolation_proven` is exercised by **monkeypatching the docker-inspect helpers**
  (`is_sandbox_up` / `_sandbox_networks` / `_network_is_internal`) — refuses for a non-internal network,
  a down sandbox, and a no-network sandbox; passes internal-only. Hermetic (no daemon needed). Also a
  `validate_request`-level test: with gates 1–3 passed, a failing isolation check surfaces as
  `gate=sandbox`, and a passing one clears all four.
- **ordering**: a request failing several gates is rejected at the FIRST (allowlist beats target beats
  approval); a fully valid request reaches (only) the isolation gate.
- Added **`backend/run_safety_tests.sh`** (one command: hermetic tests; `--with-proof` adds the live
  Docker isolation proof) and a **`backend/README.md`** documenting the invariants + how to re-verify.
- **Invariant note (not a weakness, a naming clarification):** the `ExecRejected.gate` literal uses
  `allowlist` / `target` / `approval` / `sandbox`. The prompt's "gate=target_lock" and "gate=isolation"
  map to `target` and `sandbox`. Tests assert the ACTUAL strings so a rename can't silently pass. Also
  observed (pre-existing, intended): `allowlist.validate` enforces command membership + metachars +
  `max_args` + per-command `extra` validators, but does NOT reject flags outside `allowed_flags`
  (`allowed_flags` drives the UI + the `extra` validators do the real per-command narrowing). Left
  as-is — not a hole (recon tools, argv exec, no shell), but flagged for Zaid's awareness.
  **[UPDATE 2026-07-24: this is now STRICTLY ENFORCED — see the strict-flags session at the end.]**

### Part B — test the M3 engagement/report path ✅ (commit QA-B)
Added hermetic `backend/test_engagement.py` (throwaway temp DB pointed at by both the sessions layer and
the runstore, exactly like prod shares `sessions.db`; no live LLM):
- a cockpit run is **recorded against a session** and **listed back read-only** via runstore + the
  router's `GET /cockpit/runs` handler (scoped — an unknown session sees nothing; listing doesn't mutate);
- the report generator **folds the run's command + verbatim output into the authoritative Evidence
  section** and **cites it by run id** in the prompt;
- **out-of-scope hosts are surfaced** as an OUT-OF-SCOPE directive (excluded from findings), and a
  no-scope path emits **no** directive (Companion behaviour unchanged — the additive change is gated).
Wired into `run_safety_tests.sh`. Full suite = **16 checks, all green**.

### Part C — app-wide broken-state sweep (behaviour-preserving)
Swept Companion (home, library categories, entry, command palette/search), attack-path, cockpit,
engagements (list + detail + report + print). **The app is in genuinely good shape** — no fix was
warranted, so there is no Part-C commit. What was checked and found solid:
- **Error states**: invalid entry id and invalid category both render a graceful "Not found · back home"
  (backend 404 handled). Compose/report failures already surface the backend message; a 503 (Ollama/
  agent-sdk down) surfaces its detail.
- **Console**: **zero** console errors across every page and through interactions (palette, search).
- **a11y**: both `<img>` sites carry `alt` + `onError` fallback; icon controls (accent swatches, ⌘K,
  thumbnails) carry `aria-label`; inputs are labelled. No dead links (the M3 nav cleanup removed them);
  no `href="#"`, no `TODO`/`FIXME`.
- **Empty states**: engagements list, cockpit ("plot a path to begin"), palette ("start typing…") all fine.

**Bugs found → deliberately LOGGED, not fixed (per the behaviour-preserving / don't-guess gate):**
1. **Report model mis-attribution (real, minor).** `ReportScreen` fills "generated by **{model}**" for a
   *persisted* report from `getLLMConfig()` (the CURRENT config), not the model that actually generated
   it — because `save_report`/`get_session`/`SessionDetail` don't persist the report's model. Repro: the
   M3 report was generated by Ollama `qwen3:8b` but the report view shows "generated by opus" (current
   config). The report **content is correct**; only the attribution label is wrong, and only on reload.
   Correct fix = persist a `report_model` column (a `sessions.db` schema + API-contract change across
   ~5 files). That's a non-trivial change on the live data layer — **skipped per the gate**; recommended
   for a supervised change. (A display-only fix is ambiguous: dropping the model label degrades the
   intended design for all old reports.)
2. **Hybrid search has no "no results" state (minor, expected).** A nonsense query still returns 20
   nearest-neighbour hits because the vector half always returns neighbours. Expected vector-search
   behaviour; adding a relevance threshold is a feature/behaviour change — left as-is.
3. **Cockpit readiness banner (minor).** If the backend is unreachable, the banner stays on
   "connecting to backend…" rather than an explicit "backend unreachable". Acceptable degradation;
   changing it risks masking the genuine start-up state — left as-is.
4. **Mobile/responsive NOT verified this session.** The browser `resize_window` tool did not change the
   actual viewport (`innerWidth` stayed 1879), so narrow-width layouts couldn't be validated. No
   horizontal overflow was seen at the tested widths. Flagged for Zaid rather than guessing at CSS
   breakpoints (which would be a redesign, out of scope).

### Part D — the two M3 open questions (safe defaults) ✅ (decisions, no code change)
1. **Attach cockpit runs to a path step?** → **Keep them at the engagement level (`step_id` null).**
   The cockpit has no "active step" concept — the operator picks an allowlisted command (nmap/curl/
   whatweb), not a composed-path step — so no run is ever *unambiguously* the active step. Attaching one
   would mean either guessing (which would mis-attribute evidence in the report) or building an
   active-step selector (a new feature, gated). Both are excluded, so the safe version **is** the current
   `step_id`-null behaviour; no code change. If Zaid wants step attachment, it needs a deliberate
   active-step UI.
2. **Report system-prompt** → **Keep the shared Companion/cockpit prompt with the additive cockpit
   clauses (no change).** Re-reviewed: the added clauses (sandbox runs are authoritative evidence; the
   out-of-scope directive) are gated on `execution_runs` / `out_of_scope` being present, so they no-op for
   Companion sessions — the M3 and Part-B tests confirm Companion output is unchanged. No concrete
   problem found; a cockpit-specific variant would be duplication for no benefit.

### Part E — optional
- **Pre-existing lint debt NOT touched.** The 10 `react-hooks/set-state-in-effect` errors (`useApi.ts`,
  `CommandPalette.tsx`, `EngagementAssistant.tsx`, `Intro.tsx`, `useReducedMotion.ts`, …) are app-wide
  with no test coverage; a fix can't be proven behaviour-neutral without regressing risk. Per the gate,
  skipped. (This session's new code added none.)
- **Docs refreshed**: `cockpit-plan.md` status + `docs/README.md` now point at the one-command safety
  suite; `backend/README.md` documents the invariants.

### Open questions for Zaid
- **Report model attribution** (Part C bug #1): OK to persist a `report_model` column so the report view
  shows the model that actually generated it? (Recommended — small, backward-compatible migration; I left
  it for a supervised change since it touches `sessions.db`.)
- **Mobile support**: is a responsive pass in scope for a future milestone? (Couldn't verify this session.)
- **`allowed_flags` enforcement** (Part A note): ~~today it's advisory~~ **RESOLVED 2026-07-24** — now
  STRICTLY ENFORCED (see the strict-flags session below). `validate` rejects any flag outside a command's
  `allowed_flags`, naming it, at the allowlist gate.

---

## Session 2026-07-24 (unsupervised, Milestone 3 — engagement integration + polish)

Goal: turn the cockpit from a live-execution demo into a **recorded engagement** — every approved
run is captured into the existing sessions layer and rolls up into the reused report generator, with
planning-side scope. **No new execution capability**: same allowlist (recon-only), same sandbox,
same target-lock, same four gates. Also two UI cleanups (M2 aesthetic preserved: clean gradient, no
video, progressive disclosure).

### Pre-work this session (before M3 proper)
- **Removed the video backdrops** from the cockpit (kept `VideoBackdrop.tsx` + the gitignored files
  for later use) and made the cockpit **progressive**: it opens as just header + plot bar with a
  "plot a path to begin" hint; the kill-chain map and live-execution panel stay hidden until a real
  path composes, then reveal in (Framer Motion, skipped under reduced-motion). Removed the default
  `cockpitSample`. (Commit `cockpit: drop video backdrops + gate map/exec behind a real composed path`.)

### What was built (each committed after verify)
- **Part A — nav cleanup**: the home top-nav showed dead KB-category spans (`:ad :web :privesc
  :tools`). Replaced with real **product-section** links — `:library · :attack-paths · :cockpit ·
  :engagements` — with active-route highlighting (`NAV` in `lib/data.ts`, `TopBar.tsx`,
  `usePathname`). KB category browsing stays in the library bento (live `/categories`). **No `:kali`
  link** (not built — adding a dead link is the thing we removed). Verified: home shows the four
  product links, no category spans, build/lint clean.
- **B1 — Scope/RoE in the cockpit**: mirrored the attack-path screen's optional collapsible Scope /
  Rules-of-Engagement field into the plot bar (`CockpitView.tsx`, reusing the `hp-ap-scope` styles),
  passed as `scope_text` to the existing `composeAttackPath`. Same behaviour as the Companion
  (profiler biases bug classes; out-of-scope steps dropped). Verified: field expands + is wired.
- **B2 — record every cockpit run into an engagement**: `CockpitView` now creates a session
  (`POST /sessions`) from the composed path and threads its id into `CockpitScreen`, which passes
  `session_id` on `/cockpit/exec`. The **executor already persisted `session_id`/`step_id` into the
  `cockpit_runs` table** (M1.3), so a run lands as a recorded engagement step with zero change to the
  exec path. Added the read side: `runstore.list_runs_for_session` + `GET /cockpit/runs?session_id`
  (read-only) + a `listCockpitRuns` client. Verified at the API level: created a session, ran
  `curl -sSI http://hackpit-lab-target:3000/` with `session_id` → exit 0, listed back with verbatim
  HTTP-200 output attached to the session.
- **B3 — report folds in the recorded runs + scope**: **reused** the existing report generator. The
  `POST /sessions/{id}/report` endpoint now attaches the session's cockpit runs as `execution_runs`;
  `report.py` renders each run's command line + captured output **VERBATIM** in the authoritative
  (code-built, not model-written) Evidence section — same collision-proof fencing as pasted evidence
  — and lists them in the prompt as first-class, citable evidence (`run-<id>`). The composed path's
  `profile.out_of_scope` is surfaced in the Scope section. **Additive only**: Companion sessions with
  no runs / no scope render exactly as before (verified — the new blocks are gated on presence).
  Verified with **Ollama (`qwen3:8b`)**: generated report carried the `curl` command, the verbatim
  `HTTP/1.1 200 OK` output, the `run-…` citation, the methodology phase, and the Evidence section.
- **B4 — engagement UI in the cockpit** (`CockpitEngagement.tsx`): a panel under the exec surface
  (shown once a path composes) listing the runs recorded against the engagement — each with its
  command line, exit code, and captured output — plus a **generate report** button that reuses
  `POST /sessions/{id}/report` and renders the Markdown in the M2 amber/terminal aesthetic. Panel is
  keyed by `sessionId` (fresh per engagement) and re-pulls its runs after each run via a token — no
  synchronous `setState` in an effect, so **no new lint debt** was introduced.
- **B5 — end-to-end verified (Ollama), with screenshots**: on `http://localhost:3000/cockpit`, with
  scope pasted ("out of scope: /admin, billing.internal") and goal "web app bug bounty on
  hackpit-lab-target": **plot** → real path composed (~60s, `qwen3:8b`) and an engagement session
  created; **APPROVE & RUN** `nmap -sT -Pn -p 3000,80,22 hackpit-lab-target` → streamed live
  (**3000/tcp open**, exit 0) and appeared instantly in the engagement panel as a recorded step with
  its full output; **generate report** → rendered a report whose Scope & Target section explicitly
  **excluded `/admin` and `billing.internal`**, Methodology listed the composed path's phases, and the
  Evidence carried the `nmap` command + verbatim scan output. Screenshots captured at each stage.

### Verification summary (how)
- Frontend: `npm run build` clean and `npm run lint` shows **no new errors in any touched file** at
  every increment (the 10 pre-existing `react-hooks/set-state-in-effect` errors are unchanged — see
  "Deliberately skipped").
- Backend: `test_cockpit.py` (allowlist / target-lock / gate-order) **all pass** — the execution
  security model is untouched; all backend modules import clean.
- Deterministic report check (no LLM variance): `build_prompt` + `build_evidence_section` on a session
  with a run + out-of-scope → command line, verbatim output, exit code, target, and out-of-scope all
  present; a session with neither renders byte-identically to before.
- Full UI e2e (above) exercised over the real streaming endpoint + real Ollama compose/report.

### llm_config.json + running stack (final state)
- Per gate 3, all compose/report verification used **local Ollama (`qwen3:8b`)** — switched via the
  app's own `POST /llm-config`. **Restored to its prior value `{provider: claude-agent-sdk, model:
  opus}`** at the end (confirmed live + on disk). It stays gitignored.
- Backend runs `uvicorn main:app --reload` (PID observed 22128) — a **reloading** server, so every
  backend `.py` edit hot-reloaded (confirmed: the new `/cockpit/runs` endpoint went live, and reports
  picked up the new code). `llm.load_config()` is read **per request**, so the restored config is
  already in effect with no manual restart needed. **Stack left running**: Docker isolated stack
  (`hackpit-kali-sandbox` + `hackpit-lab-target`, ready+isolated), backend `:8000`, frontend dev
  `:3000`.
- Cleaned up the throwaway B2 API-test session (deleted). The e2e demo session (nmap run + report) is
  left in the local gitignored `sessions.db` as demo data.

### Deliberately skipped (Part C — optional, low-risk only)
- **Pre-existing lint debt NOT fixed.** The 10 `react-hooks/set-state-in-effect` errors live in
  `useApi.ts`, `CommandPalette.tsx`, `EngagementAssistant.tsx`, `Intro.tsx`, `useReducedMotion.ts`,
  and others. `useApi` is used app-wide; moving its `setState` out of the effect genuinely risks
  behaviour change, and there is **no test coverage** to catch a regression. Per the gate ("if any
  fix is non-trivial or risks behaviour change, SKIP and log — do not guess"), left untouched. My own
  new engagement panel was written to avoid adding to this debt.

### Open questions for Zaid
- **Mapping runs to path steps?** A cockpit run is recorded against the *engagement* (session) but not
  tied to a specific composed **path step** (`step_id` left null — the allowlisted recon commands
  don't cleanly map onto the KB-driven writeup steps). The report treats each run as its own
  "SANDBOX EXECUTION" evidence block. If you'd rather each run attach to a chosen path step
  (check it off + fill its evidence), that's a small follow-up — flagging the design choice.
- **Report system-prompt is shared** between the Companion and the cockpit. I added one additive
  clause (sandbox runs are authoritative evidence) + one Scope/out-of-scope line; both no-op for
  Companion sessions. Confirm you're happy with the shared prompt vs a cockpit-specific variant.
- Roadmap numbering: the Phase-0 plan's roadmap and these build sessions use different M-numbers
  (noted in `cockpit-plan.md`). Worth reconciling if it bothers you.

---

## Session 2026-07-24 (unsupervised, Milestone 2 — cinematic UI)

Goal: build the command-center **face** of the Cockpit — visualize existing data (composed
attack-path + M1 execution). No new execution, sandbox/allowlist changes, or autonomy.

### What was built (each committed after verify)
- **M2.1 — attack-map centerpiece** (`CockpitAttackMap.tsx`): a composed path rendered as a lit
  kill-chain route — 5 phase stations (01–05) down a spine, each step a node (solid amber =
  grounded, dashed/dim = ai_suggested "unverified"), on_success/on_blocked as branch forks, the
  profile `target_class` + `priority_bug_classes` as the "why these steps" HUD, skipped phases dim
  ("not on this path"). Click a node → slide-in detail (why, `target_adaptation`, branches, copyable
  commands, technique link). `CockpitView.tsx` composes the map (with a live `/attack-path` plot
  bar) above the M1 exec panel; a labelled **sample path** renders until one is composed.
- **M2.2 — ignite sequence**: nodes + station dots light phase-by-phase (Framer Motion, staggered
  by kill-chain index). `prefers-reduced-motion` → final state instantly (`initial={false}`, 0 delay).
- **M2.3 — video backdrops** (`VideoBackdrop.tsx`): lazy (IntersectionObserver, never SSR'd),
  muted/loop/playsinline/autoplay, a per-variant CSS gradient that is BOTH poster and missing-file
  fallback, reduced-motion skips the video, a scrim keeps text readable. Wired `hero-loop.mp4`
  (page bg) + `cockpit-map.mp4` (behind the map). Node bg bumped to 0.92 opacity for readability.
- **M2.4 — cinematic exec panel**: restyle only (M1 logic untouched) — lit green
  isolated/target-locked status, terminal chrome on the output pane ("SANDBOX · TERMINAL",
  amber activity pip), blinking cursor while running (off under reduced-motion), `waveform.mp4`
  ambient texture behind the panel.
- **M2.5 — assemble + verify**: `next build` clean (emits `/cockpit`), eslint + tsc clean.
  Screenshots verified: full view, mid-ignite stagger, node-detail drawer, and the **without-video**
  fallback (files moved out → gradient stands in, everything readable, restored after).

### Decisions / notes for Zaid
- **Videos gitignored** (`frontend/public/video/*.mp4`, ~22MB) + a README lists the expected files;
  the UI falls back to CSS gradients when absent so the repo stays code-only. Your call whether to
  commit them / use Git LFS / a CDN.
- **Sample path**: `frontend/src/lib/cockpitSample.ts` — a schema-faithful demo path (real web-app
  methodology) so the map is never empty and is demoable offline. Labelled "sample path" in the UI.
- **Live compose not runtime-tested this session.** The plot bar reuses the same `composeAttackPath`
  client as the working attack-path screen, but I couldn't run a live compose: `backend/llm_config.json`
  is set to `claude-agent-sdk/opus` while the running backend had an Ollama env override → Ollama got
  asked for model "opus" → 404. I did NOT touch your llm_config. With your normal frontier config it
  will compose real paths into the same map.
- **reticle.mp4** is unused (it's the optional loading sting) — left available for a future compose loader.
- Browser extension offline again → screenshots via headless Edge, not the in-app click-through.

---

## Session 2026-07-23 (unsupervised, Milestone 1)

### Context / grounding
- Companion is feature-complete. This session begins the **Cockpit** (live, human-approved
  execution against an isolated lab), per the "Cockpit: scope, then build Milestone 1" prompt.
- Read PROJECT_PLAN.md (locked decisions: Kali Docker sandbox, two-network isolation,
  human-in-the-loop, web module first, mechanisms-not-payloads, authorized/lab targets only).
- Grounded in the existing backend: `attack_path.py` (ordered grounded `{phase}-{n}` steps),
  `sessions.py` + `sessions.db` (per-step state), `llm.py` (provider-swappable), FastAPI `main.py`.

### Runtime reality found
- Docker CLI **29.1.3** + Compose **v5.0.1** installed. WSL2 **Ubuntu** is the default distro.
- **Docker Desktop daemon was NOT running** when checked (`docker info` failed on the pipe).
  → M1.2 config + proof scripts can be authored, but the isolation *proof* cannot be executed
  until the daemon is up. This is the gate before any execution code (M1.3).

### Phase 0 — scope & architecture ✅
- Wrote **`docs/cockpit-plan.md`**: reuse map, architecture (planner → orchestrator → exec →
  sandbox → live UI with 3 human control points), **safety-by-architecture** (3 independent
  layers + operational gates), phased roadmap (web first, each phase shippable), and the M1 spec.
- Recorded 6 assumed defaults + 6 open questions for Zaid at the top of the plan.

### M1.1 — Cockpit module scaffold (in progress)
- Created `backend/cockpit/` (interfaces, execution stubbed until M1.2/M1.3 proof):
  - `config.py` — hardcoded sandbox/lab/network constants + exec timeout (the target lock's source of truth).
  - `allowlist.py` — the M1 safe command set (nmap/curl/whatweb, recon-only) + **pure** validation
    (allowlisted command, no shell metachars, per-command arg rules). No execution.
  - `models.py` — Pydantic contracts (ExecRequest/Accepted/Rejected, RunRecord, Allowlist*).
  - `sandbox.py` — lifecycle interface; `is_sandbox_up()` / `assert_isolation_proven()` raise until M1.3.
  - `executor.py` — `check_target_lock()` (pure, real) + `run_command()` (raises NotImplementedError until M1.3).
  - `router.py` — FastAPI routes; `/cockpit/allowlist` is real (read-only), exec/stream return 501.
    **NOT mounted into main.py yet** (mounted in M1.3, after the isolation proof).
- Created `docker/README.md` (M1.2 lands the compose stack + proof here).

### M1.2 — Isolated Docker stack + isolation PROOF ✅ (HARD GATE PASSED)
- Started Docker Desktop (was down); daemon came up (linux engine, server 29.1.3).
- Authored `docker/docker-compose.yml` (two services on ONE `internal: true` network:
  `hackpit-kali-sandbox` + `hackpit-lab-target` = OWASP Juice Shop), `docker/Dockerfile.sandbox`
  (Debian-slim + nmap/curl/whatweb baked at build time; runtime egress-less; `cap_drop: ALL`,
  `no-new-privileges`, unprivileged user), and `docker/proof/isolation_proof.sh`.
- Build hiccup fixed: Debian ships a built-in `operator` user → renamed sandbox user to `sandbox`.
- **Isolation PROVEN** (`docker/proof/PROOF.md`, exit 0): sandbox → lab = HTTP 200; sandbox → public
  IP 1.1.1.1, → https://example.com, → external DNS, → host.docker.internal all FAIL.
  Structural evidence: the `internal: true` network installs no default route — the sandbox's
  routing table has only the on-link `172.23.0.0/16` route and no `0.0.0.0` gateway, so there is
  no path off the bridge by construction (not a toggleable filter).
- **Gate cleared:** execution code (M1.3) is now permitted to be wired.

### M1.3 — Execution API ✅ (verified end-to-end)
- Wired the four safety gates + real `docker exec` (allowlist → target lock → approval → isolation),
  now that M1.2 cleared the gate. Nothing runs unless all four pass.
  - `sandbox.py`: `is_sandbox_up()` + `assert_isolation_proven()` (structural, always-on: the running
    sandbox must be attached ONLY to `internal` networks, else refuse — an egress path = no exec).
  - `executor.py`: refined target lock (lab must be explicitly targeted; curl method tokens like `GET`
    are not treated as hosts; any non-lab host rejected) + threaded streaming `docker exec` (argv, never
    a shell) with a hard timeout; persists a RunRecord.
  - `runstore.py`: `cockpit_runs` table in the shared `sessions.db` (gitignored).
  - `router.py`: `GET /cockpit/allowlist`, `GET /cockpit/status`, `POST /cockpit/exec` (SSE stream; 403
    naming the failed gate), `GET /cockpit/runs/{id}`. Mounted in `main.py`; runstore init in lifespan.
- **Verified against the live server + isolated sandbox:**
  - `GET /cockpit/status` → `{up:true, isolated:true, ready:true}`.
  - Gate rejections (no execution): unapproved → 403 approval; `scanme.nmap.org` → 403 target;
    `bash` → 403 allowlist.
  - Real streamed exec `curl -sSI http://hackpit-lab-target:3000/` → HTTP 200 (Juice Shop banner
    `X-Recruiting: /#/jobs`), streamed live, exit 0, record persisted + refetched.
  - Real streamed exec `nmap -sT -Pn -p 3000,80,22 hackpit-lab-target` → port 3000 open, streamed
    live, exit 0, persisted with `step_id=recon-1`.
- `test_cockpit.py` updated (M1.1's "refuses until wired" replaced by gate-order tests) — all green.

### M1.4 — Minimal cockpit UI ✅ (build + lint clean)
- `src/lib/api.ts`: cockpit types + client — `getCockpitAllowlist`, `getCockpitStatus`,
  `getCockpitRun`, and `execCockpitStream()` (a fetch-based SSE reader that parses `data:`
  frames and calls back per event; a 403 gate rejection surfaces as an ApiError naming the gate).
- `src/components/CockpitScreen.tsx`: readiness/isolation banner (from `/cockpit/status`),
  command builder (allowlist dropdown + editable args prefilled per command, lab target shown),
  an **APPROVE & RUN** button (the human control point — sends `approved: true`), and a live
  terminal output panel that streams stdout/stderr and shows the exit code / rejection reason.
- `src/app/cockpit/page.tsx` (route) + `:cockpit` nav link in `TopBar.tsx` + `hp-ck-*` styles in
  `globals.css` (matches the amber cinematic theme).
- Verified: `eslint` clean; `tsc --noEmit` clean; `next build` succeeds and emits the `/cockpit`
  route (○ static). NOTE: the first `next build` crashed the TS-check worker with a Windows-native
  exit code (3221225794) — a Turbopack/Windows flake, not a code issue; `tsc` passed directly and
  the build succeeded on retry.

### M1.5 — End-to-end verified demo ✅ (with one caveat)
Goal: approve `nmap <lab>` in the UI → runs in the isolated sandbox → output streams to the UI.

Verified against the default-port backend the UI targets (backend :8000, frontend dev :3000):
- **Route renders:** `GET /cockpit` → 200; the SSR HTML contains every control — `:cockpit`,
  `APPROVE & RUN`, the "arguments (must target …)" label, the `output` panel, the `isolated`
  banner, and `hackpit-lab-target`. (Confirmed by fetching the page HTML.)
- **Page-load calls** (what CockpitScreen fetches on mount): `/cockpit/allowlist` → the 3-command
  set; `/cockpit/status` → `{up:true, isolated:true, ready:true}`.
- **APPROVE & RUN path** (the exact payload the button posts, `approved:true`): `nmap -sT -Pn -p
  3000,80,22 hackpit-lab-target` streamed live → **3000/tcp open**, exit 0, run-record persisted
  (`step_id=recon-1`). This is the M1 goal, exercised over the real streaming endpoint.

**Caveat (one step left for Zaid's eyes):** the Claude browser extension is offline in this session,
so I could not perform the literal in-browser button click + watch the pixels stream. Every layer
_behind_ that click is verified (route + SSR controls + the identical streaming request). To see it
live: open **http://localhost:3000/cockpit** (both servers are left running) and click APPROVE & RUN.

### What's running right now (left up for Zaid)
- Docker Desktop + the isolated stack (`hackpit-kali-sandbox` + `hackpit-lab-target`). I started
  Docker Desktop (it was down). Tear down: `docker compose -f docker/docker-compose.yml down -v`.
- Backend on `:8000`, frontend dev on `:3000` (so the cockpit is clickable immediately). Stop them
  when done (they're just left for convenience).

### Reproduce from scratch
```
docker compose -f docker/docker-compose.yml up -d --build     # isolated lab + sandbox
sh docker/proof/isolation_proof.sh                            # HARD GATE — must exit 0
cd backend && .venv/Scripts/python -m uvicorn main:app --port 8000
cd frontend && npm run dev                                    # http://localhost:3000/cockpit
```

### ★ Milestone 1 COMPLETE — summary
Phase 0 plan + all five increments landed, each committed after verification:
- M1.1 scaffold (safety layers, execution stubbed) — tests green.
- M1.2 isolated two-network stack + **PROVEN isolation** (the hard gate) — sandbox reaches the lab,
  nothing else; structural (`internal:true`, no default route).
- M1.3 execution API — 4 gates (allowlist → target → approval → isolation) + streamed `docker exec`;
  verified live (gate 403s + real curl/nmap streamed & persisted).
- M1.4 cockpit UI — approve + live stream; build/lint/tsc clean.
- M1.5 E2E — full data path verified; only the in-browser click awaits Zaid (extension offline).

No autonomy was built (per the gate). Nothing runs outside the isolated lab. `data/kb/*`, secrets,
`sessions.db`, and `llm_config.json` remain gitignored; the repo is code-only. Commits are local
(not pushed) — Zaid reviews + pushes on return.

### Open questions for Zaid
See docs/cockpit-plan.md §"Open questions for Zaid" (sandbox choice, lab target, allowlist scope,
frontier model/key, Docker daemon start, exec transport). Note: I started Docker Desktop myself and
ran the proof (open question #5 resolved for this session).

---

## Session 2026-07-24 (:kali — human-only interactive sandbox shell)

Goal: build `:kali`, the ONE feature that runs **arbitrary** commands (`sh -c`) inside the
already-isolated M1 sandbox. Built in four verified increments (K1–K4), each committed
locally. **NOT pushed** — Zaid reviews the safety-critical bits first.

### The containment model, as implemented
Arbitrary shell is safe here ONLY because of these — all hold in code:

1. **Hardcoded target container.** Every exec is `docker exec <config.SANDBOX_CONTAINER> sh -c
   "<command>"`. The container is a code constant; `KaliRequest` has exactly two fields —
   `command` + `session_id` — and **no** container/target/host field. Nothing in a request can
   redirect the exec to the host, another container, or anywhere else. (`cockpit/kali.py`.)
2. **Egress-less + hardened + disposable sandbox (M1).** `internal:true` network, `cap_drop: ALL`,
   `no-new-privileges`. `curl evil.com` simply fails; `docker compose down -v` resets it.
3. **Isolation re-checked before EVERY exec.** `run_kali` calls the M1 gate
   `assert_isolation_proven` first; if the sandbox is ever on a non-internal network it raises
   `KaliRefused` and **nothing runs** (HTTP 409). `:kali` drops M1's allowlist / target-lock /
   per-command-approval (a human typing IS the approval) but **never** drops isolation.
4. **Human-only.** `run_kali` is imported/called ONLY by `router.py` (the HTTP route) and
   `test_kali.py`. The executor / attack-path / orchestrator path has **zero** reference to it
   (`grep run_kali` confirms) — there is deliberately no code path from the autonomous agent to
   the shell.
5. **Audit + limits.** Every command + output is recorded to the engagement session (reuses the M1
   run store; `target` = the sandbox itself). 60s per-command timeout; 200k-char per-stream output
   cap. Both enforced and tested.
6. **Local-only.** No auth. A code comment on both the module and the route states it MUST get
   auth before any exposure/deploy. Egress is the point of `sh -c` here — there is deliberately
   **no** fake input sanitisation pretending arbitrary shell is "safe"; the containment is the control.

### Tests (regression-locked)
`backend/test_kali.py` (hermetic; wired into `sh backend/run_safety_tests.sh`):
- **isolation-refusal** — `assert_isolation_proven` patched to raise ⇒ `run_kali` raises + subprocess
  is never touched + nothing recorded.
- **hardcoded container** — argv always execs `SANDBOX_CONTAINER` even when the command *string*
  smuggles `docker exec other-container` / another host; and `KaliRequest.model_fields == {command,
  session_id}`.
- **audit** — a run is recorded to the session with `target == sandbox`, `approved == True`.
- plus timeout-contained + output-capped. All 5 pass; full safety suite green.

### Live e2e (verified this session, stack up)
`docker/proof/kali_containment_proof.sh` over the exact exec path → **4/4 PASS, CONTAINMENT PROVEN**:
a free shell runs (`id`/`ls`), reaches the lab (`nmap hackpit-lab-target` → 3000 open), and CANNOT
egress (`curl https://example.com` fails). Also exercised the real HTTP endpoint (`POST /cockpit/kali`)
for `id` (exit 0, uid=1000 sandbox), `nmap` (3000 open), `curl` egress (exit 6 — blocked), and
confirmed all four runs recorded to the engagement session. UI verified in-browser at
`http://localhost:3000/kali`: `id` → EXIT 0, `curl https://example.com` → EXIT 6, green
"sandbox isolated · egress blocked · shell contained to this box" banner. Frontend build + lint +
tsc clean; `/kali` route builds.

### Commits (local, NOT pushed)
- K1 backend `:kali` shell (`cockpit/kali.py` + route)
- K2 `:kali` terminal page (`KaliShell` + `runKali` + styles)
- K3 `:kali` added to top nav
- K4 containment tests + live proof, wired into the safety runner

**Orchestrator-has-no-path confirmed** (grep clean). DO NOT push — Zaid reviews the safety-critical
bits first, then pushes.

---

## Session 2026-07-24 (:kali — wide-open egress, two-sandbox split)

Zaid's informed decision: give `:kali` a human-only shell with **full network reach** (internet
+ host + LAN). Built in verified increments, committed locally. **NOT pushed** — Zaid reviews the
network config + the human-only confirmation first.

### The change, and why it does NOT touch the cockpit's safety net
`:kali`'s previous shell ran inside the **isolated** sandbox. Making that container egress-capable
would have broken `assert_isolation_proven` for the **cockpit executor** too — and that isolation is
the safety net the future autonomous agent depends on. So instead of opening the shared sandbox, we
**split into two sandboxes**:

- **`hackpit-kali-sandbox` (ISOLATED — UNCHANGED).** Still `internal: true`, egress-less. The cockpit
  executor + future agent keep targeting it with all four gates, `assert_isolation_proven` included.
  Verified unchanged: `test_cockpit.py` green; `docker/proof/isolation_proof.sh` → 4/4, ISOLATION PROVEN
  (reaches only the lab; no internet, no host).
- **`hackpit-kali-open` (NOT ISOLATED — new).** On a new non-internal bridge (`hackpit-open`) with NAT
  egress → internet + host + LAN. Used by `:kali` **only**. Keeps `cap_drop: ALL` +
  `no-new-privileges`; still disposable.

### `:kali` changes (the changed invariant)
- `run_kali` execs `docker exec <config.KALI_OPEN_CONTAINER> sh -c "<cmd>"` — hardcoded to
  `hackpit-kali-open`, **never** a request field (containment rule #1 stays; test-locked, incl. that it
  can't hop to the isolated box).
- **Isolation gate dropped from the `:kali` path only.** `kali.py` no longer imports the sandbox module
  or calls `assert_isolation_proven` (it's intentionally not isolated). Replaced with an honest
  **availability** check (409 if the open container is down) — explicitly NOT an isolation gate.
- **KEPT:** hardcoded container, audit-every-run to the session (`target = hackpit-kali-open`), 60s
  timeout, output cap.
- **Banner honesty:** UI now reads `GET /cockpit/kali/status` and shows an amber
  "shell hackpit-kali-open · full network reach · **NOT isolated** · human-only" — never claims
  isolation. Header/footer copy + a strengthened localhost-only/no-auth warning (an exposed `:kali` now
  reaches host + LAN — exposure is far worse than before).

### Safety rules that stay absolute (now more load-bearing)
- **Human-only** — the rule that matters most now. `run_kali` is referenced ONLY by `router.py` (the
  HTTP route) + `test_kali.py`. The executor/agent/orchestrator path has ZERO reference to it, now
  **regression-locked** by `test_kali_is_human_only` (scans the source tree; also asserts the cockpit
  executor exposes no kali hook). An autonomous agent + a full-reach shell = autonomous attacks on
  host/LAN/internet — this test fails loudly if anyone wires it in.
- **Cockpit execution stays isolated + lab-locked.** Unchanged; full safety suite green.
- **localhost-only; auth required before exposure.**

### Verified this session (stack up)
- `docker/proof/kali_open_egress_proof.sh` → 3/3, OPEN EGRESS CONFIRMED (shell works; `curl
  example.com` → 200; on a non-internal network). Isolated sandbox unaffected.
- Real endpoint `POST /cockpit/kali`: `id` → open container; `curl https://example.com` → **exit 0,
  HTTP 200** (full reach, intended); runs recorded with `target=hackpit-kali-open`.
  `GET /cockpit/kali/status` → `{container: hackpit-kali-open, isolated: false, ready: true}`.
- UI at `http://localhost:3000/kali`: amber "NOT isolated · full network reach" banner; live
  `curl … https://example.com | head -1` → `HTTP/2 200`, EXIT 0.
- Frontend `next build` + lint + tsc clean.

### Commits (local, NOT pushed)
1. docker: separate egress-capable `hackpit-kali-open` (isolated sandbox unchanged)
2. backend: `:kali` execs the open container; isolation gate dropped (`:kali` only); status endpoint;
   tests rewritten + human-only source-scan test
3. frontend: banner honesty (full network reach · NOT isolated)
4. docs + proof (`kali_open_egress_proof.sh`)

DO NOT push — Zaid reviews the network config + human-only confirmation, then pushes.

---

## Session 2026-07-24 (the orchestrator loop — the autonomy mechanic, human-in-the-loop)

Built the guided agent loop: the composer's plan is driven step-by-step — the agent
proposes the next command, **the human approves every one**, it runs through the M1
executor, the result feeds back, the agent adapts and proposes the next. Design in
docs/cockpit-loop.md. Local commits, **NOT pushed** — Zaid reviews the human-in-the-loop
gate first.

### The loop model
propose → **await-approval** → execute (M1 executor) → capture → feed-back → propose | stop.
The only new backend surface is `POST /sessions/{id}/loop/propose` (backend/orchestrator.py),
which **proposes and does not execute**. Everything else is reused unchanged: the composer
(the plan/seed), the M1 executor (`POST /cockpit/exec` — the loop's "execute", four gates),
the engagement/run store (plan + recorded runs = the loop's whole state + its feedback
channel), and the M3 report generator (the recorded run sequence is its evidence).

### The human-approval gate (where autonomy enters)
- **Every command is human-approved.** The loop PAUSES at `awaiting-approval` and runs
  nothing until the operator approves. No batching, no auto-run, no "approve all". skip /
  stop always available. The agent PROPOSES; it never runs anything itself — the frontend
  only ever executes via the M1 executor after an explicit approve.
- **Recon-only + lab-locked + isolated, unchanged.** Execution is the M1 executor's four
  gates (allowlist recon → target-lock lab → approval → isolation). The proposer is *told*
  to stay recon/lab and PRE-CHECKS each proposal against the real allowlist + target-lock,
  flagging a stray one — but the enforcement is the executor's gates at run time. The frozen
  cockpit safety suite is green, unchanged.
- **No :kali / no egress path for the agent.** orchestrator.py imports only `llm` +
  `cockpit.{allowlist,config,executor}` and calls only the pure `check_target_lock` — never
  iter_run/run_command/subprocess, never the `:kali` shell. Loop runs go to the ISOLATED
  `hackpit-kali-sandbox` (verified: recorded run target=hackpit-lab-target), never the open
  `:kali` box. Regression-locked by test_loop.py (proposer-cannot-execute) and the :kali
  human-only source scan (which covers orchestrator.py); both green.

### Increments (local commits, NOT pushed)
- phase0 — design (docs/cockpit-loop.md)
- L1 — propose endpoint (no execution) + orchestrator.py + test_loop.py
- L2 — the human-gated loop (CockpitLoop: propose → approve → M1 executor → feed back)
- L3 — cinematic map (nodes light phase-by-phase; active pulses, done goes green)
- L4/L5 — report reuse (pure) + end-to-end, this section

### Verified live (local Ollama qwen3:8b for automation; frontier config restored after)
Plotted a lab path → started the loop → agent proposed `nmap -sV -p 3000 hackpit-lab-target`
(step recon-1) with a rationale, AWAITING approval → approved → ran through the M1 executor,
EXIT 0 (real Juice Shop fingerprint), recorded to the session → loop fed back and re-proposed,
ADAPTING. The agent then proposed an off-policy XSS payload (shell metachars); the pre-check
FLAGGED it in red with APPROVE disabled — surfaced, never auto-run (the safety story, live).
Report generated over the recorded run: folds it into the authoritative Evidence section and
cites it by run id. Full safety suite green (cockpit isolation unchanged); build + lint + tsc
clean. llm_config.json restored to {claude-agent-sdk, opus}.

**No autonomy without approval; execution stayed recon/lab/isolated; the agent has no
:kali/egress path.** DO NOT push — Zaid reviews the human-in-the-loop gate first.

---

## Session 2026-07-24 (SUPERVISED — strict per-command flag enforcement, safety-critical hardening)

Goal: turn `allowed_flags` from advisory into a **STRICTLY ENFORCED per-command allowlist** — the
prerequisite that makes the later active-tools expansion (sqlmap/ffuf/nuclei…) safe. Those tools carry
genuinely dangerous flags (`--os-shell`, `--file-write`, `-e`, intrusive `--script`, output/write flags)
AND legitimately need metacharacters in payload args, so the metachar filter can no longer blanket-apply;
the load-bearing defense shifts to target-lock + isolation + a strict flag schema. Hardened NOW, while the
allowlist is still recon-only and any mistake is low-stakes.

**Scope unchanged**: still recon-only (`nmap`/`curl`/`whatweb`), same sandbox, target-lock, four gates. No
new tools, no new execution capability. This only TIGHTENS the model — it adds stricter rejection of
un-listed flags. All prior safety tests stay green.

### The enforced flag schema (frozen — widening trips `test_flag_schema_frozen`)
| command | `allowed_flags` | `value_flags` (consume the next/inline token as a value) |
|---|---|---|
| `nmap` | `-sV -sT -sS -p -p- -T4 -T3 -Pn -n -oN-` | `-p` (e.g. `-p 80,443`; `-p-` = all-ports, atomic) |
| `curl` | `-s -S -i -I -L -v -X` | `-X` (e.g. `-X GET`; the method is a value, not a flag) |
| `whatweb` | `-a --color=never -v` | *(none; `--color=never` is a pinned exact form)* |

- Dropped the bogus `GET`/`HEAD` from curl's `allowed_flags` — they are operands, never flags (operands
  are not flag-checked, so validation behavior is unchanged; the frozen set is now honest).
- `_nmap_extra` is kept and runs BEFORE the strict gate so its precise recon-scope reason
  (`scripting` / `file output`) still wins for `--script`/`-sC`/`-A`/`-oN`/`-oX`; the strict gate catches
  everything else and names the offending flag.

### The parser (the crux — a bug here fails OPEN, so every form is handled + tested)
`_first_disallowed_flag(spec, args)` walks argv left→right, deterministic, no shell. Forms covered:
- **short atomic** `-sV`, `-T4`, `-p-`, `-oN-` — matched whole first;
- **combined short cluster** `-sI` = `-s` + `-I` (each letter a flag); a bad letter is **named** (`-sZ` →
  `-Z`), not the whole token;
- **short value-flag, space form** `-p 80,443`, `-X GET`;
- **short value-flag, inline getopt form** `-p3000`, `-XGET` — the value-flag stops the cluster and takes
  the token remainder as its value (does not decompose `-G`/`-E`/`-T`);
- **long bool** `--flag`; **long `=`-joined** `--pin=on` (a pinned `--color=never` permits only that exact
  value; `--color=always` is rejected); **long value-flag** space (`--opt val`) + `=`-arbitrary (`--opt=x`);
- **values that look like flags / negative numbers are NEVER misread as flags** — after a value-flag the
  next (or inline remainder) token is consumed as a value: `-X -I`, `-p -1`, `-x-z` all resolve correctly;
- **fail-closed on ambiguity**: a lone `-` is an operand; `--` (POSIX end-of-options) is **deliberately NOT
  honored** as an operand marker — honoring it would switch off flag enforcement AND the target-lock (via
  `extract_hostish`) for every following token, a fail-open hole — so `--` is rejected as an un-listed flag.
  No recon command needs it.

### Increments (local commits, NOT pushed)
- **F1** `loop(F1): strict per-command flag enforcement` — `allowed_flags` made authoritative; `validate`
  rejects any un-listed flag at the allowlist gate, naming it; `CommandSpec` gains `value_flags`.
- **F2** `loop(F2): robust flag parser` — inline getopt values + fail-closed `--`; a flag-like/negative
  value is never re-scanned as a flag.
- **F3** `loop(F3): tests + freeze` — extended `test_cockpit.py`: every allowed flag validates; un-listed
  flags rejected + named + land on the allowlist gate; the parser exercised across every form against a
  synthetic spec; and the per-command flag schema FROZEN (verified it trips on an injected widening).

### Verified
Full safety suite green (`sh backend/run_safety_tests.sh` — attack-path composer + cockpit + :kali +
orchestrator-loop + engagement, all `ALL … pass`). Confirmed: recon commands still run (`nmap -sV -T4`,
`nmap -sV -p 80,443`, `curl -sI`, `curl -X GET`, `whatweb --color=never`); an un-listed flag (`-O`,
`--data`, `--min-rate`, `--color=always`, `-sZ`) is rejected at the allowlist gate, naming the flag; the
parser resolves combined/joined/valued/flag-like forms; and the freeze test trips on a widening. Nothing
about execution, the sandbox, or allowlist MEMBERSHIP changed — only flag STRICTNESS.

**DO NOT push — Zaid reviews the parser + the frozen schemas first.**
