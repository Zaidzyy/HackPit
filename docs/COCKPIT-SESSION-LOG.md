# Cockpit — Session Log

*Running log of the unsupervised Cockpit build session(s). Newest entries at the bottom
of each section. Zaid reviews this + docs/cockpit-plan.md on return.*

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
