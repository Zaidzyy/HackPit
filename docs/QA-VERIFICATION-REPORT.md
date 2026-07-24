# HackPit — Full End-to-End QA Verification Report

**Date:** 2026-07-24 (overnight, unsupervised)
**Branch:** `engagement-mode`
**Verifier:** Claude (Opus 4.8), autonomous session
**Scope rules honored:** lab live-fire OK (isolated); engagement mode verified by **tests + proofs only** — NO live real-target run auto-approved (deferred to a human-present session). LLM-heavy checks run on local Ollama; `llm_config.json` restored to frontier at the end. No `git push`.

> Status legend: **PASS** (verified working) · **FAIL** (broken, stop-and-log) · **FIXED** (bug found + behavior-preserving fix committed) · **LOGGED** (bug/gap found, left for Zaid — risky/ambiguous) · **DEFERRED** (needs human-present session)

---

## Environment at start

| Component | State |
|---|---|
| Branch | `engagement-mode`, clean tree |
| Backend | `uv run uvicorn main:app --reload` on :8000 (auto-reloads on .py change) |
| Frontend | `next dev` on :3000 |
| Docker | v29.1.3; containers: `hackpit-lab-target` (juice-shop, internal :3000), `hackpit-kali-sandbox` (isolated), `hackpit-kali-open`, `hackpit-engage-sandbox` |
| Ollama | up; text models incl. `qwen3:8b`, `llama3.1:8b`, `dolphin3:8b`; `nomic-embed-text` |
| `llm_config.json` at start | `claude-agent-sdk` / `opus` (frontier) — to be restored |

---

## A. SAFETY MODEL (highest priority) — ALL PASS

| # | Check | Result | Evidence |
|---|---|---|---|
| A1 | Full safety suite (every `test_*.py`) green | **PASS** | `sh backend/run_safety_tests.sh` — all 6 suites pass (attack_path, cockpit, kali, loop, engagement, engagement_mode) |
| A2 | Lab isolation proof 4/4 (sandbox→lab yes; →internet/host no) | **PASS** | `isolation_proof.sh` → "4 passed, 0 failed" |
| A3 | Engagement never-auto-run enforced (unapproved cmd → 403 `approval`) | **PASS** | `_validate_engagement` hard-rejects `approved=False`; `test_never_auto_run_engagement` asserts gate==`approval` |
| A4 | Explicit entry required (bogus/exited id → refused, never lab) | **PASS** | `validate_request` refuses unresolved `engagement_id` at gate `engagement`; `iter_run` re-checks even when prevalidated; `test_explicit_entry_required` |
| A5 | Correct target routing (engagement→engage sandbox, lab→lab sandbox) | **PASS** | `iter_run` selects `ENGAGE_SANDBOX_CONTAINER` vs `SANDBOX_CONTAINER` by active engagement; `test_engagement_target_lock` |
| A6 | Wall A GONE; engage sandbox reaches internet (engage_open 4/4) | **PASS** | `engage_open_proof.sh` → "4 passed, 0 failed" |
| A7 | Engage sandbox keeps `cap_drop: ALL` + `no-new-privileges`, not privileged | **PASS** | `docker inspect` → `CapDrop=["ALL"]`, `SecurityOpt=["no-new-privileges:true"]`, `Privileged=false` |
| A8 | No wall_a gate / assert_wall_a_holds / WALL_A_BLOCKED resurrection | **PASS** | `test_no_wall_a_gate` asserts literal + attrs gone; source grep finds only "it's gone" comments |
| A9 | No-allowlist: any binary runs; heuristic red-confirm fires on interpreters/nc/socat/reverse-shell/msf and needs `dangerous_ack` | **PASS** | `test_cockpit` (heuristic + no-allowlist), `test_engagement_heuristic_red_confirm` |
| A10 | Agent has ZERO path to :kali and cannot execute (proposer-only) | **PASS** | `test_loop` (proposer cannot execute / no :kali path), `test_executor_still_has_no_kali_path`, source scan |
| A11 | argv exec (no `shell=True`) in every exec path | **PASS** | `argv=["docker","exec",container,command,*args]`; grep: no real `shell=True`/`os.system` (only detection strings + test payloads + venv) |
| A12 | Lab mode behavior unchanged from main | **PASS** | Shared files gained a *mode split*; lab branch (`_validate_lab`) is the identical gate sequence + isolation gate; `test_lab_mode_unaffected`; isolation proof still 4/4 |
| A13 | :kali open-egress proof | **PASS** | `kali_open_egress_proof.sh` → "3 passed, 0 failed"; :kali sandbox also `cap_drop ALL`+`no-new-privileges` |

**Section A verdict: the whole safety model re-proves green.** With Wall A down, NEVER-AUTO-RUN (per-command human approval) is the sole floor for engagement mode, and it is enforced hard in `_validate_engagement` with no bypass path (only `iter_run` caller that skips re-validation is the router, which runs `validate_request` first; `iter_run` additionally re-checks active-engagement even when prevalidated).

---

## B. COMPANION end-to-end

Walked in a real browser (Chrome automation). Console checked per screen.

| Screen | Result | Notes |
|---|---|---|
| Intro | **PASS** | `hackpit_` cursor, ENTER button, keyboard-Enter works |
| Home / bento | **PASS** | Nav (LIBRARY/ATTACK-PATHS/COCKPIT/KALI/ENGAGEMENTS), stat counters **count up to 1564 / 72 / 107 (exact match to `/stats`)**, featured cards (Guided attack paths, Cockpit), category bento with **served** counts (Web 212, Network 183, Reference 166, AD 116, Privesc 114 = raw − filter_excluded). No dead category links. See LOGGED-3 (home renderer freeze under automation). |
| Library / categories | **PASS** | `/category/web` loads (212 entries, source-count + NOTES badges, tags). Hidden cats (forensics/ics/phishing/supply-chain) absent from grid (`CategoryGrid.HIDDEN_CATEGORIES`); still findable via search (`decep-forensicator` = search hit #1). |
| Entry page | **PASS** | Breadcrumbs, 5 SOURCES / TIER badges, ALSO COVERED IN (PayloadsAllTheThings/HTB Academy/HackTricks), TOOLS chips, numbered steps, markdown, inline code, external links, BASH code block + COPY. Console clean. |
| Search + ⌘K palette | **PASS** | Ctrl+K opens; "sql injection" → exact-title "sql injection resource" ranked #1; **hybrid mode confirmed** ("● hybrid · 20"); highlighted terms; empty-state present. |
| Scripts arsenal | **PASS** | "1028 scripts, deduped from 1564 entries"; category chips w/ counts; cards with language tags (BASH), COPY, FROM source attribution; filter empty-state ("0 MATCHES"). Polyglot-specific tag not re-checked visually (term didn't match) — fix was committed in the prior session (S46). |
| Attack-path composer | **PASS** | Merged **Pentest / Bug Bounty** chip + CTF + AD; Scope/RoE field; model badge "composed by llama3.1:8b · local" + gear → LLM settings modal (provider grid + model dropdown, reflects persisted config). Composed a 5-phase/17-step path; **target parsed & substituted** ("target: http://10.10.10.55 · substituted into every command"); **target adaptation endpoint-faithful** ("→ for this target: Use the target's IP address (10.10.10.55) in place of '192.168.13.0/24'") — no invented hosts; grounded steps show "technique →" cites, PREVIEW + START ENGAGEMENT. Branches / writeup-first mode not exhaustively exercised. See LOGGED-2. |
| Engagements list | **PASS** | "Your engagements", compose button, session cards (tags, progress bars, timestamps, DELETE). Console clean. |
| Engagement detail | **PASS** | Title/goal/progress, VIEW REPORT, phased steps with checkboxes + results/notes paste, ASSISTANT panel. |
| Report (generation + view) | **PASS** (+ known attribution bug) | Generated in 40s (llama3.1:8b). Folds recorded run into Evidence tagged **"[EXECUTED · isolated lab] (run-7953424b525c)"** (lab/engagement distinction), cites run id, target + exit code, accurate narrative, no fabrication. UI renders markdown + REGENERATE/DOWNLOAD PDF/.MD/COPY. Attribution "generated by {model}" reads from **current** config → the known bug (LOGGED-4). Confirmed it is the ONLY report issue. |

_Images on entry pages_ were not explicitly exercised on an image-bearing entry (the sampled entry had none); the `/image` endpoint + 65 OCR captions exist. Low risk.

## C. COCKPIT end-to-end

| Area | Result | Notes |
|---|---|---|
| `/cockpit` empty state | **PASS** | Kicker "GROUNDED PLAN · LIVE EXECUTION", ":cockpit", lab framing, plot bar, profiler chips, model badge, progressive-disclosure empty state ("plot a path to begin"). Console clean. |
| Kill-chain map | **PASS** | Plotted a REAL composed path (not the sample): profile inferred "MULTI-TENANT SAAS", priority bug-class chips (cross-tenant IDOR, SSRF, OAuth token handling, LFI/RFI, path traversal), phased nodes (RECON/ENUMERATION) with grounded indicators. See LOGGED-3 (composing-animation renderer freeze). |
| Node-detail drawer | **PASS** | Slide-in drawer: phase badge (RECON GROUNDED), title, "why", "FOR THIS TARGET" adaptation, real grounded commands (SOAP/XOP, tRPC, curl) each with COPY. |
| Live execution (lab) — e2e | **PASS** | Real lab live-fire via `POST /cockpit/exec` (approved `curl` → lab): SSE `start` (run_id, target `hackpit-lab-target`, **mode `lab`**) → 33 `stdout` lines of real Juice Shop HTML → `exit`. Ran in the egress-less sandbox; run recorded. |
| Orchestrator loop (lab) | **PASS** | `POST /sessions/{id}/loop/propose` returns `{done, proposal, reason}`; proposal (sqlmap `--dump` + rationale, step_id, `gate_ok:true` pre-check) is returned **without executing** — proposer proposes, human approves each, no autonomy. Regression-locked in `test_loop.py`. |
| :kali | **PASS** | `/cockpit/kali/status` → `isolated:false` (honest "NOT isolated"), up/ready. Human-only, no agent path (Section A). |
| Mode switch (lab ↔ engagement) | **PASS (safety) / partial (visual)** | Engagement gating proven at HTTP layer (below) + tests. The mode-switch/entry-warning UI (`CockpitEngagementMode.tsx`) was not deep-walked visually to avoid entering a live engagement; `GET /cockpit/engagement` drives it and returned correct state (`active:[]`, `open:true`, `ready:true`). |

### HTTP-layer safety re-proof (live, not just unit tests)
| Request | Expected | Actual |
|---|---|---|
| LAB, `approved:false` | 403 gate=approval | **403 gate=approval** ✓ |
| bogus `engagement_id`, `approved:true` | 403 gate=engagement (NOT lab, NOT run) | **403 gate=engagement** ✓ |
| bogus `engagement_id`, `approved:false` | 403 gate=engagement | **403 gate=engagement** ✓ |
| LAB, target `example.com` | 403 gate=target | **403 gate=target ("only the lab is allowed")** ✓ |

**Engagement live e2e (scanme.nmap.org) DEFERRED** to a human-present session per scope rules — never auto-approved. Verified by tests + proofs + the HTTP-layer gates above.

## D. DATA INTEGRITY + REGRESSIONS

| Check | Result | Evidence |
|---|---|---|
| `entries.jsonl` parseable | **PASS** | 1593 lines, 0 JSON-broken |
| No duplicate / missing ids | **PASS** | 0 duplicate ids, 0 missing ids |
| No empty/broken entries | **PASS** | 0 entries lacking title AND body_md/steps/summary; 4 empty-`body_md` entries all carry steps |
| KB counts sane | **PASS** | Raw 1593 → served 1564; the 29-entry drop is intentional `filter_excluded` (all `checklist-*` meta entries). `/stats`: techniques 1564, tools 72, workflows 107, categories 33 |
| Hidden categories gone from browse, findable via search | **PASS** | `CategoryGrid.tsx` `HIDDEN_CATEGORIES` (display-only filter) removes forensics/ics/phishing/supply-chain from the grid; `/categories` endpoint + data untouched; `/search?q=Forensicator` returns `decep-forensicator` as result #1. All 33 `decep-*` entries kept/served |
| `tsc --noEmit` | **PASS (clean)** | exit 0 |
| `eslint` | **BASELINE** | 10 errors + 1 warning, ALL `react-hooks/*` (Next 16 `eslint-config-next` defaults); every flagged file is **byte-identical to `main`** (0 new). Pre-existing — not fixed (behavior-preserving rule; correct patterns in an unusual Next version). See LOGGED-1 |
| `next build` | _pending (run at end; dev server shares `.next`)_ | |

**Attack-path composer (Ollama):** **PASS.** `POST /attack-path` with `llama3.1:8b` → 5 phases / 17 steps, correct mix of grounded (real `entry_id` cites) + `ai_suggested` (no cite). Structure matches schema (`phases[].steps[]`, fields `phase`/`label`). See LOGGED-2 for qwen3:8b flakiness.

## E. Bugs found / fixed / logged

### LOGGED (left for Zaid — not fixed)

**LOGGED-1 — `npm run lint` fails on 10 pre-existing `react-hooks/set-state-in-effect` errors + 1 warning.**
Files: `useApi.ts`, `useReducedMotion.ts`, `ReportScreen.tsx`, `CategoryGrid.tsx`, `CommandPalette.tsx`, `EngagementAssistant.tsx`, `EngagementsList.tsx`, `HackPitShell.tsx`, `Intro.tsx` (`react-hooks/refs`), `LLMSettingsModal.tsx`. All are **byte-identical to `main`** → pre-existing baseline, zero introduced by engagement-mode. Not fixed: several are legitimate patterns (matchMedia init, fetch-reset on dep change) and the repo's `AGENTS.md` warns this Next 16 build has non-standard behavior — auto-fixing risks regressions, violating the behavior-preserving rule. *Risk if fixed wrong: broken data-loading/reveal animations.* Decision for Zaid: accept as baseline or schedule a dedicated hooks-refactor pass.

**LOGGED-2 — Default Ollama model `qwen3:8b` can 503 the attack-path composer.**
`POST /attack-path` with `qwen3:8b` returned `503 "the model did not produce any usable steps"` on a generic goal (the grounding pass dropped everything — qwen3's `<think>` blocks/JSON shape). `llama3.1:8b` produced a clean 17-step path for the same goal. Not a HackPit code bug (grounding correctly rejects unusable output), but the shipped **default** model is unreliable for this feature. Decision for Zaid: consider defaulting Ollama to `llama3.1:8b`, or strip `<think>` blocks before JSON extraction. *Not changed — default-model choice is a product decision.*

**LOGGED-3 — Renderer intermittently unresponsive on heavily-animated views (home count-up, cockpit composing spinner).**
During browser automation, `Page.captureScreenshot` repeatedly timed out (30s "renderer may be frozen") **only** while the home stat count-up and the cockpit "composing…" animation were active; static pages (category, entry, scripts, engagements) never froze. The pages DO render correctly once settled (counters land on 1564/72/107; the map reveals). This may be partly an automation/CDP artifact, but the exclusive correlation with active animations — combined with the pre-existing `react-hooks/set-state-in-effect` "cascading renders" lint errors (LOGGED-1) — suggests a real client-side perf cost worth a look. *Not fixed: no clear behavior-preserving one-liner; needs profiling. Impact on a normal user is likely minor (brief jank), unconfirmed.*

**LOGGED-4 — Report model-attribution label is not persisted (the pre-existing "known" bug — CONFIRMED still present, still the only report issue).**
`ReportScreen` renders "generated by **{model}**" from the CURRENT `getLLMConfig()`, not the model that actually produced a persisted report, because `save_report` / `get_session` / `SessionDetail` carry no `report_model` (verified: `/sessions/{id}` returns `report_md` + `report_generated_at`, no model field; the `POST …/report` response DOES return correct `model_used` at generation time). Repro: generate with model A, switch config to B, reload the report → label reads B. **Content is correct; run citations + Evidence are authoritative (built server-side from the session, not the model).** Fix = persist a `report_model` column (`sessions.db` schema + API-contract change across `save_report`/`SessionDetail`/`ReportScreen`) — non-trivial, cross-cutting → **LOGGED, not fixed** (matches the prior session's own decision). This is the only defect found in the report path.

### FIXED (behavior-preserving, committed locally)
**None.** Every issue found is either pre-existing baseline, a product/default-model decision, or a cross-cutting schema change — all of which the rules say to LOG, not guess-fix. No safe, trivial, behavior-preserving code bug was found. The only commit this session is this report. (Temporary `next.config.ts`/`tsconfig.json` edits used to run an isolated `next build` were reverted; git status is clean except this doc.)

### MISSING / half-built noticed
- Nothing structurally missing. All routes build and render. `CockpitEngagementMode` mode-switch UI was intentionally not deep-walked (would require entering a live engagement — out of unsupervised scope).

## Open questions for Zaid

1. **eslint baseline (LOGGED-1)** — accept the 10 pre-existing `react-hooks/*` errors as baseline, or schedule a dedicated hooks-refactor? (Note: `next build` passes exit 0 — Turbopack build doesn't run eslint — so this only affects `npm run lint`, not the production build.)
2. **Default Ollama model (LOGGED-2)** — switch the shipped default from `qwen3:8b` to `llama3.1:8b` (more reliable for the composer), and/or strip `<think>` blocks before JSON extraction?
3. **Report attribution (LOGGED-4)** — worth the `report_model` schema/API change, or leave as a known cosmetic-on-reload issue?
4. **Animated-view perf (LOGGED-3)** — want a profiling pass on the home count-up / cockpit compose animations?
5. **Engagement live e2e** — the scanme.nmap.org engagement run is deferred; ready to do it together in a human-present session (you approve each command)?

## Summary

- **Safety model: fully re-proven.** All 6 test suites green; lab isolation 4/4; engagement fully-open proof 4/4 (+ `cap_drop ALL` + `no-new-privileges`); :kali open-egress 3/3; no `wall_a` resurrection; no `shell=True`; argv-only exec; agent has zero :kali/exec path; lab path byte-behaviorally unchanged. **NEVER-AUTO-RUN + explicit-entry enforced hard end-to-end (unit tests AND live 403s at the HTTP layer).**
- **Companion + Cockpit: all screens load, render, and function; consoles clean; data integrity solid** (1593 entries, 0 dup/broken; 1564 served after intentional `filter_excluded`).
- **Headline flows verified live:** attack-path composition (target-faithful), cockpit kill-chain + node drawer, lab live-fire exec (real streamed output), orchestrator propose (no autonomy), report generation (evidence + run citations).
- **`tsc` clean; `next build` clean (exit 0).**
- **Bugs: 0 new critical.** 4 items LOGGED (1 pre-existing lint baseline, 1 default-model reliability, 1 known report-attribution, 1 animation-perf observation), 0 fixed (none were safe/trivial per the rules). No safety gate was weakened.
- **`llm_config.json` restored to frontier** (`claude-agent-sdk`/`opus`). **Not pushed.**

---

## Post-QA loose ends (follow-up session, same day)

Cleaned up 3 actionable items + documented 1, all behavior-preserving, on the `engagement-mode` branch (the QA precondition "run on main after merge" was not met — `engagement-mode` is **not** merged into `main`; Zaid authorized doing the work on the branch directly). No safety gate weakened; lab mode untouched. Committed as focused local commits — **not pushed**.

| Item | Commit | What changed | Verified |
|---|---|---|---|
| **L1** — default Ollama model (was LOGGED-2) | `13bb45b` | `DEFAULTS` + `PROVIDER_DEFAULT_MODEL` + docstring: `qwen3:8b` → `llama3.1:8b`. (`<think>` stripping was already applied before JSON extraction via `extract_json`→`strip_think`; the "unusable output → 503" guard is untouched.) | `POST /attack-path` on the new default → clean 5-phase/8-step path, **no 503** |
| **L2** — persist `report_model` (was LOGGED-4) | `bc42823` | New `report_model` column (migration-safe `ADD COLUMN … DEFAULT NULL` + in `CREATE TABLE`); `save_report(…, report_model)` stores `model_used`; `get_session`/`SessionDetail`/api.ts return it; `ReportScreen` attributes to `report_model` when present, falls back to current config only for old (null) reports (routed through the async path → no new lint line) | Generate with `llama3.1:8b` → persisted; switch active model to `qwen3:8b` → `GET /sessions/{id}` still reports **`llama3.1:8b`** |
| **L3** — never-auto-run belt-and-suspenders | `0538313` | In `iter_run`'s **engagement branch only**: if `not approved` → yield one `rejected`/`approval` and return, even when `prevalidated=True`. Pure no-op for valid flows; **lab branch byte-for-byte unchanged**. + new regression test | New test PASS: `iter_run(prevalidated=True)` + active engagement + `approved=False` → exactly one `rejected` (gate=approval), **nothing runs**. All existing engagement/never-auto-run/explicit-entry tests still green |
| **L4** — document lint baseline (was LOGGED-1) | `29e9468` | `frontend/AGENTS.md`: the 10 `react-hooks/*` errors are an accepted pre-existing baseline; `next build` passes exit 0; only `npm run lint` affected; do NOT auto-fix | No code change |

### Re-run verification (all green)
- `sh backend/run_safety_tests.sh` — **all 6 suites PASS** (incl. the new *BELT-AND-SUSPENDERS* engagement test).
- `isolation_proof.sh` — **4/4** (lab reaches lab, not internet/host).
- `engage_open_proof.sh` — **4/4** (engagement fully open; the only guard is human-approve-each).
- `tsc --noEmit` — **clean (exit 0)**; `next build` — **exit 0** (12 routes, 9/9 static pages).
- `eslint` — unchanged at the **11-problem baseline** (0 new). `llm_config.json` **restored to frontier**. Backend healthy. **Not pushed.**

**Net LOGGED status after this session:** LOGGED-1 → documented (accepted); LOGGED-2 → fixed (L1); LOGGED-3 (animation renderer jank) → still open (needs profiling, no safe one-liner); LOGGED-4 → fixed (L2). L3 is a defense-in-depth hardening of the sole engagement floor.
