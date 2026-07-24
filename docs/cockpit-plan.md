# HackPit Cockpit — Scope & Architecture Plan

*Phase 0 deliverable. Owner: Zaid · Drafted by: Claude (unsupervised session, 2026-07-23).*
*Status (updated 2026-07-24): Phase 0 plan **shipped**. Build progress — **M1 (live human-approved
execution vs the isolated lab) COMPLETE**; **M2 (cinematic command-center UI) COMPLETE**; **M3
(engagement integration + polish) COMPLETE** — cockpit runs are recorded into the existing engagement
sessions layer and roll up into the reused report generator (scope + composed path + recorded
commands/outputs); **Hardening/QA night COMPLETE** — the four safety gates are now regression-locked
by automated tests (`sh backend/run_safety_tests.sh`), the M3 engagement/report path is tested, and an
app-wide broken-state sweep was run (findings in the session log). See `docs/COCKPIT-SESSION-LOG.md`
for the per-increment build + verification log.
The roadmap table below is the original Phase-0 numbering (M2 there = "guided execution over a path");
the build sessions numbered differently (M2 = UI, M3 = engagement integration). No autonomy has been
built; execution stays allowlisted-recon, lab-only, human-approved (the four gates are unchanged).*

> The **Companion** is feature-complete (search → attack-path → engagement → report over a 1480-entry KB).
> The **Cockpit** is the flagship the name always pointed to: an AI that *executes* a pentest live against
> an authorized target, watched through the cinematic UI. This document scopes it and specifies Milestone 1.

---

## 0. Defaults assumed this session (Zaid: override any of these)

Zaid is away. Where the original prompt left a real choice, I took the stated default, recorded it here, and
kept moving. Each is cheap to change later.

| # | Decision | Default taken | Why / how to override |
|---|----------|---------------|-----------------------|
| D1 | Sandbox runtime | **Built-in Kali Docker container** (self-contained, reproducible), NOT SSH-to-own-Kali | Reproducible, disposable, no host creds in the loop. Override: add an `ssh` executor behind the same interface. |
| D2 | Lab target | **OWASP Juice Shop** container (web module first) | Modern web-vuln surface, matches "web module first". DVWA is the fallback / addition. Both are self-hosted on the isolated net. |
| D3 | Orchestrator | **Explicit Python loop** now; LangGraph pattern later | M1 runs ONE command — no graph needed yet. Keep the executor interface graph-agnostic. |
| D4 | Autonomy at M1 | **Human-approve-each-command.** No autonomous multi-step loop this session | Safety gate. The loop is a later, separately-shipped phase. |
| D5 | Exec transport | **`docker exec` into the sandbox** from the FastAPI backend | Backend already owns process lifecycle. Override: gRPC/HTTP agent inside the sandbox if we outgrow `docker exec`. |
| D6 | Command allowlist | **Hardcoded safe set** (nmap, curl, whatweb, nikto-safe, gobuster/ffuf against the lab only) | No arbitrary/weaponized commands while unsupervised. Human can extend the list in code review. |

**Runtime reality found this session:** Docker CLI 29.1.3 + Compose v5.0.1 installed; WSL2 Ubuntu is the default
distro. **The Docker Desktop daemon was NOT running** when checked — so M1.2's isolation *proof* cannot be
executed until the daemon is up. All Docker config and proof scripts can be authored now; the proof itself is
gated on a running daemon (see M1.2).

---

## (a) Reuse map — what exists vs what's new

The Cockpit is a **new module bolted onto the existing FastAPI backend + Next.js frontend**, reusing the KB,
LLM layer, and session store. It does NOT fork the app.

### Reuse as-is (no change)
- **`backend/main.py`** — FastAPI app, CORS to `:3000`, ~30 endpoints, Pydantic response models. Cockpit adds a router here.
- **`backend/llm.py`** — provider-swappable chat (`ollama` default `qwen3:8b`; `openai`/`anthropic`/`openrouter`/`claude-agent-sdk` via gitignored `llm_config.json`). The Cockpit planner/analyst reuses this untouched. Frontier model recommended for the attack engine (per PROJECT_PLAN §3).
- **`data/kb/entries.jsonl`** (gitignored, 1480 entries) + **`pipeline/search.py`** hybrid retrieval — the grounding brain for both Companion and Cockpit.
- **Cinematic frontend shell** — `HackPitShell`, `WaveGrid`, TopBar, mono `:nav`, amber accent (`#ffb03a`). The Cockpit is a new `:cockpit` destination in the same shell.

### Reuse the *pattern*, adapt for live execution
- **`backend/attack_path.py`** — already composes ordered, grounded, phased steps with stable `{phase}-{n}` ids across the 5 canonical phases (recon → enumeration → exploitation → privesc → post-ex). **This IS the Cockpit's planner output format.** The Cockpit consumes the same step objects but, instead of only *displaying* them, offers to *execute* the ones that map to an allowlisted command. Stable ids let live run-state hang off each step exactly like the engagement layer does.
- **`backend/sessions.py`** + **`sessions.db`** (SQLite, WAL, gitignored) — per-step check-off/results/chat keyed by `{phase}-{n}`. The Cockpit's live-run records (command, stdout, stderr, exit, timestamps) attach to the same session/step model. A **cockpit run is an engagement that executed some of its steps.**
- **`backend/report.py`** — grounded, byte-exact-evidence report generator. Cockpit run output feeds it directly (real captured output = real evidence).

### New (this is the Cockpit build)
- **`cockpit/` module** (backend): sandbox lifecycle, command allowlist + validator, executor (`docker exec`), live output streaming, run-record persistence.
- **`docker/` sandbox+lab**: two-container, two-network isolated Compose stack (Kali sandbox ↔ lab target only; no egress).
- **Execution API**: `POST /cockpit/exec` (one allowlisted command, requires an explicit approval flag) + a stream channel (SSE/WebSocket).
- **Cockpit UI**: enter/approve a command, watch output stream live from the sandbox.
- **Isolation proof harness** + documented evidence.

### Referenced, NOT wired this milestone
- `../hacks/Decepticon` — **two-network isolation pattern only** (adapt, don't copy).
- `../cyber/hexstrike-ai` — MCP tool engine, a *later* phase (M-later). Not M1.

---

## (b) Architecture — planner → orchestrator → exec/tool layer → sandbox → live UI

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  FRONTEND  (Next.js + Tailwind + Framer, existing cinematic shell)            │
│  :cockpit  →  live command-center view                                        │
│   • command box + [APPROVE & RUN] gate (human control point #1)               │
│   • live stdout/stderr stream (SSE)                                            │
│   • run history, exit codes, per-step run-state                               │
└───────────────▲─────────────────────────────────────────────┬────────────────┘
                │ SSE stream (output)          POST /cockpit/exec (approved cmd) │
┌───────────────┴─────────────────────────────────────────────▼────────────────┐
│  BACKEND  (FastAPI, existing app + new cockpit/ router)                        │
│                                                                               │
│  PLANNER      reuse attack_path.py → ordered grounded {phase}-{n} steps       │
│               (+ llm.py for reasoning; frontier model recommended)            │
│      │                                                                        │
│      ▼                                                                        │
│  ORCHESTRATOR   explicit loop (M1: single step, no autonomy).                 │
│               Decides WHICH step to offer. Never auto-runs — waits for the    │
│               human APPROVE flag. (LangGraph pattern slots in here later.)     │
│      │                                                                        │
│      ▼                                                                        │
│  EXEC / TOOL LAYER   cockpit/executor.py                                       │
│    1. allowlist check      (cockpit/allowlist.py — command must be in set)     │
│    2. target check         (target must be the lab container, nothing else)    │
│    3. approval check       (request.approved is True, per-command)             │
│    4. run: docker exec <sandbox> <cmd>  → capture stdout/stderr/exit, stream   │
│    5. persist run-record   (sessions.db, keyed to step id)                     │
└───────────────────────────────────────┬───────────────────────────────────────┘
                                         │ docker exec  (the ONLY bridge in)
┌────────────────────────────────────────▼──────────────────────────────────────┐
│  SANDBOX  (Docker)                                                             │
│                                                                               │
│   ┌────────────────────┐   isolated internal net    ┌───────────────────────┐ │
│   │  kali-sandbox      │◄──────────────────────────►│  lab-target           │ │
│   │  (nmap/curl/…)     │   (sandbox ↔ lab ONLY)     │  (Juice Shop / DVWA)  │ │
│   │  NO egress ────────┼──✗ internet                └───────────────────────┘ │
│   │  NO host access ───┼──✗ host                                              │
│   └────────────────────┘                                                      │
│   Network: `internal: true` → no gateway, no NAT, no route off the bridge.    │
└───────────────────────────────────────────────────────────────────────────────┘
```

**Human control points (transparency / human-in-the-loop, per PROJECT_PLAN §2):**
1. **Approve-to-run** — every command is shown and requires an explicit human approval flag before execution. Nothing runs hidden.
2. **Allowlist** — even an approved command must be in the hardcoded safe set (belt + suspenders).
3. **Target lock** — even an approved, allowlisted command may only target the lab container.

**Concrete tech per box:** FastAPI (backend), Pydantic (contracts), `docker exec` via subprocess/SDK (executor),
SSE via `StreamingResponse` (live output — simpler than WebSocket for one-way stdout, reuses HTTP/CORS already set up),
Docker Compose with an `internal: true` network (isolation), Next.js + existing shell (UI), SQLite (run records).

---

## (c) SAFETY BY ARCHITECTURE — the centerpiece

This is offensive tooling. Safety is not a feature bolted on; it is the shape of the system. Three independent
layers, each of which alone blocks misuse, plus hard operational gates.

### Layer 1 — Network isolation (proven before any exec code exists)
- The sandbox and lab live on a Docker network created with **`internal: true`** → Docker attaches **no gateway** to it, so containers on it have **no route to the host and no route to the internet**. NAT/egress is structurally absent, not firewall-filtered.
- The sandbox reaches the lab **only** because both are on that one internal network.
- **Proof is a hard gate (M1.2).** Before a single line of exec code ships, a documented harness must show:
  - ✅ `kali-sandbox` **CAN** curl the lab target (e.g. `curl http://lab-target:3000` → HTTP response).
  - ✅ `kali-sandbox` **CANNOT** reach the internet (`curl https://example.com` → fails/timeout; `getent hosts` → no resolution or no route).
  - ✅ `kali-sandbox` **CANNOT** reach the host (host loopback / host LAN IP → fails).
  - If any check is wrong, **STOP. Do not wire execution.** (Original prompt, non-negotiable.)

### Layer 2 — Target allowlist (only the lab, ever)
- The executor resolves the requested target and **rejects anything that is not the built-in lab container.** No external, real, or user-supplied host — full stop while unsupervised.
- Implemented as an explicit constant (the lab service name / its isolated-net IP), checked before exec. External targets are a *deliberate future feature* behind Zaid's explicit authorization + a real scope gate — out of scope for this session.

### Layer 3 — Command allowlist + per-command human approval
- **Allowlist:** a hardcoded set of safe, read-mostly recon commands (nmap, curl, whatweb, and similar) with argument validation. No shell metacharacters, no arbitrary binaries, no weaponized payloads. Claude builds *mechanisms, not payloads* (PROJECT_PLAN §2).
- **Per-command approval:** `POST /cockpit/exec` refuses to run unless `approved: true` is set for *that* command. By design there is no "approve all / run autonomously" switch in M1.
- **No autonomy:** M1 executes exactly ONE approved command and streams its output. No multi-step attack loop is built this session (original prompt, non-negotiable).

### Operational gates (kept out of git, always)
- `data/kb/*`, `backend/llm_config.json` (may hold an API key), `sessions.db`, secrets, and any sandbox artifacts stay **gitignored** (already enforced by root + backend `.gitignore`). The repo ships **code only**.
- The sandbox is disposable: `docker compose down -v` leaves no residue.

---

## (d) Phased roadmap (web module first; each phase independently shippable)

| Phase | Ships | Autonomy | Gated on |
|-------|-------|----------|----------|
| **M1 — One approved command, live** | Approve → run ONE allowlisted cmd in the isolated sandbox vs the lab → stream output to the UI | None (human approves each) | This session |
| **M2 — Guided execution over a path** | Attack-path steps that map to allowlisted commands get a per-step [Run] button; results captured into the engagement + report | None (still per-step approval) | M1 verified |
| **M3 — Tool engine** | Wire `hexstrike-ai` (MCP) as a broader tool surface behind the same allowlist/approval/target gates | None | M2; scope expansion review |
| **M4 — Assisted loop** | LangGraph-style orchestrator proposes the *next* step from live output; human still approves each execution (checkpointed autonomy) | Opt-in, checkpointed | M3; explicit Zaid sign-off |
| **M5 — Cinematic live cockpit** | Full command-center: animated attack map, live agent reasoning, MITRE kill-chain replay over real runs | — | M4 |
| **later** | External authorized targets behind a real scope gate + written authorization; CTF box & host modules | — | Separate, deliberate, Zaid-driven |

Web module is first throughout (Juice Shop/DVWA). CTF-box and host modules follow the same isolation model later.

---

## (e) Milestone 1 — spec

**Goal:** A human approves `nmap <lab>` (or another allowlisted command) → it runs inside the isolated Kali
sandbox against the lab target → output streams live to the Cockpit UI. Nothing runs without approval; nothing
can reach anything but the lab.

**Increments (verify + commit each):**

- **M1.1 — Scaffold + this plan.** `cockpit/` module dirs + interfaces (no logic), `docker/` dir, this doc, session log. Backend imports clean, frontend build clean. *Commit.*
- **M1.2 — Isolated Docker stack + isolation PROOF (hard gate).** Compose stack: `kali-sandbox` + `lab-target` on an `internal: true` network. Prove & document: sandbox→lab OK; sandbox→internet blocked; sandbox→host blocked. If unprovable → stop, do not proceed. *Commit.*
- **M1.3 — Execution API.** `POST /cockpit/exec`: allowlist + target + approval checks → `docker exec` → capture stdout/stderr/exit → persist run-record. Test order: echo dry-run → real allowlisted `nmap`/`curl` at the lab. *Commit.*
- **M1.4 — Cockpit UI.** Command box + APPROVE gate + live SSE output stream, wired to M1.3. `npm run build`/`lint` clean. *Commit.*
- **M1.5 — E2E verified demo.** Human approves `nmap <lab>` → runs in sandbox → streams to UI. Document the run. *Commit.*

**Explicit M1 non-goals:** no autonomous loop; no external targets; no arbitrary/weaponized commands; no hexstrike wiring.

**M1 contracts (sketch — firm up in M1.3):**
```
POST /cockpit/exec
  { "command": "nmap", "args": ["-sV", "-T4", "lab-target"], "approved": true, "session_id": "...", "step_id": "recon-1" }
  → 200 { "run_id": "...", "started_at": "...", "stream_url": "/cockpit/exec/{run_id}/stream" }
  → 403 if not approved / not allowlisted / target not the lab
GET  /cockpit/exec/{run_id}/stream   (SSE: {stdout|stderr|exit} events)
GET  /cockpit/exec/{run_id}          (final record: cmd, output, exit, timings)
GET  /cockpit/allowlist              (the safe command set, for the UI)
```

---

## Open questions for Zaid

1. **Sandbox: built-in Kali container vs SSH to your own Kali?** Defaulted to built-in container (D1). Your call if you'd rather point it at your Kali VM.
2. **Lab target: Juice Shop, DVWA, or both?** Defaulted to Juice Shop first (D2).
3. **Allowlist scope:** initial safe set = nmap, curl, whatweb, gobuster/ffuf (vs lab), nikto-safe. Want anything added/removed for M1?
4. **Frontier model for the attack engine?** llm.py supports `anthropic`/`claude-agent-sdk`/`openrouter` with a key. M1 needs no LLM (single command), but M2+ reasoning wants one — which provider/key?
5. **Docker Desktop:** the daemon wasn't running this session, so I can author the M1.2 stack + proof scripts but cannot execute the isolation proof until it's up. OK for me to attempt starting it, or do you want to start it and let me run the proof next session?
6. **Exec transport:** `docker exec` from the backend (D5) vs a small agent inside the sandbox. Defaulted to `docker exec` (simplest, backend already owns processes).

---

*Next: M1.1 scaffold, then M1.2 (isolation is the gate for everything after it).*
