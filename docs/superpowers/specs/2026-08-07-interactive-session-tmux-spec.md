# Build spec — Interactive persistent-session engine (tmux + auto prompt-detection)

**Status:** ready to execute in a fresh session. **Author:** planning session, 2026-08-07.
**One line:** upgrade HackPit's `:terminal` / C2 session panel to Decepticon's **persistent named-tmux-session** model — named sessions with per-session cwd/env/background-jobs, **automatic interactive-prompt detection** (msfconsole / sliver-client / evil-winrm / REPLs), background + auto-background-at-60s with completion notifications, and wedge/pipe-degradation recovery. Ported from Decepticon (`tools/bash/bash.py`, `tools/bash/prompt.py`; Apache-2.0 — attribute). **HackPit twist: stdin stays human-driven / approve-each** (the C2 panel's HUMAN-ONLY-stdin rule); we take the session *mechanics*, never agent autonomy over input.

---

## 0. Guiding constraint (read first, do not weaken)

Adds **NO new gate.** The sandbox containment is unchanged (hardcoded kali container, the `:kali`/`:terminal` two-sandbox model). **Stdin remains HUMAN-ONLY / approve-each** — the orchestrator must NEVER send `is_input` (that is Decepticon's autonomy, explicitly NOT adopted; see the C2-panel HUMAN-ONLY-stdin invariant and the `:terminal`-vs-`:kali` separation). What we adopt is the *session engine*: named persistence, prompt-detection, background lifecycle, output management, recovery. Maximally open otherwise (real interactive C2/tooling), gated exactly as today.

## 1. Read-first

**HackPit (the host):**
- `backend/cockpit/terminal.py` — the PTY `:terminal` surface (a real pty inside the container). This is the primary upgrade target. Memory: **`:kali`'s sentinel shell must never grow a pty** — keep the two-sandbox separation.
- The **C2 session panel** (catch + drive ONE live shell; **gated START + HUMAN-ONLY stdin**) — gains named sessions + prompt-detection, keeps human-only stdin.
- `backend/cockpit/lifecycle.py` — the shared spawn+OBSERVE path (listener lifecycle); the session engine plugs into it.
- `backend/cockpit/config.py` — `KALI_OPEN_CONTAINER` / the sandbox container constant.
- Frontend: `/terminal`, `/c2`, `/cockpit/session`.

**Decepticon (port from, Apache-2.0 — attribute):**
- `packages/decepticon/decepticon/tools/bash/prompt.py` — **read it in full**: the session semantics (`bash`/`bash_output`/`bash_status`/`bash_kill`), the return-value markers (`[BACKGROUND]`, `[AUTO-BACKGROUND]`, `[TIMEOUT]`, the interactive marker), the background-job lifecycle, output management (≤15K inline / >15K to scratch / >5M watchdog), the **wedged-session recovery** + **tmux pipe-degradation detector** ladders.
- `packages/decepticon/decepticon/tools/bash/bash.py` — the implementation (tmux drive, PS1 marker detection, pipe-pane logging to `.sessions/`, ANSI stripping).

## 2. What to build — a session engine under `backend/cockpit/`

### 2a. Named persistent sessions
Named tmux sessions in the kali sandbox; per-session cwd/env/background-jobs persist across calls; a session starts in the engagement workspace. Different names = independent parallel sessions. Port the model from `bash.py`.

### 2b. Auto prompt-detection (the headline feature)
Detect when a running program is **waiting at an interactive prompt** (msfconsole `msf6 >`, `sliver >`, `evil-winrm` PS, generic REPLs) via PS1/prompt heuristics, and surface an **"interactive — awaiting input"** state. In HackPit, the **human** then sends the next line (approve-each), never the orchestrator. This is the real upgrade over today's one-shot PTY: interactive tools become first-class without workarounds.

### 2c. Background lifecycle
`background=True` + **auto-background at 60s**; PS1-marker completion detection; a completion **notification inlined once** (mirror HackPit's existing job/OBSERVE notification path); `status`/`output`/`kill` (kill preserves the session log under `.sessions/`).

### 2d. Output management + recovery
Inline ≤15K, auto-save >15K to the workspace `.scratch/` (preview + path), size watchdog >5M. Port the **wedged-session recovery** and **tmux pipe-degradation detector** (the three-condition signature) as operator-facing diagnostics/actions. ANSI stripping, repetitive-line compression.

### 2e. Frontend — `/terminal`, `/c2`, `/cockpit/session`
Named-session tabs, a **prompt-detection banner** ("interactive — send input"), a background-job tracker (running/done/consumed), per-session logs. Stdin box is the human's (approve-each on the C2 surface). `hp-tn-*`; **look at the screen**.

## 3. Tests
- `backend/test_session_engine.py` — named sessions keep independent cwd; prompt-detection flips a fixture session to "interactive"; auto-background triggers past the threshold; completion notifies once (consumed thereafter); kill preserves the log; wedge/pipe-degradation signatures are detected from fixtures.
- `backend/test_session_engine_safety.py` — **stdin is human-only**: assert no orchestrator/proposer path can send `is_input` (AST/source-scan, mirror the C2 HUMAN-ONLY-stdin test); the engine runs only in the hardcoded container; `:kali` sentinel never gets a pty; no new gate. Add to `run_safety_tests.sh`.

## 4. Acceptance criteria
- Operator opens `sliver-client`/`msfconsole`/`evil-winrm` in a named session; the UI shows "interactive — awaiting input"; the operator sends follow-up input (approve-each) and drives the tool without workarounds; long scans run `background=True` in named sessions with a completion notification.
- Containment unchanged; stdin human-only; the orchestrator cannot send input; `:kali` sentinel gets no pty; no new gate.
- `run_safety_tests.sh` green; `next build` exits 0; screen looked at; assessment + README updated (same commit). Decepticon attribution in `THIRD_PARTY_LICENSES`/NOTICE.

## 5. Assumptions (flip any)
- Primary target is the `:terminal` PTY surface + the C2 session panel; the general `bash()`-tool ergonomics are for the human operator, not an autonomous agent.
- Prompt-detection covers msf/sliver/evil-winrm/common REPLs first; extend the heuristic set later.
- Keep the two-sandbox separation intact — the session engine lives on the OPEN/terminal side, not the `:kali` sentinel side.

---

## 6. README + screenshot + assessment (do exactly like prior sessions)

**Not done until README + a real screenshot ship.** Screen route: **`/terminal`** (or `/c2` with an interactive session).
- Headless-Edge screenshot (`headless-edge-screenshots`), app running, a **synthetic/local** interactive session (never a real target's live shell in the shot):
  ```
  EDGE="/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"
  "$EDGE" --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=1 \
    --user-data-dir=<tmp-profile> --window-size=1440,950 --virtual-time-budget=8000 \
    --screenshot=out.png "http://localhost:3000/terminal"
  ```
  **View it** — named sessions + prompt-detection banner + job tracker render (not blank/error).
- Add screenshot to `assets/screenshots/`; README feature section + "at a glance" row (interactive persistent sessions + prompt-detection).
- Update `docs/ASSESSMENT-2026-07-26.md` + regen html/pdf (`python docs/build-assessment.py`) same commit (`keep-assessment-current`; verify vs html).
- **Look at the screen** (`frontend-class-vocabulary`): `hp-tn-*`, never a bare `hp-card`.
