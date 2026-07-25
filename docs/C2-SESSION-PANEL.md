# C2 session panel — catch and drive one live shell

The one C2 slice worth having: a **persistent interactive session** you drive by hand
from the cockpit. Start a listener, catch a reverse shell that stays alive, stream its
output, and type into it over time.

This is **not** a C2 subsystem. There is deliberately no beacon management, no
multi-implant dashboard, no pivoting and no lateral automation — just **one** live
session, driven by a human, one keystroke line at a time.

- Backend: `backend/cockpit/session.py` (the manager) + routes in `backend/cockpit/router.py`
- Frontend: `frontend/src/components/CockpitSession.tsx` at `/cockpit/session`
- Tests: `backend/test_session.py` (18 tests, in `run_safety_tests.sh`)

---

## The safety model (this is the whole review)

A live interactive shell cannot be approved keystroke-by-keystroke, so the gates land in
**two** places and **both** must hold.

### 1. STARTING a session is a GATED COMMAND

`session.start()` calls the **real** `executor.validate_request()` — not a copy — so a
session-start clears exactly the gates a one-shot command clears, in the same order:

| mode | gate order |
|------|-----------|
| **lab** | target-lock → approval → heuristic danger → **isolation** |
| **engagement** | engagement → target-lock (program scope) → approval → heuristic danger |

A listener/handler (`nc`/`ncat`/`socat`, a `python`/`perl`/`ruby` interpreter, an
exploitation framework) trips `dangerous_command_heuristic`, so starting one additionally
requires an explicit `dangerous_ack`. In the UI that surfaces as a **red confirm**: the
first click sends `dangerous_ack=false`, the backend refuses with the heuristic's reasons,
and the panel shows those reasons behind an "I understand — start it" button that re-sends
with the ack. You cannot start a shell-catcher without reading why it was flagged.

Session-start is **not a new capability** — it is a command that happens to be
long-lived, and it buys no bypass of anything.

**The declared bind target.** A listener has no target by definition (`nc -lvnp 4444` has
no host-shaped token), so a start request carries an explicit `target` and the gate runs
over `args + [target]`. This is strictly **more** strict than gating `args` alone: the
extra token can only satisfy "a target was named" or add heuristic reasons — it can never
mask a bad host sitting in the real args, which are still scanned and still rejected
(`test_start_is_target_locked`). The argv that actually runs is `command + args` (the
target is **not** appended), and the UI header shows this gate-validated target, so what
you see bound is what passed the gate.

### 2. A LIVE SESSION'S STDIN is HUMAN-ONLY (the load-bearing invariant)

`session.write_stdin()` is the **only** way to reach a running process's stdin, and it is
reachable **only** from the HTTP route in `router.py` that a human's UI action drives. The
orchestrator / agent / loop has **zero** code path to it — the same rule as `:kali`.

Why it matters: a live session is an **already-approved, already-running** process. Anything
able to type into it would be executing **un-gated** commands — exactly the autonomy the
approve-each model exists to prevent. So a live session must never become an un-gated
execution channel for autonomy.

The loop **may propose** starting a session — that is just a command a human approves,
which needs **no new code** at all. It can **never** type into a live one.

This is regression-locked by a source scan (`test_session_stdin_is_human_only`) over
`backend/*.py` + `cockpit/*.py` + `adgraph/*.py`, mirroring the agent-zero-`:kali` test.
The allowlist is `{cockpit/session.py, cockpit/router.py}` and is matched by **relative
path**, not filename, so `adgraph/router.py` is not accidentally allowed alongside
`cockpit/router.py`. Both are tamper-tested: wiring `write_stdin` into either
`orchestrator.py` or `adgraph/router.py` makes the test fail.

> Note: teardown is registered with `atexit` **inside** `session.py` rather than called
> from `main.py`. `main.py` hosts the orchestrator-loop endpoint, so importing the session
> module there would force the human-only source scan to whitelist it. Keeping teardown
> self-contained keeps that allowlist minimal.

### Containment = the mode the session started in

The session module adds **no reach** and removes none. The container comes from
`executor.resolve_mode()` — the **same** mapping one-shot runs use, extracted so a
long-lived session can never bind to a different sandbox than a one-shot command would:

- **lab** → `hackpit-kali-sandbox` (isolated, egress-less; the isolation gate is asserted
  at start)
- **engagement** → `hackpit-engage-sandbox` (fully open; scope-lock + approve-each are the
  bound, no isolation floor)

There is no `container`/`sandbox` field on the start request — nothing in the request can
redirect the exec (mirrors `:kali` containment rule #1). Execution is **argv-only**
(`docker exec -i <container> <command> <args…>`); `session.py` never builds a `sh -c`
invocation.

---

## Lifecycle + bidirectional mechanism

```
start ──▶ active ──▶ exited      (the process ended on its own)
              └────▶ killed      (operator hit KILL, idle timeout, max lifetime, or shutdown)
```

- **Process**: `docker exec -i <container> <command> <args…>` with `stdin=PIPE`,
  `stdout`/`stderr` piped. `-i` keeps stdin open (the whole feature). **No `-t`** — no PTY,
  so line-oriented shells and listeners work, full-screen curses programs do not, and the
  transcript stays readable in the report.
- **Output** streams over **SSE** (`GET /cockpit/session/{sid}/stream`), cursor-based
  (`?after=<seq>`) so a reconnect replays the rolling tail instead of losing it. Two reader
  threads pump stdout/stderr into a bounded event deque (live view) plus a capped transcript
  (the record).
- **Input** is a **separate** authenticated POST (`/cockpit/session/{sid}/stdin`). Keeping
  stdin on its own endpoint — not multiplexed onto a websocket — is deliberate: that seam is
  exactly what the human-only invariant locks down.
- **Bounds**: idle timeout (15 min), max lifetime (4 h), max concurrent sessions (8), a
  per-write stdin cap (8 KB), a rolling live buffer (4000 events) and a full-transcript cap
  (200 000 chars, matching `:kali`). A background reaper enforces the timeouts; `atexit`
  teardown kills every live session so a caught shell is never left running.

Two ids, kept distinct: **`sid`** identifies the live session; **`session_id`** keeps its
repo-wide meaning — the engagement the transcript is recorded against.

### Endpoints

| method | path | purpose |
|--------|------|---------|
| `GET`  | `/cockpit/session/status` | live count + bounds (panel header) |
| `GET`  | `/cockpit/session` | list sessions (live + finished) |
| `POST` | `/cockpit/session/start` | **gated** start; 403 names the failing gate |
| `GET`  | `/cockpit/session/{sid}/stream` | SSE output; read-only |
| `POST` | `/cockpit/session/{sid}/stdin` | **HUMAN-ONLY** write one line |
| `POST` | `/cockpit/session/{sid}/kill` | terminate + flush transcript |

---

## The mode-binding UI

The panel (`/cockpit/session`) reuses the existing terminal chrome. It always states, in
two places, which box you are driving so it is **never ambiguous** whether the shell is in
the isolated lab or on a real engagement target:

- a banner — **green** for the isolated lab, deliberately **red** for a real-target
  engagement (a live shell on a real host must never render as a safe/green state)
- the terminal title bar and the input prompt, both prefixed with the mode and target

The input line is the **only** caller of `writeSessionStdin`, fires on a human keypress,
and is documented as such in both the component and the API client so the frontend stays
honest to the backend's human-only lock.

---

## Recording

The session is persisted as a `RunRecord` (`command = "session"`, `args` = the argv that
started it, `mode` = lab|engagement, `target` = the bound target). It is written at start
and re-saved on every write/flush/kill via `INSERT OR REPLACE`, so a crash mid-session
still leaves the transcript-so-far on disk. The transcript interleaves output (verbatim)
with the operator's typed lines (marked `$ `).

It flows into the report's evidence section (`report.py`) with no new plumbing, and is
called out honestly there:

- header says **"interactive session"** and keeps the lab vs **REAL-TARGET ENGAGEMENT**
  tag, so a real-target session is never blurred with lab evidence
- the internal `session` marker is dropped from the command line — the reader sees the
  actual listener command that was approved
- the block is labelled a transcript and states that `$ `-prefixed lines are what the
  operator typed, everything else is what the session returned

(The `"session"` marker is a **literal** in `report.py`, not an import from
`cockpit.session` — importing it there would break the module's human-only source-scan
lock, and the report has no business reaching the session module.)

---

## Verification

- **C1–C5** committed incrementally, each verified. Full hermetic safety suite green
  (`sh backend/run_safety_tests.sh` — 12 suites including the new live-session suite);
  frontend `tsc` exit 0, `eslint` at the documented baseline (10 errors + 1 warning,
  unchanged), `next build` exit 0 with `/cockpit/session` prerendered.
- **C6 — LAB e2e (supervised).** Through the real HTTP API and again through the browser
  panel: started `python3 /opt/listen.py` (a minimal listener; the sandbox image ships no
  `nc`/`socat`) in the isolated `hackpit-kali-sandbox` — refused unapproved, refused
  without the danger ack, refused an off-lab target, then started once approved + acked. A
  **node reverse shell** from `hackpit-lab-target` (a distroless image — no shell, so a
  node one-liner) connected back over the isolated network; typed commands streamed their
  output; KILL ended it; the full transcript was recorded against the engagement and
  rendered in the report tagged as a lab interactive session.

**ENGAGEMENT (real-target) session e2e is DEFERRED** to a human-present session — it is not
auto-run. The engagement path is unit-covered (`test_engagement_session_*`): scope-locked
to the engagement sandbox, out-of-scope refused, approve-each + red-confirm enforced, no
isolation floor.
