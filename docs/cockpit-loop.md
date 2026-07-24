# Cockpit — the orchestrator loop (design)

The guided agent loop: the composer's plan is **driven step-by-step** — the agent
proposes the next command, **the human approves it**, it runs through the M1 executor,
the result feeds back, the agent adapts and proposes the next. This is the "watch it
think" core.

This is the milestone where autonomy enters, so the human-in-the-loop gate is the whole
safety story. Read that section first.

## What this IS / IS NOT

**IS:** agent PROPOSES → human APPROVES each command → M1 executor runs it → result feeds
back → agent proposes the next. Recon-only, on the **isolated** lab (`hackpit-kali-sandbox`),
reusing M1's executor + all four gates. The human is in the loop on **every** command.

**IS NOT:** hands-off autonomy (never auto-run), real targets, egress, or the `:kali`
open sandbox. Those are a later milestone. `:kali` is not touched and the agent has **no
path** to it (already test-locked; kept that way).

## State machine

```
        ┌─────────── stop ───────────────────────────────┐
        │                                                 ▼
   ┌────────┐  propose   ┌───────────┐  approve   ┌──────────┐  exit   ┌──────────┐
   │  idle  │──────────▶ │ proposing │──────────▶ │ awaiting │───────▶ │executing │──┐
   └────────┘            └───────────┘            │ approval │         └──────────┘  │
        ▲                     ▲   ▲               └──────────┘              capture   │
        │                     │   │ skip / edit        │                     │        │
        │                     │   └────────────────────┘                     ▼        │
        │                     │                                        ┌──────────┐   │
        │                     └──────── feed back (re-propose) ────────│ captured │◀──┘
        │                                                              └──────────┘
        └──────────── stop (any state) → report ──────────────────────────┘
```

- **idle** — a plan (session) exists; loop not started.
- **proposing** — backend is asked for the next single command (no execution).
- **awaiting-approval** — proposal shown; **the loop does nothing until the human acts.**
  This is the pause point that makes every command human-approved.
- **executing** — an *approved* command streams through the M1 executor (4 gates).
- **captured** — run recorded to the engagement; result available to feed back.
- back to **proposing** with the updated results, or **stop → report**.

There is **no** transition from `proposing` straight to `executing`. Execution is only ever
reachable through `awaiting-approval` + an explicit human approve.

## Human control points (at `awaiting-approval`)

| control | effect |
|---------|--------|
| **approve** | run the proposed command as-is, through the M1 executor |
| **edit** | change the args, then approve — the executor still re-gates the edited command |
| **skip** | discard this proposal; re-propose a *different* next step (passes the skipped command in `avoid`) |
| **pause** | stop asking for proposals; the loop idles, nothing runs |
| **stop** | end the loop → offer the report over what actually ran |

Reject == skip. Nothing auto-advances: after each run the loop returns to
`awaiting-approval` for the *next* proposal.

## How prior results feed back

State lives entirely in the **existing engagement/run store** — no new state store:

- The **plan** is the saved session's composed path (`sessions.db` → `path_json`), which
  seeds and grounds every proposal.
- The **results-so-far** are the recorded cockpit runs for the session
  (`cockpit_runs` via `runstore.list_runs_for_session`) — each is a real command + its
  captured stdout/stderr + exit code.

`propose` reads both, builds a prompt (plan steps + the allowlist + the lab target + the
runs-so-far), and asks the LLM for the **single next** recon command as JSON
`{command, args, rationale, step_id, done}`. Because propose reads the run store fresh each
call, feed-back is automatic: running a command (which records it) changes the next proposal.

## Safety gates (non-negotiable — where autonomy enters)

1. **Human approves EVERY command.** The loop *pauses* at `awaiting-approval` and does
   nothing until the human approves. No batching, no auto-run, no "approve all". Skip / stop
   are always available. The agent **proposes**; it never runs anything itself.
2. **Recon-only + lab-locked + isolated.** Execution goes through M1's existing executor
   **unchanged** — allowlist (recon: nmap/curl/whatweb) → target-lock (lab) → approval →
   isolation gate. The frozen-allowlist test stays green. The proposer is *told* to stay
   recon/lab, but the **executor's four gates are the enforcement** — a proposal that strays
   is rejected at run time (403), never silently run. `propose` also pre-checks each proposal
   against the allowlist + target-lock and flags a non-conforming one so the human sees it can't run.
3. **The agent has NO path to `:kali` and NO path to real targets / egress.** The orchestrator
   calls only the LLM (to propose) and the M1 executor (to run against the isolated lab).
   It never imports the `:kali` shell. Grep-confirmed + test-locked; the human-only `:kali`
   test stays green.

## Reuse (no new execution path, no new state store)

- **Composer** (`attack_path.compose`) — already produces the plan; the loop runs over a saved session.
- **Executor** (`POST /cockpit/exec`, `cockpit/executor.py`) — the loop's "execute" is this
  M1 endpoint **unchanged**: `{command, args, approved: true, session_id, step_id}`, streamed,
  gated, recorded. The loop adds **no** new way to run anything.
- **Engagement / run store** (`sessions.py`, `cockpit/runstore.py`) — plan + runs = the loop's
  entire state and its feedback channel.
- **Report** (`report.compose_report`, `POST /sessions/{id}/report`) — at loop end, the recorded
  run sequence is the report's authoritative evidence (already wired via `session_id`).

## New surface (deliberately minimal)

Only **one** new backend endpoint — the proposer, which **does not execute**:

- `POST /sessions/{session_id}/loop/propose` → `{done, proposal?: {command, args, rationale,
  step_id?, gate_ok, gate_reason}, reason?}`. Pure suggestion + a read of the run store.

Everything else (execute, record, report) is the existing M1/M3 surface. The frontend
orchestrator drives the state machine: `propose → show → (human) approve → /cockpit/exec
(stream) → re-propose | stop → report`, animating the kill-chain map as steps complete.

## Increments

- **L1** — `propose` endpoint (no execution).
- **L2** — the loop, human-gated: propose → approve → M1 executor → capture → feed back → next.
- **L3** — cinematic UI: reasoning + proposed command + APPROVE/skip/stop, streamed output,
  kill-chain map animating phase-by-phase.
- **L4** — report over the recorded run sequence (reuse M3).
- **L5** — end-to-end on the lab, screenshots per stage.
