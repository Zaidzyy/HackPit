# Cockpit live chat — talk to the loop, and the loop talks back

**Date:** 2026-08-15
**Status:** built
**Surface:** cockpit guided loop (`/cockpit`), engagement + lab modes

## Problem

The guided loop proposes → human approves, one command at a time. The only way the
operator could give the loop new information mid-run was the **ask-the-operator** card
(`kind:"ask"`) — a blocking request for a specific value (a session cookie, a 2FA code).
There was no way to:

- **talk to the loop** freely while it works ("forget Glassdoor, focus on Fishbowl IDOR"), or
- have the loop **talk back** on its own — think out loud, or raise a doubt it isn't blocked on.

The engagement **assistant chat** (`chat.py`, `POST /sessions/{id}/chat`,
`EngagementAssistant.tsx`) already existed, but (a) it lived on the attack-path screen, not
next to the cockpit loop; (b) it was grounded only on the attack-path session, not the loop's
live `state.store`; and (c) it was a side Q&A — nothing the operator typed influenced what the
loop proposed.

## Design (Option 3 + 1: two-way chat + non-blocking notes)

One shared transcript per session; **two writers** (operator + loop), and it **feeds the loop**.

### Steering (operator → loop)
`orchestrator.build_user_prompt` gains a `CONVERSATION WITH THE OPERATOR` block
(`_conversation_reference`, last 6 turns), placed just under the authoritative ask-answers.
A direct instruction there is treated as authoritative, so a chat message changes the *next*
proposal. Read-only and guarded — a chat-store hiccup yields no block, never a broken loop.

### Notes (loop → operator, non-blocking)
The propose response may carry an optional top-level `"note"` (see `_NOTE_CONTRACT`), distinct
from `rationale` (which stays on the approval card). `propose_next` attaches it to the returned
proposal (command **or** ask). It rides the existing propose turn — **no extra model call**.

### One transcript
`sessions.append_agent_note` persists a note as a single `{role:"assistant", kind:"note"}`
turn (no paired user turn). The `/loop/propose` endpoint persists any note best-effort after
the proposal — persisting a *string*, so the loop/propose safety surface stays inert. Notes
flow back into the next prompt via `_conversation_reference`, so the loop sees its own remarks.

### Loop-state grounding (chat answers about the loop)
`chat.build_loop_state_block` renders the loop's live `state.store` summary (counts, recent
findings, sampled endpoints); `chat.answer(..., loop_state=...)` folds it into the prompt, and
`session_chat` passes `state_store.load(session_id)`. Duck-typed + guarded: a None/empty state
contributes nothing. Now the assistant can answer "why is the loop stuck?" about the loop.

### Frontend
`EngagementAssistant` (the existing drawer) is mounted at `CockpitView` level so it sits beside
the loop in both engagement and lab modes, seeded from `getSession().chat_history`. A
`noteSignal` prop (a `{note, ts}` pulse) appends a distinct **agent note** bubble and opens the
drawer when the loop leaves a note; `CockpitLoop.onAgentNote` fires it, forwarded through
`CockpitEngagementMode`. New-effect `setState` sites carry pinned `eslint-disable` (baseline 11).

## Invariants

- **Chat executes nothing.** The pane has no run path; steering only changes what is
  *proposed*. Every command is still human-approved through the existing four gates. No new
  execution surface — `test_sliver_safety` / `test_obfuscation_safety` / `test_engagement_mode`
  (NO AUTONOMY on real targets) all still pass.
- **Deterministic KB citations** and the never-break guards are preserved.

## Tests

`backend/test_loop.py`: `test_note_and_chat_steering` (note rides any proposal; operator chat +
loop notes reach the next prompt), `test_chat_grounds_on_live_loop_state`. Frontend: tsc 0,
build 0, lint at the 11 baseline.

## Files

`backend/`: `orchestrator.py`, `chat.py`, `sessions.py`, `main.py`, `test_loop.py`.
`frontend/src/`: `lib/api.ts`, `components/{CockpitView,CockpitEngagementMode,CockpitLoop,EngagementAssistant}.tsx`, `app/globals.css`.
