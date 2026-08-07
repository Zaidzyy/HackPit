# Build spec — Formal engagement-governance: RoE / ConOps / Deconfliction / OPPLAN

**Status:** ready to execute in a fresh session. **Author:** planning session, 2026-08-07.
**One line:** before an engagement goes live, generate + persist a **formal governance package** — **Rules of Engagement, Concept of Operations, Deconfliction Plan, and an OPPLAN** (objectives with a status state machine + **MITRE ATT&CK** mapping + OPSEC level) — and make the RoE the formal, referenceable frame the human-gate approves against. Ported from Decepticon (`tools/opplan.py`, `tools/defense/conops.py`, `middleware/roe.py`, `tools/references/killchain.yaml`; Apache-2.0 — keep attribution in `THIRD_PARTY_LICENSES`/NOTICE). This is HackPit's single most on-brand addition: it turns "human approves each command" into "human approves each command *inside a written, agreed operating frame*."

---

## 0. Guiding constraint (read first, do not weaken)

Adds **NO new gate.** Per-command human approval stays THE bound. The governance package is **authored + human-approved documentation + a formalized scope frame** — it **executes nothing** and it does not become a second automated gate. It **tightens the existing scope-lock from a "handrail" into a written RoE the operator signs off**, but the RoE is advisory-to-the-human, not a machine veto (consistent with the standing model: human approval is the actual bound). Generation is **propose-only** — the model drafts RoE/ConOps/Deconfliction/OPPLAN from the scope + target; the human edits and approves before the engagement is "live." Maximally open otherwise.

## 1. Read-first

**HackPit (the host):**
- `backend/state/` — the engagement state model (upsert-only, executes-nothing, loot ingest). The governance docs persist here as engagement-scoped records.
- The **scope model** (wildcards/CIDR/exclusions, the target-lock handrail) — the RoE formalizes and references it; do NOT replace it.
- `backend/main.py` — cross-cutting wiring (cockpit/arsenal decoupling).
- The cockpit **orchestrator loop** — objectives become the thing the orchestrator proposes *toward* (targeting), each step still human-approved.
- The engagement frontend (`/engagements`, `/engagement/[id]`, the report surface) — add governance tabs.
- Existing **MITRE ATT&CK** touchpoints (persistence TA0003 KB, detection describe-side, arsenal technique tags) — reuse for the OPPLAN mapping.

**Decepticon (port from, Apache-2.0 — attribute):**
- `packages/decepticon/decepticon/tools/opplan.py` — **`OPPLAN`, `Objective`, `ObjectivePhase`, `ObjectiveStatus`, `C2Tier`, `OpsecLevel`**, the objective **status state machine** (`_VALID_TRANSITIONS`: pending→in-progress→completed/blocked/cancelled), versioned JSON persistence + summary. Port the data model + state machine wholesale.
- `packages/decepticon/decepticon/tools/defense/conops.py` — the ConOps generator.
- `packages/decepticon/decepticon/middleware/roe.py` — RoE structure + how it frames actions.
- `packages/decepticon/decepticon/tools/references/killchain.yaml` — the ATT&CK kill-chain reference for objective mapping.
- `docs/engagement-workflow.md` (Decepticon) — the RoE→ConOps→Deconfliction→OPPLAN flow.

## 2. What to build — `backend/state/governance.py` (+ generation, + routes)

### 2a. The four documents (data model + persistence)
- **RoE (Rules of Engagement)**: authorized scope (reference the scope model), authorized/forbidden techniques, OPSEC level, time windows, excluded targets/actions, sensitive-data handling, stop conditions, emergency contacts. Persist as a versioned, engagement-scoped record.
- **ConOps (Concept of Operations)**: the high-level approach + phases (recon → exploit → post-ex → objectives), success criteria.
- **Deconfliction Plan**: how this engagement's traffic is distinguished from a real incident — source markers, notification contacts, a per-engagement signature/tag, blue-team coordination notes.
- **OPPLAN**: a list of **`Objective`s**, each with `phase`, `status` (the ported state machine), **MITRE ATT&CK** technique id(s), OPSEC level, optional C2 tier, and notes. Versioned JSON + a summary block (total/completed/in-progress/blocked/cancelled). Port `opplan.py`'s payload builder + transition validation.

### 2b. Generation (propose-only)
An LLM-assisted drafter (`backend/llm.py`) that, from the scope + target profile, **drafts** all four docs → the human edits/approves. Nothing is "live" until approved. The drafter executes nothing.

### 2c. Objectives drive targeting
The cockpit orchestrator proposes steps **toward an active objective** and can `update_objective` status as an approved step completes (exit-0, human-approved) — reuse the graph/orchestrator `advance` evidence pattern. Objectives are the engagement's backbone; findings link to the objective they advanced.

### 2d. MITRE ATT&CK coverage
Map objectives (and, opportunistically, findings) to ATT&CK techniques; render a coverage view (which tactics/techniques the engagement exercised) — a professional deliverable and a report input.

### 2e. Routes + frontend
Routes in `main.py`: draft/get/update each doc, objective CRUD (mirror `opplan.py`'s tool set: add/update/get/list/expand/collapse/load). Frontend: `/engagement/[id]` gains **RoE / ConOps / Deconfliction / OPPLAN** tabs, an **objectives board** (status columns), and an **ATT&CK coverage** view. Feed the governance docs into the existing report. `hp-tn-*`; **look at the screen**.

## 3. Tests
- `backend/test_governance.py` — the OPPLAN state machine rejects invalid transitions (completed is terminal, etc.); versioned JSON round-trips; RoE references the live scope (an out-of-RoE target is flagged in the UI, not machine-blocked — human-gate stays the bound); objective→ATT&CK mapping renders coverage; the drafter executes nothing.
- Safety: governance adds **no new gate**; generation is propose-only; the module executes nothing (AST). Add to `run_safety_tests.sh`.

## 4. Acceptance criteria
- Starting an engagement, the operator drafts (LLM-assisted) and approves RoE + ConOps + Deconfliction + OPPLAN; objectives carry status + ATT&CK ids; the orchestrator proposes toward active objectives; an ATT&CK coverage view + the docs flow into the report.
- The RoE formalizes (does not replace) the scope handrail; human approval remains THE bound; governance executes nothing; no new gate.
- `run_safety_tests.sh` green; `next build` exits 0; screen looked at; assessment + README updated (same commit). Decepticon attribution recorded in `THIRD_PARTY_LICENSES`/NOTICE.

## 5. Assumptions (flip any)
- Ship **OPPLAN (objectives + state machine + ATT&CK)** first — it's the backbone and the most reusable; then RoE, ConOps, Deconfliction as the framing docs. Say so in the PR if only some land.
- The RoE is a written frame the human approves against, NOT a machine veto (matches the standing "target lock is a handrail" decision).
- Objectives integrate with the existing orchestrator/graph `advance` evidence model, not a parallel one.

---

## 6. README + screenshot + assessment (do exactly like prior sessions)

**Not done until README + a real screenshot ship.** Screen route: **`/engagement/[id]`** (governance tabs / objectives board).
- Headless-Edge screenshot (`headless-edge-screenshots`), app running, **synthetic** engagement (no real client/scope in the shot):
  ```
  EDGE="/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"
  "$EDGE" --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=1 \
    --user-data-dir=<tmp-profile> --window-size=1440,950 --virtual-time-budget=8000 \
    --screenshot=out.png "http://localhost:3000/engagement/<demo>"
  ```
  **View it** — RoE/OPPLAN tabs + objectives board + ATT&CK coverage render (not blank/error).
- Add screenshot to `assets/screenshots/`; README feature section + "at a glance" row (engagement governance: RoE/ConOps/Deconfliction/OPPLAN + ATT&CK).
- Update `docs/ASSESSMENT-2026-07-26.md` + regen html/pdf (`python docs/build-assessment.py`) same commit (`keep-assessment-current`; verify vs html).
- **Look at the screen** (`frontend-class-vocabulary`): `hp-tn-*`, never a bare `hp-card`.
