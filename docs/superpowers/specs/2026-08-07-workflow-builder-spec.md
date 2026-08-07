# Build spec — Reusable prompt-workflow builder

**Status:** ready to execute in a fresh session. **Author:** planning session, 2026-08-07.
**One line:** port open·kritt's **workflow builder** (which the operator owns) — a surface to compose, edit, import/export, and run **reusable prompt-step playbooks** with variables, batches, and depth/sibling fan-out — so operators author their own research playbooks on top of the AI code-audit engine instead of only using the built-ins.

**Best built AFTER** `2026-08-07-ai-codeaudit-fanout-spec.md` — this is the authoring UI over that engine. It is the **most product-polish / optional** of the Kritt-derived specs; A ships usable built-ins without it.

---

## 0. Guiding constraint (read first, do not weaken)

Adds **NO new gate.** Running a workflow is ONE approved job (the fan-out justification); authoring/editing a workflow executes nothing. Keep it **maximally open** — a workflow can chain aggressive research steps — but every step that runs a command is **approve-each** via the executor + kali sandbox, and imported third-party workflows are **inspected before running** (surface the prompt text; never auto-run an imported workflow). No autonomy.

## 1. Read-first

**HackPit (the host):**
- `2026-08-07-ai-codeaudit-fanout-spec.md` — the engine a workflow drives (enumerate → per-flow agent → concrete-or-stub, dedup+rank). Read it first.
- `backend/reasoning/` + the Workflow orchestration primitive — the fan-out/pipeline the steps compile to.
- `backend/state/` — findings a workflow produces.
- Memory: **cockpit/arsenal decoupling**; `frontend-class-vocabulary` (hp-tn-*).

**open·kritt (port from, operator owns — steal freely):**
- `backend/src/routes/workflows.js` + `steps.js` + `workflowLocks.js` — the workflow/step CRUD + concurrency locks.
- `backend/src/lib/defaultWorkflows.js` + `defaultWorkflowSeeds.json` — seeded workflows.
- `engine/open_kritt_engine/prompting.py` — `{{var}}` ref rendering, `resolve_ref` (dotted paths), `render_prompt`, the variable/context model.
- `docs-site/workflows/*` — the exact semantics to reproduce: `steps.mdx`, `batches.mdx`, `depth-and-siblings.mdx`, `prompt-variables.mdx`, `built-in-variables.mdx`, `extra-variable.mdx`, `import-and-export.mdx`, `prompt-editor.mdx`.

## 2. What to build

### 2a. Workflow + step model (`backend/codescan/workflows.py` + routes)
A **workflow** = an ordered set of **steps**; each step = a focused prompt + an **output schema** (the dynamic finding schema from the finding-pipeline spec) + fan-out controls:
- **Variables** (`{{var}}`): built-in (repo, ref, entrypoint, flow, prior-step output via dotted refs) + operator-defined + per-run "extra" variables. Port `resolve_ref`/`render_prompt`.
- **Batches**: a step that fans out over a list (one agent per item) — the map-once/verify-each primitive generalized.
- **Depth & siblings**: how a step's outputs spawn child steps (depth) and how many parallel branches (siblings) — the fan-out shape controls.
- **Import/export**: serialize a workflow to a portable JSON and load one back (inspect-before-run).

### 2b. Runner
Compile a workflow to the fan-out engine: each step renders its prompt with resolved variables, runs (single or batched) through `reasoning/`/the Workflow primitive, validates output against the step schema, and passes outputs as variables to downstream steps. One approval per run; command steps are approve-each; dedup+rank the final findings (finding-pipeline spec).

### 2c. Frontend — `/workflows`
A builder: list/create/edit workflows, a **prompt editor** per step (variable autocomplete, output-schema editor), fan-out controls (batch/depth/siblings), import/export, and a "run scan" that hands off to `/code-scan`. Ship the seeded built-ins visible on first load. `hp-tn-*`; **look at the screen**.

## 3. Tests
- `backend/test_workflows.py` — variable resolution (`{{repo}}`, dotted `{{step1.output.x}}`, extra vars); a batch step fans out one task per item; depth/siblings produce the right child-step shape; import→export round-trips a workflow; a step's output validates against its schema.
- Safety: authoring executes nothing; a run is one gated job; command steps are approve-each; imported workflows are not auto-run. Add to `run_safety_tests.sh`.

## 4. Acceptance criteria
- Operator composes a multi-step workflow with variables + a batch fan-out in `/workflows`, exports it, re-imports it, and runs it (one approval) → the engine executes the steps, passes variables downstream, and produces deduped/ranked findings.
- The two built-ins (external-flow + a web3 one) are visible and runnable.
- Authoring executes nothing; runs are gated; imports inspect-before-run; no new gate.
- `run_safety_tests.sh` green; `next build` exits 0; screen looked at; assessment + README updated (same commit).

## 5. Assumptions (flip any)
- Depends on the code-audit-fanout engine (A) and pairs with the finding-pipeline schema (D). If run before D, use a fixed finding shape and note it.
- This is the optional/product-polish Kritt spec — if deprioritized, A's built-ins still deliver the core value.
- Reproduce open·kritt's step/batch/depth-sibling/variable semantics faithfully (they're proven); adapt storage to HackPit's stack.

---

## 6. README + screenshot + assessment (do exactly like prior sessions)

**Not done until README + a real screenshot ship.** Screen route: **`/workflows`**.
- Headless-Edge screenshot (`headless-edge-screenshots`), app running, **synthetic** workflow:
  ```
  EDGE="/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"
  "$EDGE" --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=1 \
    --user-data-dir=<tmp-profile> --window-size=1440,950 --virtual-time-budget=8000 \
    --screenshot=out.png "http://localhost:3000/workflows"
  ```
  **View it** — the builder + steps + fan-out controls render (not blank/error).
- Add screenshot to `assets/screenshots/`; README feature section + "at a glance" row (reusable workflow builder).
- Update `docs/ASSESSMENT-2026-07-26.md` + regen html/pdf same commit (`keep-assessment-current`; verify vs html).
- **Look at the screen** (`frontend-class-vocabulary`): `hp-tn-*`, never a bare `hp-card`.
