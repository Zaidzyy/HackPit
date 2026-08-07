# Build spec — AI-agent code-audit fan-out (`codescan` upgrade)

**Status:** BUILT 2026-08-07 — `codescan/ai_audit.py` (three-stage fan-out reusing `reasoning/`), heuristic-analyst degradation + bundled sample repo, `patched-since` (injected diff provider), engagement-state sink (injected), `/code-scan` AI mode. Tests `test_ai_audit.py` + `test_ai_audit_safety.py` green in `run_safety_tests.sh` (108 files); `next build` exit 0; screenshot `assets/screenshots/38-code-scan-ai-audit.png`. **Author:** planning session, 2026-08-07.
**One line:** upgrade `codescan` from rule/semgrep-only to an **AI-agent audit** that uses open·kritt's context-saving decomposition — **map entrypoints/flows once, hand each downstream agent exactly ONE flow to verify against source, each returning a concrete vuln-with-attacker-path or a no-finding stub** — then dedup + severity-rank into engagement findings. Ports the good parts of open·kritt's engine (which the operator owns; license is a non-issue) onto HackPit's `reasoning/` specialist substrate, **human-gated**.

---

## 0. Guiding constraint (read first, do not weaken)

Adds **NO new gate.** The scan is **ONE approved job** — the ZAP-scanner / nuclei justification: one approval buys many analysis tasks (the fan-out), no new gate class. Keep it **maximally aggressive in what it hunts** (real exploitable bugs with an attacker path — RCE, authz bypass, loss-of-funds, consensus halt), maximally open otherwise. **DO NOT adopt open·kritt's autonomy model** (agents as root, disposable containers, direct internet) — that is the exact inverse of HackPit's approve-each invariant. HackPit's agents **read source and PROPOSE**; any PoC/confirmation command runs **approve-each** through the existing executor + kali sandbox. The proposer never executes.

## 1. Read-first

**HackPit (the host):**
- `backend/codescan/` — `runner.py` (rule scan today), `findings.py`, `kb_link.py`, `report.py`, `router.py`, `rules/`. You add an **AI-audit mode** alongside the rule mode.
- `backend/reasoning/` — `specialists.py`, `critic.py`, `frontier.py`, `tiering.py`, `retrieval.py`, `schema.py`, `ledger.py`. **This is the fan-out substrate** — specialists = the per-flow agents, critic = the concrete-or-stub gate, frontier = the flow queue, tiering = model selection, retrieval = KB grounding. Reuse it; don't reinvent.
- The **Workflow orchestration primitive** (the pipeline/parallel fan-out) — the code-audit run is a pipeline: enumerate → per-flow verify → dedup+rank.
- `backend/state/` (`upsert_findings`) — audit findings land here.
- `frontend/src/app/code-scan/page.tsx` — the surface to extend.

**open·kritt (port from, operator owns — steal freely):**
- `engine/open_kritt_engine/prompting.py` — `{{var}}` ref rendering, `scan_context`, **`patched_since` diff context** (audit only what changed since a ref — huge for real targets), `native_agent_skills_prompt`.
- `engine/open_kritt_engine/post_processing.py` — **dedup + `IMPACT_LEVELS` severity rank** (`BATCH_SIZE=50`), the concrete-finding extraction.
- `engine/open_kritt_engine/schema.py` — **dynamic finding output schema** + jsonschema validation (`output_schema`, `validate_payload`) → force each agent to return a structured finding-or-stub.
- `engine/open_kritt_engine/generation.py` + `harnesses.py` — the generation/agent-runner abstraction (adapt to HackPit's `backend/llm.py`, do NOT import open·kritt's Codex/Claude harness).
- `docs-site/workflows/built-in-workflows.mdx` — the two proven playbooks (`external-flow-analysis`, `Cosmos ABCI Panic Halt Review`) — ship `external-flow-analysis` as the built-in.

## 2. What to build

### 2a. The three-stage decomposition (`backend/codescan/ai_audit.py`, reusing `reasoning/`)
1. **Enumerate entrypoints** (one pass): scan the repo once for externally-reachable entrypoints + the handlers that process attacker-controlled input. Output: a list of entrypoints (context-cheap, mapped once).
2. **Trace flows** (per entrypoint): enumerate materially-different production paths — validation outcomes, authz boundaries, state changes, external calls, sensitive sinks. Output: the flow **frontier** (reuse `reasoning/frontier.py`).
3. **Verify each flow** (fan-out, one agent per flow): each downstream specialist spends its whole context on **one** flow and returns **only** a concrete vuln (title, attacker path, source refs, impact) **or a no-finding stub** — enforced by the dynamic output schema (ported `schema.py`). Reuse `reasoning/specialists.py` + `critic.py` (the critic rejects non-concrete findings).

This "map once, fan out per-flow" is the whole point — it saves context and produces attacker-path-backed findings, not repo-wide hand-waving.

### 2b. Dedup + rank (port `post_processing.py`)
Combine all agents' findings, **de-duplicate** (same bug found by multiple flows), **severity-rank** by `IMPACT_LEVELS` (critical/high/medium/low/informational), write to engagement state as `Finding`s with source refs + the attacker path.

### 2c. Aggressive extras worth stealing
- **`patched-since` mode** (port from `prompting.py`): audit only the diff since a git ref — turns a huge repo into a reviewable delta; ideal for real targets/CI.
- **PoC hand-off**: a concrete finding offers a "confirm / build PoC" action → an **approve-each** executor run in the kali sandbox (never auto-run). This is HackPit's gated answer to open·kritt's autonomous PoC building.
- **KB grounding** (`reasoning/retrieval.py`): ground each specialist in the HackPit KB (the fingerprint/CVE/methodology corpus) — an edge HackPit has that open·kritt does not.

### 2d. Frontend — extend `/code-scan`
Add an "AI audit" mode: pick target repo (remote/local) + optional `patched-since` ref + a built-in playbook → one approval → live view of entrypoints → flows → per-flow verdicts → ranked deduped findings, each with source refs + a "build PoC" (approve-each) button. `hp-tn-*`; **look at the screen**.

## 3. Tests
- `backend/test_ai_audit.py` — decomposition: enumerate → flows → per-flow agents each return schema-valid concrete-or-stub; dedup collapses duplicate findings; ranking orders by IMPACT_LEVELS; a no-finding stub is not a finding; `patched-since` restricts scope to the diff.
- `backend/test_ai_audit_safety.py` — the audit is ONE gated job (no new gate); the proposer **executes nothing** (AST — reads source + calls the LLM layer, no `subprocess` against a target); PoC/confirmation is approve-each through the executor. Add to `run_safety_tests.sh`.

## 4. Acceptance criteria
- Point `/code-scan` (AI mode) at a repo, one approval → entrypoints mapped once, flows fanned out, each agent returns a concrete vuln-with-attacker-path or a stub; results deduped + severity-ranked into engagement findings with source refs.
- `patched-since` mode audits only the diff; PoC building is approve-each in the sandbox; findings are KB-grounded.
- Proposer executes nothing; no new gate; rule-mode codescan still works.
- `run_safety_tests.sh` green; `next build` exits 0; screen looked at; assessment + README updated (same commit).

## 5. Assumptions (flip any)
- Reuse `reasoning/` (specialists/critic/frontier/tiering/retrieval) as the fan-out engine rather than a new one — if it doesn't fit cleanly, build a thin `codescan/ai_audit` engine but say so in the PR.
- Ship the `external-flow-analysis` playbook as the built-in; the web3 playbooks come in the web3 spec.
- Agent runs use HackPit's `backend/llm.py` (Codex-login/OpenAI/Anthropic/OpenRouter as HackPit already supports), NOT open·kritt's harness.

---

## 6. README + screenshot + assessment (do exactly like prior sessions)

**Not done until README + a real screenshot ship.** Screen route: **`/code-scan`** (AI mode).
- Headless-Edge screenshot (`headless-edge-screenshots`), app running, on a **synthetic/local sample repo** (never a real client's private source in the shot):
  ```
  EDGE="/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"
  "$EDGE" --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=1 \
    --user-data-dir=<tmp-profile> --window-size=1440,950 --virtual-time-budget=8000 \
    --screenshot=out.png "http://localhost:3000/code-scan"
  ```
  **View it** — entrypoints/flows/ranked findings render (not blank/error).
- Add screenshot to `assets/screenshots/`; README feature section + "at a glance" row (AI code-audit fan-out).
- Update `docs/ASSESSMENT-2026-07-26.md` + regen html/pdf (`python docs/build-assessment.py`) same commit (`keep-assessment-current`; verify vs html).
- **Look at the screen** (`frontend-class-vocabulary`): `hp-tn-*`, never a bare `hp-card`.
