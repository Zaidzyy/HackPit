# Dual-candidate commands ("second opinion") + home model picker — design

**Date:** 2026-08-09
**Status:** approved (design), pending implementation plan
**Scope:** two folded-together features that both concern *how the AI's command output is presented and which model produces it*.

---

## 0. Motivation

HackPit's grounding invariant — *"commands come from the KB, never invented by the model; anything the AI adds is badged `AI-SUGGESTED · VERIFY`"* — is enforced in code today: a grounded step emits only an `entry_id` and the system attaches the KB entry's command **verbatim**; the model never authors a trusted command.

This design adds an **operator-requested second opinion** on top of that invariant, without weakening it: for any generated command, the operator can ask for **one** alternative candidate plus a plain-language **which-is-better verdict**. The AI decides whether that alternative is *a different technique* or *a tuned form of the same command* (curated, one per request). The primary is never touched; the alternative is always badged by kind; the verdict is advisory prose only.

Folded in: a **home-screen model dropdown**, because "which model produced this" is the same concern — every generated candidate (primary *and* alternative) is composed by the single global model, and the operator should be able to switch it from the launcher.

---

## Feature 1 — dual-candidate commands

### 1.1 Shared engine — `backend/alternatives.py`

One new module. **Read-only, executes nothing** (AST safety test, mirroring `cockpit/proposals.py` and the graph orchestrators). Lives at `backend/` level — *not* inside any graph package — so the cockpit/graph decoupling rule holds; `main.py` wires it to each surface and passes that surface's **own** KB search + grounder in (never bypassing a surface's grounder).

```
best_alternative(primary, context) -> {"alternative": Alternative | None, "verdict": Verdict}
```

- Consumes the **global `/llm-config`** (`llm.load_config()` → `cfg`), exactly as `attack_path` does. The second opinion is composed by whatever model the operator has selected.
- The AI picks **technique-vs-tuned** each call (curates a single best alternative — the chosen "Option 3").
- Returns **data only** — no approval/gate field, ever.

### 1.2 Common data shapes (identical on all 5 surfaces)

```python
class Alternative(BaseModel):
    kind: str            # "grounded" | "ai_suggested"
    entry_id: str = ""   # set + REAL when grounded; "" otherwise. Never invented.
    entry_title: str = ""
    title: str
    commands: list[PlannedCommand]   # reuses the existing per-command shape
                                     #  (lang, cmd, unverified, scope fields)

class Verdict(BaseModel):
    recommendation: str  # "primary" | "alternative" | "situational"
    summary: str         # the which-&-why prose
    factors: list[str] = []   # optional tradeoff bullets: stealth / speed / WAF / destructive
    model_used: str
    provider: str
```

- **grounded** alternative = a *real second KB entry*, its command used **verbatim** (target-substituted, scope-checked). If the engine cannot resolve a servable entry that actually carries commands, it **demotes to `ai_suggested`** or returns `None` — it never fabricates an `entry_id`.
- **ai_suggested** alternative = the AI's own tuned command, **capped** (reuse the `_AI_STEPS_PER_PHASE` / `_ai_commands` caps discipline from `attack_path`), marked `unverified`.
- **Both kinds run through the same scope check** as primaries (reuse the existing per-command scope machinery).

### 1.3 Per-surface integration (5 on-demand endpoints, all wired in `main.py`)

| Surface | Endpoint (POST) | Primary source | New fields |
|---|---|---|---|
| Attack-path | `/plan/alternative` | grounded step (verbatim) | `alternative`, `verdict` on `AttackStep` |
| Cockpit orchestrator | `/cockpit/proposals/{id}/alternative` | proposer's command | `alternative`, `verdict` on `Proposal` |
| AD graph | `/cockpit/ad/alternative` | `adgraph.orchestrator.proposal_for_edge` cmd | on the proposal dict |
| Cloud graph | `/cockpit/cloud/alternative` | `cloudgraph` proposal cmd | on the proposal dict |
| Killchain | `/cockpit/killchain/alternative` | seam bridge cmd | on the proposal dict |

- **All on-demand.** No alternative is computed at compose/propose time — only when the operator clicks. Keeps the common path cheap and the AI spend opt-in.
- For the three graphs, "alternative" means *a different way to abuse the same edge/seam*. The engine invokes the surface's **existing** grounder (AD → AD/Windows categories; cloud → cloud-CLI heads; killchain imports neither graph package). Respecting each grounder's domain restriction is a hard requirement, not a nicety — an off-topic hit mis-grounding an abuse edge is exactly the failure the restrictions exist to prevent.
- Per the attack-step-schema-in-three-places rule: the attack-path fields must land in `attack_path.py`, the `main.py` Pydantic `AttackStep`, **and** the frontend type, or the response model strips them.

### 1.4 Frontend — one shared component

`AlternativeDisclosure` (modeled on the existing `DetectionDisclosure`): a **"second opinion"** control on each step / edge / proposal card. On click → fetches → renders **primary vs. alternative side-by-side**, the alternative badged by kind (`GROUNDED · kb:<id>` or `AI-SUGGESTED · VERIFY`), verdict below. Rendered in `AttackPathScreen`, the proposals/orchestrator view, and the three `Cockpit*Orchestrator` screens. Uses the established cockpit class vocabulary (`hp-*`), not bare `.hp-card`.

### 1.5 Honesty invariants (the point of the feature — enforced by tests)

1. **Primary is never modified.** The feature only ever *adds* a second candidate.
2. **Alternative is always badged by kind**; grounded = verbatim KB command, ai_suggested = model's own + `unverified`.
3. **Every alternative command is scope-checked**, same machinery as primaries.
4. **Verdict is prose only** — no gate/approval field, cannot reorder steps, cannot auto-select.
5. **Orchestrator `Proposal` still carries no `approved`/`dangerous_ack`.** `alternative`/`verdict` are display-only; `gate_preview` is still computed with `approved=False`. The "exactly one place approval is expressed" rule is untouched.
6. **Engine executes nothing** — AST safety test.
7. **Never invents an `entry_id`** — a grounded alternative must resolve to a real servable entry with commands, else it is demoted or dropped.

### 1.6 Error handling

On-demand ⇒ failure is **soft**. LLM unreachable → `{"alternative": null, "verdict": {"summary": "no second opinion available — model unreachable", ...}}`. The primary path (plan/proposal) never 503s because of this. "No better move exists" → `alternative: null`, verdict states the primary is best and why.

### 1.7 Testing

- **Engine unit tests:** technique-vs-tuned selection; grounded-verbatim; ai_suggested capped + `unverified`; scope-check applied to alternative commands; verdict carries no gate field.
- **AST safety test:** `alternatives.py` executes nothing (no subprocess/exec calls).
- **Per-surface endpoint tests:** alternative + verdict returned; primary unchanged; out-of-scope alternative flagged; `Proposal` still has no approval field after the call.
- **Frontend:** alternative badge renders distinctly per kind; control is on-demand.

---

## Feature 2 — home-screen model dropdown

### 2.1 Today

Model selection is a **single global setting**: `GET /llm-config` (`getLLMConfig`) / `POST /llm-config` (`setLLMConfig({provider, model?, api_key?})`), persisted to a gitignored file. Default = `claude-agent-sdk` / `opus`. Every generative feature reads it (attack-path, cockpit, chat, and the new alternatives engine). The ⚙ gear in attack-path and cockpit both open the **same** `LLMSettingsModal` writing the **same** config.

The home `StatusRail` shows an `llm` cell (`llm_provider` + `llm_model`, green dot) that is **status-only by design** — `test_home_summary.py` asserts no secret is ever in the rail payload.

### 2.2 Change

Turn the home `StatusRail` `llm` cell into a **quick model switcher**, preserving the secret boundary:

- **No-key providers** (`claude-agent-sdk` → aliases opus / sonnet / haiku; local `ollama` → models from `list_ollama_models`) → an **inline dropdown** writes the global config via `setLLMConfig` with **no key handling**. The rail payload stays secret-free.
- **Remote providers** (openai / anthropic / openrouter, which need a key) → a **"more…"** entry opens the existing `LLMSettingsModal`. Key entry never touches the rail.

So: inline quick-switch for the no-key models, modal fallback for anything needing a provider/key change. Reuses `getLLMConfig`, `setLLMConfig`, `list_ollama_models`, `LLMSettingsModal` — the only genuinely new UI is the dropdown on the rail cell.

### 2.3 Invariants / testing

- `StatusRail`'s rail **payload** remains status-only and secret-free — the dropdown reads options from `/llm-config` + `list_ollama_models`, not from the rail summary. `test_home_summary.py` stays green unchanged.
- Switching to a no-key provider/model requires no key; switching to a remote provider routes through the modal, which owns key handling.
- Test: selecting an inline (no-key) model calls `setLLMConfig` and the badge/rail reflects the new model; selecting a remote provider opens the modal rather than writing a keyless config.

---

## Cross-cutting

- **Single model, everywhere.** Both features rest on the one global `/llm-config`. The alternatives engine composes with it; the home dropdown changes it. There is no per-surface model.
- **Assessment currency (standing rule):** update `docs/ASSESSMENT-2026-07-26.md` and regenerate the html/pdf via `docs/build-assessment.py` **in the same commit** as the implementation. Verify against the html (the pdf isn't greppable).
- **Single branch:** all work on `main`.

## Out of scope

- **Chat** (`chat.py`) — freeform Markdown has no discrete command object to attach an alternative to; would need a separate UX. Excluded.
- **Cockpit tool-forms** (intruder, recon, nuclei, discover, race, smuggle, …) — operator-driven tool invocations, not AI-proposed command candidates; nothing to compare. Excluded.
- **"Approve and run"** on proposals — remains deliberately absent (see `proposals.py` docstring).

## Decisions made during design

- **Option 3** for the alternative: AI curates a *single* best alternative (technique **or** tuned form), rather than always showing both or a fixed rule.
- **On-demand**, not compute-at-compose-time.
- **v1 = all 5 structured surfaces** (attack-path, orchestrator, AD, cloud, killchain) in one build — the engine is written once, the per-surface integration is stereotyped repetition.
- Engine lives at **`backend/` level** to preserve decoupling.
- **Verdict is advisory prose**, never a machine-actionable field that could drive auto-selection.
- The home model dropdown is **folded into this spec** (same concern: model → AI output).
