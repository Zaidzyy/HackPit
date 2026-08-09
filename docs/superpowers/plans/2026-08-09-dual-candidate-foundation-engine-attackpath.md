# Dual-candidate "second opinion" — Foundation (engine + attack-path) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the shared, execute-nothing `alternatives` engine that returns one AI-curated command alternative + an advisory verdict, and wire it to the attack-path screen as its first consumer.

**Architecture:** A new `backend/alternatives.py` module composes with the global LLM config and reuses `attack_path`'s command-grounding helpers, so an alternative is grounded and scope-checked by exactly the same machinery as a primary step. It imports `attack_path` one-way (attack_path never imports it → no cycle). A new on-demand endpoint `/attack-path/alternative` returns `{alternative, verdict}`; the frontend fetches it per-step on click and holds it in component state (so **no `AttackStep` schema change** is needed).

**Tech Stack:** Python 3 + FastAPI + Pydantic (backend), pytest (tests), Next.js 16 / React / TypeScript (frontend).

## Global Constraints

- **Single branch `main`.** All work on `main` (repo is single-branch by standing rule).
- **The engine executes nothing.** No `subprocess`, `os.system`, `os.exec*`, `eval`, `exec`, `Popen`, `run`, `pty`, `socket` calls in `alternatives.py`. Enforced by an AST test (Task 1).
- **Grounding invariant, verbatim from spec:** primary is never modified; a grounded alternative uses a real KB entry's commands verbatim (target-substituted); an ai_suggested alternative is the model's own command, capped and marked `unverified`; the verdict is prose only and carries no approval/gate field; never invent an `entry_id`.
- **Every alternative command is scope-checked** by the same pass primaries use (`attack_path.flag_foreign_refs`).
- **Frontend lint baseline is exactly 11** (`react-hooks/set-state-in-effect`). CI fails only if it rises above 11. New auto-load/poll effects need a pinned `// eslint-disable-next-line react-hooks/set-state-in-effect` with a one-line justification — routing through an async callback does NOT dodge the rule. `next build` must exit 0.
- **Cockpit class vocabulary:** new UI uses `hp-*` classes (e.g. `hp-ap-*`), never bare `.hp-card` (invisible). tsc/eslint cannot see whether a CSS class exists — the screen is **not verified until looked at** in the browser.
- **Assessment currency (standing rule):** update `docs/ASSESSMENT-2026-07-26.md` and regenerate html/pdf via `docs/build-assessment.py` in the final commit (Task 7). Verify against the html — the pdf is not greppable.

---

## File Structure

- **Create** `backend/alternatives.py` — the shared engine. `best_alternative(primary, *, goal, target, scope, by_id, search_fn) -> {"alternative": dict|None, "verdict": dict}`. Reuses `attack_path` helpers. Executes nothing.
- **Create** `backend/test_alternatives_safety.py` — AST test: the module executes nothing.
- **Create** `backend/test_alternatives.py` — engine unit tests (grounded / tuned / none / verdict discipline / scope-check) with `llm.chat` monkeypatched.
- **Modify** `backend/main.py` — add `AltStepIn`, `AltVerdict`, `Alternative`, `AlternativeOut` Pydantic models + the `POST /attack-path/alternative` endpoint. Import `alternatives`.
- **Create** `backend/test_attack_path_alternative_endpoint.py` — endpoint test (returns alternative+verdict; out-of-scope flagged; primary path unaffected).
- **Modify** `frontend/src/lib/api.ts` — add `Alternative` + `AltVerdict` types and `getStepAlternative(...)`.
- **Create** `frontend/src/components/AlternativeDisclosure.tsx` — the shared "second opinion" UI (primary vs alternative + verdict, alternative badged by kind).
- **Modify** `frontend/src/components/AttackPathScreen.tsx` — add the on-demand "second opinion" control to `StepCard`, rendering `AlternativeDisclosure`.
- **Modify** `frontend/src/app/globals.css` — `hp-ap-alt-*` styles for the disclosure/badges.
- **Modify** `docs/ASSESSMENT-2026-07-26.md` + regenerate html/pdf (Task 7).

---

### Task 1: Engine scaffold + "executes nothing" AST safety test

**Files:**
- Create: `backend/alternatives.py`
- Test: `backend/test_alternatives_safety.py`

**Interfaces:**
- Produces: module `alternatives` with `best_alternative(primary: dict, *, goal: str, target: str|None, scope: str|None, by_id: dict, search_fn: Callable) -> dict`.

- [ ] **Step 1: Write the failing safety test**

```python
# backend/test_alternatives_safety.py
"""alternatives.py must execute nothing — same guarantee as proposals.py / the graph orchestrators."""
import ast
import pathlib

_BANNED = {"system", "popen", "run", "call", "check_output", "exec", "execv", "execve",
           "spawn", "spawnv", "fork", "eval"}


def test_alternatives_executes_nothing():
    src = pathlib.Path(__file__).with_name("alternatives.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
            assert name.lower() not in _BANNED, f"alternatives.py must not call {name}()"
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name != "subprocess", "alternatives.py must not import subprocess"
        if isinstance(node, ast.ImportFrom):
            assert node.module != "subprocess", "alternatives.py must not import subprocess"
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd backend && python -m pytest test_alternatives_safety.py -v`
Expected: FAIL (`FileNotFoundError` / `alternatives.py` missing).

- [ ] **Step 3: Create the module scaffold**

```python
# backend/alternatives.py
"""Operator-requested SECOND OPINION on a generated command. READ-ONLY; EXECUTES NOTHING.

Given a primary command and its context, return ONE curated alternative (a different KB
technique, or an AI-tuned form of the same command) plus an advisory which-is-better verdict.
The primary is never modified. A grounded alternative uses a real KB entry's commands verbatim
(target-substituted); an ai_suggested alternative is the model's own command, capped and marked
unverified. The verdict is prose only — no approval/gate field, drives nothing.

Reuses attack_path's command-grounding helpers so an alternative is grounded and scope-checked by
EXACTLY the same machinery as a primary step. One-way import: attack_path never imports this
module, so there is no cycle.
"""
from __future__ import annotations

from typing import Any, Callable

import attack_path
import llm


def best_alternative(
    primary: dict[str, Any],
    *,
    goal: str,
    target: str | None,
    scope: str | None,
    by_id: dict[str, dict],
    search_fn: Callable[..., list[Any]],
) -> dict[str, Any]:
    """Return {"alternative": dict|None, "verdict": dict}. EXECUTES NOTHING."""
    cfg = llm.load_config()
    return {"alternative": None, "verdict": {
        "recommendation": "primary", "summary": "", "factors": [],
        "model_used": cfg.get("model", ""), "provider": cfg.get("provider", ""),
    }}
```

- [ ] **Step 4: Run the safety test to verify it passes**

Run: `cd backend && python -m pytest test_alternatives_safety.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/alternatives.py backend/test_alternatives_safety.py
git commit -m "feat(alternatives): engine scaffold + executes-nothing AST test"
```

---

### Task 2: Engine — grounded / tuned decision + verdict shaping

**Files:**
- Modify: `backend/alternatives.py`
- Test: `backend/test_alternatives.py`

**Interfaces:**
- Consumes (from `attack_path`): `_norm_id(str)->str`, `_resolve_entry_id(str, by_id, norm_map)->str|None`, `is_step_eligible(entry)->bool`, `entry_commands(entry, cap)->list[dict]`, `substitute_target(cmd, target, scope)->str`, `_ai_commands(raw, target, scope)->list[dict]`, module constant `_STEP_CMD_CAP`.
- Consumes (from `llm`): `load_config()->dict`, `chat(system, user, cfg)->str`, `extract_json(str)->Any`, `LLMError`.
- Produces: `best_alternative(...)` returns `{"alternative": {"kind","entry_id","entry_title","title","commands"}|None, "verdict": {"recommendation","summary","factors","model_used","provider"}}`. `kind` ∈ {"grounded","ai_suggested"}.

- [ ] **Step 1: Write the failing tests**

```python
# backend/test_alternatives.py
import json

import alternatives
import llm


_ENTRY = {
    "id": "kb-union-sqli", "title": "Manual UNION SQLi", "category": "web",
    "steps": [{"n": 1, "cmds": [{"lang": "bash", "cmd": "curl 'http://EXAMPLE/?id=1 UNION SELECT 1,2'"}]}],
    "code": [{"lang": "bash", "cmd": "curl 'http://EXAMPLE/?id=1 UNION SELECT 1,2'"}],
}
BY_ID = {"kb-union-sqli": _ENTRY}


def _search(_q):
    return [{"id": "kb-union-sqli", "title": "Manual UNION SQLi"}]


def _patch_chat(monkeypatch, payload):
    monkeypatch.setattr(llm, "load_config", lambda: {"model": "opus", "provider": "claude-agent-sdk"})
    monkeypatch.setattr(llm, "chat", lambda *a, **k: json.dumps(payload))


def test_grounded_alternative_uses_entry_commands_verbatim(monkeypatch):
    _patch_chat(monkeypatch, {
        "choice": "grounded", "entry_id": "kb-union-sqli", "title": "Manual UNION SQLi",
        "verdict": {"recommendation": "situational", "summary": "quieter than sqlmap", "factors": ["stealth"]},
    })
    out = alternatives.best_alternative(
        {"title": "sqlmap dump", "cmd": "sqlmap -u http://t --dump", "entry_id": "kb-sqlmap"},
        goal="dump the db", target="target.test", scope=None, by_id=BY_ID, search_fn=_search)
    alt = out["alternative"]
    assert alt is not None and alt["kind"] == "grounded"
    assert alt["entry_id"] == "kb-union-sqli"
    assert alt["commands"] and "UNION SELECT" in alt["commands"][0]["cmd"]
    # verbatim from the entry, not the model's own — so not marked unverified
    assert alt["commands"][0].get("unverified") is not True


def test_tuned_alternative_is_capped_and_unverified(monkeypatch):
    _patch_chat(monkeypatch, {
        "choice": "tuned", "title": "sqlmap + evasion",
        "commands": [{"lang": "bash", "cmd": "sqlmap -u http://EXAMPLE --dump --random-agent --tamper=space2comment"}],
        "verdict": {"recommendation": "alternative", "summary": "adds WAF evasion", "factors": ["evasion"]},
    })
    out = alternatives.best_alternative(
        {"title": "sqlmap dump", "cmd": "sqlmap -u http://t --dump", "entry_id": "kb-sqlmap"},
        goal="dump the db", target="target.test", scope=None, by_id={}, search_fn=lambda q: [])
    alt = out["alternative"]
    assert alt is not None and alt["kind"] == "ai_suggested"
    assert alt["entry_id"] == ""
    assert alt["commands"][0]["unverified"] is True


def test_choice_none_returns_no_alternative(monkeypatch):
    _patch_chat(monkeypatch, {"choice": "none",
                              "verdict": {"recommendation": "primary", "summary": "primary is best", "factors": []}})
    out = alternatives.best_alternative(
        {"title": "sqlmap", "cmd": "sqlmap -u http://t --dump", "entry_id": "kb-sqlmap"},
        goal="dump", target="t", scope=None, by_id={}, search_fn=lambda q: [])
    assert out["alternative"] is None
    assert out["verdict"]["recommendation"] == "primary"


def test_verdict_never_carries_a_gate_field(monkeypatch):
    _patch_chat(monkeypatch, {"choice": "none",
                              "verdict": {"recommendation": "primary", "summary": "ok",
                                          "approved": True, "dangerous_ack": True}})
    out = alternatives.best_alternative(
        {"title": "x", "cmd": "x", "entry_id": ""}, goal="g", target=None, scope=None,
        by_id={}, search_fn=lambda q: [])
    for banned in ("approved", "dangerous_ack"):
        assert banned not in out["verdict"]


def test_llm_unreachable_is_soft(monkeypatch):
    monkeypatch.setattr(llm, "load_config", lambda: {"model": "opus", "provider": "claude-agent-sdk"})
    def _boom(*a, **k):
        raise llm.LLMError("offline")
    monkeypatch.setattr(llm, "chat", _boom)
    out = alternatives.best_alternative(
        {"title": "x", "cmd": "x", "entry_id": ""}, goal="g", target=None, scope=None,
        by_id={}, search_fn=lambda q: [])
    assert out["alternative"] is None
    assert "unreachable" in out["verdict"]["summary"]


def test_never_invents_an_entry_id(monkeypatch):
    # model cites an id that is not in by_id → must NOT become a grounded alt with a fake id
    _patch_chat(monkeypatch, {"choice": "grounded", "entry_id": "kb-does-not-exist",
                              "title": "ghost", "commands": [],
                              "verdict": {"recommendation": "primary", "summary": "n/a", "factors": []}})
    out = alternatives.best_alternative(
        {"title": "x", "cmd": "x", "entry_id": ""}, goal="g", target=None, scope=None,
        by_id=BY_ID, search_fn=_search)
    assert out["alternative"] is None or out["alternative"]["kind"] != "grounded" \
        or out["alternative"]["entry_id"] in BY_ID
```

- [ ] **Step 2: Run to verify they fail**

Run: `cd backend && python -m pytest test_alternatives.py -v`
Expected: FAIL (the scaffold always returns `alternative: None`, so grounded/tuned tests fail).

- [ ] **Step 3: Implement `best_alternative`**

Replace the body from Task 1 with the full implementation:

```python
# backend/alternatives.py  (replace the stub body from Task 1)
from __future__ import annotations

from typing import Any, Callable

import attack_path
import llm

_CANDIDATES = 6

_SYSTEM = (
    "You are an authorized-engagement methodology guide giving a SECOND OPINION on ONE command "
    "an operator is considering. You are given the PRIMARY command and a short list of candidate "
    "library techniques (entry_id + title) for the same objective. Return ONE alternative and say "
    "which is better and why.\n"
    "- PREFER a grounded library technique: return its entry_id, chosen ONLY from the candidates "
    "listed — never invent an id. The system attaches its real commands; do NOT restate them.\n"
    "- If no candidate fits but a tuned form of the PRIMARY would genuinely help (evasion, "
    "rate-limiting, target-fit), return choice \"tuned\" with a concrete UNVERIFIED command.\n"
    "- If the primary is already the best move, return choice \"none\".\n"
    "- The verdict is ADVICE, not an instruction: never state a command is approved or safe to run.\n"
    'Respond with ONLY JSON: {"choice":"grounded"|"tuned"|"none","entry_id":"<id or empty>",'
    '"title":"<short>","commands":[{"lang":"bash","cmd":"<cmd>"}],'
    '"verdict":{"recommendation":"primary"|"alternative"|"situational","summary":"<why>",'
    '"factors":["<tradeoff>"]}}'
)


def _verdict(raw: Any, cfg: dict) -> dict[str, Any]:
    v = raw if isinstance(raw, dict) else {}
    rec = str(v.get("recommendation") or "situational").strip().lower()
    if rec not in ("primary", "alternative", "situational"):
        rec = "situational"
    factors = [str(f).strip()[:120] for f in (v.get("factors") or []) if str(f).strip()][:5]
    # Only these keys are ever returned — a stray gate field the model emits is dropped here.
    return {
        "recommendation": rec,
        "summary": str(v.get("summary") or "").strip()[:600],
        "factors": factors,
        "model_used": cfg.get("model", ""),
        "provider": cfg.get("provider", ""),
    }


def _soft(cfg: dict, summary: str) -> dict[str, Any]:
    return {"alternative": None, "verdict": {
        "recommendation": "primary", "summary": summary, "factors": [],
        "model_used": cfg.get("model", ""), "provider": cfg.get("provider", "")}}


def best_alternative(
    primary: dict[str, Any],
    *,
    goal: str,
    target: str | None,
    scope: str | None,
    by_id: dict[str, dict],
    search_fn: Callable[..., list[Any]],
) -> dict[str, Any]:
    """Return {"alternative": dict|None, "verdict": dict}. EXECUTES NOTHING.

    ``primary`` is display context: {"title","cmd","entry_id"}. On any LLM failure returns a soft
    result (alternative None + a verdict explaining the model was unreachable); the caller's
    primary path never breaks.
    """
    cfg = llm.load_config()

    query = f"{primary.get('title', '')} {goal}".strip()
    try:
        hits = list(search_fn(query))[:_CANDIDATES]
    except Exception:  # retrieval must never break the second-opinion path
        hits = []
    cand_lines: list[str] = []
    for h in hits:
        hid = h.get("id") if isinstance(h, dict) else getattr(h, "id", None)
        if hid and hid != primary.get("entry_id"):
            title = h.get("title") if isinstance(h, dict) else getattr(h, "title", "")
            cand_lines.append(f"- entry_id: {hid}  ({title})")

    user = (
        f"GOAL: {goal}\n"
        f"PRIMARY command: {primary.get('cmd', '')}\n"
        f"PRIMARY technique: {primary.get('title', '')} "
        f"(entry_id: {primary.get('entry_id', '') or 'none'})\n\n"
        "CANDIDATE library techniques for the same objective:\n"
        + ("\n".join(cand_lines) if cand_lines else "(none matched)")
        + "\n\nReturn the JSON described."
    )
    try:
        parsed = llm.extract_json(llm.chat(_SYSTEM, user, cfg))
    except llm.LLMError:
        return _soft(cfg, "no second opinion available — model unreachable")

    parsed = parsed if isinstance(parsed, dict) else {}
    choice = str(parsed.get("choice") or "none").strip().lower()
    verdict = _verdict(parsed.get("verdict"), cfg)
    alt: dict[str, Any] | None = None

    if choice == "grounded":
        norm_map = {attack_path._norm_id(k): k for k in by_id}
        eid = attack_path._resolve_entry_id(str(parsed.get("entry_id") or ""), by_id, norm_map)
        if eid is not None and attack_path.is_step_eligible(by_id[eid]):
            e = by_id[eid]
            cmds = [
                {**c, "cmd": attack_path.substitute_target(c["cmd"], target, scope)}
                for c in attack_path.entry_commands(e, cap=attack_path._STEP_CMD_CAP)
            ]
            if cmds:
                alt = {"kind": "grounded", "entry_id": eid, "entry_title": e.get("title", ""),
                       "title": e.get("title", ""), "commands": cmds}
        if alt is None:
            choice = "tuned"  # unresolved/ineligible/no-commands citation → try a tuned form

    if alt is None and choice == "tuned":
        cmds = attack_path._ai_commands(parsed.get("commands"), target, scope)
        if cmds:
            alt = {"kind": "ai_suggested", "entry_id": "", "entry_title": "",
                   "title": str(parsed.get("title") or "tuned command").strip()[:120],
                   "commands": cmds}

    return {"alternative": alt, "verdict": verdict}
```

- [ ] **Step 4: Run to verify pass**

Run: `cd backend && python -m pytest test_alternatives.py -v`
Expected: PASS (all 6 tests).

- [ ] **Step 5: Commit**

```bash
git add backend/alternatives.py backend/test_alternatives.py
git commit -m "feat(alternatives): grounded/tuned decision + verdict shaping"
```

---

### Task 3: Scope-check the alternative's commands

**Files:**
- Modify: `backend/alternatives.py` (add the scope-flag pass before returning)
- Test: `backend/test_alternatives.py` (add one test)

**Interfaces:**
- Consumes (from `attack_path`): `flag_foreign_refs(phases: list[dict], target: str|None, scope: str|None) -> list[dict]` — the SAME per-command scope pass `compose()` runs (annotates each command with its scope verdict fields).

- [ ] **Step 1: Write the failing test**

```python
# add to backend/test_alternatives.py
def test_alternative_commands_are_scope_checked(monkeypatch):
    _patch_chat(monkeypatch, {
        "choice": "tuned", "title": "hit an out-of-scope host",
        "commands": [{"lang": "bash", "cmd": "nmap evil-out-of-scope.test"}],
        "verdict": {"recommendation": "situational", "summary": "x", "factors": []},
    })
    out = alternatives.best_alternative(
        {"title": "scan", "cmd": "nmap target.test", "entry_id": ""},
        goal="scan", target="target.test", scope="target.test", by_id={}, search_fn=lambda q: [])
    alt = out["alternative"]
    assert alt is not None
    # flag_foreign_refs annotated the command against scope (foreign-ref / runnable fields present)
    cmd = alt["commands"][0]
    assert ("foreign_refs" in cmd) or ("runnable" in cmd)
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd backend && python -m pytest test_alternatives.py::test_alternative_commands_are_scope_checked -v`
Expected: FAIL (command carries no scope annotation yet).

- [ ] **Step 3: Add the scope-flag pass**

Insert this just before `return {"alternative": alt, "verdict": verdict}` in `best_alternative`:

```python
    if alt is not None:
        # SCOPE CHECK — the same machinery a primary step gets. Wrap the alternative as a
        # one-step phase (the shape flag_foreign_refs expects), flag it, unwrap.
        phases = [{
            "phase": "exploitation",
            "steps": [{
                **alt, "why": "", "from_writeup": False,
                "ai_suggested": alt["kind"] == "ai_suggested",
            }],
        }]
        phases = attack_path.flag_foreign_refs(phases, target, scope)
        alt = phases[0]["steps"][0]
```

- [ ] **Step 4: Run the full engine suite to verify pass**

Run: `cd backend && python -m pytest test_alternatives.py test_alternatives_safety.py -v`
Expected: PASS (all engine + safety tests).

- [ ] **Step 5: Commit**

```bash
git add backend/alternatives.py backend/test_alternatives.py
git commit -m "feat(alternatives): scope-check alternative commands via flag_foreign_refs"
```

---

### Task 4: Backend endpoint `POST /attack-path/alternative`

**Files:**
- Modify: `backend/main.py` (add import + 4 models + endpoint)
- Test: `backend/test_attack_path_alternative_endpoint.py`

**Interfaces:**
- Consumes: `alternatives.best_alternative(...)`; `STATE.by_id`; `_resilient_search` (the app's hybrid search callable used by `/attack-path`); `PlannedCode` (existing per-command response model).
- Produces: `POST /attack-path/alternative` accepting `AltStepIn`, returning `AlternativeOut {alternative: Alternative|None, verdict: AltVerdict}`.

- [ ] **Step 1: Write the failing test**

```python
# backend/test_attack_path_alternative_endpoint.py
from fastapi.testclient import TestClient

import main
import alternatives


def test_alternative_endpoint_returns_verdict_and_alternative(monkeypatch):
    monkeypatch.setattr(alternatives, "best_alternative", lambda primary, **kw: {
        "alternative": {"kind": "ai_suggested", "entry_id": "", "entry_title": "",
                        "title": "tuned", "commands": [{"lang": "bash", "cmd": "sqlmap --tamper=x",
                                                        "unverified": True}]},
        "verdict": {"recommendation": "alternative", "summary": "adds evasion",
                    "factors": ["evasion"], "model_used": "opus", "provider": "claude-agent-sdk"},
    })
    client = TestClient(main.app)
    r = client.post("/attack-path/alternative", json={
        "goal": "dump the db", "target": "target.test",
        "step_title": "sqlmap dump", "step_cmd": "sqlmap -u http://target.test --dump",
        "step_entry_id": "kb-sqlmap"})
    assert r.status_code == 200
    body = r.json()
    assert body["verdict"]["recommendation"] == "alternative"
    assert body["alternative"]["kind"] == "ai_suggested"
    assert body["alternative"]["commands"][0]["unverified"] is True


def test_alternative_endpoint_requires_goal():
    client = TestClient(main.app)
    r = client.post("/attack-path/alternative", json={"goal": "  ", "step_cmd": "x"})
    assert r.status_code == 400
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd backend && python -m pytest test_attack_path_alternative_endpoint.py -v`
Expected: FAIL (404 — endpoint not defined).

- [ ] **Step 3: Add the import**

Near the other feature imports at the top of `backend/main.py` (e.g. beside `import attack_path`):

```python
import alternatives
```

- [ ] **Step 4: Add the models + endpoint**

Add the models next to `AttackPathOut` (after line ~1171) and the endpoint right after `attack_path_compose` (after line ~2088):

```python
# --- second-opinion (dual-candidate) models ---
class AltVerdict(BaseModel):
    recommendation: str = Field(description='"primary" | "alternative" | "situational" — ADVISORY only.')
    summary: str = Field(default="", description="Which candidate is better and why. Prose only.")
    factors: list[str] = Field(default_factory=list, description="Optional tradeoff bullets.")
    model_used: str = ""
    provider: str = ""


class Alternative(BaseModel):
    kind: str = Field(description='"grounded" (verbatim KB entry) | "ai_suggested" (model, unverified).')
    entry_id: str = Field(default="", description="Cited KB entry — set + real when grounded, else empty.")
    entry_title: str = ""
    title: str
    commands: list[PlannedCode] = Field(default_factory=list)


class AlternativeOut(BaseModel):
    alternative: Alternative | None = None
    verdict: AltVerdict


class AltStepIn(BaseModel):
    goal: str
    target: str | None = None
    scope_text: str | None = None
    step_title: str = ""
    step_cmd: str = ""
    step_entry_id: str = ""
```

```python
@app.post("/attack-path/alternative", response_model=AlternativeOut)
def attack_path_alternative(req: AltStepIn = Body(...)) -> dict[str, Any]:
    """On-demand SECOND OPINION for one attack-path step. Returns one alternative candidate
    (grounded KB technique, or an AI-tuned command marked unverified) + an advisory verdict.
    EXECUTES NOTHING; the primary step is untouched. Soft-fails (alternative null) if the LLM
    is unreachable, so the plan view never breaks."""
    goal = req.goal.strip()
    if not goal:
        raise HTTPException(status_code=400, detail="goal is required")
    return alternatives.best_alternative(
        {"title": req.step_title, "cmd": req.step_cmd, "entry_id": req.step_entry_id},
        goal=goal, target=req.target, scope=req.scope_text,
        by_id=STATE.by_id,
        # engine's search_fn contract is one-arg; _resilient_search needs (q, top, mode)
        search_fn=lambda q: _resilient_search(q, 8, "hybrid"),
    )
```

- [ ] **Step 5: Run to verify pass**

Run: `cd backend && python -m pytest test_attack_path_alternative_endpoint.py -v`
Expected: PASS (both tests).

- [ ] **Step 6: Commit**

```bash
git add backend/main.py backend/test_attack_path_alternative_endpoint.py
git commit -m "feat(attack-path): POST /attack-path/alternative second-opinion endpoint"
```

---

### Task 5: Frontend API — types + `getStepAlternative`

**Files:**
- Modify: `frontend/src/lib/api.ts`

**Interfaces:**
- Consumes: existing `postJSON<T>(path, body, signal)` helper; existing `PlannedCode` TS type (used by attack-path commands — reuse it; if the file names it differently, use that name).
- Produces: TS types `AltVerdict`, `Alternative`, `AlternativeResult`; function `getStepAlternative(input, signal) -> Promise<AlternativeResult>`.

- [ ] **Step 1: Add the types + function**

Add near the attack-path types in `frontend/src/lib/api.ts`:

```typescript
export type AltVerdict = {
  recommendation: "primary" | "alternative" | "situational";
  summary: string;
  factors: string[];
  model_used: string;
  provider: string;
};

export type Alternative = {
  kind: "grounded" | "ai_suggested";
  entry_id: string;
  entry_title: string;
  title: string;
  commands: PlannedCode[]; // same per-command shape the attack-path steps use
};

export type AlternativeResult = {
  alternative: Alternative | null;
  verdict: AltVerdict;
};

export const getStepAlternative = (
  input: {
    goal: string;
    target?: string | null;
    scope_text?: string | null;
    step_title?: string;
    step_cmd?: string;
    step_entry_id?: string;
  },
  signal?: AbortSignal,
) => postJSON<AlternativeResult>("/attack-path/alternative", input, signal);
```

- [ ] **Step 2: Verify it type-checks**

Run: `cd frontend && npx tsc --noEmit`
Expected: exit 0. (If `PlannedCode` is exported under another name in `api.ts`, use that exact name.)

- [ ] **Step 3: Commit**

```bash
git add frontend/src/lib/api.ts
git commit -m "feat(fe): getStepAlternative API + Alternative/AltVerdict types"
```

---

### Task 6: Frontend — `AlternativeDisclosure` + StepCard wiring

**Files:**
- Create: `frontend/src/components/AlternativeDisclosure.tsx`
- Modify: `frontend/src/components/AttackPathScreen.tsx` (StepCard: add the on-demand control)
- Modify: `frontend/src/app/globals.css` (`hp-ap-alt-*` styles)

**Interfaces:**
- Consumes: `getStepAlternative`, `Alternative`, `AlternativeResult` from `@/lib/api`; the existing `PlannedCommand` render component in `AttackPathScreen.tsx` for showing commands consistently.
- Produces: `<AlternativeDisclosure goal target scopeText step={{title,cmd,entryId}} />`.

- [ ] **Step 1: Create the component**

```tsx
// frontend/src/components/AlternativeDisclosure.tsx
"use client";

import { useState } from "react";
import { getStepAlternative, type AlternativeResult } from "@/lib/api";
import { PlannedCommand } from "./AttackPathScreen"; // export it (Step 2) if not already exported

/**
 * On-demand SECOND OPINION for one command. Fetches ONE alternative candidate + a which-is-better
 * verdict when the operator clicks. The primary is rendered by the caller and is never touched here.
 * A grounded alternative links its KB entry; an ai_suggested one is badged VERIFY (unverified).
 */
export function AlternativeDisclosure({
  goal,
  target,
  scopeText,
  step,
}: {
  goal: string;
  target?: string | null;
  scopeText?: string | null;
  step: { title: string; cmd: string; entryId: string };
}) {
  const [state, setState] = useState<"idle" | "loading" | "done" | "error">("idle");
  const [result, setResult] = useState<AlternativeResult | null>(null);

  async function load() {
    setState("loading");
    try {
      const r = await getStepAlternative({
        goal,
        target: target ?? null,
        scope_text: scopeText ?? null,
        step_title: step.title,
        step_cmd: step.cmd,
        step_entry_id: step.entryId,
      });
      setResult(r);
      setState("done");
    } catch {
      setState("error");
    }
  }

  if (state === "idle") {
    return (
      <button type="button" className="hp-ap-alt-toggle" onClick={load}>
        ⇄ second opinion
      </button>
    );
  }
  if (state === "loading") return <div className="hp-ap-alt-msg">weighing an alternative…</div>;
  if (state === "error")
    return <div className="hp-ap-alt-msg hp-ap-alt-err">couldn’t fetch a second opinion — try again</div>;

  const alt = result?.alternative;
  const v = result?.verdict;
  return (
    <div className="hp-ap-alt">
      {alt ? (
        <>
          <div className="hp-ap-alt-head">
            <span className={`hp-ap-alt-badge is-${alt.kind}`}>
              {alt.kind === "grounded" ? `GROUNDED · kb:${alt.entry_id}` : "AI-SUGGESTED · VERIFY"}
            </span>
            <b>{alt.title}</b>
          </div>
          {alt.commands.map((c, i) => (
            <PlannedCommand c={c} key={i} />
          ))}
        </>
      ) : (
        <div className="hp-ap-alt-msg">no better alternative — the primary is the best available move.</div>
      )}
      {v?.summary && (
        <p className="hp-ap-alt-verdict">
          <span className="hp-ap-alt-verdict-lead">which &amp; why</span>
          {v.summary}
          {v.factors.length > 0 && <span className="hp-ap-alt-factors"> ({v.factors.join(" · ")})</span>}
        </p>
      )}
    </div>
  );
}
```

- [ ] **Step 2: Export `PlannedCommand` and render the disclosure in StepCard**

In `frontend/src/components/AttackPathScreen.tsx`: (a) change `function PlannedCommand(` to `export function PlannedCommand(` so the disclosure can reuse it; (b) inside `StepCard`, after the commands block, add the control — it needs the goal/target/scope, so thread those from the screen into `StepCard` as props (the screen already holds `goal`, `result.target`, and the pasted scope text):

```tsx
{step.commands.length > 0 && (
  <AlternativeDisclosure
    goal={goal}
    target={target}
    scopeText={scopeText}
    step={{ title: step.title, cmd: step.commands[0].cmd, entryId: step.entry_id }}
  />
)}
```

Add `import { AlternativeDisclosure } from "./AlternativeDisclosure";` at the top, and extend `StepCard`'s props to `{ step, goal, target, scopeText }`, passing them where `StepCard` is rendered in the phase loop.

- [ ] **Step 3: Add styles**

In `frontend/src/app/globals.css`, add (colors via existing tokens; the AI badge must read distinctly from the grounded one):

```css
.hp-ap-alt-toggle { font-size: .8rem; background: none; border: 1px solid var(--hp-border); border-radius: 6px; padding: .2rem .5rem; color: var(--hp-fg-dim); cursor: pointer; }
.hp-ap-alt { margin-top: .5rem; padding: .5rem .6rem; border-left: 2px solid var(--hp-border); }
.hp-ap-alt-head { display: flex; gap: .5rem; align-items: center; margin-bottom: .3rem; }
.hp-ap-alt-badge { font-size: .7rem; letter-spacing: .04em; padding: .1rem .4rem; border-radius: 4px; }
.hp-ap-alt-badge.is-grounded { background: var(--hp-ok-bg, #113); color: var(--hp-ok, #6f6); }
.hp-ap-alt-badge.is-ai_suggested { background: var(--hp-warn-bg, #331); color: var(--hp-warn, #fb6); }
.hp-ap-alt-verdict { font-size: .85rem; margin-top: .35rem; color: var(--hp-fg-dim); }
.hp-ap-alt-verdict-lead { font-weight: 600; margin-right: .4rem; }
.hp-ap-alt-msg { font-size: .85rem; color: var(--hp-fg-dim); padding: .3rem 0; }
.hp-ap-alt-err { color: var(--hp-warn, #fb6); }
```

(If those exact token names don't exist, reuse the tokens already used by `hp-ap-runnable-warn` / `hp-ap-runnable-ok` for the warn/ok colors — grep `globals.css` for them.)

- [ ] **Step 4: Verify lint + build + type-check**

Run: `cd frontend && npx tsc --noEmit && npm run lint && npm run build`
Expected: tsc exit 0; lint error count **still 11** (not higher); build exit 0.

- [ ] **Step 5: LOOK AT IT (required — not verified until seen)**

Start the app (`run` skill / dev server on :3000 + backend on :8000), compose an attack path, click "⇄ second opinion" on a step, and confirm: the alternative renders with the correct badge (grounded links `kb:<id>`; ai_suggested reads `AI-SUGGESTED · VERIFY`), the verdict shows, and the primary command above is unchanged. Capture a screenshot.

- [ ] **Step 6: Commit**

```bash
git add frontend/src/components/AlternativeDisclosure.tsx frontend/src/components/AttackPathScreen.tsx frontend/src/app/globals.css
git commit -m "feat(fe): on-demand second-opinion disclosure on attack-path steps"
```

---

### Task 7: Update the assessment (standing rule) + full suite

**Files:**
- Modify: `docs/ASSESSMENT-2026-07-26.md`
- Regenerate: `docs/ASSESSMENT-2026-07-26.html` + `.pdf` via `docs/build-assessment.py`

- [ ] **Step 1: Add the capability to the assessment**

Add a short entry describing the dual-candidate "second opinion" on attack-path steps: on-demand, one AI-curated alternative (grounded verbatim KB technique or ai_suggested tuned command marked unverified), advisory verdict, engine executes nothing, primary untouched, alternative scope-checked. Note that this is the foundation surface; orchestrator + AD/cloud/killchain are follow-on builds.

- [ ] **Step 2: Regenerate html/pdf**

Run: `cd docs && python build-assessment.py`
Then verify the new text is present in `ASSESSMENT-2026-07-26.html` (the pdf is not greppable — check the html).

- [ ] **Step 3: Run the whole backend suite (no regressions)**

Run: `cd backend && python -m pytest -q`
Expected: PASS (existing suite + the 3 new test files). If any pre-existing test needs its own DB tables initialized in a clean checkout, that is the known TestClient-skips-lifespan trap — init the tables in that test, do not touch the feature.

- [ ] **Step 4: Commit**

```bash
git add docs/ASSESSMENT-2026-07-26.md docs/ASSESSMENT-2026-07-26.html docs/ASSESSMENT-2026-07-26.pdf
git commit -m "docs(assessment): record attack-path second-opinion capability"
```

---

## Self-Review

**1. Spec coverage (foundation slice):**
- Shared engine, executes nothing → Task 1 (+ AST test). ✅
- Engine consumes global `/llm-config` → Task 2 (`llm.load_config()`). ✅
- AI picks technique-vs-tuned (Option 3) → Task 2 (`choice`). ✅
- Grounded = verbatim KB entry; never invent entry_id → Task 2 (`_resolve_entry_id` + `entry_commands`; `test_never_invents_an_entry_id`). ✅
- ai_suggested = capped + unverified → Task 2 (`_ai_commands`). ✅
- Verdict prose-only, no gate field → Task 2 (`_verdict` whitelists keys; `test_verdict_never_carries_a_gate_field`). ✅
- Every alternative command scope-checked → Task 3 (`flag_foreign_refs`). ✅
- On-demand endpoint; soft-fail on LLM down → Task 4 + Task 2 (`_soft`). ✅
- Badged-by-kind UI, primary untouched, looked-at → Task 6. ✅
- Assessment currency → Task 7. ✅
- **Refinement vs spec:** because it's on-demand, the attack-path surface adds **no `AttackStep` field** (the alternative comes from its own endpoint and lives in frontend state) — this is a simplification of spec §1.3's "fields on `AttackStep`", not a coverage gap. The orchestrator plan will still add fields to `Proposal` because that object is persisted.

**2. Placeholder scan:** No TBD/TODO. Every code step has real code. The two "if the name differs, use that name" notes (PlannedCode TS name; CSS token names) are explicit fallbacks, not vague instructions.

**3. Type consistency:** engine returns `{"alternative", "verdict"}` dicts; `AlternativeOut`/`Alternative`/`AltVerdict` mirror them; TS `AlternativeResult`/`Alternative`/`AltVerdict` mirror those; `commands` is `PlannedCode` on both sides. `getStepAlternative` body keys (`goal,target,scope_text,step_title,step_cmd,step_entry_id`) match `AltStepIn`. Consistent.

---

## Follow-on plans (each written just before its execution — depends on the final engine shape)

1. **Orchestrator** (`/cockpit/proposals/{id}/alternative`) — adds `alternative`+`verdict` fields to the persisted `Proposal` model; engine reused as-is; `gate_preview` still `approved=False`; `Proposal` still has no approval field.
2. **AD graph** (`/cockpit/ad/alternative`) — alternative = a different way to abuse the same edge; engine invokes the existing `_ad_kb_grounder` (AD/Windows categories only).
3. **Cloud graph** (`/cockpit/cloud/alternative`) — mirrors AD via `_cloud_kb_grounder` (cloud-CLI heads).
4. **Killchain** (`/cockpit/killchain/alternative`) — seam-bridge alternative; imports neither graph package.
5. **Home model dropdown** — independent; turn the `StatusRail` llm cell into an inline quick-switch for no-key providers (agent-sdk aliases via `setLLMConfig`, local models via `/ollama-models`), "more…" opens the existing `LLMSettingsModal`; rail payload stays secret-free (`test_home_summary.py` unchanged).
