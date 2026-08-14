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

#: how many candidate KB entries to offer the model as grounding for the alternative
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
    """Shape the model's verdict. Whitelists keys — a stray gate field (approved/dangerous_ack)
    the model emits is dropped here, so the verdict can never carry a machine-actionable flag."""
    v = raw if isinstance(raw, dict) else {}
    rec = str(v.get("recommendation") or "situational").strip().lower()
    if rec not in ("primary", "alternative", "situational"):
        rec = "situational"
    factors = [str(f).strip()[:120] for f in (v.get("factors") or []) if str(f).strip()][:5]
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
    search_fn: Callable[[str], list[Any]],
) -> dict[str, Any]:
    """Return {"alternative": dict|None, "verdict": dict}. EXECUTES NOTHING.

    ``primary`` is display context: {"title","cmd","entry_id"}. ``search_fn`` is a ONE-arg KB
    search callable (the caller adapts a wider signature). On any LLM failure returns a soft
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
        parsed = llm.extract_json(llm.chat(_SYSTEM, user, cfg, json_mode=True))
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

    if alt is not None:
        # SCOPE CHECK — the same machinery a primary step gets. Wrap the alternative as a
        # one-step phase (the shape flag_foreign_refs expects), flag it, unwrap. Any foreign
        # host still named in a command lands as ``foreign_refs`` on the returned alternative.
        phases = [{
            "phase": "exploitation",
            "steps": [{
                **alt, "why": "", "from_writeup": False,
                "ai_suggested": alt["kind"] == "ai_suggested",
            }],
        }]
        phases = attack_path.flag_foreign_refs(phases, target, scope)
        alt = phases[0]["steps"][0]

    return {"alternative": alt, "verdict": verdict}
