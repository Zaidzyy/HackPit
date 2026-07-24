"""The orchestrator loop — propose the NEXT single command (no execution).

This is the L1 core of the guided agent loop (docs/cockpit-loop.md): given the composed
plan + the results-so-far, ask the LLM for the ONE next recon command to run against the
isolated lab. It returns a PROPOSAL — it does NOT run anything.

Safety posture (this is where autonomy enters, so read carefully):
* The proposer only SUGGESTS. Execution happens elsewhere, through the M1 executor
  (`POST /cockpit/exec`), which re-checks all four gates (allowlist → target-lock →
  approval → isolation). This module never execs, never touches Docker, and never
  imports the `:kali` shell — it has no path to run anything itself.
* A human approves every command. This module is called once per step to fill the
  `awaiting-approval` state; nothing here advances the loop or runs a command.
* Recon-only + lab-locked is what we ASK for, and we PRE-CHECK each proposal against the
  real M1 allowlist + target-lock so the UI can flag a proposal that wouldn't run — but
  the enforcement is the executor's gates at run time, not this pre-check.

State is read from the existing engagement/run store (the session's plan + its recorded
runs); this module holds none of its own.
"""

from __future__ import annotations

import json
from typing import Any

import llm
from cockpit import allowlist, config, executor

# The commands the loop may propose (== the M1 recon allowlist). Kept in sync with
# cockpit.allowlist.ALLOWLIST — the pre-check below uses that module directly, so this
# is only for the prompt text.
_ALLOWED = sorted(allowlist.ALLOWLIST)

# How much of each prior run's output to feed back (keeps the prompt bounded).
_RUN_OUTPUT_CHARS = 600
_MAX_RUNS_FED = 12
_MAX_PLAN_STEPS = 30


def _system_prompt() -> str:
    lab = config.LAB_TARGET_HOST
    cmds = ", ".join(_ALLOWED)
    return (
        "You are driving an AUTHORIZED, RECON-ONLY penetration test against a single, "
        "ISOLATED lab target. You do NOT run commands yourself — you propose ONE next "
        "command and a human approves it before it runs.\n"
        "HARD RULES:\n"
        f"- You may ONLY use these commands: {cmds}. Nothing else.\n"
        f"- The ONLY target is the lab host '{lab}' (or a URL on it, e.g. "
        f"http://{lab}:3000/). NEVER propose any other host, IP, or the internet.\n"
        "- Recon/enumeration only: service/version scans, HTTP fetches, web "
        "fingerprinting. No exploitation, no writes, no scripting engines "
        "(no nmap --script/-sC/-A, no file output).\n"
        "- Propose the SINGLE most useful next step given the plan and what has already "
        "been run — adapt to prior results (e.g. after finding a web port, fetch it; "
        "after a redirect, follow it). Do not repeat a command already run.\n"
        "- When the recon in the plan is sufficiently covered, or no useful allowlisted "
        'next step remains, return {"done": true}.\n'
        "Output ONLY a JSON object, no prose, shaped exactly like:\n"
        '{"done": false, "command": "nmap", "args": ["-sV", "-p", "3000", "'
        + lab
        + '"], "rationale": "<1-2 sentences: why this is the next step>", '
        '"step_id": "<the plan step id this realizes, or omit>"}'
    )


def _plan_digest(plan: dict) -> str:
    """Compact view of the composed plan to seed/ground the proposals."""
    lines: list[str] = []
    n = 0
    for phase in plan.get("phases") or []:
        label = phase.get("label") or phase.get("phase") or ""
        steps = phase.get("steps") or []
        if not steps:
            continue
        lines.append(f"## {label}")
        for s in steps:
            if n >= _MAX_PLAN_STEPS:
                break
            sid = s.get("id") or ""
            title = (s.get("title") or "").strip()
            lines.append(f"- {sid}: {title}")
            cmds = s.get("commands") or []
            if cmds:
                first = (cmds[0].get("cmd") or "").splitlines()[0][:160]
                if first:
                    lines.append(f"    e.g. {first}")
            n += 1
    return "\n".join(lines) if lines else "(the plan has no steps)"


def _runs_digest(runs: list[dict]) -> str:
    """What has already been run: command line + exit + a short output excerpt."""
    if not runs:
        return "(nothing has been run yet — propose the first recon step)"
    lines: list[str] = []
    for r in runs[-_MAX_RUNS_FED:]:
        cmdline = " ".join(
            [str(r.get("command") or ""), *[str(a) for a in (r.get("args") or [])]]
        ).strip()
        out = ((r.get("stdout") or "") + (r.get("stderr") or "")).strip()
        if len(out) > _RUN_OUTPUT_CHARS:
            out = out[:_RUN_OUTPUT_CHARS] + " …[truncated]"
        lines.append(f"$ {cmdline}")
        lines.append(f"  exit {r.get('exit_code')}")
        if out:
            # indent the captured output so it reads as a block
            for ln in out.splitlines():
                lines.append(f"  | {ln}")
    return "\n".join(lines)


def build_user_prompt(plan: dict, runs: list[dict], avoid: list[str]) -> str:
    goal = plan.get("goal") or ""
    lab = config.LAB_TARGET_HOST
    lines = [f"GOAL: {goal}", f"LAB TARGET: {lab}", ""]
    lines.append("THE PLAN (composed; use it to ground your next step):")
    lines.append(_plan_digest(plan))
    lines.append("")
    lines.append("ALREADY RUN (results so far — adapt to these):")
    lines.append(_runs_digest(runs))
    avoid = [a for a in (avoid or []) if a.strip()]
    if avoid:
        lines.append("")
        lines.append(
            "DO NOT propose any of these (the operator skipped them) — pick a different "
            "next step:"
        )
        for a in avoid[:10]:
            lines.append(f"- {a}")
    lines.append("")
    lines.append(
        "Propose the single next recon command as JSON (or {\"done\": true} if recon is "
        "sufficiently covered). Only the allowlisted commands, only the lab target."
    )
    return "\n".join(lines)


def precheck(command: str, args: list[str]) -> tuple[bool, str]:
    """Pre-check a proposal against the REAL M1 gates that will run it: the allowlist
    (recon commands, metachar-free args) + the target-lock (lab only). Returns
    (ok, reason). This is advisory transparency for the UI — the executor re-checks
    these (plus approval + isolation) at run time; nothing runs on the basis of this.
    """
    ok, reason = allowlist.validate(command, args)
    if not ok:
        return False, reason
    ok, reason = executor.check_target_lock(args)
    if not ok:
        return False, reason
    return True, ""


def _coerce_args(raw: Any) -> list[str]:
    if isinstance(raw, list):
        return [str(a) for a in raw]
    if isinstance(raw, str) and raw.strip():
        return raw.split()
    return []


def propose_next(
    plan: dict, runs: list[dict], cfg: dict, avoid: list[str] | None = None
) -> dict[str, Any]:
    """Ask the LLM for the next single proposed command (no execution).

    Returns ``{done, proposal|None, reason}`` where a proposal is
    ``{command, args, rationale, step_id, gate_ok, gate_reason}``. ``gate_ok`` is the
    advisory pre-check (see :func:`precheck`); a False proposal is returned flagged so
    the human sees it can't run — it is NEVER auto-executed. Raises ``llm.LLMError`` if
    the model is unreachable / unparseable (the API maps that to 503).
    """
    system = _system_prompt()
    user = build_user_prompt(plan, runs, avoid or [])
    raw = llm.chat(system, user, cfg, max_tokens=700)
    parsed = llm.extract_json(raw)
    if not isinstance(parsed, dict):
        raise llm.LLMError("the model did not return a proposal object")

    if parsed.get("done") is True:
        return {"done": True, "proposal": None, "reason": "the agent judged recon complete"}

    command = str(parsed.get("command") or "").strip()
    args = _coerce_args(parsed.get("args"))
    if not command:
        return {
            "done": True,
            "proposal": None,
            "reason": "the agent proposed no further command",
        }

    gate_ok, gate_reason = precheck(command, args)
    # Dangerous flags are DETECTED (never blocked): surfaced so the UI shows them RED and
    # requires an explicit confirm before approve. Empty for recon + benign active commands.
    dangerous = allowlist.dangerous_flags_present(command, args)
    step_id = parsed.get("step_id")
    proposal = {
        "command": command,
        "args": args,
        "rationale": str(parsed.get("rationale") or "").strip(),
        "step_id": str(step_id).strip() if isinstance(step_id, str) and step_id.strip() else None,
        "gate_ok": gate_ok,
        "gate_reason": gate_reason,
        "dangerous_flags": dangerous,
    }
    return {"done": False, "proposal": proposal, "reason": None}
