"""The orchestrator loop — propose the NEXT single command (no execution).

This is the L1 core of the guided agent loop (docs/cockpit-loop.md): given the composed
plan + the results-so-far, ask the LLM for the ONE next command. It returns a PROPOSAL —
it does NOT run anything.

TWO MODES (the proposer is mode-aware; see docs/ENGAGEMENT-LOOP-REAL-TARGET.md):
* LAB (``scope_ctx is None``) — the default and completely unchanged: the only target is the
  isolated lab host, and the prompts/pre-check are byte-for-byte what they always were.
* REAL TARGET — the caller passes a :class:`ScopeContext` describing the authorized PROGRAM
  SCOPE (in-scope patterns, exclusions, the live allowed hosts incl. recon-discovered ones).
  The proposer is then told to target that scope, never the lab, and the pre-check is run
  against the same scope matcher the executor's target-lock uses.

Safety posture (this is where autonomy enters, so read carefully):
* The proposer only SUGGESTS. Execution happens elsewhere, through the M1 executor
  (`POST /cockpit/exec`), which re-checks the mode's gates. This module never execs, never
  touches Docker, and never imports the `:kali` shell — it has no path to run anything.
* It also has NO capability to enter or resolve a real-target mode: it cannot tag a proposal
  for one, and it never reads the mode registry. The caller resolves the mode and hands in a
  plain, read-only context — regression-locked in test_engagement_mode.py.
* A human approves every command, in BOTH modes. This module is called once per step to fill
  the `awaiting-approval` state; nothing here advances the loop or runs a command.
* The pre-check is advisory transparency so the UI can flag a proposal that wouldn't run —
  enforcement is the executor's gates at run time, not this pre-check.

State is read from the existing session/run store (the session's plan + its recorded runs);
this module holds none of its own.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable

import llm
from cockpit import allowlist, config, executor

# How much of each prior run's output to feed back (keeps the prompt bounded).
_RUN_OUTPUT_CHARS = 600
_MAX_RUNS_FED = 12
# A real engagement pivots on detail buried in tool output (service banners, subdomain lists,
# parameter names), so it gets a wider window + a bigger excerpt than the lab loop.
_RUN_OUTPUT_CHARS_REAL = 1600
_MAX_RUNS_FED_REAL = 20
_MAX_PLAN_STEPS = 30
_MAX_HOSTS_LISTED = 40


@dataclass(frozen=True)
class ScopeContext:
    """The authorized REAL-TARGET scope the loop is driving (``None`` everywhere = lab mode).

    Read-only and inert: it carries what the proposer must know (what it may target) and the
    matcher the pre-check uses. It holds no ids, no capability, and nothing that could run.
    """

    target: str                                  # the primary named target
    scope: str                                   # the scope spec as the operator wrote it
    include: tuple[str, ...] = ()                # in-scope patterns (hosts, *.wildcards, CIDRs)
    exclude: tuple[str, ...] = ()                # exclusions — never target these
    allowed_hosts: tuple[str, ...] = ()          # live allowed set (scope hosts + discovered)
    out_of_scope_seen: tuple[str, ...] = ()      # discovered but OUT of scope — never target
    in_scope: Callable[[str], bool] | None = field(default=None, compare=False)

    def label(self) -> str:
        return self.scope or self.target


def _system_prompt(scope_ctx: ScopeContext | None = None) -> str:
    if scope_ctx is not None:
        return _real_target_system_prompt(scope_ctx)
    lab = config.LAB_TARGET_HOST
    return (
        "You are driving an AUTHORIZED penetration test against a single, ISOLATED lab "
        "target (a deliberately vulnerable web app). You do NOT run commands yourself — you "
        "propose ONE next command and a human approves it before it runs.\n"
        "HARD RULES:\n"
        "- You may propose ANY single command (one binary + its args) — any tool on the "
        "sandbox (nmap, curl, sqlmap, ffuf, nuclei, gobuster, nikto, and more). There is no "
        "allowlist. It runs argv-style (never a shell), so give the binary and its args, not "
        "a shell pipeline.\n"
        f"- The ONLY target is the lab host '{lab}' (or a URL on it, e.g. "
        f"http://{lab}:3000/). NEVER propose any other host, IP, or the internet. Point the "
        f"tool's target at the lab (e.g. -u http://{lab}:3000/…).\n"
        "- Work the kill chain: recon/enumerate first (service scan, HTTP fetch, "
        "fingerprint), then exploit what you find (e.g. sqlmap against a parameter you saw, "
        "ffuf to discover paths, nuclei to check known CVEs).\n"
        "- Commands that run arbitrary code (python/bash -c, nc -e, reverse shells, "
        "msfvenom) are ALLOWED when they genuinely advance the test, but the human must give "
        "an EXTRA explicit confirm for them — so only propose one when it is clearly the "
        "right next step, and say why in the rationale.\n"
        "- Propose the SINGLE most useful next step given the plan and what has already "
        "been run — adapt to prior results. Do not repeat a command already run.\n"
        "- When the objective is met, or no useful next step remains, return "
        '{"done": true}.\n'
        "Output ONLY a JSON object, no prose, shaped exactly like:\n"
        '{"done": false, "command": "sqlmap", "args": ["-u", "http://'
        + lab
        + ':3000/rest/products/search?q=1", "--batch", "--dbs"], '
        '"rationale": "<1-2 sentences: why this is the next step>", '
        '"step_id": "<the plan step id this realizes, or omit>"}'
    )


def _real_target_system_prompt(ctx: ScopeContext) -> str:
    """The REAL-TARGET system prompt. The lab is never mentioned; the authorized program scope
    replaces it, and staying inside it is the hardest rule in the prompt."""
    primary = ctx.allowed_hosts[0] if ctx.allowed_hosts else ctx.target
    inc = ", ".join(ctx.include) or ctx.target
    exc = ", ".join(ctx.exclude)
    return (
        "You are driving an AUTHORIZED penetration test against a REAL, PRODUCTION target, "
        "under a written program scope the operator has confirmed they are authorized to test. "
        "You do NOT run commands yourself — you propose ONE next command and a human reviews "
        "and approves it before it runs. Every single command is approved individually.\n"
        "HARD RULES:\n"
        "- You may propose ANY single command (one binary + its args) — any tool on the "
        "sandbox (nmap, curl, sqlmap, ffuf, nuclei, gobuster, nikto, dig, whatweb, and more). "
        "There is no allowlist. It runs argv-style (never a shell), so give the binary and its "
        "args, not a shell pipeline.\n"
        f"- SCOPE IS ABSOLUTE. You may ONLY target hosts inside the authorized scope: {inc}. "
        + (f"NEVER target these, they are explicitly out of scope: {exc}. " if exc else "")
        + "Never target any other host, any third-party service, the operator's own machine or "
        "LAN, or the internet at large. A '*.domain' pattern covers its SUBdomains. If you are "
        "not certain a host is in scope, do not propose it.\n"
        "- You MAY pivot between in-scope hosts: prefer the KNOWN HOSTS listed in the user "
        "message (they are confirmed in scope, including ones earlier recon discovered), and "
        "you may also target any other host that matches an in-scope pattern.\n"
        "- This is a real target, so be deliberate: recon and enumerate first (resolve, port/"
        "service scan, HTTP fingerprint, subdomain/content discovery), then test what you "
        "actually found (e.g. sqlmap against a parameter you SAW, nuclei against the stack you "
        "IDENTIFIED). Do not fire destructive or noisy tooling speculatively.\n"
        "- Commands that run arbitrary code (python/bash -c, nc -e, reverse shells, msfvenom) "
        "are ALLOWED when they genuinely advance the test, but the human must give an EXTRA "
        "explicit confirm for them — so only propose one when it is clearly the right next "
        "step, and say why in the rationale.\n"
        "- Propose the SINGLE most useful next step given the plan and what has already been "
        "run — adapt to prior results, follow up on what the output revealed. Do not repeat a "
        "command already run.\n"
        "- When the objective is met, or no useful next step remains, return "
        '{"done": true}.\n'
        "Output ONLY a JSON object, no prose, shaped exactly like:\n"
        '{"done": false, "command": "nmap", "args": ["-sV", "-p-", "'
        + primary
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


def _runs_digest(
    runs: list[dict], max_runs: int = _MAX_RUNS_FED, out_chars: int = _RUN_OUTPUT_CHARS
) -> str:
    """What has already been run: command line + exit + a short output excerpt.

    The defaults are the lab window (12 runs × 600 chars, unchanged); a real engagement passes
    the wider one so the model can act on detail buried further back in the output.
    """
    if not runs:
        return "(nothing has been run yet — propose the first recon step)"
    lines: list[str] = []
    for r in runs[-max_runs:]:
        cmdline = " ".join(
            [str(r.get("command") or ""), *[str(a) for a in (r.get("args") or [])]]
        ).strip()
        out = ((r.get("stdout") or "") + (r.get("stderr") or "")).strip()
        if len(out) > out_chars:
            out = out[:out_chars] + " …[truncated]"
        lines.append(f"$ {cmdline}")
        lines.append(f"  exit {r.get('exit_code')}")
        if out:
            # indent the captured output so it reads as a block
            for ln in out.splitlines():
                lines.append(f"  | {ln}")
    return "\n".join(lines)


def build_user_prompt(
    plan: dict, runs: list[dict], avoid: list[str], scope_ctx: ScopeContext | None = None
) -> str:
    goal = plan.get("goal") or ""
    if scope_ctx is not None:
        lines = [f"GOAL: {goal}", f"REAL TARGET: {scope_ctx.target}", ""]
        lines.append("AUTHORIZED SCOPE — you may ONLY target hosts matching these patterns:")
        for pat in scope_ctx.include or (scope_ctx.target,):
            lines.append(f"  IN SCOPE: {pat}")
        for pat in scope_ctx.exclude:
            lines.append(f"  OUT OF SCOPE (never target): {pat}")
        if scope_ctx.allowed_hosts:
            lines.append("")
            lines.append(
                "KNOWN IN-SCOPE HOSTS (confirmed — includes hosts earlier recon discovered; "
                "you may target any of these):"
            )
            for host in scope_ctx.allowed_hosts[:_MAX_HOSTS_LISTED]:
                lines.append(f"  - {host}")
        if scope_ctx.out_of_scope_seen:
            lines.append("")
            lines.append(
                "SEEN BUT OUT OF SCOPE (recon revealed these; they are NOT authorized — never "
                "propose a command against them):"
            )
            for host in scope_ctx.out_of_scope_seen[:_MAX_HOSTS_LISTED]:
                lines.append(f"  - {host}")
        lines.append("")
        digest = _runs_digest(runs, _MAX_RUNS_FED_REAL, _RUN_OUTPUT_CHARS_REAL)
    else:
        lab = config.LAB_TARGET_HOST
        lines = [f"GOAL: {goal}", f"LAB TARGET: {lab}", ""]
        digest = _runs_digest(runs)
    lines.append("THE PLAN (composed; use it to ground your next step):")
    lines.append(_plan_digest(plan))
    lines.append("")
    lines.append("ALREADY RUN (results so far — adapt to these):")
    lines.append(digest)
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
    if scope_ctx is not None:
        lines.append(
            "Propose the single next command as JSON (or {\"done\": true} if the objective is "
            "covered). It must target a host inside the authorized scope above — nothing else."
        )
    else:
        lines.append(
            "Propose the single next recon command as JSON (or {\"done\": true} if recon is "
            "sufficiently covered). Only the allowlisted commands, only the lab target."
        )
    return "\n".join(lines)


def precheck(
    command: str, args: list[str], scope_ctx: ScopeContext | None = None
) -> tuple[bool, str]:
    """Pre-check a proposal against the real run-time gate that can REJECT it: the
    best-effort target-lock. In LAB mode a host-shaped token must be the lab (unchanged); with
    a ``scope_ctx`` it must be inside the authorized program scope — the SAME matcher the
    executor uses, so the UI's verdict matches the run-time one. There is no allowlist anymore,
    so any binary passes; a command flagged dangerous is NOT a pre-check failure (it runs after
    an explicit confirm — see the proposal's ``dangerous_flags``). Advisory transparency for the
    UI — the executor re-checks target + approval + danger (+ isolation, in lab mode).
    """
    if scope_ctx is not None:
        ok, reason = executor.check_target_lock(
            args,
            command,
            allowed=frozenset(scope_ctx.allowed_hosts) | {scope_ctx.target},
            label=scope_ctx.label(),
            in_scope=scope_ctx.in_scope,
        )
    else:
        ok, reason = executor.check_target_lock(args, command)
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
    plan: dict,
    runs: list[dict],
    cfg: dict,
    avoid: list[str] | None = None,
    scope_ctx: ScopeContext | None = None,
) -> dict[str, Any]:
    """Ask the LLM for the next single proposed command (no execution).

    ``scope_ctx`` selects the mode: ``None`` = the isolated lab (unchanged); a context =
    the authorized real-target program scope it must propose against.

    Returns ``{done, proposal|None, reason}`` where a proposal is
    ``{command, args, rationale, step_id, gate_ok, gate_reason}``. ``gate_ok`` is the
    advisory pre-check (see :func:`precheck`); a False proposal is returned flagged so
    the human sees it can't run — it is NEVER auto-executed, in either mode. Raises
    ``llm.LLMError`` if the model is unreachable / unparseable (the API maps that to 503).
    """
    system = _system_prompt(scope_ctx)
    user = build_user_prompt(plan, runs, avoid or [], scope_ctx)
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

    gate_ok, gate_reason = precheck(command, args, scope_ctx)
    # Heuristic danger reasons are surfaced (never a pre-check failure): the UI shows them
    # RED and requires an explicit confirm before approve. Empty for a plainly-safe command.
    dangerous = allowlist.dangerous_command_heuristic(command, args)
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
