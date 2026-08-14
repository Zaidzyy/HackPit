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
import reasoning
from cockpit import allowlist, config, executor
from reasoning import critic as _critic
from reasoning import diagnosis as _diagnosis
from reasoning import frontier as _frontier
from reasoning import ledger as _ledger
from reasoning import retrieval as _retrieval
from reasoning import schema as _schema
from reasoning import specialists as _specialists
from reasoning import tiering as _tiering

# KB RETRIEVER — injected by main.py at startup (dependency injection, like the AD scope
# resolver and the arsenal catalog). It stays None in the hermetic tests, which makes the
# fingerprint block "" and the prompt byte-for-byte what it was without it. Both are READ-ONLY
# callables: a KB search and a full-entry lookup by id. Neither runs anything.
_KB_SEARCH: Callable[[str], list[Any]] | None = None
_KB_GET_ENTRY: Callable[[str], Any] | None = None


def set_kb_retriever(
    search: Callable[[str], list[Any]] | None,
    get_entry: Callable[[str], Any] | None = None,
) -> None:
    """Wire the KB search + full-entry lookup the fingerprint block (2.7) retrieves through.

    ``search`` takes a query string and returns KB result rows; ``get_entry`` maps a result id to
    its full entry so the structured ``meta.fingerprint`` (which the lightweight search index does
    not carry) is available to the version-range match. Both are read-only."""
    global _KB_SEARCH, _KB_GET_ENTRY
    _KB_SEARCH = search
    _KB_GET_ENTRY = get_entry


# How much of each prior run's output to feed back (keeps the prompt bounded).
_RUN_OUTPUT_CHARS = 600
_MAX_RUNS_FED = 12
# A real engagement pivots on detail buried in tool output (service banners, subdomain lists,
# parameter names), so it gets a wider window + a bigger excerpt than the lab loop — but BOUNDED:
# the structured STATE block is authoritative (it dedupes + keeps every endpoint), so the raw run
# excerpts are only for detail the parsers miss. Feeding 20×1600 chars of raw tool output on top
# of the state pushed the real-target prompt past ~8k tokens, which STARVED small local models
# (an 8192-context model like a Llama-3 got a truncated prompt and no room to generate — it emitted
# "{" and stopped). These keep the prompt inside a small model's window with room to answer.
_RUN_OUTPUT_CHARS_REAL = 800
_MAX_RUNS_FED_REAL = 12
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
        "- You may propose ANY single command (one binary + its args) — any tool installed on "
        "the sandbox. There is no allowlist. Prefer tools from the TOOL ARSENAL block below: it "
        "is generated from what this sandbox actually has installed, so anything listed there is "
        "certain to exist. It runs argv-style (never a shell), so give the binary and its args, "
        "not a shell pipeline.\n"
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
        '"step_id": "<the plan step id this realizes, or omit>"'
        + _TASK_OPS_CONTRACT
        + _ASK_CONTRACT
        + _NOTE_CONTRACT
        + _schema.SYSTEM_CONTRACT
    )


#: How the model updates the live plan. Appended to BOTH system prompts so lab and
#: real-target loops keep the task tree current the same way.
#:
#: Operations, not a rewritten tree: the model says what CHANGED and code validates each
#: change against the stored tree. A bad id is rejected on its own and the rest still apply,
#: so one wrong reference never costs the other observations in the same response.
_TASK_OPS_CONTRACT = (
    ', "task_ops": [<optional; update the task tree with what this run established>]}\n'
    "TASK TREE — when a task tree is shown, keep it current in the SAME response. Add "
    '"task_ops" as a list of operations, each one of:\n'
    '  {"op": "mark_done", "id": "1.2", "evidence_run": "<run id that showed it>"}\n'
    '  {"op": "mark_na", "id": "3.1", "why": "<what ruled this branch out>"}\n'
    '  {"op": "add_subtask", "parent": "2", "title": "<what the results newly opened up>"}\n'
    '  {"op": "add_root", "title": "<a whole new line of attack>"}\n'
    '  {"op": "retitle", "id": "2.1", "title": "<a sharper description>"}\n'
    "Only reference ids that appear in the tree. Mark a branch not-applicable as soon as "
    "the evidence rules it out — a dead branch left open wastes later turns. Omit task_ops "
    "entirely when nothing changed."
)

#: How the model asks the OPERATOR for something a command cannot get. Appended to both prompts.
#: The answer is stored and fed back into the next turn's prompt (build_user_prompt), so the
#: loop can continue past a human-only blocker (a login/session cookie, a 2FA code, a CAPTCHA
#: solved, an authorization call) instead of stalling or inventing a command that cannot work.
_ASK_CONTRACT = (
    "\nASK THE OPERATOR — some steps need something only the human can provide: a session "
    "cookie or bearer token after they log in, a 2FA/OTP code, an anti-bot/CAPTCHA challenge "
    "solved, or an authorization decision. When THAT is the blocker, do NOT invent a command. "
    'Instead return {"done": false, "ask": {"instructions": "<clear step-by-step for the '
    'operator to produce the value>", "label": "<short name, e.g. session cookie>"}} and NO '
    '"command" field. The operator\'s answer is added to your context for the next turn. Ask '
    "only for what a command genuinely cannot obtain — prefer a real command whenever one works."
)

#: How the model TALKS to the operator — a running-commentary note beside the proposal, not a
#: blocker. Distinct from ``rationale`` (which explains the command on the approval card): a
#: note is conversational, lands in the operator's chat pane, and is fed back into the next
#: prompt (see :func:`_conversation_reference`) so the loop and the operator hold one thread.
#: Optional and additive — omitting it leaves the proposal unchanged.
_NOTE_CONTRACT = (
    "\nTALK TO THE OPERATOR (optional) — you MAY add a top-level \"note\": \"<one plain-language "
    "sentence>\", but ONLY when there is genuinely something worth flagging. Concretely, add one "
    "when: a result is surprising or telling ('that 401 is app-key gated, not a login problem — "
    "the key isn't in the web bundle'); you have a doubt or a judgement call the operator should "
    "weigh ('not sure this host is in scope — worth a check?'); or you hit a decision point / "
    "dead end worth surfacing. On ordinary routine steps, OMIT it — do not narrate every command "
    "and never just restate the rationale (which already justifies the command on the approval "
    "card). Skipping it saves tokens and keeps the channel signal, not noise. The note is "
    "conversational and goes to the operator's CHAT. It never replaces the command — still "
    "propose your best next step."
)


def _ask_proposal(
    *, instructions: str, label: str, rationale: str, step_id: str | None
) -> dict[str, Any]:
    """A proposal that is a QUESTION FOR THE OPERATOR, not a command. It carries no command and
    EXECUTES NOTHING — the loop UI renders an input, and the answer is stored
    (state.store.add_operator_context) and fed into the next prompt. Every LoopProposal field is
    present so the response model validates; the command fields are empty and gate_ok is False."""
    return {
        "kind": "ask",
        "ask_instructions": instructions,
        "ask_label": label,
        "note": "",
        "command": "",
        "args": [],
        "rationale": rationale,
        "step_id": step_id,
        "gate_ok": False,
        "gate_reason": "",
        "dangerous_flags": [],
        "hypothesis": "",
        "expected_signal": "",
        "citations": [],
        "schema_valid": True,
        "schema_problems": [],
        "critique": {},
        "specialist": "generalist",
        "frontier": {},
    }


def _operator_context_reference(session_id: str | None) -> str:
    """Answers the operator gave to earlier 'ask' steps, rendered for the next prompt. Read-only."""
    if not session_id:
        return ""
    try:
        from state import store as state_store

        items = state_store.list_operator_context(session_id)
    except Exception:  # noqa: BLE001 - a reference block must never break the loop
        return ""
    if not items:
        return ""
    lines = [
        "OPERATOR-PROVIDED CONTEXT (you asked for these and the operator answered — use them "
        "in the next command; a value here is authoritative):"
    ]
    for it in items:
        label = (it.get("label") or "answer").strip()
        lines.append(f"  - {label}: {it.get('text', '')}")
    return "\n".join(lines)


#: How many recent chat turns to feed the proposer, and the per-turn cap. Small: the
#: conversation STEERS the next step, it doesn't replace the state/plan grounding.
_MAX_CHAT_TURNS = 6
_CHAT_TURN_CHARS = 500


def _conversation_reference(session_id: str | None) -> str:
    """The recent operator<->loop chat, so a message the operator typed STEERS the next
    proposal (and so the loop sees its OWN prior notes). Read-only; wrapped so a chat-store
    hiccup can never break the loop — it just yields no steering block.

    Both sides live in one transcript: operator messages (role 'user'), the assistant's chat
    replies, and the loop's own notes (kind 'note'). A direct instruction here is treated as
    authoritative — it is what makes the loop feel hands-on-the-wheel."""
    if not session_id:
        return ""
    try:
        import sessions as sessions_db

        session = sessions_db.get_session(session_id)
        history = (session or {}).get("chat_history") or []
    except Exception:  # noqa: BLE001 - a reference block must never break the loop
        return ""
    if not history:
        return ""
    lines = [
        "CONVERSATION WITH THE OPERATOR (most recent last — the operator may STEER you here; a "
        "direct instruction is authoritative, weigh it above your default plan). Turns tagged "
        "'YOU (note)' are your own earlier remarks:"
    ]
    for turn in history[-_MAX_CHAT_TURNS:]:
        who = "OPERATOR" if turn.get("role") == "user" else "YOU"
        tag = " (note)" if turn.get("kind") == "note" else ""
        content = (turn.get("content") or "").strip().replace("\n", " ")
        if len(content) > _CHAT_TURN_CHARS:
            content = content[:_CHAT_TURN_CHARS] + " …"
        if content:
            lines.append(f"  {who}{tag}: {content}")
    return "\n".join(lines) if len(lines) > 1 else ""


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
        "- You may propose ANY single command (one binary + its args) — any tool installed on "
        "the sandbox. There is no allowlist. Prefer tools from the TOOL ARSENAL block below: it "
        "is generated from what this sandbox actually has installed, so anything listed there is "
        "certain to exist. It runs argv-style (never a shell), so give the binary and its args, "
        "not a shell pipeline.\n"
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
        "- RECON ORDERING (advisory — you still propose ONE approved command at a time, never a "
        "chain): subdomain enumeration compounds in this order — passive (subfinder, "
        "github-subdomains) -> certificate transparency (amass -passive) -> ASN/CIDR (asnmap, "
        "mapcidr) -> permutations (gotator, regulator) -> resolve + wildcard-filter (puredns) -> "
        "NOERROR (dnsx) -> TLS/CSP scraping (tlsx, csprecon). For web content: harvest URLs (gau, "
        "waybackurls, katana) -> triage by bug class (gf) -> inject values (qsreplace) -> scan "
        "that class (dalfox, nuclei -dast, sqlmap), and mine JS (subjs, jsluice) for endpoints and "
        "secrets. The KB 'recon-methodology-*' entries carry the full sequences.\n"
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
        '"step_id": "<the plan step id this realizes, or omit>"'
        + _TASK_OPS_CONTRACT
        + _ASK_CONTRACT
        + _NOTE_CONTRACT
        + _schema.SYSTEM_CONTRACT
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


def _arsenal_reference(goal: str) -> str:
    """The tool catalog's invocations, as prompt reference for the next proposal.

    Best-effort and additive: any problem loading the catalog yields "", which makes the
    proposer prompt byte-for-byte what it was before the arsenal existed.

    Grounded in what the sandbox ACTUALLY has: the block is filtered by the startup
    reconciliation probe (D7), so a tool that is catalogued but not installed is never
    shown to the model and therefore never proposed. When the probe could not run (Docker
    down), the filter passes everything — absence has to be proven, not assumed.
    """
    try:
        import attack_path
        from arsenal import planner as arsenal_planner
        from cockpit import reconcile

        return arsenal_planner.prompt_block(
            attack_path._arsenal(),
            needle=goal,
            is_available=reconcile.current().is_present,
        )
    except Exception:  # noqa: BLE001 - a reference block must never break the loop
        return ""


def _state_reference(session_id: str | None) -> str:
    """The accumulated engagement state as prompt text.

    This is what replaces re-reading stdout tails: hosts, services, endpoints, credentials,
    findings and the live task tree, deduplicated across every run so far. A tail window
    forgets — a service found on run 3 is gone by run 20 — and state does not.

    Best-effort and additive: no session, no state, or any failure yields "", which makes
    the prompt byte-for-byte what it was before the state model existed.
    """
    if not session_id:
        return ""
    try:
        from state import render as state_render
        from state import store as state_store

        return state_render.render_state(state_store.load(session_id), session_id)
    except Exception:  # noqa: BLE001 - a reference block must never break the loop
        return ""


def _reasoning_reference(
    runs: list[dict], avoid: list[str], session_id: str | None
) -> str:
    """The reasoning-copilot prompt blocks: the tried/failed ledger (2.1), a failure diagnosis
    hint (2.4) and the candidate frontier (2.3), assembled in one place.

    Best-effort and additive, exactly like :func:`_state_reference`: any failure (a table that
    does not exist yet, an empty session) yields "", so the prompt is byte-for-byte what it was
    before this package existed. None of these blocks executes anything — they are memory and
    guidance the proposer reads.
    """
    parts: list[str] = []
    try:
        parts.append(_ledger.render(runs, avoid, session_id or ""))
    except Exception:  # noqa: BLE001 - a reference block must never break the loop
        pass
    try:
        parts.append(_diagnosis.advice(runs))
    except Exception:  # noqa: BLE001
        pass
    if session_id:
        try:
            parts.append(_frontier.render(session_id))
        except Exception:  # noqa: BLE001
            pass
    return "\n".join(p for p in parts if p)


def _specialist_reference(session_id: str | None, runs: list[dict]) -> str:
    """The domain-specialist framing (2.6) for the current situation. "" for the generalist."""
    if not session_id:
        return ""
    try:
        from state import store as state_store

        state = state_store.load(session_id)
        last_cmd = ""
        if runs:
            last = runs[-1]
            last_cmd = " ".join(
                [str(last.get("command") or ""), *[str(a) for a in (last.get("args") or [])]]
            )
        return _specialists.prompt_fragment(_specialists.route(state, last_cmd))
    except Exception:  # noqa: BLE001
        return ""


_MAX_FP_SERVICES = 4
_MAX_FP_ENTRIES = 2


def _fingerprint_reference(session_id: str | None) -> str:
    """Case-based KB writeups (2.7) for the fingerprinted services in state.

    For each discovered service that carries a version, retrieve the exploitation-writeup entries
    whose service+version fingerprint MATCHES — by the version verdict, not a keyword hit — and
    offer them as "this exact stack is commonly solved via X" grounding. Best-effort and additive:
    no retriever wired (the hermetic tests), no versioned services, or any failure yields "", so
    the prompt is byte-for-byte what it was without this block. Read-only: it retrieves, never runs.
    """
    if not session_id or _KB_SEARCH is None:
        return ""
    try:
        state = _load_state(session_id)
        seen: set[str] = set()
        lines: list[str] = []
        for svc in state.services:
            version = (getattr(svc, "version", "") or "").strip()
            product = (getattr(svc, "product", "") or getattr(svc, "name", "") or "").strip()
            if not (version and product):
                continue
            key = f"{product}/{version}".lower()
            if key in seen:
                continue
            seen.add(key)
            hits = _retrieval.retrieve(
                svc, _KB_SEARCH, limit=_MAX_FP_ENTRIES, get_entry=_KB_GET_ENTRY
            )
            for h in hits:
                if not h.fingerprint_match:
                    continue
                entry = h.entry
                eid = entry.get("id") if isinstance(entry, dict) else getattr(entry, "id", "")
                title = entry.get("title") if isinstance(entry, dict) else getattr(entry, "title", "")
                meta = (entry.get("meta") if isinstance(entry, dict) else getattr(entry, "meta", {})) or {}
                solved = (meta.get("fingerprint") or {}).get("solved_via") or ""
                lines.append(f"  - {product} {version} -> {title} [{eid}]" + (f": {solved}" if solved else ""))
            if len(seen) >= _MAX_FP_SERVICES:
                break
        if not lines:
            return ""
        header = (
            "\nFINGERPRINT-MATCHED WRITEUPS — case-based KB material for the exact service+version "
            "you have observed (matched by the version verdict, not keywords). Treat these as "
            "'this stack is commonly solved via X' leads; cite the entry id if you act on one:"
        )
        return "\n".join([header, *lines[: _MAX_FP_SERVICES * _MAX_FP_ENTRIES]])
    except Exception:  # noqa: BLE001 - a reference block must never break the loop
        return ""


def build_user_prompt(
    plan: dict,
    runs: list[dict],
    avoid: list[str],
    scope_ctx: ScopeContext | None = None,
    session_id: str | None = None,
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
    # TOOL ARSENAL — well-formed invocations for the standard toolbox, as REFERENCE for the
    # one command this turn proposes. It restricts nothing (there is no allowlist); it makes
    # the proposal well-formed. The command still needs the operator's approval to run.
    arsenal_block = _arsenal_reference(goal)
    if arsenal_block:
        lines.append(arsenal_block)
        lines.append("")
    # OPERATOR-PROVIDED CONTEXT — answers to earlier 'ask' steps (a session cookie, a decision).
    # Placed high so a value the human handed back steers the next command, not buried under runs.
    ctx_block = _operator_context_reference(session_id)
    if ctx_block:
        lines.append(ctx_block)
        lines.append("")
    # CONVERSATION — recent operator<->loop chat, placed high so a message the operator typed
    # steers this step (and the loop sees its own prior notes). Below the authoritative
    # ask-answers, above the plan/state grounding.
    convo_block = _conversation_reference(session_id)
    if convo_block:
        lines.append(convo_block)
        lines.append("")
    lines.append("THE PLAN (composed; use it to ground your next step):")
    lines.append(_plan_digest(plan))
    lines.append("")
    # STATE FIRST, raw output second. The structured picture is authoritative and complete;
    # the excerpts below it are only for detail the parsers do not model yet (banner text,
    # error messages, a tool whose output has no parser). Before this, the excerpts were
    # ALL the model had, which is why it could not reason about an attack surface.
    state_block = _state_reference(session_id)
    if state_block:
        lines.append(state_block)
        lines.append("")
        lines.append(
            "RAW OUTPUT EXCERPTS (recent runs only — for detail the state above does not "
            "capture; the state is authoritative):"
        )
    else:
        lines.append("ALREADY RUN (results so far — adapt to these):")
    lines.append(digest)
    # REASONING COPILOT — working memory (2.1), failure diagnosis (2.4) and the candidate
    # frontier (2.3). Additive: empty for a fresh session, so the base prompt is unchanged.
    reasoning_block = _reasoning_reference(runs, avoid or [], session_id)
    if reasoning_block:
        lines.append(reasoning_block)
    specialist_block = _specialist_reference(session_id, runs)
    if specialist_block:
        lines.append(specialist_block)
    # 2.7 — case-based KB writeups for the exact service+version fingerprints in state.
    fingerprint_block = _fingerprint_reference(session_id)
    if fingerprint_block:
        lines.append(fingerprint_block)
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


def _step_kind(session_id: str | None) -> str:
    """Is the next step 'hard' (worth a bigger model tier, if configured) or 'routine'?

    Hard once there is a foothold or a finding to exploit — that is where reasoning depth earns
    its cost. Best-effort; 'routine' on any doubt keeps the default-cheap path.
    """
    if not session_id:
        return "routine"
    try:
        from state import store as state_store

        st = state_store.load(session_id)
        if st.findings or st.credentials:
            return "hard"
    except Exception:  # noqa: BLE001
        pass
    return "routine"


def _load_state(session_id: str | None):
    from state import store as state_store

    return state_store.load(session_id or "")


def _exploit_index():
    """The CVE->exploit index if it is loaded and ready, else None (critic skips CVE checks)."""
    try:
        from exploits import index as exploit_index

        idx = exploit_index.get_index()
        return idx if getattr(idx, "ready", False) else None
    except Exception:  # noqa: BLE001
        return None


def _review_proposal(proposal: dict[str, Any], session_id: str | None) -> dict[str, Any]:
    """Critic pass (2.5): refute the proposal against state + the CVE index.

    ADVISORY ONLY — it downranks and flags, it never suppresses. A refuted proposal (e.g. a
    version-mismatched CVE) is surfaced with its concerns and a lowered confidence so the human
    sees it is shaky, but it is NOT recorded as a dead lead, so the proposer stays free to raise
    it again. The human decides; the critic only advises. (The persisted dead-lead path in
    ledger.record_dead exists for an explicit operator/critic ruling, and is intentionally not
    invoked here.)
    """
    try:
        state = _load_state(session_id)
        return _critic.critique(proposal, state, _exploit_index()).to_dict()
    except Exception:  # noqa: BLE001 - the critic must never break the loop
        return {"ok": True, "downrank": False, "confidence": 1.0, "concerns": [], "checks": []}


def _route_domain(session_id: str | None, runs: list[dict]) -> str:
    if not session_id:
        return "generalist"
    try:
        last = runs[-1] if runs else {}
        last_cmd = " ".join(
            [str(last.get("command") or ""), *[str(a) for a in (last.get("args") or [])]]
        )
        return _specialists.route(_load_state(session_id), last_cmd).domain
    except Exception:  # noqa: BLE001
        return "generalist"


def _update_frontier(
    session_id: str | None, parsed: dict[str, Any], command: str, args: list[str]
) -> dict[str, Any]:
    """Persist candidate leads the model surfaced (2.3) and mark the pursued one. The frontier
    holds UNTRIED leads a human may pivot to — it never runs or approves anything."""
    if not session_id:
        return {"open": 0, "pushed": 0}
    try:
        pushed = 0
        leads: list[Any] = []
        for c in parsed.get("candidates") or parsed.get("frontier") or []:
            if not isinstance(c, dict):
                continue
            cmd = str(c.get("command") or "").strip()
            if not cmd:
                continue
            try:
                evid = float(c.get("evidence", 0.5) or 0.5)
                payoff = float(c.get("payoff", 0.5) or 0.5)
            except (TypeError, ValueError):
                evid, payoff = 0.5, 0.5
            leads.append(
                _frontier.Lead(
                    hypothesis=str(c.get("hypothesis") or ""),
                    command=cmd,
                    args=[str(a) for a in (c.get("args") or [])],
                    evidence=evid,
                    payoff=payoff,
                    rationale=str(c.get("rationale") or ""),
                )
            )
        if leads:
            pushed = _frontier.push(session_id, leads)
        _frontier.mark(session_id, command, args, "pursued")
        return {"open": len(_frontier.open_leads(session_id)), "pushed": pushed}
    except Exception:  # noqa: BLE001
        return {"open": 0, "pushed": 0}


def propose_next(
    plan: dict,
    runs: list[dict],
    cfg: dict,
    avoid: list[str] | None = None,
    scope_ctx: ScopeContext | None = None,
    session_id: str | None = None,
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
    user = build_user_prompt(plan, runs, avoid or [], scope_ctx, session_id)
    # 2.8 model-tier routing — inert unless ``reasoning_tiers`` is configured, in which case a
    # hard step (a foothold/finding to exploit) can be routed to a more capable model.
    step_cfg = _tiering.select(cfg, _step_kind(session_id))
    raw = llm.chat(system, user, step_cfg, max_tokens=900, json_mode=True)
    parsed = llm.extract_json(raw)
    if not isinstance(parsed, dict):
        raise llm.LLMError("the model did not return a proposal object")

    # NOTE (build 2026-08-15): an optional conversational remark to the operator, carried on
    # whatever proposal we return and persisted to the chat transcript by the API layer.
    # Separate from ``rationale`` (which explains the command on the approval card).
    note = str(parsed.get("note") or "").strip()

    # TASK TREE (D-PTT): the model may return operations that update the live plan. They
    # are VALIDATED AND APPLIED BY CODE, never trusted wholesale — an unknown id or a bad
    # status is rejected individually and the rest still apply. The tree is the durable
    # record; the model can only mutate it in defined ways. Applying it here, before the
    # proposal is even validated, is deliberate: what the model LEARNED from the last run
    # is worth keeping even when the command it wants next turns out to be unusable.
    tree_result: dict[str, Any] | None = None
    if session_id and parsed.get("task_ops"):
        try:
            from state import tasks as task_tree

            tree_result = task_tree.apply_ops(session_id, parsed.get("task_ops")).to_dict()
        except Exception:  # noqa: BLE001 - the tree must never break the loop
            tree_result = None

    if parsed.get("done") is True:
        return {
            "done": True, "proposal": None,
            "reason": "the agent judged recon complete",
            "task_tree": tree_result,
        }

    # ASK THE OPERATOR (build 2026-08-14): the model can request a value only the human can
    # provide (a session cookie, a 2FA code, a CAPTCHA solved, an authorization call) instead
    # of a command. It executes nothing; the answer is stored and fed back into the next prompt.
    ask = parsed.get("ask")
    if isinstance(ask, dict) and str(ask.get("instructions") or "").strip():
        step_id = parsed.get("step_id")
        ask_prop = _ask_proposal(
            instructions=str(ask.get("instructions")).strip(),
            label=str(ask.get("label") or "").strip(),
            rationale=str(parsed.get("rationale") or "").strip(),
            step_id=str(step_id).strip()
            if isinstance(step_id, str) and step_id.strip()
            else None,
        )
        ask_prop["note"] = note
        return {
            "done": False,
            "proposal": ask_prop,
            "reason": None,
            "task_tree": tree_result,
        }

    command = str(parsed.get("command") or "").strip()
    args = _coerce_args(parsed.get("args"))
    if not command:
        return {
            "done": True,
            "proposal": None,
            "reason": "the agent proposed no further command",
            "task_tree": tree_result,
        }

    gate_ok, gate_reason = precheck(command, args, scope_ctx)
    # Heuristic danger reasons are surfaced (never a pre-check failure): the UI shows them
    # RED and requires an explicit confirm before approve. Empty for a plainly-safe command.
    dangerous = allowlist.dangerous_command_heuristic(command, args)
    step_id = parsed.get("step_id")
    proposal = {
        "kind": "command",
        "command": command,
        "args": args,
        "rationale": str(parsed.get("rationale") or "").strip(),
        "step_id": str(step_id).strip() if isinstance(step_id, str) and step_id.strip() else None,
        "gate_ok": gate_ok,
        "gate_reason": gate_reason,
        "dangerous_flags": dangerous,
        "note": note,
    }
    # REASONING FIELDS (2.2): the hypothesis, expected signal and citations the model led with,
    # plus whether they satisfy the invariant-3 schema gate. Additive — the command/args/gate
    # fields above are unchanged, so every existing consumer keeps working.
    proposal.update(_schema.normalize(parsed))
    schema_ok, schema_problems = _schema.validate(proposal)
    proposal["schema_valid"] = schema_ok
    proposal["schema_problems"] = schema_problems
    # CRITIC (2.5): refute-first review; SPECIALIST (2.6): which expert lens; FRONTIER (2.3):
    # persist candidate leads + mark this one pursued. All read-only / propose-only.
    proposal["critique"] = _review_proposal(proposal, session_id)
    proposal["specialist"] = _route_domain(session_id, runs)
    proposal["frontier"] = _update_frontier(session_id, parsed, command, args)
    return {"done": False, "proposal": proposal, "reason": None, "task_tree": tree_result}
