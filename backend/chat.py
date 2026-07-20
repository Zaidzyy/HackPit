"""Engagement assistant — a session-aware, KB-grounded chat turn.

Where ``attack_path.py`` composes a path up-front and ``report.py`` writes it up
afterwards, this module answers questions *while the tester works*. One turn is:

  1. **Session context** — assemble what the engagement knows: goal/target, the
     composed path (phases + step titles), which steps are checked, and — the key
     adaptive signal — the output the tester pasted per step.
  2. **Retrieve** grounding — hybrid-search the KB with the tester's message plus
     salient session context, and fold in the engagement's own techniques, to get
     a small set of relevant KB entries (id/title/summary/real commands).
  3. **Compose** — prompt the LLM (see ``llm.py``) as an assistant on THIS
     authorized engagement, given the session context + retrieved techniques +
     prior chat history, to answer or suggest a grounded next step. It must reuse
     the retrieved entries' real commands and never invent commands.

Grounding of citations is **deterministic**, not trust-the-model: after the reply
is written we scan it for the retrieved entry_ids (and titles) it actually drew
on, and only emit ids that resolve to a real, servable KB entry — the same
"never link to a 404" guarantee ``attack_path`` gives.

The KB (``by_id`` + a search callable) is passed in, so this stays decoupled from
FastAPI and from how the KB is loaded.
"""

from __future__ import annotations

import re
from typing import Any, Callable

import attack_path
import llm

SearchFn = Callable[[str, int, str], list[dict]]

# tuning
_MAX_TECHNIQUES = 8        # retrieved entries handed to the model / eligible to cite
_CMDS_PER_ENTRY = 5        # commands shown per technique in the prompt
_SUMMARY_CHARS = 240
_CMD_CHARS = 300           # cap one command line in the prompt
_RESULT_CHARS = 800        # cap a step's pasted result in the session context
_HISTORY_TURNS = 6         # prior chat turns folded into the prompt
_HISTORY_CHARS = 700       # cap one prior turn when replaying it
_SALIENT_CHARS = 600       # cap the session signal mixed into the search query
_MAX_TOKENS = 1024         # replies are short and practical, not long-form
_PATH_BASELINE = 0.1       # score floor so the path's own techniques stay candidates


_SYSTEM = (
    "You are HackPit's engagement assistant, helping a security professional work "
    "through an AUTHORIZED penetration-testing engagement. You are given the "
    "tester's live session (goal, the attack path they are working, which steps "
    "are done, and the output they pasted) and a set of TECHNIQUES retrieved from "
    "their own knowledge base.\n"
    "Hard rules:\n"
    "- Ground every recommendation in the RETRIEVED TECHNIQUES. Reuse their real "
    "commands (they are the tester's own tested commands) — copy them, do not "
    "rewrite them. NEVER invent commands, flags, tools, or techniques that are "
    "not in the retrieved techniques.\n"
    "- When you use a technique, cite it by writing its entry_id in backticks, "
    "e.g. `ad-kerberoasting`, so the tester can open it.\n"
    "- Use the pasted RESULTS to decide the next move (e.g. 'you found 445 open "
    "and got a null session -> enumerate shares with ...'). If a step failed or "
    "returned nothing, suggest a grounded ALTERNATIVE from the techniques.\n"
    "- If the retrieved techniques do not cover the question, say so briefly "
    "instead of inventing an answer.\n"
    "- Be practical and concise: a short direct answer, then the concrete next "
    "command(s). This is a working tool, not a lecture.\n"
    "Formatting (GitHub-flavoured Markdown):\n"
    "- Write a brief prose answer — 1-3 short paragraphs or a tight bullet list.\n"
    "- Reference a technique by writing its entry_id inline in SINGLE backticks, "
    "e.g. `ad-kerberoasting`. NEVER put an entry_id in a triple-backtick code "
    "block or on a line by itself.\n"
    "- Use triple-backtick ```bash fenced blocks ONLY for shell commands."
)


# --------------------------------------------------------------------------- #
# 1) session context
# --------------------------------------------------------------------------- #
def build_session_context(session: dict) -> str:
    """Render the engagement into a grounding block for the prompt.

    Goal/target, progress, then each phase's steps marked done/not-done with the
    tester's pasted result (the key adaptive signal) inlined under each step.
    """
    goal = session.get("goal", "")
    ttype = session.get("target_type") or "unspecified"
    path = session.get("path") or {}
    target = path.get("target")

    lines: list[str] = [f"GOAL: {goal}", f"TARGET TYPE: {ttype}"]
    if target:
        lines.append(f"TARGET: {target}")
    lines.append(
        f"PROGRESS: {session.get('checked', 0)} of {session.get('total', 0)} "
        "steps done"
    )
    lines.append("")
    lines.append(
        "ATTACK PATH (✓ = done, ▢ = not done; RESULT = output the tester pasted):"
    )
    for phase in path.get("phases", []) or []:
        lines.append(f"## {phase.get('label', phase.get('phase', ''))}")
        for step in phase.get("steps", []) or []:
            mark = "✓" if step.get("checked") else "▢"
            sid = step.get("id", "")
            eid = step.get("entry_id", "")
            lines.append(f"{mark} ({sid}) {step.get('title', '')}  [technique: {eid}]")
            res = (step.get("result_text") or "").strip()
            if res:
                snippet = res[:_RESULT_CHARS]
                if len(res) > _RESULT_CHARS:
                    snippet += " …"
                lines.append(f"    RESULT: {snippet}")
        lines.append("")
    return "\n".join(lines).strip()


def _salient(session: dict) -> str:
    """A short signal string (goal + checked step titles + result snippets) that
    biases the retrieval query toward where the engagement actually is."""
    parts: list[str] = [session.get("goal", "")]
    for phase in (session.get("path") or {}).get("phases", []) or []:
        for step in phase.get("steps", []) or []:
            if step.get("checked"):
                parts.append(step.get("title", ""))
            res = (step.get("result_text") or "").strip()
            if res:
                parts.append(res[:200])
    return " ".join(p for p in parts if p and p.strip())[:_SALIENT_CHARS]


# --------------------------------------------------------------------------- #
# 2) retrieval
# --------------------------------------------------------------------------- #
def retrieve(
    by_id: dict[str, dict], message: str, session: dict, search_fn: SearchFn
) -> list[dict]:
    """Gather relevant KB techniques for the tester's message.

    A broad query on message + session signal, a sharper query on the message
    alone, then the engagement's own step techniques folded in as candidates so
    the assistant can always reference the path it is working. Ranked by best
    score, capped, each carrying its real commands.
    """
    best: dict[str, float] = {}

    def ingest(hits: list[dict]) -> None:
        for h in hits:
            eid = h.get("id")
            if not eid or eid not in by_id:
                continue
            if not attack_path.is_step_eligible(by_id[eid]):
                continue  # writeup/ctf, coarse grab-bag, or personal/log page — not a technique
            score = float(h.get("score") or 0.0)
            if eid not in best or score > best[eid]:
                best[eid] = score

    ingest(search_fn(f"{message} {_salient(session)}".strip(), 16, "hybrid"))
    ingest(search_fn(message, 10, "hybrid"))

    # the engagement's own techniques are always relevant candidates
    for phase in (session.get("path") or {}).get("phases", []) or []:
        for step in phase.get("steps", []) or []:
            eid = step.get("entry_id")
            if (eid and eid in by_id and eid not in best
                    and attack_path.is_step_eligible(by_id[eid])):
                best[eid] = _PATH_BASELINE

    ranked = sorted(best.items(), key=lambda kv: kv[1], reverse=True)
    out: list[dict] = []
    for eid, _score in ranked[:_MAX_TECHNIQUES]:
        e = by_id[eid]
        out.append(
            {
                "entry_id": eid,
                "title": e["title"],
                "summary": (e.get("summary") or "")[:_SUMMARY_CHARS],
                "commands": attack_path.entry_commands(e, cap=_CMDS_PER_ENTRY),
            }
        )
    return out


# --------------------------------------------------------------------------- #
# 3) prompt construction
# --------------------------------------------------------------------------- #
def build_prompt(
    session: dict,
    techniques: list[dict],
    history: list[dict],
    message: str,
) -> str:
    lines: list[str] = ["SESSION CONTEXT", build_session_context(session), ""]

    lines.append(
        "RETRIEVED TECHNIQUES (from the tester's knowledge base — cite these by "
        "entry_id, reuse their commands, invent nothing else):"
    )
    if not techniques:
        lines.append(
            "(none matched — tell the tester their notes don't seem to cover this "
            "and suggest how they might search for it.)"
        )
    for t in techniques:
        lines.append("")
        lines.append(f"- entry_id: {t['entry_id']}")
        lines.append(f"  title: {t['title']}")
        if t["summary"]:
            lines.append(f"  summary: {t['summary']}")
        for c in t["commands"]:
            cmd = (c.get("cmd") or "").strip().replace("\n", " ")
            if not cmd:
                continue
            if len(cmd) > _CMD_CHARS:
                cmd = cmd[:_CMD_CHARS] + " …"
            lines.append(f"  $ {cmd}")

    if history:
        lines.append("")
        lines.append("RECENT CONVERSATION (oldest first):")
        for turn in history[-_HISTORY_TURNS:]:
            who = "TESTER" if turn.get("role") == "user" else "ASSISTANT"
            content = (turn.get("content") or "").strip()[:_HISTORY_CHARS]
            lines.append(f"{who}: {content}")

    lines.append("")
    lines.append(f"TESTER'S QUESTION: {message}")
    lines.append("")
    lines.append(
        "Answer now. Ground the answer in the retrieved techniques, cite their "
        "entry_ids in backticks, reuse their real commands, and use the pasted "
        "RESULTS to choose the next move. Markdown only — no preamble."
    )
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# 4) grounding + compose
# --------------------------------------------------------------------------- #
_FENCE_OPEN_RE = re.compile(r"^```[a-zA-Z0-9]*\s*$")


def _unwrap_fence(text: str) -> str:
    """Drop a whole-document ``` fence ONLY if the model wrapped its ENTIRE reply.

    Guarded so it can't corrupt a reply that merely opens with an (ill-advised)
    fenced entry_id: the opener line must be a bare fence marker (``` or
    ```lang) and the final line must be a closing fence.
    """
    text = text.strip()
    lines = text.split("\n")
    if (
        len(lines) >= 2
        and _FENCE_OPEN_RE.match(lines[0])
        and lines[-1].strip() == "```"
    ):
        return "\n".join(lines[1:-1]).strip()
    return text


def ground_citations(
    reply: str, techniques: list[dict], by_id: dict[str, dict]
) -> list[str]:
    """Which retrieved techniques did the reply actually draw on?

    Deterministic: a technique is cited if its entry_id (or its title, when the
    title is distinctive enough to avoid trivial matches) appears in the reply.
    Emitted ids are guaranteed servable by ``/entry/{id}``, in relevance order.
    """
    low = reply.lower()
    cited: list[str] = []
    for t in techniques:
        eid = t["entry_id"]
        if eid in cited or eid not in by_id:
            continue
        title = (t.get("title") or "").strip().lower()
        if eid.lower() in low or (len(title) >= 6 and title in low):
            cited.append(eid)
    return cited


def answer(
    by_id: dict[str, dict], session: dict, message: str, search_fn: SearchFn
) -> tuple[str, list[str], str]:
    """Answer one engagement question. Returns (reply_markdown, cited_ids, model).

    Raises ``llm.LLMError`` if the provider is unreachable or returns nothing —
    the API layer maps that to a 503 the frontend renders.
    """
    cfg = llm.load_config()
    techniques = retrieve(by_id, message, session, search_fn)
    history = session.get("chat_history") or []

    user = build_prompt(session, techniques, history, message)
    raw = llm.chat(_SYSTEM, user, cfg, max_tokens=_MAX_TOKENS)
    reply = _unwrap_fence(llm.strip_think(raw))
    if not reply:
        raise llm.LLMError("the model returned an empty reply")

    cited = ground_citations(reply, techniques, by_id)
    return reply, cited, cfg["model"]
