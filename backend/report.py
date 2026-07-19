"""Pentest report generation — turn a worked engagement into a written report.

Given a session (goal, the composed path, and per-step ``checked`` + pasted
``result_text``), the LLM drafts a professional penetration-test report in
Markdown. The hard constraint is **grounding**: findings, evidence, and the
attack narrative come ONLY from steps the user actually completed and the
output they pasted — the model must not invent findings or fabricate command
output that isn't in the session.

The full path is still described as the *methodology* (what the engagement set
out to do), but the Findings / Evidence sections are anchored to real work.

Reports are long-form, so the caller raises the token budget (`_MAX_TOKENS`).
This module imports ``llm`` (the provider-swappable chat layer) but not FastAPI.
"""

from __future__ import annotations

import llm

# Reports are long; give the model room so sections aren't truncated. Local
# models are slower at this length — acceptable for a one-shot report.
_MAX_TOKENS = 4096

_SYSTEM = (
    "You are a senior penetration tester writing the final report for an "
    "AUTHORIZED engagement. You write in clean professional Markdown with the "
    "concise, factual tone of an OSCP/CPTS report.\n"
    "STRICT GROUNDING RULES:\n"
    "- Base all findings, evidence, and the attack narrative ONLY on the steps "
    "marked COMPLETED and the evidence pasted by the tester. NEVER invent "
    "findings, command output, hashes, credentials, IPs, or results that are "
    "not present in the provided data.\n"
    "- A completed step with no pasted evidence may be described as performed, "
    "but do NOT fabricate its output.\n"
    "- Steps that were NOT completed must not appear as findings; the full "
    "planned path may be summarised under Methodology only.\n"
    "- When you show evidence, use fenced code blocks containing the tester's "
    "actual pasted text — do not paraphrase or embellish it.\n"
    "Write the report with these sections as Markdown headings:\n"
    "1. Executive Summary\n"
    "2. Scope & Target\n"
    "3. Methodology (the phases followed)\n"
    "4. Findings & Attack Narrative (walk the COMPLETED steps in order, per "
    "phase — what was done, the command(s) used, and the evidence)\n"
    "5. Evidence (the pasted results as output blocks)\n"
    "6. Remediation Recommendations\n"
    "7. Conclusion\n"
    "Output ONLY the Markdown report — no preamble, no explanation."
)


def _clean_markdown(text: str) -> str:
    """Strip reasoning and unwrap a whole-document ``` fence if the model added one."""
    text = llm.strip_think(text).strip()
    if text.startswith("```"):
        # drop the opening fence line (``` or ```markdown) and a trailing fence
        first_nl = text.find("\n")
        if first_nl != -1:
            text = text[first_nl + 1 :]
        if text.rstrip().endswith("```"):
            text = text.rstrip()[:-3]
    return text.strip()


def _fmt_commands(step: dict) -> list[str]:
    lines: list[str] = []
    for c in step.get("commands", []) or []:
        cmd = (c.get("cmd") or "").strip()
        if cmd:
            lines.append(cmd)
    return lines


def build_prompt(session: dict) -> str:
    """Render the session into a grounding-first prompt for the report."""
    goal = session.get("goal", "")
    ttype = session.get("target_type") or "unspecified"
    checked = session.get("checked", 0)
    total = session.get("total", 0)

    lines: list[str] = []
    lines.append(f"ENGAGEMENT: {session.get('label', goal)}")
    lines.append(f"GOAL: {goal}")
    lines.append(f"TARGET TYPE: {ttype}")
    lines.append(f"PROGRESS: {checked} of {total} steps completed")
    lines.append("")
    lines.append(
        "Below is the engagement. Each phase lists its steps. Each step is "
        "marked [COMPLETED] or [NOT DONE], with its commands and — where the "
        "tester captured output — an EVIDENCE block. Use COMPLETED steps and "
        "their EVIDENCE for the findings/narrative; use the whole list for "
        "methodology only."
    )
    lines.append("")

    for phase in session.get("path", {}).get("phases", []) or []:
        lines.append(f"## PHASE: {phase.get('label', phase.get('phase',''))}")
        for step in phase.get("steps", []) or []:
            status = "COMPLETED" if step.get("checked") else "NOT DONE"
            lines.append(f"### [{status}] {step.get('title','')}")
            cmds = _fmt_commands(step)
            if cmds:
                lines.append("Commands:")
                for c in cmds:
                    lines.append(f"    {c}")
            evidence = (step.get("result_text") or "").strip()
            if evidence:
                lines.append("EVIDENCE (tester's pasted output — use verbatim):")
                lines.append("<<<EVIDENCE")
                lines.append(evidence)
                lines.append("EVIDENCE>>>")
            else:
                lines.append("EVIDENCE: (none captured)")
            lines.append("")

    lines.append(
        "Now write the full Markdown penetration-test report following the "
        "required sections. Remember: do not fabricate any finding or output "
        "not shown above."
    )
    return "\n".join(lines)


def compose_report(session: dict) -> tuple[str, str]:
    """Draft the report for a session. Returns (markdown, model_used).

    Raises ``llm.LLMError`` if the provider is unreachable or returns nothing.
    """
    cfg = llm.load_config()
    user = build_prompt(session)
    raw = llm.chat(_SYSTEM, user, cfg, max_tokens=_MAX_TOKENS)
    md = _clean_markdown(raw)
    if not md:
        raise llm.LLMError("the model returned an empty report")
    return md, cfg["model"]
