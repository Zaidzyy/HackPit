"""Pentest report generation — turn a worked engagement into a written report.

Given a session (goal, the composed path, and per-step ``checked`` + pasted
``result_text``), the LLM drafts a professional penetration-test report in
Markdown. Two hard constraints:

* **Grounding** — findings, evidence, and the attack narrative come ONLY from
  steps the user actually completed and the output they pasted; the model must
  not invent findings or fabricate output that isn't in the session.
* **Evidence integrity** — the captured evidence is reproduced *verbatim*. The
  model has been observed to mis-transcribe pasted output (e.g. a port ``445``
  became ``433``), so the **Evidence section is built programmatically from the
  session, not written by the model**. The LLM writes the narrative and may
  reference evidence, but the code-built Evidence section is the authoritative,
  byte-for-byte record. It is spliced in at a ``{{EVIDENCE}}`` placeholder (or,
  as a fallback, immediately before the Remediation section).

Reports are long-form, so the caller raises the token budget (`_MAX_TOKENS`).
This module imports ``llm`` (the provider-swappable chat layer) but not FastAPI.
"""

from __future__ import annotations

import re

import llm

# Reports are long; give the model room so sections aren't truncated. Local
# models are slower at this length — acceptable for a one-shot report.
_MAX_TOKENS = 4096

_EVIDENCE_MARKER = "{{EVIDENCE}}"

_SYSTEM = (
    "You are a senior penetration tester writing the final report for an "
    "AUTHORIZED engagement. You write in clean professional Markdown with the "
    "concise, factual tone of an OSCP/CPTS report.\n"
    "STRICT RULES:\n"
    "- Base all findings and the attack narrative ONLY on the steps marked "
    "COMPLETED and the evidence pasted by the tester. NEVER invent findings, "
    "command output, hashes, credentials, IPs, hostnames, or results not "
    "present in the provided data.\n"
    "- A completed step with no pasted evidence may be described as performed, "
    "but do NOT fabricate its output.\n"
    "- Steps that were NOT completed must not appear as findings.\n"
    "- EVIDENCE INTEGRITY: do NOT reproduce raw command output as fenced code "
    "blocks. The system inserts an authoritative, verbatim Evidence section. "
    "In your narrative, refer to captured evidence in prose and cite it by step "
    "id, e.g. '(see Evidence: recon-1)'. You may mention key values, but do NOT "
    "paste multi-line raw output — it would compete with the authoritative "
    "record.\n"
    "- METHODOLOGY: describe ONLY the phases listed in the engagement data "
    "below, using their exact names and order. Do NOT add, rename, or invent "
    "phases (e.g. do not add a 'Post-Exploitation' phase if it is not listed).\n"
    "Write the report with these sections as Markdown headings, in order:\n"
    "1. Executive Summary\n"
    "2. Scope & Target\n"
    "3. Methodology (the phases followed)\n"
    "4. Findings & Attack Narrative (walk the COMPLETED steps in order, per "
    "phase — what was done, the command(s) used, and what the evidence showed, "
    "citing it by step id)\n"
    f"5. Evidence — put a single line containing exactly {_EVIDENCE_MARKER} "
    "here and nothing else; do NOT write an Evidence heading or any output "
    "yourself. The system replaces the placeholder with the authoritative "
    "Evidence section.\n"
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


def _commands(step: dict) -> list[str]:
    out: list[str] = []
    for c in step.get("commands", []) or []:
        cmd = (c.get("cmd") or "").strip()
        if cmd:
            out.append(cmd)
    return out


def _completed_steps_with_evidence(session: dict):
    """Yield (step, commands, result_text) for completed steps that have output."""
    for phase in session.get("path", {}).get("phases", []) or []:
        for step in phase.get("steps", []) or []:
            if not step.get("checked"):
                continue
            raw = step.get("result_text") or ""
            if not raw.strip():
                continue
            yield step, _commands(step), raw


def _fence_for(content: str) -> str:
    """A backtick fence guaranteed longer than any backtick run in ``content``.

    So pasted output that itself contains ``` can't break out of the block —
    the evidence stays byte-for-byte intact.
    """
    longest = run = 0
    for ch in content:
        if ch == "`":
            run += 1
            longest = max(longest, run)
        else:
            run = 0
    return "`" * max(3, longest + 1)


def build_evidence_section(session: dict) -> str:
    """Construct the Evidence section programmatically — the source of truth.

    For each COMPLETED step with pasted output: the step id + title, its exact
    command(s), and the pasted ``result_text`` rendered VERBATIM in a fenced
    block. Nothing here passes through the model, so it can't be mistranscribed.
    """
    out: list[str] = [
        "## Evidence",
        "",
        "_Captured during the engagement and reproduced verbatim — this is the "
        "authoritative record._",
        "",
    ]
    any_ev = False
    for step, cmds, raw in _completed_steps_with_evidence(session):
        any_ev = True
        out.append(f"### {step.get('id','')} · {step.get('title','')}".rstrip())
        out.append("")
        if cmds:
            joined = "\n".join(cmds)
            cf = _fence_for(joined)
            out.append("Command(s):")
            out.append("")
            out.append(f"{cf}bash")
            out.append(joined)
            out.append(cf)
            out.append("")
        of = _fence_for(raw)
        out.append("Output:")
        out.append("")
        # raw is emitted exactly as pasted, wrapped in a collision-proof fence.
        out.append(f"{of}\n{raw}\n{of}")
        out.append("")
    if not any_ev:
        out.append("_No command output was captured for the completed steps._")
        out.append("")
    return "\n".join(out).rstrip() + "\n"


_REMEDIATION_RE = re.compile(r"^#{1,6}\s+.*remediation", re.IGNORECASE | re.MULTILINE)
# an optional model-written Evidence heading sitting just before the marker
_MARKER_RE = re.compile(
    r"(?:^#{1,6}[^\n]*\bevidence\b[^\n]*\n+)?" + re.escape(_EVIDENCE_MARKER),
    re.IGNORECASE | re.MULTILINE,
)


def _insert_evidence(md: str, session: dict) -> str:
    """Splice the authoritative Evidence section into the model's report.

    Prefers the ``{{EVIDENCE}}`` placeholder (also absorbing an Evidence heading
    the model may have put right before it); otherwise inserts before the
    Remediation section; otherwise appends. Any stray markers are removed.
    """
    section = build_evidence_section(session)

    if _EVIDENCE_MARKER in md:
        md = _MARKER_RE.sub(lambda _m: section, md, count=1)
        # drop any leftover markers so the placeholder never leaks to the reader
        md = md.replace(_EVIDENCE_MARKER, "").rstrip() + "\n"
        return md

    m = _REMEDIATION_RE.search(md)
    if m:
        return md[: m.start()].rstrip() + "\n\n" + section + "\n" + md[m.start() :]

    return md.rstrip() + "\n\n" + section


def build_prompt(session: dict) -> str:
    """Render the session into a grounding-first prompt for the report."""
    goal = session.get("goal", "")
    ttype = session.get("target_type") or "unspecified"
    checked = session.get("checked", 0)
    total = session.get("total", 0)
    phases = session.get("path", {}).get("phases", []) or []
    phase_names = [p.get("label", p.get("phase", "")) for p in phases]

    lines: list[str] = []
    lines.append(f"ENGAGEMENT: {session.get('label', goal)}")
    lines.append(f"GOAL: {goal}")
    lines.append(f"TARGET TYPE: {ttype}")
    lines.append(f"PROGRESS: {checked} of {total} steps completed")
    if phase_names:
        lines.append(
            "PHASES (use exactly these in Methodology, in this order): "
            + " → ".join(phase_names)
        )
    lines.append("")
    lines.append(
        "Below is the engagement. Each phase lists its steps. Each step is "
        "marked [COMPLETED] or [NOT DONE], with its commands and — where the "
        "tester captured output — an EVIDENCE block you may READ to write "
        "accurate findings. Do NOT copy raw EVIDENCE into your report; cite it "
        f"by step id and leave the {_EVIDENCE_MARKER} placeholder for the "
        "authoritative section."
    )
    lines.append("")

    for phase in phases:
        lines.append(f"## PHASE: {phase.get('label', phase.get('phase',''))}")
        for step in phase.get("steps", []) or []:
            status = "COMPLETED" if step.get("checked") else "NOT DONE"
            sid = step.get("id", "")
            lines.append(f"### [{status}] ({sid}) {step.get('title','')}")
            cmds = _commands(step)
            if cmds:
                lines.append("Commands:")
                for c in cmds:
                    lines.append(f"    {c}")
            evidence = (step.get("result_text") or "").strip()
            if evidence:
                lines.append(
                    f"EVIDENCE for {sid} (read only — cite as 'Evidence: {sid}', "
                    "do not reproduce):"
                )
                lines.append("<<<EVIDENCE")
                lines.append(evidence)
                lines.append("EVIDENCE>>>")
            else:
                lines.append("EVIDENCE: (none captured)")
            lines.append("")

    lines.append(
        "Now write the full Markdown penetration-test report following the "
        f"required sections. Put {_EVIDENCE_MARKER} where the Evidence section "
        "belongs. Do not fabricate anything, and do not paste raw output."
    )
    return "\n".join(lines)


def compose_report(session: dict) -> tuple[str, str]:
    """Draft the report for a session. Returns (markdown, model_used).

    The LLM writes the prose; the Evidence section is inserted programmatically
    so captured output is reproduced verbatim. Raises ``llm.LLMError`` if the
    provider is unreachable or returns nothing.
    """
    cfg = llm.load_config()
    user = build_prompt(session)
    raw = llm.chat(_SYSTEM, user, cfg, max_tokens=_MAX_TOKENS)
    md = _clean_markdown(raw)
    if not md:
        raise llm.LLMError("the model returned an empty report")
    md = _insert_evidence(md, session)
    return md, cfg["model"]
