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

from cockpit.secretargs import REDACTED

import re

import llm
# NOT `operator.py` — `backend/` is first on sys.path, so that filename would shadow
# the STDLIB `operator` module for every import in the process.
import operator_identity

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
    "- SANDBOX EXECUTION runs (real allowlisted commands executed against the "
    "lab, each with its captured output and exit code) are ALSO authoritative "
    "evidence — treat them exactly like completed steps: state what was run and "
    "what the output showed, and cite them by run id, e.g. '(see Evidence: "
    "run-ab12cd34)'. Do NOT paste their raw output; the authoritative Evidence "
    "section carries it.\n"
    "- EVIDENCE INTEGRITY: do NOT reproduce raw command output as fenced code "
    "blocks. The system inserts an authoritative, verbatim Evidence section. "
    "In your narrative, refer to captured evidence in prose and cite it by step "
    "id, e.g. '(see Evidence: recon-1)'. You may mention key values, but do NOT "
    "paste multi-line raw output — it would compete with the authoritative "
    "record.\n"
    "- METHODOLOGY: describe ONLY the phases listed in the engagement data "
    "below, using their exact names and order. Do NOT add, rename, or invent "
    "phases (e.g. do not add a 'Post-Exploitation' phase if it is not listed).\n"
    "- DETECTION FOOTPRINT: the system appends an authoritative, purple-team "
    "'Detection footprint' block under each recorded run — the MITRE ATT&CK "
    "technique, the telemetry it generated and the public detection rule that "
    "would fire. Do NOT write that yourself, and do NOT contradict it. It "
    "DESCRIBES what a defender would have seen; it is not evasion guidance, so "
    "never suggest how the tester could have been quieter, avoided detection, or "
    "evaded a rule. If you reference detectability at all, frame it for the "
    "DEFENDER: what they should have seen, and whether they would have.\n"
    "Write the report with these sections as Markdown headings, in order:\n"
    "1. Executive Summary\n"
    "2. Scope & Target\n"
    "3. Methodology (the phases followed)\n"
    "4. Findings & Attack Narrative (walk the COMPLETED steps in order, per "
    "phase, AND the recorded SANDBOX EXECUTION runs — what was done, the "
    "command(s) used, and what the evidence showed, citing it by step id or "
    "run id)\n"
    f"5. Evidence — put a single line containing exactly {_EVIDENCE_MARKER} "
    "here and nothing else; do NOT write an Evidence heading or any output "
    "yourself. The system replaces the placeholder with the authoritative "
    "Evidence section.\n"
    "6. Remediation Recommendations\n"
    "7. Conclusion\n"
    "Output ONLY the Markdown report — no preamble, no explanation."
)


# --------------------------------------------------------------------------- #
# EXAM / FORMAT TEMPLATES (Phase 4 item 5)
# --------------------------------------------------------------------------- #
# Each template swaps the SECTION LIST + tone the model writes to. The grounding rules, the
# programmatic Evidence splice and the detection footprint are IDENTICAL across all of them —
# only the report SHAPE changes. The shared rules block is factored out so a template only
# states its own sections.
_RULES = (
    "STRICT RULES:\n"
    "- Base all findings and the attack narrative ONLY on the steps marked COMPLETED and the "
    "evidence pasted by the tester, plus the recorded SANDBOX EXECUTION runs (real commands "
    "with captured output + exit code — authoritative, cite by run id). NEVER invent findings, "
    "output, hashes, credentials, IPs, hostnames or results not present in the data.\n"
    "- A completed step with no pasted evidence may be described as performed; do not fabricate "
    "its output. Steps NOT completed must not appear as findings.\n"
    "- EVIDENCE INTEGRITY: do NOT reproduce raw command output as fenced blocks. The system "
    "inserts an authoritative verbatim Evidence section where you put the marker. Cite evidence "
    "in prose by step id or run id (e.g. '(see Evidence: run-ab12cd34)').\n"
    "- METHODOLOGY: describe ONLY the phases listed in the engagement data, in their exact "
    "names and order. Do not add or rename phases.\n"
    "- DETECTION FOOTPRINT: the system appends an authoritative purple-team block per run. Do "
    "not write it yourself or contradict it, and do not turn it into evasion advice.\n"
)

_OSCP_PROOF_MARKER = "{{PROOF_TABLE}}"

_STANDARD_TEMPLATE = _SYSTEM

_OSCP_TEMPLATE = (
    "You are writing an OSCP-style penetration-test report for an AUTHORIZED exam/lab "
    "engagement, in clean professional Markdown. The report is organised PER HOST/TARGET — an "
    "OSCP report walks each machine from enumeration to a low-privilege foothold (local.txt) to "
    "privilege escalation (proof.txt).\n"
    + _RULES +
    "- PROOF FLAGS: put a single line containing exactly " + _OSCP_PROOF_MARKER + " where the "
    "proof-summary table belongs (High-Level Summary section). The system replaces it with the "
    "authoritative per-host local.txt/proof.txt table built from state — do NOT write that table "
    "or invent any flag value; if you mention a flag, cite it as recorded, never transcribe it.\n"
    "Write these sections as Markdown headings, in order:\n"
    "1. Introduction (engagement + objective)\n"
    "2. High-Level Summary (2-3 sentences, then the " + _OSCP_PROOF_MARKER + " line for the "
    "proof table)\n"
    "3. Per-Target Walkthrough — one `##` subsection PER host, each covering: Service "
    "Enumeration, Initial Access / Foothold (how local.txt was reached), Privilege Escalation "
    "(how proof.txt was reached). Walk the COMPLETED steps + recorded runs for that host in "
    "order, citing evidence by id.\n"
    f"4. Evidence — a single line containing exactly {_EVIDENCE_MARKER} and nothing else.\n"
    "5. Remediation Recommendations (per finding)\n"
    "Output ONLY the Markdown report — no preamble."
)

_CPTS_TEMPLATE = (
    "You are writing an HTB CPTS-style professional penetration-test report for an AUTHORIZED "
    "engagement, in clean professional Markdown. The CPTS format separates a business-facing "
    "Executive Summary from a detailed technical walkthrough and a findings register with "
    "severity ratings and remediation.\n"
    + _RULES +
    "Write these sections as Markdown headings, in order:\n"
    "1. Executive Summary (business language: what was tested, the risk posture, the headline "
    "findings — no jargon)\n"
    "2. Scope & Rules of Engagement\n"
    "3. Assessment Methodology (the phases followed, in order)\n"
    "4. Findings — one `##` subsection per finding: Severity, Affected Asset, Description, "
    "Impact, Evidence (cite by id), Remediation. Order findings by severity.\n"
    "5. Attack Narrative (the chronological path through the engagement, citing evidence)\n"
    f"6. Evidence — a single line containing exactly {_EVIDENCE_MARKER} and nothing else.\n"
    "7. Remediation Summary (prioritised)\n"
    "8. Appendix / Conclusion\n"
    "Output ONLY the Markdown report — no preamble."
)

_BUGBOUNTY_TEMPLATE = (
    "You are writing a bug-bounty vulnerability report for a HackerOne / Bugcrowd submission, in "
    "clean Markdown, IMPACT-FIRST and concise. One vulnerability per report (the primary finding "
    "of this engagement). Human tone — no 'could potentially'; state what IS.\n"
    + _RULES +
    "- CVSS: the system appends an authoritative CVSS block if a vector is provided; do not "
    "invent a score. You may reference the severity in words.\n"
    "Write these sections as Markdown headings, in order:\n"
    "1. Title (one line: the vuln + the asset)\n"
    "2. Summary (2-3 sentences: what it is and why it matters)\n"
    "3. Steps to Reproduce (numbered, exact — the triager must be able to follow them; cite "
    "captured evidence by id)\n"
    "4. Impact (concrete: what an attacker gains, in business terms)\n"
    f"5. Evidence — a single line containing exactly {_EVIDENCE_MARKER} and nothing else.\n"
    "6. Remediation (specific, actionable)\n"
    "Output ONLY the Markdown report — no preamble."
)

TEMPLATES: dict[str, str] = {
    "standard": _STANDARD_TEMPLATE,
    "oscp": _OSCP_TEMPLATE,
    "cpts": _CPTS_TEMPLATE,
    "bugbounty": _BUGBOUNTY_TEMPLATE,
}


# --------------------------------------------------------------------------- #
# CVSS 3.1 base score (bug-bounty template)
# --------------------------------------------------------------------------- #
_CVSS_METRICS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"N": 0.85, "L": 0.62, "H": 0.27},        # unchanged-scope values; see _cvss_pr
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_CVSS_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}


def _roundup(x: float) -> float:
    """CVSS 3.1 roundup — smallest number to 1 decimal >= x."""
    import math
    return math.ceil(x * 10) / 10


def cvss31_base(vector: str) -> dict[str, Any] | None:
    """Compute the CVSS 3.1 BASE score from a vector string. None if it cannot be parsed.

    Deterministic and offline — the score is arithmetic, so (like the evidence) it is computed,
    never written by the model. Only the eight base metrics are read; temporal/environmental
    metrics in the vector are ignored.
    """
    v = (vector or "").strip()
    if v.upper().startswith("CVSS:3.1/") or v.upper().startswith("CVSS:3.0/"):
        v = v.split("/", 1)[1]
    parts = {}
    for tok in v.split("/"):
        if ":" in tok:
            k, val = tok.split(":", 1)
            parts[k.strip().upper()] = val.strip().upper()
    required = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
    if not all(k in parts for k in required):
        return None
    try:
        scope_changed = parts["S"] == "C"
        pr = (_CVSS_PR_CHANGED if scope_changed else _CVSS_METRICS["PR"])[parts["PR"]]
        av = _CVSS_METRICS["AV"][parts["AV"]]
        ac = _CVSS_METRICS["AC"][parts["AC"]]
        ui = _CVSS_METRICS["UI"][parts["UI"]]
        c = _CVSS_METRICS["C"][parts["C"]]
        i = _CVSS_METRICS["I"][parts["I"]]
        a = _CVSS_METRICS["A"][parts["A"]]
    except KeyError:
        return None

    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        base = 0.0
    elif scope_changed:
        base = _roundup(min(1.08 * (impact + exploitability), 10))
    else:
        base = _roundup(min(impact + exploitability, 10))

    if base == 0:
        sev = "None"
    elif base < 4.0:
        sev = "Low"
    elif base < 7.0:
        sev = "Medium"
    elif base < 9.0:
        sev = "High"
    else:
        sev = "Critical"
    return {"score": round(base, 1), "severity": sev, "vector": f"CVSS:3.1/{v}"}


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


# internal status tags from the prompt format (e.g. "[COMPLETED]") that the
# model sometimes echoes into the prose — never meant for the reader.
_STATUS_TAG_RE = re.compile(
    r"\[\s*(?:COMPLETED|DONE|NOT[\s_-]?DONE|IN[\s_-]?PROGRESS|PENDING|SKIPPED)"
    r"\s*\]\s*",
    re.IGNORECASE,
)


def _strip_status_tags(md: str) -> str:
    """Remove leaked ``[COMPLETED]`` / ``[NOT DONE]`` style tags from the prose.

    The Evidence section is built afterwards and never contains these, so this
    only touches the model's narrative. Tidies up empty bold left behind
    (``**[COMPLETED]**`` → nothing) and doubled spaces.
    """
    md = _STATUS_TAG_RE.sub("", md)
    md = re.sub(r"\*\*\s*\*\*", "", md)  # empty bold left by a removed tag
    md = re.sub(r"[ \t]{2,}", " ", md)  # collapse runs of spaces (not newlines)
    return md


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


def _execution_runs(session: dict) -> list[dict]:
    """Recorded cockpit sandbox runs attached to the session (may be empty).

    Each is a ``cockpit.models.RunRecord`` dumped to a dict: run_id, command,
    args, exit_code, stdout, stderr, target, started_at, … These are real
    allowlisted commands the tester approved and ran against the lab.
    """
    runs = session.get("execution_runs") or []
    return [r for r in runs if isinstance(r, dict)]


def _run_ref(run: dict) -> str:
    """Stable citation id for a run, e.g. 'run-ffd5acb0e78a'."""
    return f"run-{run.get('run_id', '')}"


# A live interactive session records itself with this command name (see
# cockpit/session.py). Kept as a LITERAL on purpose: importing the session module here
# would break its human-only source-scan lock, and the report has no business reaching it.
_SESSION_RUN_COMMAND = "session"


def _is_session_run(run: dict) -> bool:
    """True if this record is an interactive session transcript, not a one-shot command."""
    return (run.get("command") or "") == _SESSION_RUN_COMMAND


def _run_cmdline(run: dict) -> str:
    """The exact command line for a run: 'curl -sSI http://…'.

    For a SESSION record the stored command is the marker ``session`` and the args are
    the argv that started it, so the marker is dropped — what is shown is the real
    listener/handler command line the operator approved.
    """
    args = run.get("args") or []
    if _is_session_run(run):
        return " ".join(str(a) for a in args).strip()
    return " ".join([run.get("command", ""), *[str(a) for a in args]]).strip()


def _run_output(run: dict) -> str:
    """Combined captured output (stdout then stderr), verbatim."""
    out = run.get("stdout") or ""
    err = run.get("stderr") or ""
    if err.strip():
        return f"{out}{'' if out.endswith(chr(10)) or not out else chr(10)}{err}"
    return out


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


def _detection_block(run: dict) -> list[str]:
    """The purple-team 'Detection footprint' block for one recorded run.

    What a DEFENDER would have observed while this ran: the ATT&CK technique + tactic, the
    telemetry it generated, the public SigmaHQ rule that would fire, and the loud-vs-quiet
    rating. Written programmatically from the curated ATT&CK/SigmaHQ map — like the evidence
    itself, it never passes through the model, so it cannot be mistranscribed or embellished.

    GROUNDED ONLY (``allow_llm=False``). A report is an authoritative artefact: if the curated
    map does not cover the command, this says so plainly rather than asserting a model's guess.

    THE LINE: this block describes the footprint. It never says how to leave a smaller one.
    """
    try:
        from detection.resolver import footprint_for_run
        fp = footprint_for_run(run, allow_llm=False)
    except Exception:
        return []

    out: list[str] = ["**Detection footprint** — what a defender would have observed:", ""]

    if not fp.get("grounded"):
        out.append(
            "- Not in the curated ATT&CK/SigmaHQ map, so no footprint is asserted for this "
            "command. Unmapped is not the same as untraceable — treat the footprint as unknown."
        )
        out.append("")
        return out

    techs = fp.get("techniques") or []
    if techs:
        parts = []
        for t in techs:
            tacs = ", ".join(tac["name"] for tac in t.get("tactics", []))
            parts.append(f"[{t['id']}]({t['url']}) {t['name']}" + (f" ({tacs})" if tacs else ""))
        out.append("- **ATT&CK:** " + "; ".join(parts))

    loud = fp.get("loudness") or {}
    if loud.get("level"):
        why = (loud.get("why") or "").strip()
        out.append(f"- **Signal:** {loud['level']}" + (f" — {why}" if why else ""))

    if fp.get("blue_view"):
        out.append(f"- **What blue sees:** {fp['blue_view']}")

    for line in (fp.get("telemetry") or [])[:6]:
        out.append(f"  - {line}")

    sigma = fp.get("sigma") or []
    if sigma:
        out.append("- **Detections that would fire (SigmaHQ):**")
        for r in sigma:
            out.append(f"  - [{r['title']}]({r['url']}) — {r['level']} · `{r['id']}`")

    if (fp.get("stealth") or {}).get("present"):
        out.append(f"- **Note:** {fp['stealth']['note']}")

    for sig in fp.get("signals") or []:
        out.append(f"- **{sig['label']}:** {sig['note']}")

    out.append("")
    return out


def build_detection_summary(session: dict) -> str:
    """The engagement-level ATT&CK coverage roll-up — the report's purple-team header.

    Turns the report into an artefact a blue team can act on: which techniques and tactics this
    engagement exercised, how loud the loudest action was, and how much of it the curated map
    could speak to. Grounded-only and model-free, like every other authoritative block.
    """
    try:
        from detection import tagging
    except Exception:
        return ""

    runs = _execution_runs(session)
    if not runs:
        return ""
    tags = [tagging.tag_run(r) for r in runs]
    summary = tagging.summarize(tags)
    if not summary["techniques"]:
        return ""

    out: list[str] = [
        "## Detection footprint (purple team)",
        "",
        "_What this engagement would have looked like from the defender's side. Every technique "
        "below is mapped to MITRE ATT&CK and, where a public detection exists, to the SigmaHQ "
        "rule that would fire; the per-run detail sits with each run in Evidence. This section "
        "describes the footprint the testing left — it is not, and must not be read as, guidance "
        "on avoiding detection._",
        "",
        f"- **Runs ATT&CK-tagged:** {summary['tagged']} of {summary['tagged'] + summary['untagged']}"
        + (f" ({summary['untagged']} not in the curated map)" if summary["untagged"] else ""),
        "- **Tactics exercised:** "
        + ", ".join(
            t["name"] + (f" ({t['also_known_as']})" if t.get("also_known_as") else "")
            for t in summary["tactics"]
        ),
        f"- **Loudest action:** {summary['loudest']}" if summary["loudest"] else "",
        "",
        "| ATT&CK | Technique | Tactic(s) |",
        "| --- | --- | --- |",
    ]
    for t in summary["techniques"]:
        out.append(
            f"| [{t['id']}]({t['url']}) | {t['name']} | {', '.join(t['tactic_names'])} |"
        )
    out.append("")
    out.append(
        "_A defender who sees none of the above for this window has a monitoring gap worth "
        "closing; the telemetry named per run is where to start._"
    )
    out.append("")
    return "\n".join(x for x in out if x is not None)


def build_opsec_summary(session: dict) -> str:
    """The OFFENSIVE-half roll-up (D10) — the red-team OPSEC counterpart to the blue summary.

    OFF unless a report explicitly opts in (``include_opsec`` in :func:`compose_report`), because
    a normal client deliverable does not carry evasion tradecraft. When a report IS scoped to
    assess detection (a purple-team / CRTP-style engagement), this section states, per loud action
    the engagement ran: what made it loud, the quieter approach, and — mandatorily — what still
    records it. Built programmatically and grounded-only, like the blue summary; the OPSEC copy
    comes from the curated table, never the model, so it cannot drift into an evasion how-to.
    """
    try:
        from detection import catalog, tagging
    except Exception:
        return ""

    runs = _execution_runs(session)
    if not runs:
        return ""

    # One OPSEC note per distinct command family the engagement exercised, loudest first.
    seen: dict[str, Any] = {}
    for run in runs:
        tag = tagging.tag_run(run)
        key = tag.get("spec_key") if tag else None
        if not key or key in seen:
            continue
        note = catalog.opsec_for(key)
        if note is None:
            continue
        spec = catalog.SPECS.get(key)
        seen[key] = (spec, note)
    if not seen:
        return ""

    ordered = sorted(
        seen.values(),
        key=lambda sn: -catalog.loudness_score(sn[0].loudness if sn[0] else "quiet"),
    )

    out: list[str] = [
        "## OPSEC assessment (red team)",
        "",
        "_The offensive counterpart to the detection footprint above: for each loud action this "
        "engagement ran, the quieter tradecraft a real adversary would use — and, in every case, "
        "what STILL records it. This is included because this engagement was scoped to assess "
        "detection; it is honest about its own limits, not a guide to evading monitoring. No "
        "action here disables, clears or tampers with a defender's telemetry._",
        "",
    ]
    for spec, note in ordered:
        label = spec.label if spec else note.key
        loud = spec.loudness if spec else ""
        out.append(f"### {label}" + (f" — {loud}" if loud else ""))
        out.append(f"- **Loud because:** {note.loud_because}")
        out.append("- **Quieter approach:**")
        for q in note.quieter:
            out.append(f"  - {q}")
        out.append(f"- **Still recorded:** {note.still_recorded}")
        out.append(f"- **Tradeoff:** {note.tradeoff}")
        out.append("")
    return "\n".join(out)


def build_proof_table(session: dict) -> str:
    """The OSCP per-host proof table, built from state — never retyped, never model-written.

    One row per host that has a foothold (local.txt) or is owned (proof.txt), rendered straight
    from the structured engagement state. A half-owned host (local but no proof) reads as such.
    Empty string when no flags were captured (so the marker just disappears).
    """
    hosts = [h for h in (session.get("state_hosts") or [])
             if (h.get("local_txt") or h.get("proof_txt"))]
    if not hosts:
        return ("_No local.txt / proof.txt captured yet — record flags as you capture them "
                "(they populate this table automatically)._")
    owned = sum(1 for h in hosts if h.get("proof_txt"))
    out = [
        f"**Proofs captured — {owned}/{len(hosts)} host(s) fully owned**",
        "",
        "| Host | local.txt | proof.txt | Status |",
        "| --- | --- | --- | --- |",
    ]
    for h in sorted(hosts, key=lambda x: str(x.get("address", ""))):
        addr = h.get("address", "")
        name = h.get("hostname", "")
        label = f"{addr}" + (f" ({name})" if name else "")
        local = f"`{h['local_txt']}`" if h.get("local_txt") else "—"
        proof = f"`{h['proof_txt']}`" if h.get("proof_txt") else "—"
        status = {"owned": "**OWNED**", "foothold": "foothold", "": "—"}.get(
            h.get("ownership", ""), "—"
        )
        out.append(f"| {label} | {local} | {proof} | {status} |")
    out.append("")
    return "\n".join(out)


def build_cvss_block(session: dict) -> str:
    """The authoritative CVSS block for the bug-bounty template, computed from a stored vector.

    The vector lives in ``session['cvss_vector']`` (set by the operator). The SCORE is arithmetic,
    so like the evidence it is computed here, never written by the model.
    """
    vector = (session.get("cvss_vector") or "").strip()
    if not vector:
        return ""
    res = cvss31_base(vector)
    if res is None:
        return f"_CVSS vector could not be parsed: `{vector}`._"
    return (
        f"**CVSS 3.1:** {res['score']} ({res['severity']}) · `{res['vector']}`  \n"
        "_Score computed from the vector, not asserted by the model._"
    )


# --------------------------------------------------------------------------- #
# BUGCROWD VRT PRIORITY (bug-bounty template) — alongside CVSS, never derived from it
#
# Bugcrowd triages on the Vulnerability Rating Taxonomy: a P1–P5 priority attached to a
# vulnerability TYPE, not computed from a CVSS vector. The two genuinely disagree — a stored
# XSS is P2 whatever its CVSS works out to, and a 9.8 on a class the program rates P3 gets
# paid as a P3. Reports carried CVSS only, so the number a triager will actually act on was
# missing.
#
# THIS IS A LOOKUP, NOT A CALCULATION, and that distinction is load-bearing. Deriving a
# priority from the CVSS score would produce a plausible P-number with no relationship to
# the taxonomy — a fabricated claim in the one field a triager reads first. So the operator
# names the category and this maps it; with no category named, the block says the priority
# is unrated rather than inventing one.
#
# SCOPE OF THIS TABLE, stated because it bounds the claim: a curated subset of the VRT's
# common categories at their DEFAULT priorities. It is not the full taxonomy, VRT versions
# change, and a program may override any entry in its own brief. The rendered block says all
# of that, so the output is never mistaken for an authoritative rating.
# --------------------------------------------------------------------------- #
_VRT: dict[str, tuple[str, str]] = {
    # key                    -> (default priority, VRT category path)
    "rce": ("P1", "Server-Side Injection > Remote Code Execution (RCE)"),
    "sqli": ("P1", "Server-Side Injection > SQL Injection"),
    "command-injection": ("P1", "Server-Side Injection > Command Injection"),
    "auth-bypass": ("P1", "Broken Authentication and Session Management > Authentication Bypass"),
    "privesc-vertical": ("P1", "Broken Access Control > Privilege Escalation > Vertical"),
    "ssrf-internal": ("P1", "Server-Side Injection > Server-Side Request Forgery > Internal High Impact"),
    "secret-exposure": ("P1", "Sensitive Data Exposure > Critically Sensitive Data"),
    "xxe": ("P2", "Server-Side Injection > XML External Entity Injection"),
    "xss-stored": ("P2", "Cross-Site Scripting (XSS) > Stored > Non-Self"),
    "idor": ("P2", "Broken Access Control > Insecure Direct Object Reference (IDOR)"),
    "lfi": ("P2", "Server-Side Injection > File Inclusion > Local"),
    "subdomain-takeover": ("P2", "Server Security Misconfiguration > Misconfigured DNS > Subdomain Takeover"),
    "ssrf-limited": ("P3", "Server-Side Injection > Server-Side Request Forgery > Internal Scan and/or Medium Impact"),
    "xss-reflected": ("P3", "Cross-Site Scripting (XSS) > Reflected > Non-Self"),
    "csrf": ("P3", "Broken Authentication and Session Management > Cross-Site Request Forgery (CSRF)"),
    "broken-crypto": ("P3", "Insecure Data Storage > Sensitive Application Data Stored Unencrypted"),
    "rate-limit": ("P4", "Server Security Misconfiguration > Lack of Password Confirmation"),
    "open-redirect": ("P4", "Unvalidated Redirects and Forwards > Open Redirect"),
    "user-enumeration": ("P4", "Broken Authentication and Session Management > Username Enumeration"),
    "clickjacking": ("P4", "Server Security Misconfiguration > Clickjacking"),
    "xss-self": ("P5", "Cross-Site Scripting (XSS) > Stored > Self"),
    "missing-headers": ("P5", "Server Security Misconfiguration > Missing Security Headers"),
    "info-disclosure": ("P5", "Sensitive Data Exposure > Non-Sensitive Data Disclosure"),
}

#: What each priority means to a triager, in one clause.
_VRT_MEANING = {
    "P1": "Critical — immediate escalation",
    "P2": "Severe — high business impact",
    "P3": "Moderate",
    "P4": "Low",
    "P5": "Informational — typically not awarded",
}

#: Which CVSS severity band a VRT priority usually sits in. Used ONLY to notice when the two
#: DISAGREE — never to derive one from the other. A P3 carrying a 9.8 is worth arguing in the
#: submission; a P1 carrying a 3.1 usually means the wrong category was picked.
_VRT_EXPECTED_CVSS = {
    "P1": ("High", "Critical"),
    "P2": ("Medium", "High", "Critical"),
    "P3": ("Low", "Medium", "High"),
    "P4": ("None", "Low", "Medium"),
    "P5": ("None", "Low"),
}


def vrt_categories() -> list[dict[str, str]]:
    """The catalogue, for a picker. Sorted by priority then key."""
    return [
        {"key": k, "priority": p, "category": path, "meaning": _VRT_MEANING[p]}
        for k, (p, path) in sorted(_VRT.items(), key=lambda kv: (kv[1][0], kv[0]))
    ]


def vrt_priority(category: str) -> dict[str, str] | None:
    """Look up one VRT category key. None when it is not in this table.

    Returns None rather than a best guess: an unrecognised category means we do not know the
    priority, and saying "P3" because it sounds middling would be the fabrication this whole
    block exists to avoid.
    """
    entry = _VRT.get((category or "").strip().lower())
    if entry is None:
        return None
    priority, path = entry
    return {
        "key": (category or "").strip().lower(),
        "priority": priority,
        "category": path,
        "meaning": _VRT_MEANING[priority],
    }


def build_vrt_block(session: dict) -> str:
    """The VRT priority block for the bug-bounty template, from a stored category.

    The category lives in ``session['vrt_category']`` (set by the operator), exactly as the
    CVSS vector does. Empty when none is set — a report with no VRT line is honest; one with
    a guessed P-number is not.
    """
    key = (session.get("vrt_category") or "").strip()
    if not key:
        return ""
    res = vrt_priority(key)
    if res is None:
        known = ", ".join(sorted(_VRT))
        return (
            f"_VRT category `{key}` is not in HackPit's table, so no priority is claimed. "
            f"Known keys: {known}._"
        )

    line = (
        f"**Bugcrowd VRT:** {res['priority']} ({res['meaning']}) · {res['category']}  \n"
    )
    # Flag a genuine disagreement with the CVSS score, if one was computed. This is the
    # useful part: the triager acts on the P-number, and the two metrics rating the same
    # finding very differently is something to argue in the submission, not to hide.
    cvss = cvss31_base((session.get("cvss_vector") or "").strip())
    note = ""
    if cvss and cvss["severity"] not in _VRT_EXPECTED_CVSS[res["priority"]]:
        note = (
            f"_Note: CVSS rates this {cvss['severity']} ({cvss['score']}) while the VRT "
            f"default is {res['priority']}. Bugcrowd triages on the VRT — if the CVSS "
            "reading is the right one, argue it explicitly in the submission._  \n"
        )
    return (
        line
        + note
        + "_Default priority from a curated subset of the Bugcrowd VRT; the program's own "
        "brief and VRT version override it._"
    )


# --------------------------------------------------------------------------- #
# THE KNOWN-ISSUE CHECK — flag, never suppress
#
# Bug bounty programs publish what they already know about and will not pay for; the MAF
# program's scope table has a "Known issues" column. Submitting one of those burns the
# report, and on some programs it costs signal. Nothing compared a finding against that list.
#
# THE DESIGN RULE, and it is the whole feature: this FLAGS a possible match and never drops
# anything. A false match that silently removed a real finding would be far worse than a
# warning the operator glances at and dismisses — one wastes ten seconds, the other loses a
# paid bug and nobody ever learns it happened. So the output is a table headed by what was
# compared, the matching is deliberately loose, and no code path anywhere removes a finding.
# --------------------------------------------------------------------------- #
#: Words too common to carry a match on their own. A finding titled "Missing header" and a
#: known issue reading "Missing rate limit" share "missing" and nothing that matters.
_KI_STOPWORDS = frozenset({
    "the", "a", "an", "and", "or", "of", "in", "on", "at", "to", "for", "with", "is", "are",
    "was", "were", "be", "been", "by", "as", "from", "that", "this", "it", "its", "not", "no",
    "all", "any", "can", "may", "via", "used", "using", "issue", "issues", "vulnerability",
    "vuln", "finding", "known", "we", "our", "you", "your", "will", "does", "do",
})
#: How much of the FINDING has to be covered by a known-issue line before it is flagged, and
#: how many distinctive words that has to be in absolute terms. Two thresholds because either
#: alone misfires: a ratio alone flags one-word findings on a single shared token, a count
#: alone flags a long finding that happens to share three common words.
_KI_MIN_RATIO = 0.5
_KI_MIN_TERMS = 2


def _ki_terms(text: str) -> set[str]:
    """Distinctive lowercase words in a title or a known-issue line."""
    words = re.split(r"[^A-Za-z0-9]+", (text or "").lower())
    return {w for w in words if len(w) > 2 and w not in _KI_STOPWORDS}


def known_issue_matches(finding: dict, known_issues: str) -> dict[str, Any] | None:
    """The known-issue line this finding may already be covered by, or None.

    Errs toward REPORTING. A spurious flag costs the operator one glance at the brief; a
    missed one costs a submission. That asymmetry is why the thresholds are loose and why
    this returns the best candidate rather than requiring certainty.
    """
    lines = [ln.strip(" \t-*•") for ln in (known_issues or "").splitlines()]
    lines = [ln for ln in lines if len(ln) > 3]
    if not lines:
        return None

    title = finding.get("title") or ""
    reference = (finding.get("reference") or "").strip()
    f_terms = _ki_terms(f"{title} {reference}")
    if not f_terms:
        return None

    best: dict[str, Any] | None = None
    for line in lines:
        # A CVE / template id named in both is not a fuzzy match, it is the same issue.
        if reference and len(reference) > 3 and reference.lower() in line.lower():
            return {"line": line, "shared": [reference], "ratio": 1.0, "exact": True}
        # ...as is the finding's whole title appearing in the line.
        if title and len(title) > 8 and title.lower() in line.lower():
            return {"line": line, "shared": [title], "ratio": 1.0, "exact": True}
        shared = f_terms & _ki_terms(line)
        ratio = len(shared) / len(f_terms)
        if len(shared) >= _KI_MIN_TERMS and ratio >= _KI_MIN_RATIO:
            if best is None or ratio > best["ratio"]:
                best = {
                    "line": line, "shared": sorted(shared), "ratio": ratio, "exact": False,
                }
    return best


def build_known_issues_block(session: dict) -> str:
    """The known-issue check section. Empty when the program published no known issues.

    Reports the check EVEN WHEN IT FINDS NOTHING — "compared against 7 findings, no matches"
    tells the operator the list was read. Silence would be indistinguishable from a check
    that never ran, which is the failure mode this project keeps designing out.
    """
    known = (session.get("known_issues") or "").strip()
    if not known:
        return ""
    findings = list(session.get("state_findings") or [])
    if not findings:
        return (
            "## Known-issue check\n\n"
            "The program's known-issues list is recorded for this engagement, but there are "
            "no structured findings to compare against it. **Check it by hand before "
            "submitting.**\n"
        )

    rows: list[str] = []
    for f in findings:
        m = known_issue_matches(f, known)
        if not m:
            continue
        how = "exact" if m["exact"] else f"{len(m['shared'])} terms: {', '.join(m['shared'][:4])}"
        title = str(f.get("title") or "").replace("|", "\\|")
        line = str(m["line"]).replace("|", "\\|")
        rows.append(
            f"| {title} | {f.get('severity', 'info')} | {line} | {how} |"
        )

    out = ["## Known-issue check", ""]
    if not rows:
        out += [
            f"Compared {len(findings)} finding(s) against the program's published known "
            "issues — **no matches**. Nothing here was filtered out; every finding stands.",
            "",
        ]
        return "\n".join(out)

    out += [
        f"**{len(rows)} of {len(findings)} finding(s) resemble something the program has "
        "already published as a known issue.** Check the brief before submitting these — a "
        "known issue is usually not awarded.",
        "",
        "**NOTHING WAS REMOVED.** This is a prompt to look, not a verdict: the match is "
        "textual, it can be wrong in both directions, and dropping a real finding on a bad "
        "match would cost far more than reading four rows.",
        "",
        "| finding | severity | published known issue | matched on |",
        "|---|---|---|---|",
        *rows,
        "",
    ]
    return "\n".join(out)


def build_session_health_block(session: dict) -> str:
    """Warn in the REPORT when the scan's traffic stopped looking authenticated.

    An authenticated scan whose session expired mid-run reports zero findings, and a report
    saying "no vulnerabilities identified" is the most expensive sentence in this codebase to
    get wrong. If the traffic went login-shaped, the report says so next to that conclusion
    rather than leaving the reader to infer it.

    Reads ``session['scan_session_health']`` — the verdict from ``cockpit/proxy.session_health``,
    folded in at report time. Absent (no authenticated scan ran) yields no block.
    """
    health = session.get("scan_session_health") or {}
    verdict = (health.get("verdict") or "").lower()
    if verdict not in ("suspect", "unknown"):
        return ""
    reasons = [str(r) for r in (health.get("reasons") or [])]
    if verdict == "unknown":
        return (
            "> **Scan session state: UNKNOWN.** "
            + (reasons[0] if reasons else "There was too little traffic to judge whether the "
               "authenticated session was still live during the scan.")
            + " A low finding count here is not evidence of a secure application."
        )
    bullets = "\n".join(f"> * {r}" for r in reasons)
    return (
        "> **⚠ THE AUTHENTICATED SESSION MAY HAVE EXPIRED DURING THIS SCAN.**\n>\n"
        f"{bullets}\n>\n"
        "> An expired session does not stop the active scanner — it keeps sending payloads at "
        "login redirects, matches nothing, and finishes cleanly. **A low or zero finding count "
        "in this report may mean the scan was never authenticated, not that the application is "
        "secure.** Re-establish the session and re-run before treating these results as coverage."
    )


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

    # Recorded cockpit sandbox runs — the command line + its captured output,
    # both reproduced verbatim (same collision-proof fencing as pasted evidence).
    for run in _execution_runs(session):
        any_ev = True
        cmdline = _run_cmdline(run)
        raw = _run_output(run)
        exit_code = run.get("exit_code")
        # A real-target engagement run is called out as such — it was NOT run against the
        # isolated lab, so the report must not blur it with lab evidence. An interactive
        # SESSION is called out too: its output is a transcript the operator drove by hand
        # over time, not the output of one command, and the reader must not read it as one.
        is_session = _is_session_run(run)
        kind = "interactive session" if is_session else "sandbox execution"
        if (run.get("mode") or "lab") == "engagement":
            header = f"### {_run_ref(run)} · REAL-TARGET ENGAGEMENT · {kind}"
        else:
            header = f"### {_run_ref(run)} · {kind} (isolated lab)"
        target = run.get("target")
        if target:
            header += f" · target {target}"
        out.append(header)
        out.append("")
        cf = _fence_for(cmdline)
        out.append("Session started with:" if is_session else "Command:")
        out.append("")
        out.append(f"{cf}bash")
        out.append(cmdline)
        out.append(cf)
        out.append("")
        of = _fence_for(raw)
        if is_session:
            out.append(
                f"Session transcript (exit {exit_code}) — lines prefixed `$ ` are what "
                "the operator typed; everything else is what the session returned:"
            )
        else:
            out.append(f"Output (exit {exit_code}):")
        out.append("")
        out.append(f"{of}\n{raw}\n{of}")
        out.append("")
        # the purple-team flip on this run: what a defender would have seen while it ran
        out.extend(_detection_block(run))

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


def _insert_proof_table(md: str, session: dict) -> str:
    """Replace the OSCP proof-table marker with the authoritative per-host table (or drop it)."""
    if _OSCP_PROOF_MARKER not in md:
        return md
    table = build_proof_table(session)
    return md.replace(_OSCP_PROOF_MARKER, table)


def _insert_evidence(md: str, session: dict, include_opsec: bool = False) -> str:
    """Splice the authoritative Evidence section into the model's report.

    Prefers the ``{{EVIDENCE}}`` placeholder (also absorbing an Evidence heading
    the model may have put right before it); otherwise inserts before the
    Remediation section; otherwise appends. Any stray markers are removed.
    """
    # The purple-team roll-up rides immediately ahead of Evidence: the ATT&CK coverage for the
    # whole engagement, then the per-run detail inside each Evidence block. Both are built
    # programmatically, so neither can be embellished by the model.
    detection = build_detection_summary(session)
    # The offensive OPSEC roll-up (D10) only when the caller opted in — off for a normal report.
    opsec = build_opsec_summary(session) if include_opsec else ""
    section = (
        (detection + "\n" if detection else "")
        + (opsec + "\n" if opsec else "")
        + build_evidence_section(session)
    )

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

    # Scope / Rules of Engagement, if the composed path carried any — so the
    # report's Scope section reflects what was in/out of scope.
    profile = (session.get("path", {}) or {}).get("profile") or {}
    target = (session.get("path", {}) or {}).get("target")
    if target:
        lines.append(f"TARGET: {target}")
    out_of_scope = [s for s in (profile.get("out_of_scope") or []) if str(s).strip()]
    if out_of_scope:
        lines.append(
            "OUT OF SCOPE (never report these as findings; they were excluded "
            "from testing): " + "; ".join(str(s) for s in out_of_scope)
        )

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

    runs = _execution_runs(session)
    if runs:
        lines.append(
            "## SANDBOX EXECUTION (recorded cockpit runs — real commands the tester "
            "approved and ran; each is tagged 'isolated lab' or 'REAL-TARGET ENGAGEMENT' "
            "— attribute findings to the correct target, never blur the two)"
        )
        lines.append(
            "Fold these into the Findings & Attack Narrative alongside the "
            "completed steps. Each has captured output you may READ to write "
            "accurate findings; cite it as 'Evidence: run-<id>' and do NOT "
            "reproduce the raw output."
        )
        for run in runs:
            ref = _run_ref(run)
            tag = "REAL-TARGET ENGAGEMENT" if (run.get("mode") or "lab") == "engagement" else "isolated lab"
            lines.append(f"### [EXECUTED · {tag}] ({ref}) {_run_cmdline(run)}")
            lines.append(f"Target: {run.get('target')} · Exit code: {run.get('exit_code')}")
            raw = _run_output(run).strip()
            if raw:
                lines.append(
                    f"EVIDENCE for {ref} (read only — cite as 'Evidence: {ref}', "
                    "do not reproduce):"
                )
                lines.append("<<<EVIDENCE")
                lines.append(raw)
                lines.append("EVIDENCE>>>")
            else:
                lines.append("EVIDENCE: (no output captured)")
            lines.append("")

    lines.append(
        "Now write the full Markdown penetration-test report following the "
        f"required sections. Put {_EVIDENCE_MARKER} where the Evidence section "
        "belongs. Do not fabricate anything, and do not paste raw output."
    )
    return "\n".join(lines)


def compose_report(
    session: dict, *, template: str = "standard", include_opsec: bool = False
) -> tuple[str, str]:
    """Draft the report for a session. Returns (markdown, model_used).

    The LLM writes the prose; the Evidence section (and the OSCP proof table, and the CVSS
    block) are inserted programmatically so captured values are reproduced verbatim rather than
    transcribed by the model. Raises ``llm.LLMError`` if the provider is unreachable / empty, and
    ``ValueError`` for an unknown template.

    ``template`` selects the exam/format mode (standard | oscp | cpts | bugbounty).
    ``include_opsec`` (D10) adds the red-team OPSEC assessment — off by default.
    """
    system = TEMPLATES.get((template or "standard").strip().lower())
    if system is None:
        raise ValueError(
            f"unknown report template {template!r} — one of: {', '.join(sorted(TEMPLATES))}"
        )
    cfg = llm.load_config()
    user = build_prompt(session)
    raw = llm.chat(system, user, cfg, max_tokens=_MAX_TOKENS)
    md = _clean_markdown(raw)
    if not md:
        raise llm.LLMError("the model returned an empty report")
    md = _strip_status_tags(md)
    # The OSCP proof table + the bug-bounty CVSS block are spliced like the evidence — computed
    # from state / a vector, never written by the model.
    md = _insert_proof_table(md, session)
    # VRT FIRST, so it ends up rendered BELOW the CVSS block — each _prepend_after_title
    # inserts directly under the title, so the last one spliced is the one on top. CVSS is
    # the computed number and leads; the VRT priority sits under it as the thing a Bugcrowd
    # triager will actually act on.
    # THE KNOWN-ISSUE CHECK rides at the TOP, above CVSS and VRT, because it is the one
    # thing that can make the whole submission pointless — and because a warning appended
    # under Evidence is a warning nobody reads before hitting submit. Computed, never
    # prompted for: the model must not be the thing that decides a finding is "already known".
    ki = build_known_issues_block(session)
    if ki and "Known-issue check" not in md:
        md = _prepend_after_title(md, ki)
    # ...and ABOVE even that: a scan whose session expired reports zero findings, and "no
    # vulnerabilities identified" is the most expensive sentence in this report to get wrong.
    # It goes first because it changes how everything below it should be read.
    health = build_session_health_block(session)
    if health and "AUTHENTICATED SESSION MAY HAVE EXPIRED" not in md:
        md = _prepend_after_title(md, health)
    vrt = build_vrt_block(session)
    if vrt and "Bugcrowd VRT" not in md:
        md = _prepend_after_title(md, vrt)
    cvss = build_cvss_block(session)
    if cvss and "CVSS 3.1" not in md:
        # Prepend the authoritative CVSS block just under the first heading (bug-bounty).
        md = _prepend_after_title(md, cvss)
    # WHO WROTE IT. Spliced, never prompted for: the model must not invent or
    # transcribe a candidate name or an OSID. An OSCP submission is not
    # attributable without this, and an unconfigured operator yields "" so the
    # report is unchanged rather than carrying empty labels.
    identity = operator_identity.report_identity(template)
    if identity:
        md = _prepend_after_title(md, identity)
    md = _insert_evidence(md, session, include_opsec=include_opsec)
    return md, cfg["model"]


def _prepend_after_title(md: str, block: str) -> str:
    """Insert ``block`` right after the first Markdown heading (or at the top)."""
    lines = md.split("\n")
    for i, ln in enumerate(lines):
        if ln.lstrip().startswith("#"):
            return "\n".join(lines[: i + 1] + ["", block, ""] + lines[i + 1:])
    return block + "\n\n" + md


# --------------------------------------------------------------------------- #
# captured-traffic redaction — THE ONE PLACE IT APPLIES (build #14 part 2)
# --------------------------------------------------------------------------- #
# The recording proxy stores request/response bodies RAW, deliberately: the request that matters
# on an engagement is usually the one carrying the token, and hiding it from the operator would
# defeat the feature. That decision (2026-08-03) put redaction HERE instead — a report is the
# artefact handed to a client or a grader, and a session token pasted into an OSCP submission is
# an easy and irreversible mistake.
#
# Masks VALUES whose parameter NAME looks secret, and nothing else. Blanking whole bodies would
# make the evidence useless, which is the failure mode the secretargs module already warns about:
# a redactor that eats the audit trail it exists to protect.
_SECRET_PARAM_NAMES = (
    "password", "passwd", "pwd", "pass", "secret", "token", "apikey", "api_key",
    "access_token", "refresh_token", "session", "sessionid", "session_id", "auth",
    "authorization", "cookie", "csrf", "private_key", "client_secret",
)
_SECRET_PARAM_RE = re.compile(
    r"(?i)\b(" + "|".join(re.escape(n) for n in _SECRET_PARAM_NAMES) + r")\b"
)
# form-encoded  name=value   (value runs to & or end)
_FORM_PAIR_RE = re.compile(r"(?i)([A-Za-z0-9_.\-\[\]]+)=([^&\s]*)")
# json          "name": "value"
_JSON_PAIR_RE = re.compile(r'(?i)("([A-Za-z0-9_.\-]+)"\s*:\s*)"([^"]*)"')


def redact_captured_body(body: str) -> str:
    """A captured request/response body with secret-looking VALUES masked. Never raises.

    Only the value is replaced, so the reader still sees WHICH parameter carried a credential —
    the same discipline ``secretargs.redact_argv`` follows for argv.
    """
    text = str(body or "")
    if not text:
        return text
    try:
        def _form(m: "re.Match[str]") -> str:
            return f"{m.group(1)}={REDACTED}" if _SECRET_PARAM_RE.search(m.group(1)) else m.group(0)

        def _json(m: "re.Match[str]") -> str:
            return f'{m.group(1)}"{REDACTED}"' if _SECRET_PARAM_RE.search(m.group(2)) else m.group(0)

        text = _JSON_PAIR_RE.sub(_json, text)
        return _FORM_PAIR_RE.sub(_form, text)
    except Exception:  # noqa: BLE001 - redaction must never break a report
        return REDACTED
