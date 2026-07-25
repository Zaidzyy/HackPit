"""Render a scan into a Markdown report — programmatic, and faithful to the tools.

Same discipline as the engagement report: everything here is assembled from the scanner
output, nothing is embellished. No severity is re-judged, no message is rewritten, no
"executive summary" is invented from findings the tools didn't make. If a scanner said it,
the report says it; if it didn't, the report doesn't.

The one piece of editorial is the caveat at the end, and it is there precisely because a
tidy report invites the wrong conclusion: SAST reports what its rules match, so a short
report is a statement about the rules, not a clean bill of health.
"""

from __future__ import annotations

from typing import Any

from .findings import SEVERITY_ORDER

_SEV_LABEL = {
    "critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
    "low": "LOW", "info": "INFO",
}


def _escape(text: str) -> str:
    """Keep tool text from breaking the table/list layout it lands in."""
    return " ".join(str(text or "").split()).replace("|", "\\|")


def render_markdown(result: dict[str, Any]) -> str:
    """A scan result (the /codescan/scan payload) -> a Markdown report."""
    summary = result.get("summary") or {}
    by_sev: dict[str, int] = summary.get("by_severity") or {}
    by_cat: dict[str, int] = summary.get("by_category") or {}
    findings: list[dict[str, Any]] = result.get("findings") or []
    tools = result.get("tools_run") or []

    out: list[str] = []
    out.append(f"# Code scan — {result.get('path', '(unknown path)')}")
    out.append("")
    out.append(
        f"**{summary.get('total', 0)} findings** across "
        f"**{summary.get('files_affected', 0)}** files · "
        f"{result.get('files_scanned', 0)} files scanned · "
        f"{result.get('duration_s', 0)}s · "
        f"scanners: {', '.join(tools) or 'none'}"
    )
    out.append("")

    # ---- method, stated up front so the numbers are read correctly -----------
    out.append("## Method")
    out.append("")
    out.append(
        "STATIC analysis only. The scanners parsed the source files; **no code from the "
        "scanned tree was executed**, no target or network was involved, and the codebase "
        "was opened read-only."
    )
    out.append("")
    out.append(f"- Scanners: `{'`, `'.join(tools) or 'none'}`")
    out.append(f"- Semgrep ruleset: `{result.get('ruleset', '(default)')}`")
    out.append("")

    for warning in result.get("warnings") or []:
        out.append(f"> ⚠ {_escape(warning)}")
    if result.get("warnings"):
        out.append("")

    # ---- roll-up -------------------------------------------------------------
    out.append("## Summary")
    out.append("")
    out.append("| Severity | Findings |")
    out.append("|---|---|")
    for sev in SEVERITY_ORDER:
        count = by_sev.get(sev, 0)
        if count:
            out.append(f"| {_SEV_LABEL[sev]} | {count} |")
    if not any(by_sev.values()):
        out.append("| — | 0 |")
    out.append("")

    if by_cat:
        out.append(
            "**By category:** "
            + ", ".join(f"{cat} ({n})" for cat, n in by_cat.items())
        )
        out.append("")

    # ---- findings, worst first ----------------------------------------------
    out.append("## Findings")
    out.append("")
    if not findings:
        out.append("No findings were reported for this tree with the ruleset above.")
        out.append("")
    else:
        current = None
        for f in findings:
            sev = str(f.get("severity") or "info")
            if sev != current:
                current = sev
                out.append(f"### {_SEV_LABEL.get(sev, sev.upper())}")
                out.append("")
            tools_for = [str(t) for t in (f.get("tools") or [f.get("tool")]) if t]
            # Corroboration reads as "both agree"; a single tool just names itself.
            attribution = (
                f"{' + '.join(sorted(tools_for))} agree"
                if len(tools_for) > 1
                else (tools_for[0] if tools_for else "unknown tool")
            )
            out.append(
                f"**`{_escape(f.get('file'))}:{f.get('line')}`** — "
                f"`{_escape(f.get('rule_id'))}` ({attribution})"
            )
            out.append("")
            out.append(f"{_escape(f.get('message'))}")
            out.append("")
            bits: list[str] = [f"category: {f.get('category')}"]
            if f.get("cwe"):
                bits.append(str(f["cwe"]))
            if f.get("owasp"):
                bits.append(str(f["owasp"]))
            if f.get("confidence"):
                bits.append(f"confidence: {str(f['confidence']).lower()}")
            if f.get("tool_severity"):
                bits.append(f"reported as: {f['tool_severity']}")
            out.append(f"<sub>{' · '.join(_escape(b) for b in bits)}</sub>")
            if f.get("kb_entry_id"):
                out.append("")
                out.append(
                    f"<sub>technique: {_escape(f.get('kb_title'))} "
                    f"(`{_escape(f.get('kb_entry_id'))}`)</sub>"
                )
            out.append("")

    # ---- the caveat ----------------------------------------------------------
    out.append("---")
    out.append("")
    out.append(
        "*Static analysis reports what its rules match. A finding here is a lead to verify, "
        "not a confirmed vulnerability — and an empty section means these rules matched "
        "nothing, which is not the same as the code being safe. Nothing in this report was "
        "produced by running the scanned code.*"
    )
    out.append("")
    return "\n".join(out)
