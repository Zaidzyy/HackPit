"""One findings schema for both scanners.

Semgrep and Bandit describe the same defect differently — different id shapes, different
severity vocabularies, one carries OWASP and the other doesn't, one reports absolute paths
and the other relative. This module flattens both into a single :class:`Finding` so the UI,
the report and the KB tie-in only ever see one shape.

Two rules govern everything here:

* **Faithful to the tool.** A finding's id, message, severity and location come from the
  scanner. Nothing is invented, rewritten or "improved" — severity is MAPPED between
  vocabularies, never re-judged, and the original label is kept in ``tool_severity`` so the
  mapping is auditable.
* **Defensive parsing.** Scanner output is treated as untrusted input: a missing key, a null,
  a wrong type or a truncated record drops that one finding, never the run.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Ordered worst-first — the display order, and the tiebreak when two tools disagree.
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
_SEV_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}

# Semgrep severity vocabulary -> ours.
_SEMGREP_SEVERITY = {
    "CRITICAL": "critical", "ERROR": "high", "WARNING": "medium",
    "INFO": "low", "INVENTORY": "info", "EXPERIMENT": "info",
}
# Bandit severity vocabulary -> ours.
_BANDIT_SEVERITY = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low", "UNDEFINED": "info"}

# CWE -> category. The category is what the UI groups on and what the KB tie-in matches
# against, so it is derived from the CWE (stable, tool-independent) wherever one exists.
_CWE_CATEGORY = {
    "CWE-20": "validation", "CWE-22": "path-traversal", "CWE-78": "injection",
    "CWE-79": "xss", "CWE-89": "injection", "CWE-90": "injection", "CWE-94": "injection",
    "CWE-95": "injection", "CWE-113": "injection", "CWE-116": "xss",
    "CWE-200": "info-disclosure", "CWE-209": "info-disclosure", "CWE-259": "secrets",
    "CWE-295": "crypto", "CWE-311": "crypto", "CWE-326": "crypto", "CWE-327": "crypto",
    "CWE-329": "crypto", "CWE-330": "crypto", "CWE-338": "crypto", "CWE-347": "auth",
    "CWE-352": "csrf", "CWE-377": "insecure-temp", "CWE-379": "insecure-temp",
    "CWE-400": "dos", "CWE-489": "misconfiguration", "CWE-502": "deserialization",
    "CWE-601": "open-redirect", "CWE-605": "misconfiguration", "CWE-611": "xxe",
    "CWE-703": "error-handling", "CWE-732": "permissions", "CWE-798": "secrets",
    "CWE-918": "ssrf", "CWE-943": "injection", "CWE-942": "misconfiguration",
}
_CWE_RE = re.compile(r"CWE[-\s]?(\d{1,4})", re.I)


def _cwe_id(value: Any) -> str | None:
    """Normalise any of Semgrep's/Bandit's CWE shapes to 'CWE-89', or None."""
    if isinstance(value, dict):  # bandit: {"id": 89, "link": "..."}
        raw = value.get("id")
        return f"CWE-{raw}" if raw not in (None, "") else None
    if isinstance(value, list):
        for item in value:
            got = _cwe_id(item)
            if got:
                return got
        return None
    m = _CWE_RE.search(str(value or ""))
    return f"CWE-{m.group(1)}" if m else None


def _first_str(value: Any) -> str | None:
    """Semgrep metadata fields are sometimes a string, sometimes a list of them."""
    if isinstance(value, list):
        return str(value[0]) if value else None
    text = str(value or "").strip()
    return text or None


def _rel(path: Any, root: Path) -> str:
    """Scanner path -> a path relative to the scan root (display + dedupe key)."""
    text = str(path or "").strip()
    if not text:
        return ""
    try:
        return os.path.relpath(Path(text).resolve(), root).replace("\\", "/")
    except (OSError, ValueError):
        return text.replace("\\", "/")


@dataclass
class Finding:
    """One normalized defect. ``tools`` holds every scanner that reported it."""

    rule_id: str
    tool: str
    severity: str
    file: str
    line: int
    message: str
    category: str
    cwe: str | None = None
    owasp: str | None = None
    confidence: str | None = None
    tool_severity: str | None = None     # the scanner's own word, kept for auditability
    tools: list[str] = field(default_factory=list)
    kb_entry_id: str | None = None       # filled by the KB tie-in (CS3), never fabricated
    kb_title: str | None = None

    def key(self) -> tuple:
        """Dedupe identity: the same defect, at the same place, of the same kind.

        Location + CWE (falling back to category) — NOT the rule id, because the whole point
        is that two tools name the same defect differently.
        """
        return (self.file, self.line, self.cwe or f"cat:{self.category}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id, "tool": self.tool, "severity": self.severity,
            "file": self.file, "line": self.line, "message": self.message,
            "category": self.category, "cwe": self.cwe, "owasp": self.owasp,
            "confidence": self.confidence, "tool_severity": self.tool_severity,
            "tools": self.tools or [self.tool],
            "kb_entry_id": self.kb_entry_id, "kb_title": self.kb_title,
        }


def _category(explicit: Any, cwe: str | None, rule_id: str) -> str:
    """Category from the rule's own metadata, else the CWE, else the rule id's own words."""
    named = _first_str(explicit)
    if named:
        return named.lower()
    if cwe and cwe in _CWE_CATEGORY:
        return _CWE_CATEGORY[cwe]
    low = rule_id.lower()
    for needle, cat in (
        ("sql", "injection"), ("command", "injection"), ("inject", "injection"),
        ("xss", "xss"), ("traversal", "path-traversal"), ("ssrf", "ssrf"),
        ("xxe", "xxe"), ("xml", "xxe"), ("pickle", "deserialization"),
        ("deserial", "deserialization"), ("hardcoded", "secrets"), ("password", "secrets"),
        ("crypto", "crypto"), ("hash", "crypto"), ("ssl", "crypto"), ("tls", "crypto"),
        ("random", "crypto"), ("jwt", "auth"), ("tmp", "insecure-temp"),
    ):
        if needle in low:
            return cat
    return "other"


# --------------------------------------------------------------------------- #
# per-tool normalisation
# --------------------------------------------------------------------------- #
def from_semgrep(data: dict[str, Any], root: Path) -> list[Finding]:
    """Semgrep JSON -> findings. A malformed record is skipped, never fatal."""
    out: list[Finding] = []
    for item in (data or {}).get("results") or []:
        if not isinstance(item, dict):
            continue
        extra = item.get("extra") if isinstance(item.get("extra"), dict) else {}
        meta = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
        rule_id = str(item.get("check_id") or "").strip()
        if not rule_id:
            continue
        # 'codescan.rules.hp-python-sql-string-build' -> 'hp-python-sql-string-build'
        short = rule_id.rsplit(".", 1)[-1]
        raw_sev = str(extra.get("severity") or "").upper()
        cwe = _cwe_id(meta.get("cwe"))
        start = item.get("start") if isinstance(item.get("start"), dict) else {}
        try:
            line = int(start.get("line") or 0)
        except (TypeError, ValueError):
            line = 0
        out.append(
            Finding(
                rule_id=short,
                tool="semgrep",
                severity=_SEMGREP_SEVERITY.get(raw_sev, "medium"),
                tool_severity=raw_sev or None,
                file=_rel(item.get("path"), root),
                line=line,
                message=" ".join(str(extra.get("message") or "").split()),
                category=_category(meta.get("category"), cwe, short),
                cwe=cwe,
                owasp=_first_str(meta.get("owasp")),
                tools=["semgrep"],
            )
        )
    return out


def from_bandit(data: dict[str, Any], root: Path) -> list[Finding]:
    """Bandit JSON -> findings. Confidence is carried through rather than folded into
    severity: Bandit's LOW-confidence hits are exactly the ones a reviewer triages first."""
    out: list[Finding] = []
    for item in (data or {}).get("results") or []:
        if not isinstance(item, dict):
            continue
        test_id = str(item.get("test_id") or "").strip()
        if not test_id:
            continue
        name = str(item.get("test_name") or "").strip()
        rule_id = f"{test_id}:{name}" if name and name != "blacklist" else test_id
        raw_sev = str(item.get("issue_severity") or "").upper()
        cwe = _cwe_id(item.get("issue_cwe"))
        try:
            line = int(item.get("line_number") or 0)
        except (TypeError, ValueError):
            line = 0
        out.append(
            Finding(
                rule_id=rule_id,
                tool="bandit",
                severity=_BANDIT_SEVERITY.get(raw_sev, "low"),
                tool_severity=raw_sev or None,
                file=_rel(item.get("filename"), root),
                line=line,
                message=" ".join(str(item.get("issue_text") or "").split()),
                category=_category(None, cwe, f"{test_id} {name}"),
                cwe=cwe,
                confidence=str(item.get("issue_confidence") or "").upper() or None,
                tools=["bandit"],
            )
        )
    return out


# --------------------------------------------------------------------------- #
# merge + summarise
# --------------------------------------------------------------------------- #
def merge(*groups: list[Finding]) -> list[Finding]:
    """Combine both tools' findings, collapsing duplicates, worst-first.

    When two scanners report the same defect at the same place, that is CORROBORATION, not
    two bugs: they collapse into one finding carrying both tool names, the higher severity,
    and the more specific rule id. Sorted worst-first, then by file and line so the list
    reads like a review queue.
    """
    merged: dict[tuple, Finding] = {}
    for group in groups:
        for finding in group:
            key = finding.key()
            existing = merged.get(key)
            if existing is None:
                merged[key] = finding
                continue
            for tool in finding.tools or [finding.tool]:
                if tool not in existing.tools:
                    existing.tools.append(tool)
            existing.tool = "+".join(sorted(existing.tools))
            if _SEV_RANK.get(finding.severity, 9) < _SEV_RANK.get(existing.severity, 9):
                existing.severity = finding.severity
                existing.tool_severity = finding.tool_severity
                existing.rule_id = finding.rule_id
                existing.message = finding.message
            existing.cwe = existing.cwe or finding.cwe
            existing.owasp = existing.owasp or finding.owasp
            existing.confidence = existing.confidence or finding.confidence
    return sorted(
        merged.values(),
        key=lambda f: (_SEV_RANK.get(f.severity, 9), f.file, f.line, f.rule_id),
    )


def summarize(findings: list[Finding]) -> dict[str, Any]:
    """Roll-up for the header + the filters: counts by severity, category, tool and file."""
    by_sev: dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    by_cat: dict[str, int] = {}
    by_tool: dict[str, int] = {}
    files: set[str] = set()
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        by_cat[f.category] = by_cat.get(f.category, 0) + 1
        for tool in f.tools or [f.tool]:
            by_tool[tool] = by_tool.get(tool, 0) + 1
        if f.file:
            files.add(f.file)
    return {
        "total": len(findings),
        "by_severity": by_sev,
        "by_category": dict(sorted(by_cat.items(), key=lambda kv: -kv[1])),
        "by_tool": by_tool,
        "files_affected": len(files),
    }
