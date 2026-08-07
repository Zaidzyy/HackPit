"""Automatic de-duplication + ranked assembly — open·kritt's ``post_processing.py``, ported.

WHAT THIS IS
Fan-out producers (the AI code-audit, a multi-host recon/nuclei sweep) report the same defect
more than once — the same SQLi found via two flows, the same missing-header on twenty endpoints.
open·kritt's ``post_processing.py`` collapses those by a stable key, keeps the worst severity,
merges the evidence, and returns a severity-ranked list. This is that pass for HackPit findings,
across every surface.

Two properties matter and are tested:
  * **Idempotent.** Re-ingesting the same finding must not multiply it. The dedup key is a
    normalized (title + location + type), so wording and endpoint jitter collapse to one; and
    re-running the pipeline over its own output is a fixed point (a survivor's merge count is
    carried, never re-inflated).
  * **Ranked.** A pluggable ranker (rankers.py) gives the operator's engagement the final say on
    severity, then the list is sorted worst-first by ``IMPACT_LEVELS``.

Pure data — string/dict operations only, executes nothing.
"""

from __future__ import annotations

import re
from typing import Any

from . import rankers
from .schema import SEVERITY_LEVELS, coerce_finding, normalize_severity

# open·kritt names.
IMPACT_LEVELS = SEVERITY_LEVELS                 # ("critical","high","medium","low","info")
_IMPACT_RANK = {s: i for i, s in enumerate(IMPACT_LEVELS)}
BATCH_SIZE = 200                               # cap on findings assembled in one pass


# --------------------------------------------------------------------------- #
# the stable dedup key
# --------------------------------------------------------------------------- #
_WS = re.compile(r"\s+")
_TRAIL = re.compile(r"[\s\-–—:;,./]+$")


def _norm_title(title: str) -> str:
    """Lowercase, collapse whitespace, strip a trailing CVE/number and punctuation so two
    wordings of the same bug ('SQL injection in ?id=1' / 'SQL Injection in ?id ') collapse."""
    t = _WS.sub(" ", str(title or "").strip().lower())
    t = re.sub(r"\(?\bcve-\d{4}-\d{3,7}\b\)?", "", t)     # a CVE tag is not identity
    t = re.sub(r"[?&#].*$", "", t)                        # drop a query string / fragment
    return _TRAIL.sub("", t).strip()


def _location(finding: dict[str, Any]) -> str:
    """The primary place the finding is about — first source ref, else the target."""
    refs = finding.get("source_refs") or []
    if isinstance(refs, list) and refs:
        return _WS.sub(" ", str(sorted(str(r) for r in refs)[0]).strip().lower())
    return _WS.sub(" ", str(finding.get("target") or "").strip().lower())


def _vuln_type(finding: dict[str, Any]) -> str:
    """The 'type' half of the key: normalized vuln class, else the reference, else the title."""
    for k in ("vuln_class", "reference"):
        v = str(finding.get(k) or "").strip().lower()
        if v:
            return _WS.sub(" ", v)
    return _norm_title(finding.get("title", ""))


def dedup_key(finding: dict[str, Any]) -> tuple[str, str, str]:
    """Stable identity: (title-or-empty, location, type). The same defect at the same place of
    the same kind is one finding, no matter which producer reported it or how it was worded.

    When a finding has BOTH a concrete location (a source ref or target) AND a type (its vuln
    class or reference), those two ARE the identity — the title is dropped from the key, so the
    same SQLi found via two flows and worded differently still collapses (open·kritt collapses by
    class+location, not by wording). Only when a finding is unlocated does the normalized title
    re-enter the key, to avoid over-merging distinct issues that share nothing but a blank."""
    loc, vtype = _location(finding), _vuln_type(finding)
    has_type = bool(str(finding.get("vuln_class") or finding.get("reference") or "").strip())
    if loc and has_type:
        return ("", loc, vtype)
    return (_norm_title(finding.get("title", "")), loc, vtype)


# --------------------------------------------------------------------------- #
# dedup + merge (post_processing.py's collapse pass)
# --------------------------------------------------------------------------- #
def _merge_into(keep: dict[str, Any], other: dict[str, Any]) -> None:
    """Fold ``other`` into ``keep``: worst severity wins, source refs union, evidence appended,
    structured fields filled where empty. ``keep`` is mutated in place."""
    if _IMPACT_RANK.get(normalize_severity(other.get("severity")), 99) < _IMPACT_RANK.get(
            normalize_severity(keep.get("severity")), 99):
        keep["severity"] = normalize_severity(other.get("severity"))
        # the worse-severity record's title/attacker-path is the more useful phrasing
        if str(other.get("attacker_path") or "").strip():
            keep["attacker_path"] = other["attacker_path"]
    refs = list(keep.get("source_refs") or [])
    for r in (other.get("source_refs") or []):
        if r not in refs:
            refs.append(r)
    keep["source_refs"] = refs
    for f in ("attacker_path", "cvss", "vuln_class", "target", "reference", "evidence"):
        if not str(keep.get(f) or "").strip() and str(other.get(f) or "").strip():
            keep[f] = other[f]
    # merge custom fields, keeping the survivor's on a clash
    extra = dict(other.get("extra") or {})
    extra.update(dict(keep.get("extra") or {}))
    keep["extra"] = extra


def dedup(findings: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    """Collapse duplicates. Returns (survivors, merged_total).

    A survivor carries ``merged_count`` = the number of duplicates absorbed, made stable across
    re-runs by ADDING any merge counts already on the inputs (so re-running the pipeline over its
    own output keeps the badge, never re-inflates it). ``merged_total`` is the count for the
    "merged N duplicates" note.
    """
    survivors: dict[tuple, dict[str, Any]] = {}
    counts: dict[tuple, int] = {}
    carried: dict[tuple, int] = {}
    for raw in findings:
        f = coerce_finding(raw)
        f["severity"] = normalize_severity(f.get("severity"))
        k = dedup_key(f)
        carried[k] = carried.get(k, 0) + int(raw.get("merged_count") or 0)
        if k not in survivors:
            survivors[k] = f
            counts[k] = 0
        else:
            _merge_into(survivors[k], f)
            counts[k] += 1
    out: list[dict[str, Any]] = []
    merged_total = 0
    for k, f in survivors.items():
        f["merged_count"] = counts[k] + carried[k]
        merged_total += counts[k]
        out.append(f)
    return out, merged_total


# --------------------------------------------------------------------------- #
# the pipeline: dedup -> rank -> sort worst-first
# --------------------------------------------------------------------------- #
def severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    by = {s: 0 for s in IMPACT_LEVELS}
    for f in findings:
        by[normalize_severity(f.get("severity"))] += 1
    return by


def run_pipeline(findings: list[dict[str, Any]],
                 ranker_id: str | None = None) -> dict[str, Any]:
    """De-duplicate, re-score with the selected ranker, sort worst-first. Executes nothing.

    Returns the assembled result: the ranked ``findings`` (each carrying ``merged_count`` and the
    ``ranker`` that scored it), the ``merged`` total, the ranker metadata, and severity counts.
    Deterministic and idempotent — safe to run on every ingest and to re-run over its own output.
    """
    ranker = rankers.get_ranker(ranker_id)
    survivors, merged_total = dedup(findings or [])
    for f in survivors:
        sev, note = ranker.rescore(f)
        f["severity"] = sev
        f["ranker"] = ranker.id
        if note:
            f.setdefault("extra", {})["ranker_note"] = note
    survivors.sort(key=lambda f: (_IMPACT_RANK.get(normalize_severity(f["severity"]), 99),
                                  -int(f.get("merged_count") or 0),
                                  _norm_title(f.get("title", ""))))
    survivors = survivors[:BATCH_SIZE]
    return {
        "findings": survivors,
        "merged": merged_total,
        "merged_note": (f"merged {merged_total} duplicate"
                        f"{'s' if merged_total != 1 else ''}" if merged_total else ""),
        "ranker": ranker.id,
        "ranker_label": ranker.label,
        "total": len(survivors),
        "by_severity": severity_counts(survivors),
    }
