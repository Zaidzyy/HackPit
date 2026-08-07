"""The MITRE ATT&CK kill-chain reference — a pure data loader for objective mapping.

PORTED FROM Decepticon (tools/references/killchain.yaml + its reader), Apache-2.0. See
THIRD_PARTY_LICENSES and NOTICE. Reshaped for HackPit: the OPPLAN maps each objective onto
ATT&CK technique ids, and the coverage view answers "which tactics/techniques did this
engagement's objectives exercise". That is a lexical id lookup over the reference below — no
ATT&CK API call, no network, no execution. This module only READS a bundled YAML file.

WHY A REFERENCE, NOT A FREE-TEXT FIELD. An objective that carries ``T1190`` is worth more
than one that carries the prose "exploit the web app": it renders in a coverage grid, feeds
the report's ATT&CK deliverable, and lets the orchestrator's proposals be checked against a
declared technique. The reference gives every id a name and a tactic so the objective's bare
id becomes a labelled cell in the grid.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

_KILLCHAIN_PATH = Path(__file__).parent / "references" / "killchain.yaml"

# The four ConOps phases an engagement moves through. Objectives declare one of these; the
# reference ties each ATT&CK tactic to the phase it typically belongs to.
PHASES = ("recon", "exploitation", "post-exploitation", "actions-on-objectives")


@lru_cache(maxsize=1)
def load_killchain() -> dict[str, Any]:
    """The parsed reference: ``{"tactics": [ {id, name, phase, techniques:[{id,name}]} ]}``.

    Cached — the file is bundled and immutable at runtime. ``yaml.safe_load`` only, so a
    malformed reference can never execute code (this module is inside the executes-nothing
    state package, and a safety test proves it).
    """
    with _KILLCHAIN_PATH.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    tactics = data.get("tactics") or []
    return {"tactics": [t for t in tactics if isinstance(t, dict)]}


@lru_cache(maxsize=1)
def _technique_index() -> dict[str, dict[str, str]]:
    """``T1190 -> {name, tactic_id, tactic_name, phase}`` for every technique in the reference."""
    idx: dict[str, dict[str, str]] = {}
    for tactic in load_killchain()["tactics"]:
        for tech in tactic.get("techniques") or []:
            tid = str(tech.get("id") or "").strip().upper()
            if not tid:
                continue
            # First tactic that lists a technique wins its "home" tactic for the grid; a few
            # techniques (T1550) appear under two tactics in ATT&CK and that is fine — the
            # coverage grid marks the cell under EVERY tactic that lists it (see below).
            idx.setdefault(tid, {
                "name": str(tech.get("name") or tid),
                "tactic_id": str(tactic.get("id") or ""),
                "tactic_name": str(tactic.get("name") or ""),
                "phase": str(tactic.get("phase") or ""),
            })
    return idx


def technique_name(technique_id: str) -> str:
    """The ATT&CK name for a technique id, or the id itself when it is not in the reference
    (an operator may map an objective to any technique — the reference is a convenience, not
    a whitelist)."""
    tid = str(technique_id or "").strip().upper()
    return _technique_index().get(tid, {}).get("name", tid)


def is_known(technique_id: str) -> bool:
    return str(technique_id or "").strip().upper() in _technique_index()


def tactics_for_phase(phase: str) -> list[dict[str, Any]]:
    p = str(phase or "").strip().lower()
    return [t for t in load_killchain()["tactics"] if str(t.get("phase") or "").lower() == p]


def coverage(technique_ids: list[str]) -> dict[str, Any]:
    """The ATT&CK coverage view for a set of exercised technique ids.

    Returns a per-tactic grid: every tactic in the reference, each technique flagged
    ``covered`` when one of ``technique_ids`` matches it, plus roll-up counts. A technique id
    that is not in the reference is still counted (``unmapped``) so a coverage claim is never
    silently dropped. Pure — a lexical id match, deterministic, no ordering surprises.
    """
    exercised = {str(t or "").strip().upper() for t in technique_ids if str(t or "").strip()}
    grid: list[dict[str, Any]] = []
    covered_total = 0
    technique_total = 0
    tactics_touched = 0
    for tactic in load_killchain()["tactics"]:
        cells = []
        tactic_hit = False
        for tech in tactic.get("techniques") or []:
            tid = str(tech.get("id") or "").strip().upper()
            hit = tid in exercised
            if hit:
                covered_total += 1
                tactic_hit = True
            technique_total += 1
            cells.append({
                "id": tid,
                "name": str(tech.get("name") or tid),
                "covered": hit,
            })
        if tactic_hit:
            tactics_touched += 1
        grid.append({
            "tactic_id": str(tactic.get("id") or ""),
            "tactic_name": str(tactic.get("name") or ""),
            "phase": str(tactic.get("phase") or ""),
            "techniques": cells,
            "covered": tactic_hit,
        })
    known = {t for t in exercised if t in _technique_index()}
    unmapped = sorted(exercised - known)
    return {
        "grid": grid,
        "counts": {
            "tactics_total": len(grid),
            "tactics_touched": tactics_touched,
            "techniques_total": technique_total,
            "techniques_covered": covered_total,
            "exercised_unique": len(exercised),
            "unmapped": unmapped,
        },
    }
