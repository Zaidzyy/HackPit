"""Compact ATT&CK tags for planned STEPS and executed RUNS.

The footprint panel (``detection.resolver``) gives the full defender's-eye view of ONE command
on demand. This module gives the small version: the technique ids + tactics + loudness that ride
along on every step of an attack path and every run in a report, so the plan and the evidence are
ATT&CK-tagged wherever they are shown.

Deliberately different from the resolver in two ways:

* **No LLM, ever.** Tagging runs over every step of every path and every run of every report; it
  must be instant, offline and deterministic. It uses the curated catalog only. A command the
  catalog does not cover simply gets no tag (``None``) rather than a guess — the drawer can still
  fetch the ai_suggested footprint for it on demand.
* **Small.** Ids, names, tactics, loudness. No telemetry lists, no Sigma rules, no prose.

RUN TAGS ARE DERIVED, NOT STORED. A run record already persists the command and argv it ran, and
the tag is a pure function of those, so it is computed at read time. That keeps the
safety-critical run store schema untouched — no migration, nothing new written by an execution
path — while giving identical results.

Executes nothing.
"""

from __future__ import annotations

from typing import Any

from . import attck, catalog


def _tag_from_match(match: catalog.Match) -> dict[str, Any] | None:
    spec = match.spec
    if spec is None and not match.signals:
        return None

    tech_ids: list[str] = list(spec.techniques) if spec else []
    loud = spec.loudness if spec else "moderate"
    for sig in match.signals:
        for tid in sig.techniques:
            if tid not in tech_ids:
                tech_ids.append(tid)
        if sig.louder:
            loud = catalog.bump(loud)

    techniques = []
    tactics: list[dict[str, Any]] = []
    seen_tac: set[str] = set()
    for tid in tech_ids:
        t = attck.technique(tid)
        if t is None:
            continue
        techniques.append({
            "id": t.id,
            "name": t.name,
            "url": t.url,
            "tactic_ids": list(t.tactics),
            "tactic_names": t.tactic_names(),
            "stealth": t.is_stealth(),
        })
        for tac in t.tactics:
            if tac not in seen_tac:
                seen_tac.add(tac)
                tactics.append({
                    "id": tac,
                    "name": attck.TACTICS.get(tac, tac),
                    "also_known_as": attck.TACTIC_ALIASES.get(tac),
                })

    if not techniques:
        return None

    return {
        "activity": spec.label if spec else "",
        "grounded": spec is not None,
        "techniques": techniques,
        "tactics": tactics,
        "stealth": any(t["stealth"] for t in techniques),
        "loudness": loud,
        "loudness_score": catalog.loudness_score(loud),
        "signals": [s.id for s in match.signals],
    }


def tag_command(command: str, args: list[str] | None = None) -> dict[str, Any] | None:
    """The compact ATT&CK tag for one command, or None when the catalog does not cover it."""
    if not str(command or "").strip():
        return None
    return _tag_from_match(catalog.lookup(str(command), [str(a) for a in (args or [])]))


def tag_argv(cmdline: str) -> dict[str, Any] | None:
    """The tag for a whole command line ('nmap -sV host')."""
    line = str(cmdline or "").strip()
    if not line:
        return None
    try:
        import shlex
        parts = shlex.split(line)
    except ValueError:
        parts = line.split()
    if not parts:
        return None
    return tag_command(parts[0], parts[1:])


def first_command(step: dict[str, Any] | Any) -> str:
    """The first real (non-comment, non-blank) command line in a step's commands."""
    if hasattr(step, "model_dump"):
        step = step.model_dump()
    for c in (dict(step or {}).get("commands") or []):
        raw = (c.get("cmd") if isinstance(c, dict) else getattr(c, "cmd", "")) or ""
        for line in str(raw).splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                return line
    return ""


def tag_step(step: dict[str, Any] | Any) -> dict[str, Any] | None:
    """The tag for one attack-path step, from its first real command."""
    return tag_argv(first_command(step))


def tag_phases(phases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Attach ``step['attck']`` to every step of an attack path, in place. Returns ``phases``.

    A step whose command the catalog does not cover keeps ``attck = None`` — the UI shows
    "not mapped" rather than a guess, and the drawer can still ask for the ai_suggested
    footprint for that one step.
    """
    for phase in phases or []:
        for step in (phase.get("steps") or []):
            try:
                step["attck"] = tag_step(step)
            except Exception:
                step["attck"] = None
    return phases


def tag_run(run: dict[str, Any] | Any) -> dict[str, Any] | None:
    """The tag for a recorded cockpit run — derived from its stored command + argv."""
    if hasattr(run, "model_dump"):
        run = run.model_dump()
    run = dict(run or {})
    return tag_command(run.get("command") or "", run.get("args") or [])


def summarize(tags: list[dict[str, Any] | None]) -> dict[str, Any]:
    """Roll a set of tags up into a coverage summary (for the report header / panel banner)."""
    techs: dict[str, dict[str, Any]] = {}
    tactics: dict[str, dict[str, Any]] = {}
    loudest = ""
    counted = 0
    for tag in tags:
        if not tag:
            continue
        counted += 1
        for t in tag.get("techniques", []):
            techs.setdefault(t["id"], t)
        for tac in tag.get("tactics", []):
            tactics.setdefault(tac["id"], tac)
        if catalog.loudness_score(tag.get("loudness", "")) > catalog.loudness_score(loudest):
            loudest = tag.get("loudness", "")
    return {
        "tagged": counted,
        "untagged": sum(1 for t in tags if not t),
        "techniques": sorted(techs.values(), key=lambda t: t["id"]),
        "tactics": sorted(tactics.values(), key=lambda t: t["id"]),
        "stealth": any(t.get("stealth") for t in techs.values()),
        "loudest": loudest,
        "loudest_score": catalog.loudness_score(loudest),
    }


__all__ = [
    "tag_command", "tag_argv", "tag_step", "tag_phases", "tag_run", "summarize", "first_command",
]
