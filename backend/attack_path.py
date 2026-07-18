"""Guided attack-path composition — HackPit's first generative feature.

Given a goal ("HackTheBox Windows AD box") the flow is:

  1. **Retrieve** grounding from the KB via the existing hybrid search, seeded
     across the five canonical phases so every phase gets candidate techniques.
  2. **Compose** — hand the goal + retrieved techniques to the LLM (see
     ``llm.py``) acting as an authorized-engagement methodology guide, asking
     for an ordered path where every step CITES a real KB ``entry_id`` and a
     1–2 line rationale. The model may only use provided ids.
  3. **Ground / validate** — drop any step whose ``entry_id`` isn't in the KB,
     then attach the *real* entry's commands (never the model's) so nothing
     copyable can be hallucinated. Each surviving step gets a STABLE id
     (``{phase}-{n}``) so a later engagement layer can hang check-off state and
     pasted results off it without the response shape changing.

The KB itself is passed in (entries + by_id + a search callable) so this module
stays decoupled from FastAPI and from how the KB is loaded.
"""

from __future__ import annotations

from typing import Any, Callable

import llm

# --------------------------------------------------------------------------- #
# the five canonical phases, in execution order
# --------------------------------------------------------------------------- #
PHASE_ORDER: list[str] = [
    "recon",
    "enumeration",
    "exploitation",
    "privesc",
    "post-exploitation",
]

PHASE_LABEL: dict[str, str] = {
    "recon": "Recon",
    "enumeration": "Enumeration",
    "exploitation": "Exploitation",
    "privesc": "Privilege escalation",
    "post-exploitation": "Post-exploitation",
}

# search terms that bias one hybrid query toward each phase
PHASE_SEED: dict[str, str] = {
    "recon": "reconnaissance port scan nmap host discovery subdomain fingerprint",
    "enumeration": "enumeration smb ldap users shares services web directories",
    "exploitation": "exploit initial access vulnerability foothold shell",
    "privesc": "privilege escalation local privesc admin root system",
    "post-exploitation": "persistence lateral movement pivoting credential dump loot",
}

# KB meta.phase values → canonical phase
_META_PHASE_MAP: dict[str, str] = {
    "recon": "recon",
    "enumeration": "enumeration",
    "ad-enum": "enumeration",
    "exploitation": "exploitation",
    "credentials": "exploitation",
    "privesc": "privesc",
    "ad-privesc": "privesc",
    "pivoting": "post-exploitation",
    "persistence": "post-exploitation",
    "ad-persistence": "post-exploitation",
}

# fallback: KB category → canonical phase (when meta.phase is absent)
_CATEGORY_MAP: dict[str, str] = {
    "recon": "recon",
    "services": "enumeration",
    "active-directory": "enumeration",
    "web": "exploitation",
    "exploitation": "exploitation",
    "credentials": "exploitation",
    "privesc": "privesc",
    "post-exploitation": "post-exploitation",
    "persistence": "post-exploitation",
}

# target-type chip → extra query context
_TARGET_CONTEXT: dict[str, str] = {
    "web": "web application bug bounty",
    "ad": "active directory windows domain",
    "linux": "linux host",
    "ctf": "capture the flag",
}

# tuning
_PER_PHASE_CAP = 6          # techniques kept per phase for the prompt
_CMDS_PER_ENTRY = 4         # commands shown per technique in the prompt
_SUMMARY_CHARS = 260
_CMD_CHARS = 320

SearchFn = Callable[[str, int, str], list[dict]]


def canonical_phase(entry: dict) -> str:
    """Map a KB entry to one of the five canonical phases."""
    meta = entry.get("meta") or {}
    ph = meta.get("phase")
    if isinstance(ph, str) and ph in _META_PHASE_MAP:
        return _META_PHASE_MAP[ph]
    cat = entry.get("category", "")
    return _CATEGORY_MAP.get(cat, "enumeration")


def entry_commands(entry: dict, cap: int = _CMDS_PER_ENTRY) -> list[dict[str, str]]:
    """Flatten an entry's step code blocks into copyable {lang, cmd} commands.

    Deduplicated (some entries repeat a command across steps) and capped so a
    single technique can't dominate the prompt or a rendered card.
    """
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for step in entry.get("steps", []) or []:
        for code in step.get("code", []) or []:
            cmd = (code.get("cmd") or "").strip()
            if not cmd or cmd in seen:
                continue
            seen.add(cmd)
            out.append({"lang": code.get("lang") or "bash", "cmd": cmd})
            if len(out) >= cap:
                return out
    return out


# --------------------------------------------------------------------------- #
# 1) retrieval
# --------------------------------------------------------------------------- #
def retrieve(
    by_id: dict[str, dict],
    goal: str,
    target_type: str | None,
    search_fn: SearchFn,
) -> dict[str, list[dict]]:
    """Gather candidate techniques from the KB, bucketed by canonical phase.

    Runs one broad hybrid query on the goal plus one phase-seeded query per
    canonical phase, unions the hits (keeping the best score seen per entry),
    then buckets each entry into its phase and keeps the top few per phase.
    """
    ctx = _TARGET_CONTEXT.get((target_type or "").lower(), "")
    base = f"{goal} {ctx}".strip()

    # entry_id -> best score seen across all queries
    best: dict[str, float] = {}

    def ingest(hits: list[dict]) -> None:
        for h in hits:
            eid = h.get("id")
            if not eid or eid not in by_id:
                continue
            score = float(h.get("score") or 0.0)
            if eid not in best or score > best[eid]:
                best[eid] = score

    # broad query on the goal itself
    ingest(search_fn(base, 24, "hybrid"))
    # one phase-seeded query each, so no phase starts empty
    for phase in PHASE_ORDER:
        ingest(search_fn(f"{base} {PHASE_SEED[phase]}", 8, "hybrid"))

    # bucket into phases
    buckets: dict[str, list[tuple[float, dict]]] = {p: [] for p in PHASE_ORDER}
    for eid, score in best.items():
        e = by_id[eid]
        buckets[canonical_phase(e)].append((score, e))

    grouped: dict[str, list[dict]] = {}
    for phase in PHASE_ORDER:
        ranked = sorted(buckets[phase], key=lambda x: x[0], reverse=True)
        techs = []
        for _score, e in ranked[:_PER_PHASE_CAP]:
            techs.append(
                {
                    "entry_id": e["id"],
                    "title": e["title"],
                    "category": e.get("category", ""),
                    "summary": (e.get("summary") or "")[:_SUMMARY_CHARS],
                    "commands": entry_commands(e),
                }
            )
        if techs:
            grouped[phase] = techs
    return grouped


# --------------------------------------------------------------------------- #
# 2) prompt construction
# --------------------------------------------------------------------------- #
_SYSTEM = (
    "You are a penetration-testing methodology guide helping a security "
    "professional on an AUTHORIZED engagement. You compose an ordered attack "
    "path strictly from a provided library of the user's own techniques. "
    "Hard rules:\n"
    "- Use ONLY the entry_id values given to you. Never invent an entry_id, a "
    "command, or a technique that is not in the library.\n"
    "- Adapt the ordering and selection to the stated goal; skip techniques "
    "that do not fit.\n"
    "- For each step give the entry_id and a 1-2 sentence rationale ('why') "
    "explaining what it achieves at that point in the engagement.\n"
    "- Group steps under the phase they belong to and order phases as: recon, "
    "enumeration, exploitation, privesc, post-exploitation.\n"
    "- Do NOT restate commands; the system attaches the real commands from each "
    "cited entry. Just cite the entry_id.\n"
    "Respond with ONLY a JSON object, no prose."
)

_SCHEMA_HINT = (
    '{"phases": [{"phase": "recon", "steps": '
    '[{"entry_id": "<one of the provided ids>", "why": "<1-2 sentences>"}]}]}'
)


def build_user_prompt(
    goal: str, target_type: str | None, grouped: dict[str, list[dict]]
) -> str:
    lines: list[str] = []
    lines.append(f"GOAL: {goal}")
    if target_type:
        lines.append(f"TARGET TYPE: {target_type}")
    lines.append("")
    lines.append(
        "TECHNIQUE LIBRARY (only these entry_ids may be cited), grouped by phase:"
    )
    for phase in PHASE_ORDER:
        techs = grouped.get(phase)
        if not techs:
            continue
        lines.append("")
        lines.append(f"## {phase}")
        for t in techs:
            lines.append(f"- entry_id: {t['entry_id']}")
            lines.append(f"  title: {t['title']}")
            if t["summary"]:
                lines.append(f"  summary: {t['summary']}")
            if t["commands"]:
                preview = t["commands"][0]["cmd"].splitlines()[0][:_CMD_CHARS]
                lines.append(f"  sample_cmd: {preview}")
    lines.append("")
    lines.append(
        "Compose the ordered attack path for the goal above. "
        "Select the most relevant techniques (2-5 per phase where useful), "
        "put them in the right order, and give each a 'why'. "
        f"Return JSON exactly shaped like: {_SCHEMA_HINT}"
    )
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# 3) grounding / validation
# --------------------------------------------------------------------------- #
def _ground(
    parsed: Any, by_id: dict[str, dict]
) -> list[dict[str, Any]]:
    """Turn the model's JSON into validated, KB-grounded phases.

    Drops steps whose entry_id isn't in the KB, replaces the model's commands
    with the real entry's commands, assigns a stable ``{phase}-{n}`` id, and
    reorders phases canonically. Duplicate entry_ids are collapsed to the first
    occurrence so the path doesn't repeat a technique.
    """
    raw_phases = parsed.get("phases") if isinstance(parsed, dict) else None
    if not isinstance(raw_phases, list):
        return []

    # collect steps per canonical phase, preserving model order
    per_phase: dict[str, list[dict]] = {p: [] for p in PHASE_ORDER}
    used: set[str] = set()

    for rp in raw_phases:
        if not isinstance(rp, dict):
            continue
        phase = str(rp.get("phase") or "").strip().lower()
        if phase not in PHASE_ORDER:
            continue
        for st in rp.get("steps") or []:
            if not isinstance(st, dict):
                continue
            eid = str(st.get("entry_id") or "").strip()
            if eid not in by_id or eid in used:
                continue
            used.add(eid)
            e = by_id[eid]
            why = str(st.get("why") or "").strip()
            per_phase[phase].append(
                {
                    "title": e["title"],
                    "entry_id": eid,
                    "why": why,
                    "commands": entry_commands(e, cap=6),
                }
            )

    out: list[dict[str, Any]] = []
    for phase in PHASE_ORDER:
        steps = per_phase[phase]
        if not steps:
            continue
        for i, step in enumerate(steps, 1):
            step["id"] = f"{phase}-{i}"  # STABLE per-step id for later layers
        out.append({"phase": phase, "label": PHASE_LABEL[phase], "steps": steps})
    return out


# --------------------------------------------------------------------------- #
# public entry point
# --------------------------------------------------------------------------- #
def compose(
    by_id: dict[str, dict],
    goal: str,
    target_type: str | None,
    search_fn: SearchFn,
) -> dict[str, Any]:
    """Retrieve → compose (LLM) → ground. Returns the frontend response dict.

    Raises ``llm.LLMError`` if the LLM is unreachable / produces no usable path
    (the API layer maps that to a clean 503 for the frontend to render).
    """
    cfg = llm.load_config()
    grouped = retrieve(by_id, goal, target_type, search_fn)
    if not grouped:
        raise llm.LLMError("no relevant techniques found in the knowledge base")

    user = build_user_prompt(goal, target_type, grouped)
    raw = llm.chat(_SYSTEM, user, cfg)
    parsed = llm.extract_json(raw)
    phases = _ground(parsed, by_id)

    if not phases:
        raise llm.LLMError(
            "the model did not cite any valid technique from the knowledge base"
        )

    return {
        "goal": goal,
        "target_type": target_type,
        "phases": phases,
        "model_used": cfg["model"],
        "provider": cfg["provider"],
    }
