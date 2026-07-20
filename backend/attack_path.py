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

import re
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

# target-type chip → extra query context.
# Chips: Pentest (general full-scope) · Bug Bounty (web-focused) · CTF · AD.
_TARGET_CONTEXT: dict[str, str] = {
    "pentest": "penetration test full scope network hosts services",
    "bugbounty": "web application bug bounty http api",
    "ctf": "capture the flag",
    "ad": "active directory windows domain",
}

# tuning
_PER_PHASE_CAP = 6          # techniques kept per phase for the prompt
_CMDS_PER_ENTRY = 4         # commands shown per technique in the prompt
_STEP_CMD_CAP = 4           # code blocks kept on a GROUNDED step (concise, not a dump)
_AI_STEPS_PER_PHASE = 3     # cap AI-suggested (gap-fill) steps per phase
_AI_CMDS_PER_STEP = 4       # cap commands on one AI-suggested step
_SUMMARY_CHARS = 260
_CMD_CHARS = 320

# a single step is a concise pointer, not the whole entry: cap one code block so
# a technique that pastes a 300-line helper script surfaces as a short excerpt +
# a "full script in the technique →" pointer (the step card already links out).
_MAX_CMD_LINES = 40
_MAX_CMD_CHARS = 1200
# broad/reference pages that are still citeable but should rank BELOW focused
# techniques, and the body size at which an unfocused entry reads as a grab-bag.
_BROAD_BODY_CHARS = 12000
GRAB_BAG_BODY_CHARS = 20000

SearchFn = Callable[[str, int, str], list[dict]]

# Categories that are worked EXAMPLES, not techniques: whole-box writeups and
# CTF-challenge indexes. They must never become path steps — grounding a step on
# "Querier" would dump another box's commands instead of the actual technique. So
# they are excluded from the retrieval/grounding pool entirely (a writeup for the
# *current* box is surfaced separately, as a link, by find_box_writeup()).
EXCLUDED_STEP_CATEGORIES = {"writeup", "ctf"}

# ingestion flag_reason values that mark a coarse, monolithic, multi-topic page
# (the big "Htb My Resources" / "More Resources" Notion dumps and multi-box raw
# dumps kept whole "for splitting"). These are grab-bags, not techniques.
_COARSE_FLAG_RE = re.compile(
    r"multi-topic|coarse|one-per-page|review for splitting|raw .*dump", re.I
)
# personal / meta / log pages — cert-completion logs, "My review", note-taking
# journals. Not techniques; excluded from steps entirely (still browsable).
_PERSONAL_LOG_RE = re.compile(
    r"\b(?:my review|my resources|my certifications|note[-\s]?taking|"
    r"cert(?:ification)?s?\s+(?:log|notes|journal)|(?:completion|progress)\s+log|"
    r"journal|diary)\b",
    re.I,
)
# broad-reference title words used only for RANKING (not exclusion): a
# cheatsheet/resource/methodology/case-study page is fine to cite, it just
# shouldn't outrank a focused single technique. Cheatsheets are NOT excluded.
_GRABBAG_TITLE_RE = re.compile(
    r"\b(?:resources?|cheat\s?sheets?|grab\s?bag|assorted|misc(?:ellaneous)?|"
    r"links?|index|methodolog(?:y|ies)|case\s?stud(?:y|ies))\b",
    re.I,
)


def is_step_eligible(entry: dict) -> bool:
    """Whether a KB entry may be GROUNDED as an attack-path / chat step.

    Rejects worked examples (writeup/ctf), coarse multi-topic pages flagged at
    ingestion, personal/meta/log pages, and — as a backstop — any very large body
    with no single-technique focus (an un-flagged grab-bag). Everything rejected
    here stays fully searchable/browsable; it just can't become a step, so a step
    is always a focused technique instead of a wall of unrelated content.
    """
    if entry.get("category", "") in EXCLUDED_STEP_CATEGORIES:
        return False
    meta = entry.get("meta") or {}
    if _COARSE_FLAG_RE.search(meta.get("flag_reason") or ""):
        return False
    if _PERSONAL_LOG_RE.search(entry.get("title") or ""):
        return False
    # backstop heuristic: large body AND no canonical single-technique focus →
    # grab-bag. Focused entries in this KB are concise; the 20 KB+ ones are all
    # "resources"/"review" dumps, none a single technique.
    if len(entry.get("body_md") or "") >= GRAB_BAG_BODY_CHARS and not meta.get(
        "canonical_keys"
    ):
        return False
    return True


def is_broad_reference(entry: dict) -> bool:
    """Eligible but broad: a reference/cheatsheet/large-topic page. Used only to
    rank focused single techniques ABOVE these when composing a path — they are
    still citeable, just not first."""
    if (entry.get("meta") or {}).get("canonical_keys"):
        return False  # explicit single-technique focus
    if entry.get("category") == "reference":
        return True
    if len(entry.get("body_md") or "") >= _BROAD_BODY_CHARS:
        return True
    return bool(_GRABBAG_TITLE_RE.search(entry.get("title") or ""))


def _cap_command(cmd: str) -> tuple[str, bool]:
    """Cap one code block to a short excerpt. Returns (text, truncated).

    A step is a pointer, not a mirror of the entry: an over-long block (e.g. a
    pasted 300-line script) is cut to its first lines with a marker directing the
    reader to the full technique. Returns the command unchanged when within caps.
    """
    lines = cmd.split("\n")
    if len(lines) <= _MAX_CMD_LINES and len(cmd) <= _MAX_CMD_CHARS:
        return cmd, False
    excerpt = "\n".join(lines[:_MAX_CMD_LINES])
    if len(excerpt) > _MAX_CMD_CHARS:
        excerpt = excerpt[:_MAX_CMD_CHARS].rstrip()
    dropped = len(lines) - excerpt.count("\n") - 1
    tail = f" ({dropped} more lines)" if dropped > 0 else ""
    return (
        excerpt.rstrip()
        + f"\n# … truncated{tail} — open the technique ↑ for the full script"
    ), True


# --------------------------------------------------------------------------- #
# target extraction + substitution
# --------------------------------------------------------------------------- #
# Pull the user's real target (IP / host / URL, optional port) out of the goal
# text, then substitute it into each cited entry's example commands so a step
# reads "nmap 10.10.11.55" instead of the note author's "nmap 192.168.13.138".
_IPV4 = r"(?:\d{1,3}\.){3}\d{1,3}"
_PORT = r"(?::\d{1,5})?"
_URL_RE = re.compile(r"https?://[^\s'\"`<>]+", re.I)
_IP_RE = re.compile(r"\b" + _IPV4 + _PORT + r"\b")
_HOST_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}" + _PORT + r"\b"
)

# placeholder tokens the notes/library use for "put the target here"
_PLACEHOLDER_RE = re.compile(
    r"(?:<[^<>\s]*(?:target|rhosts?|ip|url|hostname|host|domain|victim)[^<>\s]*>"
    r"|\{\{?\s*(?:TARGET|RHOSTS?|IP|URL|HOSTNAME|HOST|DOMAIN|VICTIM)\s*\}?\}"
    r"|\$\{?(?:TARGET|RHOSTS?|IP|URL|HOSTNAME|HOST|DOMAIN|VICTIM)\}?)",
    re.I,
)
# obvious example/lab IPs baked into notes (private + HTB/THM ranges). Localhost
# (127.*), 0.0.0.0 and netmasks (255.*) are deliberately NOT matched. The lead
# guard is (?<![\d.]) rather than \b so IPs embedded after a word char also
# match (e.g. a filename like scan_192.168.186.137.txt) while a fragment of a
# larger number/IP still can't be picked up.
_EXAMPLE_IP_RE = re.compile(
    r"(?<![\d.])(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})" + _PORT + r"(?!\d)"
)
# obvious example hostnames (lab TLDs + example.*)
_EXAMPLE_HOST_RE = re.compile(
    r"\b(?:[a-zA-Z0-9-]+\.)+(?:htb|thm|box|vh|lab|local|example|test)"
    r"(?:\.[a-zA-Z]{2,})?" + _PORT + r"\b",
    re.I,
)


def _is_ipv4(value: str) -> bool:
    return bool(re.fullmatch(_IPV4, value))


def extract_target(goal: str) -> str | None:
    """Best-effort target (URL > IP[:port] > host[:port]) parsed from the goal."""
    m = _URL_RE.search(goal)
    if m:
        return m.group(0).rstrip(".,);'\"")
    m = _IP_RE.search(goal)
    if m:
        return m.group(0)
    m = _HOST_RE.search(goal)
    if m:
        return m.group(0)
    return None


# box-context guard + generic goal words that must not be treated as a box name
_BOX_CONTEXT_RE = re.compile(
    r"\b(?:htb|hack\s?the\s?box|box|machine|thm|try\s?hack\s?me|vulnhub|"
    r"proving\s?grounds?|\bpg\b)\b", re.I)
_GOAL_STOP = {"htb", "hackthebox", "box", "machine", "thm", "tryhackme", "vulnhub",
              "root", "user", "flag", "flags", "exploit", "attack", "hack", "pwn",
              "compromise", "http", "https", "www", "com", "org", "net", "shell"}


def find_box_writeup(by_id: dict[str, dict], goal: str) -> dict | None:
    """If the goal names a box we have a WRITEUP for, return that one writeup
    ({id, title, tier}) to surface as a prominent link — never as a step. Gated
    on box-context wording so a generic web goal can't trigger it; prefers your
    own (tier-1) writeup, then the fuller one. Returns None otherwise."""
    if not _BOX_CONTEXT_RE.search(goal):
        return None
    goal_words = {w for w in re.findall(r"[a-z0-9]+", goal.lower())
                  if len(w) >= 4 and w not in _GOAL_STOP}
    if not goal_words:
        return None
    best: tuple[tuple[int, int], dict] | None = None
    for e in by_id.values():
        if e.get("category") != "writeup":
            continue
        title_words = [w for w in re.findall(r"[a-z0-9]+", (e.get("title") or "").lower())
                       if len(w) >= 4]
        if any(w in goal_words for w in title_words):
            rank = (0 if e.get("tier") == 1 else 1, -len(e.get("body_md") or ""))
            if best is None or rank < best[0]:
                best = (rank, e)
    if best is None:
        return None
    e = best[1]
    return {"id": e["id"], "title": e["title"], "tier": int(e.get("tier", 3))}


def _target_host(target: str) -> str:
    """Host[:port] portion of a target — strips a URL scheme/path if present."""
    t = re.sub(r"^https?://", "", target, flags=re.I)
    return t.split("/", 1)[0]


def substitute_target(cmd: str, target: str | None) -> str:
    """Rewrite a command's placeholders + obvious example IPs/hosts to `target`.

    Conservative: only touches recognised placeholder tokens and lab/private
    example addresses, so unrelated literals (loopback, bind-all, netmasks,
    version numbers) are left untouched.
    """
    if not target:
        return cmd
    host = _target_host(target)
    is_url = bool(_URL_RE.match(target))

    # 1) explicit placeholders → full target for URL-ish, host for the rest
    def _ph(m: re.Match[str]) -> str:
        tok = m.group(0).lower()
        return target if ("url" in tok and is_url) else host

    out = _PLACEHOLDER_RE.sub(_ph, cmd)

    # 2) obvious example IPs → target host (only when our host is an IP)
    if _is_ipv4(host.split(":", 1)[0]):
        out = _EXAMPLE_IP_RE.sub(host, out)

    # 3) obvious example hostnames → target host
    out = _EXAMPLE_HOST_RE.sub(host, out)
    return out


def canonical_phase(entry: dict) -> str:
    """Map a KB entry to one of the five canonical phases."""
    meta = entry.get("meta") or {}
    ph = meta.get("phase")
    if isinstance(ph, str) and ph in _META_PHASE_MAP:
        return _META_PHASE_MAP[ph]
    cat = entry.get("category", "")
    return _CATEGORY_MAP.get(cat, "enumeration")


def entry_commands(entry: dict, cap: int = _CMDS_PER_ENTRY) -> list[dict[str, Any]]:
    """Flatten an entry's step code blocks into copyable {lang, cmd} commands.

    Deduplicated (some entries repeat a command across steps) and capped so a
    single technique can't dominate the prompt or a rendered card.
    """
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for step in entry.get("steps", []) or []:
        for code in step.get("code", []) or []:
            cmd = (code.get("cmd") or "").strip()
            if not cmd or cmd in seen:
                continue
            seen.add(cmd)
            capped, truncated = _cap_command(cmd)
            item: dict[str, Any] = {"lang": code.get("lang") or "bash", "cmd": capped}
            if truncated:
                item["truncated"] = True
            out.append(item)
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
    ctx: dict[str, Any] | None = None,
) -> dict[str, list[dict]]:
    """Gather candidate techniques from the KB, bucketed by canonical phase.

    Runs one broad hybrid query on the goal plus one phase-seeded query per
    canonical phase, unions the hits (keeping the best score seen per entry),
    then buckets each entry into its phase and keeps the top few per phase.

    ``ctx`` (from ``parse_goal_context``) adds box-type/creds terms so retrieval
    is weighted toward the right playbook (AD+creds → BloodHound/kerberoast/
    credentialed enum; Linux → linux enum/privesc; web → web).
    """
    tctx = _TARGET_CONTEXT.get((target_type or "").lower(), "")
    box_terms = (ctx or {}).get("terms", "")
    base = " ".join(x for x in (goal, tctx, box_terms) if x).strip()

    # entry_id -> best score seen across all queries
    best: dict[str, float] = {}

    def ingest(hits: list[dict]) -> None:
        for h in hits:
            eid = h.get("id")
            if not eid or eid not in by_id:
                continue
            if not is_step_eligible(by_id[eid]):
                continue  # writeup/ctf, coarse grab-bag, or personal/log page
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
        # A step must give the user something to RUN: drop command-less overview
        # notes entirely (they never become steps — the LLM gap-fills instead).
        cmds: dict[str, list[dict]] = {}
        with_cmds: list[tuple[float, dict]] = []
        for score, e in buckets[phase]:
            c = entry_commands(e)
            if not c:
                continue
            cmds[e["id"]] = c
            with_cmds.append((score, e))

        with_cmds.sort(key=lambda x: x[0], reverse=True)

        # HARD-deprioritize broad grab-bag / methodology / resource / case-study
        # pages: a focused single technique ("Kerberoasting") always wins, and a
        # broad page is used ONLY when the phase has no focused technique at all.
        focused = [t for t in with_cmds if not is_broad_reference(t[1])]
        broad = [t for t in with_cmds if is_broad_reference(t[1])]
        chosen = (focused or broad)[:_PER_PHASE_CAP]

        techs = []
        for _score, e in chosen:
            techs.append(
                {
                    "entry_id": e["id"],
                    "title": e["title"],
                    "category": e.get("category", ""),
                    "summary": (e.get("summary") or "")[:_SUMMARY_CHARS],
                    "commands": cmds[e["id"]],
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
    "professional on an AUTHORIZED engagement. You compose an ordered, "
    "phase-by-phase attack path. You are given a LIBRARY of the user's OWN "
    "techniques (each has an entry_id and real, tested commands).\n"
    "Hard rules:\n"
    "- PREFER THE LIBRARY. For every step you can, cite a library entry_id — the "
    "system attaches that entry's real commands, so do NOT restate commands for a "
    "cited step; just give the entry_id and a 1-2 sentence 'why'.\n"
    "- Order phases as: recon, enumeration, exploitation, privesc, "
    "post-exploitation. Within a phase, put the highest-priority / earliest "
    "actions first; the order you return is preserved verbatim.\n"
    "- GAP-FILL ONLY WHERE NEEDED: if a phase has a real gap the library does not "
    "cover (a specific service, vuln, or tool named in the goal), you MAY add an "
    "AI-suggested step from your own general knowledge. Mark it EXACTLY as: "
    '{"ai_suggested": true, "title": "...", "why": "...", "commands": '
    '[{"lang": "bash", "cmd": "..."}]}. Give the concrete command(s). These are '
    "UNVERIFIED, so use them sparingly and NEVER to duplicate a library technique.\n"
    "- Grounded (entry_id) steps are trusted and come FIRST in each phase; "
    "AI-suggested steps are a clearly-marked fallback and come after.\n"
    "- Never invent an entry_id. A step is EITHER {\"entry_id\": \"<library id>\", "
    "\"why\": \"...\"} OR an ai_suggested step exactly as shown above.\n"
    "Respond with ONLY a JSON object, no prose."
)

_SCHEMA_HINT = (
    '{"phases": [{"phase": "recon", "steps": ['
    '{"entry_id": "<library id>", "why": "<1-2 sentences>"}, '
    '{"ai_suggested": true, "title": "<short title>", "why": "<why>", '
    '"commands": [{"lang": "bash", "cmd": "<command>"}]}'
    ']}]}'
)


def build_user_prompt(
    goal: str,
    target_type: str | None,
    grouped: dict[str, list[dict]],
    ctx: dict[str, Any] | None = None,
) -> str:
    ctx = ctx or {}
    lines: list[str] = []
    lines.append(f"GOAL: {goal}")
    if target_type:
        lines.append(f"TARGET TYPE: {target_type}")
    box_type = ctx.get("box_type")
    if box_type:
        creds = " with valid credentials" if ctx.get("has_creds") else ""
        lead = f"{box_type}{'/credentialed' if ctx.get('has_creds') else ''}"
        lines.append(
            f"CONTEXT: this reads as a {box_type.upper()} target{creds} — lead with "
            f"the {lead} playbook."
        )
    lines.append("")
    lines.append(
        "TECHNIQUE LIBRARY (cite these entry_ids for grounded steps), by phase:"
    )
    any_lib = False
    for phase in PHASE_ORDER:
        techs = grouped.get(phase)
        if not techs:
            continue
        any_lib = True
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
    if not any_lib:
        lines.append(
            "(the library is thin for this goal — rely more on clearly-marked "
            "ai_suggested steps, but never fabricate an entry_id.)"
        )
    lines.append("")
    gap = f" relevant to a {box_type} target" if box_type else ""
    lines.append(
        "Compose the ordered attack path. In each phase, place grounded library "
        "steps FIRST (cite entry_id, highest-priority first), then add "
        f"clearly-marked ai_suggested steps ONLY for genuine gaps{gap}. "
        f"Return JSON exactly shaped like: {_SCHEMA_HINT}"
    )
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# 3) grounding / validation
# --------------------------------------------------------------------------- #
def _norm_id(value: str) -> str:
    """Loosely normalise an id for fuzzy matching (case / separators / space)."""
    return re.sub(r"[\s_-]+", "-", value.strip().lower()).strip("-")


def _resolve_entry_id(cited: str, by_id: dict[str, dict], norm_map: dict[str, str]) -> str | None:
    """Resolve a cited id to a REAL, servable KB id, or None if it can't be.

    Exact hit first; otherwise a normalised (case/separator-insensitive) match.
    Guarantees the returned id is present in ``by_id`` — i.e. ``/entry/{id}``
    will serve it — so a composed step can never link to a 404.
    """
    if cited in by_id:
        return cited
    hit = norm_map.get(_norm_id(cited))
    return hit if hit and hit in by_id else None


def _ai_commands(raw: Any, target: str | None) -> list[dict[str, Any]]:
    """Normalise the model's OWN commands for an AI-suggested step: dedupe, cap
    count/length, substitute the target. Marked ``unverified`` (the step itself
    carries ``ai_suggested`` — these are general-knowledge, not the user's KB)."""
    out: list[dict[str, Any]] = []
    if not isinstance(raw, list):
        return out
    seen: set[str] = set()
    for c in raw:
        if isinstance(c, str):
            cmd, lang = c, "bash"
        elif isinstance(c, dict):
            cmd, lang = str(c.get("cmd") or ""), (c.get("lang") or "bash")
        else:
            continue
        cmd = substitute_target(cmd.strip(), target)
        if not cmd or cmd in seen:
            continue
        seen.add(cmd)
        capped, truncated = _cap_command(cmd)
        item: dict[str, Any] = {
            "lang": lang, "cmd": capped, "copyable": True, "unverified": True,
        }
        if truncated:
            item["truncated"] = True
        out.append(item)
        if len(out) >= _AI_CMDS_PER_STEP:
            break
    return out


def _ground(
    parsed: Any, by_id: dict[str, dict], target: str | None
) -> list[dict[str, Any]]:
    """Turn the model's JSON into validated phases: KB-grounded steps FIRST, then
    clearly-marked AI-suggested gap steps.

    A GROUNDED step resolves its cited entry_id to a REAL, eligible, servable KB
    entry that actually carries commands, and uses that entry's real commands
    (target substituted) — never the model's. An AI-SUGGESTED step (flagged by
    the model, or a step whose entry_id can't be resolved) is kept with
    ``ai_suggested=True``, no entry citation, and the model's own commands marked
    unverified — the UI renders it distinctly. Grounded steps are trusted and
    ordered before AI-suggested ones within each phase.
    """
    raw_phases = parsed.get("phases") if isinstance(parsed, dict) else None
    if not isinstance(raw_phases, list):
        return []

    # normalised-id lookup for fuzzy resolution of near-miss citations
    norm_map = {_norm_id(k): k for k in by_id}

    grounded: dict[str, list[dict]] = {p: [] for p in PHASE_ORDER}
    ai: dict[str, list[dict]] = {p: [] for p in PHASE_ORDER}
    used: set[str] = set()
    ai_seen: set[str] = set()

    for rp in raw_phases:
        if not isinstance(rp, dict):
            continue
        phase = str(rp.get("phase") or "").strip().lower()
        if phase not in PHASE_ORDER:
            continue
        for st in rp.get("steps") or []:
            if not isinstance(st, dict):
                continue
            eid = _resolve_entry_id(str(st.get("entry_id") or ""), by_id, norm_map)
            # GROUNDED: resolvable + eligible + actually has commands.
            if eid is not None and eid not in used and is_step_eligible(by_id[eid]):
                e = by_id[eid]
                cmds = [
                    {**c, "cmd": substitute_target(c["cmd"], target)}
                    for c in entry_commands(e, cap=_STEP_CMD_CAP)
                ]
                if not cmds:
                    continue  # no-command entry — never a step
                used.add(eid)
                grounded[phase].append(
                    {
                        "title": e["title"],
                        "entry_id": eid,
                        "why": str(st.get("why") or "").strip(),
                        "commands": cmds,
                        "ai_suggested": False,
                    }
                )
                continue
            # AI-SUGGESTED gap step: model-flagged, or an unresolvable citation
            # that still carries a title. Kept, marked, capped.
            if st.get("ai_suggested") or (eid is None and st.get("title")):
                title = str(st.get("title") or "").strip()
                key = _norm_id(title)
                if not title or key in ai_seen or len(ai[phase]) >= _AI_STEPS_PER_PHASE:
                    continue
                ai_seen.add(key)
                ai[phase].append(
                    {
                        "title": title,
                        "entry_id": "",
                        "why": str(st.get("why") or "").strip(),
                        "commands": _ai_commands(st.get("commands"), target),
                        "ai_suggested": True,
                    }
                )

    out: list[dict[str, Any]] = []
    for phase in PHASE_ORDER:
        steps = grounded[phase] + ai[phase]  # trusted KB steps first, AI last
        if not steps:
            continue
        for i, step in enumerate(steps, 1):
            step["id"] = f"{phase}-{i}"  # STABLE per-step id for later layers
        out.append({"phase": phase, "label": PHASE_LABEL[phase], "steps": steps})

    # every GROUNDED step must be servable by /entry/{id}; AI steps carry no id.
    assert all(
        s["entry_id"] in by_id
        for ph in out
        for s in ph["steps"]
        if s["entry_id"]
    ), "grounding emitted a non-servable entry_id"
    return out


# --------------------------------------------------------------------------- #
# goal context — box type + creds, weighting retrieval and AI-suggested steps
# --------------------------------------------------------------------------- #
_CREDS_RE = re.compile(
    r"\b(?:credentials?|creds?|password|passwd|login|user(?:name)?\s*[:=]|"
    r"authenticated)\b",
    re.I,
)
_AD_RE = re.compile(
    r"\b(?:active\s?directory|AD|domain\s?controller|DC|kerberos|ldap|"
    r"bloodhound|ntlm|windows\s?domain)\b",
    re.I,
)
_WIN_RE = re.compile(r"\bwindows\b", re.I)
_LINUX_RE = re.compile(r"\b(?:linux|unix|ubuntu|debian|centos)\b", re.I)
_WEB_RE = re.compile(r"\b(?:web\s?app(?:lication)?|website|https?|\bapi\b|\bweb\b)\b", re.I)

# box-type (+creds) → extra retrieval/gap-fill terms
_CONTEXT_TERMS: dict[str, str] = {
    "ad": "active directory ldap smb kerberos bloodhound domain enumeration",
    "ad+creds": "credentialed active directory enumeration bloodhound kerberoasting "
                "ldap smb domain users authenticated",
    "windows": "windows privilege escalation enumeration",
    "linux": "linux enumeration privilege escalation linpeas sudo suid",
    "web": "web application http api enumeration",
}


def parse_goal_context(goal: str) -> dict[str, Any]:
    """Best-effort box-type + creds signal parsed from the goal, used to weight
    both retrieval and the AI-suggested gap steps toward the right playbook
    (AD+creds → credentialed enum / BloodHound / kerberoast; Linux → linux enum /
    privesc; web → web)."""
    has_creds = bool(_CREDS_RE.search(goal))
    if _AD_RE.search(goal):
        box_type = "ad"
    elif _WIN_RE.search(goal):
        box_type = "windows"
    elif _LINUX_RE.search(goal):
        box_type = "linux"
    elif _WEB_RE.search(goal):
        box_type = "web"
    else:
        box_type = None
    key = "ad+creds" if (box_type == "ad" and has_creds) else box_type
    return {
        "box_type": box_type,
        "has_creds": has_creds,
        "terms": _CONTEXT_TERMS.get(key or "", ""),
    }


# --------------------------------------------------------------------------- #
# writeup-first path — build the path from the user's own per-box walkthrough
# --------------------------------------------------------------------------- #
# keyword → canonical phase index. A linear writeup is split into phases WITHOUT
# reordering: the assigned index is monotonic non-decreasing, so the walkthrough
# order is preserved even if a later step's keyword maps to an earlier phase.
_WU_PHASE_KEYWORDS: list[tuple[int, re.Pattern[str]]] = [
    (0, re.compile(r"\b(?:scan|nmap|port|recon|discover|ping|masscan|rustscan|"
                   r"fingerprint|initial)\b", re.I)),
    (1, re.compile(r"\b(?:enum|smb|share|ldap|bloodhound|dns|vhost|subdomain|"
                   r"director|gobuster|ffuf|rpc|snmp|nfs|users?)\b", re.I)),
    (2, re.compile(r"\b(?:exploit|foothold|shell|rce|inject|upload|payload|cve|"
                   r"credential|kerberoast|asrep|crack|hash|tgt|login|winrm|"
                   r"reverse|access)\b", re.I)),
    (3, re.compile(r"\b(?:privesc|privilege|\broot\b|admin|system|sudo|suid|"
                   r"dpapi|secretsdump|escalat|token|impersonat|dcsync)\b", re.I)),
    (4, re.compile(r"\b(?:persist|lateral|pivot|loot|backup|exfil|cleanup|flag|"
                   r"post[- ]?exploit)\b", re.I)),
]


def _wu_phase_index(text: str) -> int | None:
    for idx, pat in _WU_PHASE_KEYWORDS:
        if pat.search(text):
            return idx
    return None


def build_writeup_path(entry: dict, target: str | None) -> list[dict[str, Any]]:
    """Build attack-path phases directly from a per-box WRITEUP's ordered steps.

    The writeup is the real walkthrough for THIS box and the user's own work, so
    its steps are trusted and used verbatim (order preserved, target substituted,
    over-long blocks capped). Steps are split into canonical phases by keyword,
    but the split is monotonic — the phase index never decreases — so the
    walkthrough's linear ordering is never scrambled. Every step is grounded
    (``ai_suggested=False``) and links back to the full writeup.
    """
    per_phase: dict[str, list[dict]] = {p: [] for p in PHASE_ORDER}
    running = 0
    for st in entry.get("steps") or []:
        text = (st.get("text") or "").strip()
        guess = _wu_phase_index(text)
        if guess is not None and guess > running:
            running = guess
        phase = PHASE_ORDER[running]

        cmds: list[dict[str, Any]] = []
        seen: set[str] = set()
        for c in st.get("code") or []:
            cmd = (c.get("cmd") or "").strip()
            if not cmd or cmd in seen:
                continue
            seen.add(cmd)
            capped, truncated = _cap_command(substitute_target(cmd, target))
            item: dict[str, Any] = {
                "lang": c.get("lang") or "bash",
                "cmd": capped,
                "copyable": c.get("copyable", True),
            }
            if truncated:
                item["truncated"] = True
            cmds.append(item)
            if len(cmds) >= _STEP_CMD_CAP:
                break

        per_phase[phase].append(
            {
                "title": text or f"Step {st.get('n', '')}".strip(),
                "entry_id": entry["id"],  # "technique →" opens the full writeup
                "why": "",
                "commands": cmds,
                "ai_suggested": False,
            }
        )

    out: list[dict[str, Any]] = []
    for phase in PHASE_ORDER:
        steps = per_phase[phase]
        if not steps:
            continue
        for i, step in enumerate(steps, 1):
            step["id"] = f"{phase}-{i}"
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
    """Compose an attack path for the goal. Two modes:

    1. **Writeup-first** — if the goal names a box we have a writeup for, build
       the path from that writeup's real ordered walkthrough (trusted; no LLM).
    2. **KB-first + AI-suggested fallback** — otherwise retrieve grounded KB
       techniques (weighted by box-type context) and let the LLM order them and
       add clearly-marked ai_suggested steps for genuine gaps.

    Raises ``llm.LLMError`` (only in mode 2) if the LLM is unreachable / produces
    no usable path — the API layer maps that to a clean 503.
    """
    target = extract_target(goal)
    ctx = parse_goal_context(goal)
    box_writeup = find_box_writeup(by_id, goal)

    # (1) WRITEUP-FIRST
    if box_writeup and box_writeup["id"] in by_id:
        wu = by_id[box_writeup["id"]]
        phases = build_writeup_path(wu, target)
        if phases:
            damaged = bool((wu.get("meta") or {}).get("source_damaged"))
            return {
                "goal": goal,
                "target_type": target_type,
                "target": target,
                "phases": phases,
                "box_writeup": box_writeup,
                "origin": "writeup",
                "origin_label": f"from your writeup: {wu['title']}",
                "origin_note": (
                    "source formatting damaged — some commands may be mangled; "
                    "open the writeup to verify"
                )
                if damaged
                else None,
                "model_used": "your writeup",
                "provider": "writeup",
            }

    # (2) KB-FIRST + AI-SUGGESTED FALLBACK
    cfg = llm.load_config()
    grouped = retrieve(by_id, goal, target_type, search_fn, ctx)
    user = build_user_prompt(goal, target_type, grouped, ctx)
    raw = llm.chat(_SYSTEM, user, cfg)
    parsed = llm.extract_json(raw)
    phases = _ground(parsed, by_id, target)

    if not phases:
        raise llm.LLMError("the model did not produce any usable steps")

    return {
        "goal": goal,
        "target_type": target_type,
        "target": target,
        "phases": phases,
        "box_writeup": box_writeup,
        "origin": "composed",
        "origin_label": None,
        "origin_note": None,
        "model_used": cfg["model"],
        "provider": cfg["provider"],
    }
