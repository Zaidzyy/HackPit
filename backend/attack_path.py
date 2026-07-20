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
_MIN_PER_PHASE = 2          # keep this many even if only overview entries exist
_CMDS_PER_ENTRY = 4         # commands shown per technique in the prompt
_STEP_CMD_CAP = 4           # code blocks kept on a GROUNDED step (concise, not a dump)
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
# cheatsheet/resource page is fine to cite, it just shouldn't outrank a focused
# single technique. Cheatsheets are deliberately NOT excluded.
_GRABBAG_TITLE_RE = re.compile(
    r"\b(?:resources?|cheat\s?sheets?|grab\s?bag|assorted|misc(?:ellaneous)?|"
    r"links?|index)\b",
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
        # Prefer entries that actually carry commands: a step grounded on a
        # command-less overview note (e.g. the "Active Directory" landing page)
        # gives the user nothing to run. Partition by whether the entry has
        # commands, rank each partition by score, and take command-bearing
        # entries first. Command-less entries are only kept as a fallback when a
        # phase has too few actionable ones, so no phase silently disappears.
        cmds: dict[str, list[dict]] = {}
        with_cmds: list[tuple[float, dict]] = []
        without_cmds: list[tuple[float, dict]] = []
        for score, e in buckets[phase]:
            c = entry_commands(e)
            cmds[e["id"]] = c
            (with_cmds if c else without_cmds).append((score, e))

        with_cmds.sort(key=lambda x: x[0], reverse=True)
        without_cmds.sort(key=lambda x: x[0], reverse=True)

        # Prefer FOCUSED single techniques over broad reference/cheatsheet pages:
        # partition the command-bearing entries and take focused ones first, so a
        # step grounds on "Kerberoasting" rather than a "resources" grab-bag even
        # when both matched. Broad pages only fill the leftover slots.
        focused = [t for t in with_cmds if not is_broad_reference(t[1])]
        broad = [t for t in with_cmds if is_broad_reference(t[1])]
        chosen = (focused + broad)[:_PER_PHASE_CAP]
        # top up with a couple of overview entries only if we're short on
        # actionable ones — this is the "phase has only overview content" safety.
        if len(chosen) < _MIN_PER_PHASE:
            chosen += without_cmds[: _MIN_PER_PHASE - len(chosen)]

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
    "- WITHIN each phase, order the steps by PRIORITY: what a tester should do "
    "first / what matters most goes first, later or optional actions last. The "
    "order you return is preserved verbatim, so rank deliberately.\n"
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
        "Select the most relevant techniques (2-5 per phase where useful), and "
        "within each phase order the steps by priority — highest-impact / "
        "earliest actions first. Give each a 'why'. "
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


def _ground(
    parsed: Any, by_id: dict[str, dict], target: str | None
) -> list[dict[str, Any]]:
    """Turn the model's JSON into validated, KB-grounded phases.

    Resolves each cited entry_id to a REAL servable id (exact, else a normalised
    match), drops steps that can't be resolved, replaces the model's commands
    with the real entry's commands (with the user's ``target`` substituted in),
    assigns a stable ``{phase}-{n}`` id, and reorders phases canonically while
    preserving the model's within-phase priority order. Duplicate entries are
    collapsed to the first occurrence so the path doesn't repeat a technique.
    """
    raw_phases = parsed.get("phases") if isinstance(parsed, dict) else None
    if not isinstance(raw_phases, list):
        return []

    # normalised-id lookup for fuzzy resolution of near-miss citations
    norm_map = {_norm_id(k): k for k in by_id}

    # collect steps per canonical phase, preserving model (priority) order
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
            eid = _resolve_entry_id(str(st.get("entry_id") or ""), by_id, norm_map)
            if eid is None or eid in used:
                continue
            if not is_step_eligible(by_id[eid]):
                continue  # never ground on a writeup, grab-bag, or personal/log page
            used.add(eid)
            e = by_id[eid]
            why = str(st.get("why") or "").strip()
            cmds = [
                {**c, "cmd": substitute_target(c["cmd"], target)}
                for c in entry_commands(e, cap=_STEP_CMD_CAP)
            ]
            per_phase[phase].append(
                {
                    "title": e["title"],
                    "entry_id": eid,
                    "why": why,
                    "commands": cmds,
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

    # belt-and-suspenders: every emitted step must be servable by /entry/{id}
    assert all(
        s["entry_id"] in by_id for ph in out for s in ph["steps"]
    ), "grounding emitted a non-servable entry_id"
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

    target = extract_target(goal)

    user = build_user_prompt(goal, target_type, grouped)
    raw = llm.chat(_SYSTEM, user, cfg)
    parsed = llm.extract_json(raw)
    phases = _ground(parsed, by_id, target)

    if not phases:
        raise llm.LLMError(
            "the model did not cite any valid technique from the knowledge base"
        )

    return {
        "goal": goal,
        "target_type": target_type,
        "target": target,
        "phases": phases,
        "box_writeup": find_box_writeup(by_id, goal),
        "model_used": cfg["model"],
        "provider": cfg["provider"],
    }
