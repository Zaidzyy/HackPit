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
# generic "how to approach a machine" / process-overview meta-notes (e.g. the
# HTB-walkthrough "Machine Approach" / "HTB Attack Paths" notes, engagement
# workflow, threat-modeling). Like grab-bags, these are broad framing pages, not
# a single technique — so they are hard-deprioritized: a step only when no
# focused technique fits the phase. Distinct from _GRABBAG_TITLE_RE because these
# don't carry the "resource/methodology" title words but read the same way.
_BROAD_METHODOLOGY_RE = re.compile(
    r"\b(?:(?:machine|general|overall)\s+approach|attack\s?paths?|"
    r"engagement\s+workflow|threat\s+model(?:ing)?)\b",
    re.I,
)

# Defensive / hardening / secure-deployment guides — content about how to SECURELY
# DEPLOY or LOCK DOWN a system (nginx request allowlists, rootless podman,
# SELinux/AppArmor confinement, device-node minimization, mitigation checklists).
# These are NOT attacks: grounding one as a step would surface a hardening config
# where an exploit belongs (e.g. "AI Risks" matching an offensive AI query). They
# are excluded from step eligibility while staying fully searchable/browsable.
_DEFENSIVE_TITLE_RE = re.compile(
    r"\b(?:hardening|harden(?:ed|ing)?|securely\s+deploy(?:ing|ment)?|"
    r"secure\s+deployment|defen[cs]e[- ]in[- ]depth|"
    r"defensive\s+(?:guide|checklist|controls?)|mitigation\s+(?:guide|checklist))\b",
    re.I,
)
_DEFENSIVE_BODY_RE = re.compile(
    r"\b(?:hardening|harden(?:ed|ing)?|mitigations?|defen[cs]e[- ]in[- ]depth|"
    r"defensive|confinement|rootless|least\s+privilege|minimi[sz]ation|"
    r"securely\s+deploy|secure\s+deployment|lock(?:ing)?\s+down)\b",
    re.I,
)


def is_defensive_hardening(entry: dict) -> bool:
    """True when the entry is a DEFENSIVE hardening / secure-deployment guide (how
    to lock a system down) rather than an attack technique.

    Detection, in order:
      * an explicit ``meta.defensive`` flag → defensive;
      * a focused single technique (``canonical_keys``) → NOT defensive (trusted
        offensive), so a lone "Mitigation" aside can never misclassify it;
      * a hardening/secure-deployment TITLE → defensive;
      * otherwise the discriminator is the entry's COMMAND-bearing steps — the only
        thing it can contribute as a step. If (nearly) every command-bearing step is
        framed as hardening/config, the entry could only ever surface a defensive
        config where an attack step belongs → defensive. Offensive pages fail this:
        their command steps are attack commands, and a trailing "Mitigations"
        section is prose with no commands, so it doesn't count.
    """
    meta = entry.get("meta") or {}
    if meta.get("defensive"):
        return True
    if meta.get("canonical_keys"):
        return False
    if _DEFENSIVE_TITLE_RE.search(entry.get("title") or ""):
        return True
    cmd_steps = [
        s
        for s in (entry.get("steps") or [])
        if any((c.get("cmd") or "").strip() for c in (s.get("code") or []))
    ]
    if len(cmd_steps) < 3:
        return False  # too little to read the whole entry as a hardening guide
    defensive = sum(1 for s in cmd_steps if _DEFENSIVE_BODY_RE.search(s.get("text") or ""))
    # STRONG majority required: an offensive exploit whose steps merely mention
    # bypassing a mitigation (e.g. PrintNightmare) sits near 50% and must NOT trip;
    # a genuine hardening guide is >=2/3 config steps.
    return defensive >= 3 and defensive * 3 >= len(cmd_steps) * 2


def is_step_eligible(entry: dict) -> bool:
    """Whether a KB entry may be GROUNDED as an attack-path / chat step.

    Rejects worked examples (writeup/ctf), defensive hardening / secure-deployment
    guides, coarse multi-topic pages flagged at ingestion, personal/meta/log pages,
    and — as a backstop — any very large body with no single-technique focus (an
    un-flagged grab-bag). Everything rejected here stays fully searchable/browsable;
    it just can't become a step, so a step is always a focused ATTACK technique
    instead of a wall of unrelated content or a defensive config.
    """
    if entry.get("category", "") in EXCLUDED_STEP_CATEGORIES:
        return False
    if is_defensive_hardening(entry):
        return False  # hardening / secure-deployment guide — not an attack step
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
    title = entry.get("title") or ""
    return bool(_GRABBAG_TITLE_RE.search(title) or _BROAD_METHODOLOGY_RE.search(title))


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
# lab/example IPs written with a PLACEHOLDER octet instead of a number — the
# forms writeups love: 10.10.11.x, 10.10.10.XX, 192.168.1.<ip>, 172.16.5.{target}.
# A recognised private/lab prefix (0-2 numeric octets) then a placeholder final
# octet (x/XX, <…ip…>, {…}). Only the last octet is a placeholder, so loopback
# (127.*), bind-all, version literals and bare {lhost}/YOUR_IP are left untouched.
_PH_OCTET = r"(?:x{1,3}|<[^<>\s/]{1,24}>|\{[^}\s/]{1,24}\})"
_EXAMPLE_IP_PH_RE = re.compile(
    r"(?<![\w.])(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))"
    r"(?:\.\d{1,3}){0,2}\." + _PH_OCTET + r"(?!\w)",
    re.I,
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

    def _ph(m: re.Match[str]) -> str:
        tok = m.group(0).lower()
        return target if ("url" in tok and is_url) else host

    # Keep a trailing :port when swapping in the host — the service port belongs
    # to the target, not the example address (e.g. .../inspect on :6274). Without
    # this the substituted target (itself often a 10.x IP) gets re-matched and its
    # port stripped.
    def _to_host(m: re.Match[str]) -> str:
        tail = re.search(r":\d{1,5}$", m.group(0))
        return host + (tail.group(0) if tail else "")

    # 1) lab/example IPs with a PLACEHOLDER octet (10.10.11.x, 192.168.1.<ip>) —
    #    replaced WHOLE first so a trailing <ip>/{target} octet isn't picked apart
    #    by the generic placeholder-token rule below.
    out = _EXAMPLE_IP_PH_RE.sub(host, cmd)

    # 2) explicit placeholder tokens → full target for URL-ish, host for the rest
    out = _PLACEHOLDER_RE.sub(_ph, out)

    # 3) obvious example IPs → target host (only when our host is an IP)
    host_is_ip = _is_ipv4(host.split(":", 1)[0])
    if host_is_ip:
        out = _EXAMPLE_IP_RE.sub(_to_host, out)

    # 4) obvious example hostnames → target host — ONLY when the target is itself a
    #    host/URL. When the target is a bare IP, a note's hostname (e.g. devhub.htb)
    #    is a NAME, not an address: rewriting it to the IP breaks name-based usage
    #    and, in an "IP hostname" /etc/hosts line, collapses the two columns into a
    #    nonsensical "IP IP". Leaving the hostname intact keeps that line correct —
    #    the IP column was already substituted in step 3.
    if not host_is_ip:
        out = _EXAMPLE_HOST_RE.sub(_to_host, out)
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
    profile: dict[str, Any] | None = None,
) -> dict[str, list[dict]]:
    """Gather candidate techniques from the KB, bucketed by canonical phase.

    Runs one broad hybrid query on the goal plus one phase-seeded query per
    canonical phase, unions the hits (keeping the best score seen per entry),
    then buckets each entry into its phase and keeps the top few per phase.

    ``ctx`` (from ``parse_goal_context``) adds box-type/creds terms. ``profile``
    (from ``profile_target``) is the STRONGER steer: when it names priority bug
    classes for THIS target, those become the query bias — so the KB returns
    target-specific entries (SSRF / tenant-isolation / OAuth) instead of a
    generic web checklist. The static ``_TARGET_CONTEXT`` string is the fallback
    only when the profile is empty.
    """
    prof = profile or {}
    # priority bug classes are the dynamic, target-specific seed terms; fall back
    # to the static target-type context only when the profiler produced nothing.
    bias = " ".join(prof.get("priority_bug_classes") or [])
    if not bias:
        bias = _TARGET_CONTEXT.get((target_type or "").lower(), "")
    # fold the target class + tech signals in for extra discriminative pull
    prof_terms = " ".join(
        x
        for x in (
            prof.get("target_class") or "",
            " ".join(prof.get("tech_signals") or []),
        )
        if x
    ).strip()
    box_terms = (ctx or {}).get("terms", "")
    base = " ".join(x for x in (goal, bias, prof_terms, box_terms) if x).strip()

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
    "- BRANCHES: a step that reveals something or tests an access control has a "
    "natural next move. For such PIVOTAL steps (vuln probes, access-control / auth "
    "tests, exploitation) ADD two short prose hints — \"on_success\": what this "
    "finding unlocks / the next action or which step id to jump to; \"on_blocked\": "
    "the pivot if it 403s or fails. ONE sentence each. Include them on the pivotal "
    "steps; SKIP them on purely mechanical steps (a plain port scan, a directory "
    "brute) — do NOT force a branch onto every step, but DO add them where a real "
    "decision exists.\n"
    "Respond with ONLY a JSON object, no prose."
)

_SCHEMA_HINT = (
    '{"phases": [{"phase": "recon", "steps": ['
    '{"entry_id": "<library id>", "why": "<1-2 sentences>", '
    '"on_success": "<optional: what it unlocks / next step>", '
    '"on_blocked": "<optional: pivot if it fails>"}, '
    '{"ai_suggested": true, "title": "<short title>", "why": "<why>", '
    '"commands": [{"lang": "bash", "cmd": "<command>"}]}'
    ']}]}'
)


def build_user_prompt(
    goal: str,
    target_type: str | None,
    grouped: dict[str, list[dict]],
    ctx: dict[str, Any] | None = None,
    profile: dict[str, Any] | None = None,
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
    prof = profile or {}
    tclass = prof.get("target_class")
    pbugs = prof.get("priority_bug_classes") or []
    if tclass or pbugs:
        lines.append("")
        lines.append("TARGET PROFILE:")
        if tclass:
            lines.append(f"- target class: {tclass}")
        if pbugs:
            lines.append("- priority bug classes: " + ", ".join(pbugs))
        lines.append(
            "PRIORITISE steps that probe these bug classes for THIS target; do NOT "
            "emit generic steps that ignore the profile."
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
        "For pivotal steps (a vuln probe, an access-control or auth test, an "
        "exploit) include on_success / on_blocked branch hints; skip them on "
        "routine steps. "
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


def _branch_hints(st: dict) -> dict[str, str]:
    """Pass the model's OPTIONAL branch hints (on_success / on_blocked) through as
    trimmed prose. They are advisory next-action / pivot notes — nothing to
    validate against the KB — so a step keeps whichever it supplied and neither
    otherwise. A missing branch never affects whether the step survives."""
    out: dict[str, str] = {}
    for key in ("on_success", "on_blocked"):
        val = str(st.get(key) or "").strip()
        if val:
            out[key] = val[:240]
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
                        "from_writeup": False,
                        **_branch_hints(st),
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
                        "from_writeup": False,
                        **_branch_hints(st),
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
# target profiler — reason about WHAT KIND of target this is, so retrieval and
# composition probe the RIGHT bug classes instead of a flat web checklist.
# Optional pasted scope / Rules-of-Engagement is just another input here.
# --------------------------------------------------------------------------- #
_PROFILE_SYSTEM = (
    "You are a penetration-testing TARGET PROFILER. Given a target description "
    "(and optional Rules-of-Engagement / scope text), infer what KIND of target "
    "this is and which bug classes matter MOST for it. Output ONLY a JSON object, "
    "no prose:\n"
    '{"target_class": "<short label, e.g. multi-tenant SaaS / static site / '
    'internal API / WordPress / Windows AD>", '
    '"tech_signals": ["<observed or likely tech, e.g. multi-tenant, OAuth, '
    'webhooks, GraphQL>"], '
    '"priority_bug_classes": ["<the SPECIFIC, target-appropriate bug classes to '
    'probe FIRST — e.g. cross-tenant IDOR, SSRF via server-side integration, '
    'OAuth/integration token handling, webhook secret leakage>"], '
    '"out_of_scope": ["<exact paths/hosts the RoE forbids, copied verbatim>"]}\n'
    "Rules: priority_bug_classes MUST be specific to this target class, NOT a "
    "generic web checklist — 3 to 6 of them, highest-value first. out_of_scope: "
    "copy only paths/hosts the scope text explicitly forbids; empty list if none."
)

# the safe fallback so composition never hard-fails on the profiler
_EMPTY_PROFILE: dict[str, Any] = {
    "target_class": None,
    "tech_signals": [],
    "priority_bug_classes": [],
    "out_of_scope": [],
}


def _profile_str_list(value: Any, cap: int) -> list[str]:
    """Coerce a model value into a deduped list of non-empty trimmed strings."""
    if not isinstance(value, list):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for item in value:
        s = str(item).strip()
        key = s.lower()
        if s and key not in seen:
            seen.add(key)
            out.append(s)
        if len(out) >= cap:
            break
    return out


def _coerce_profile(parsed: dict) -> dict[str, Any]:
    """Normalise a model profile into the 4-key shape with safe types."""
    tc = parsed.get("target_class")
    return {
        "target_class": (str(tc).strip() or None) if isinstance(tc, str) else None,
        "tech_signals": _profile_str_list(parsed.get("tech_signals"), 8),
        "priority_bug_classes": _profile_str_list(
            parsed.get("priority_bug_classes"), 6
        ),
        "out_of_scope": _profile_str_list(parsed.get("out_of_scope"), 20),
    }


def profile_target(
    goal: str, scope_text: str | None, cfg: dict
) -> dict[str, Any]:
    """Infer the target class + priority bug classes (+ out-of-scope paths) that
    STEER retrieval and composition. Optional ``scope_text`` (pasted RoE) is just
    another input. Returns a safe empty profile on ANY LLM/parse failure so
    composition never hard-fails on the profiler (degrading to flat behaviour).
    """
    lines = [f"TARGET: {goal.strip()}"]
    scope = (scope_text or "").strip()
    if scope:
        lines.append("")
        lines.append("SCOPE / RULES OF ENGAGEMENT (verbatim):")
        lines.append(scope[:4000])
    try:
        raw = llm.chat(_PROFILE_SYSTEM, "\n".join(lines), cfg, max_tokens=700)
        parsed = llm.extract_json(raw)
    except llm.LLMError:
        return dict(_EMPTY_PROFILE)
    if not isinstance(parsed, dict):
        return dict(_EMPTY_PROFILE)
    return _coerce_profile(parsed)


def _filter_out_of_scope(
    phases: list[dict[str, Any]], out_of_scope: list[str]
) -> tuple[list[dict[str, Any]], bool]:
    """Drop any step whose title / rationale / commands touch an out-of-scope
    path or host, re-number the survivors, and drop now-empty phases. Returns
    ``(filtered_phases, any_dropped)`` — the caller tags the response ``scoped``.
    """
    tokens = [t.strip().lower() for t in (out_of_scope or []) if len(t.strip()) >= 4]
    if not tokens:
        return phases, False
    dropped = False
    out: list[dict[str, Any]] = []
    for ph in phases:
        kept: list[dict] = []
        for s in ph.get("steps") or []:
            hay = " ".join(
                [s.get("title") or "", s.get("why") or ""]
                + [c.get("cmd") or "" for c in (s.get("commands") or [])]
            ).lower()
            if any(tok in hay for tok in tokens):
                dropped = True
                continue
            kept.append(s)
        if not kept:
            continue
        for i, step in enumerate(kept, 1):
            step["id"] = f"{ph['phase']}-{i}"
        out.append({**ph, "steps": kept})
    return out, dropped


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
                "from_writeup": True,  # PRIMARY — the user's own trusted step
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
# writeup augmentation — supplement a (possibly terse) writeup with KB + AI steps
# --------------------------------------------------------------------------- #
_AUGMENT_SYSTEM = (
    "You are a penetration-testing methodology guide AUGMENTING the user's OWN box "
    "writeup on an AUTHORIZED engagement. The writeup's ordered steps are the "
    "PRIMARY, trusted path — you must NOT repeat them. Your only job is to "
    "SUPPLEMENT it: fill gaps where the writeup is terse, skips a jump, or omits a "
    "useful technique.\n"
    "You are given (A) the step titles the writeup ALREADY covers, per phase, and "
    "(B) a LIBRARY of the user's other techniques (entry_id + real commands).\n"
    "Rules:\n"
    "- Prefer the LIBRARY: cite an entry_id for a grounded supplement (the system "
    "attaches its real commands — don't restate them).\n"
    "- Only where the library has no fit AND there is a real gap, add an "
    "ai_suggested step from general knowledge, marked EXACTLY as "
    '{"ai_suggested": true, "title": "...", "why": "...", "commands": '
    '[{"lang": "bash", "cmd": "..."}]}, with concrete command(s); these are '
    "UNVERIFIED.\n"
    "- Supplement ONLY the phases explicitly listed as MISSING/THIN. A phase the "
    "writeup already covers substantively is COMPLETE — add nothing there, even if "
    "you can think of a related technique. A thorough writeup needs FEW or NONE; "
    "returning empty phases is the correct, expected outcome.\n"
    "- NEVER duplicate a writeup step or a technique it already implies, and never "
    "add a tangential 'nice to have' — a supplement must fill a REAL gap in a "
    "missing/thin phase.\n"
    "- Group under phases recon, enumeration, exploitation, privesc, "
    "post-exploitation. A step is EITHER {\"entry_id\": \"<library id>\", "
    "\"why\": \"...\"} OR an ai_suggested step as shown.\n"
    "Respond with ONLY a JSON object, no prose."
)


def build_augment_prompt(
    goal: str,
    ctx: dict[str, Any],
    covered: dict[str, list[str]],
    grouped: dict[str, list[dict]],
    thin: set[str],
) -> str:
    lines: list[str] = [f"GOAL: {goal}"]
    box_type = ctx.get("box_type")
    if box_type:
        creds = " with valid credentials" if ctx.get("has_creds") else ""
        lines.append(f"CONTEXT: {box_type.upper()} target{creds}.")
    lines.append("")
    eligible = [p for p in PHASE_ORDER if p in thin]
    lines.append(
        "SUPPLEMENT ONLY THESE missing/thin phases: "
        + (", ".join(eligible) or "(none — the writeup is complete; return {})")
        + ". Every other phase is already covered substantively — add NOTHING there."
    )
    lines.append("")
    lines.append("WRITEUP ALREADY COVERS (do NOT repeat these), by phase:")
    for phase in PHASE_ORDER:
        titles = covered.get(phase)
        if not titles:
            continue
        lines.append(f"## {phase}")
        for t in titles:
            lines.append(f"- {t}")
    lines.append("")
    lines.append("TECHNIQUE LIBRARY (cite entry_ids for grounded supplements), by phase:")
    any_lib = False
    for phase in PHASE_ORDER:
        techs = grouped.get(phase)
        if not techs:
            continue
        any_lib = True
        lines.append(f"## {phase}")
        for t in techs:
            lines.append(f"- entry_id: {t['entry_id']}  ({t['title']})")
    if not any_lib:
        lines.append("(no close library matches — only add ai_suggested steps for real gaps.)")
    lines.append("")
    lines.append(
        "Return ONLY supplements that fill genuine gaps in the missing/thin phases "
        "listed above — grounded (entry_id) steps first, then clearly-marked "
        "ai_suggested steps. Add nothing to any other phase. If nothing genuinely "
        "helps, return an empty object. "
        f"Return JSON exactly shaped like: {_SCHEMA_HINT}"
    )
    return "\n".join(lines)


def _merge_phases(
    primary: list[dict[str, Any]], supp: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Merge writeup phases (primary) with supplement phases. Within each phase:
    writeup steps first (unchanged, primary), then grounded KB supplements, then
    AI-suggested gap steps. Stable ids are re-assigned across the merged order."""
    prim = {p["phase"]: list(p["steps"]) for p in primary}
    extra = {p["phase"]: p["steps"] for p in supp}
    out: list[dict[str, Any]] = []
    for phase in PHASE_ORDER:
        steps = prim.get(phase, [])
        s = extra.get(phase, [])
        steps = (
            steps
            + [x for x in s if not x.get("ai_suggested")]
            + [x for x in s if x.get("ai_suggested")]
        )
        if not steps:
            continue
        for i, step in enumerate(steps, 1):
            step["id"] = f"{phase}-{i}"
        out.append({"phase": phase, "label": PHASE_LABEL[phase], "steps": steps})
    return out


def _thin_phases(primary: list[dict[str, Any]]) -> set[str]:
    """Phases where the writeup GENUINELY lacks coverage and a supplement may help:
    an empty phase (no steps at all) or a phase whose steps carry NO commands (pure
    prose, nothing to run). A phase the writeup already covers substantively — any
    step with commands — is COMPLETE and eligible for no supplements. This is what
    keeps augmentation conservative: a thorough writeup exposes few/no thin phases,
    so it gets few/no supplements."""
    present: dict[str, list[dict]] = {p["phase"]: (p.get("steps") or []) for p in primary}
    thin: set[str] = set()
    for phase in PHASE_ORDER:
        steps = present.get(phase)
        if not steps:
            thin.add(phase)  # empty phase — nothing here at all
        elif not any(s.get("commands") for s in steps):
            thin.add(phase)  # steps exist but nothing runnable — very thin
    return thin


def _augment_writeup(
    phases: list[dict[str, Any]],
    by_id: dict[str, dict],
    goal: str,
    target_type: str | None,
    ctx: dict[str, Any],
    target: str | None,
    search_fn: SearchFn,
    cfg: dict,
    profile: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Best-effort, CONSERVATIVE supplement of the writeup path: only phases the
    writeup genuinely lacks or is very thin on (empty, or no runnable commands) may
    receive grounded KB steps + marked ai_suggested gap steps. Phases the writeup
    already covers substantively get nothing. Returns the merged phases; on any LLM
    failure the original writeup phases are returned unchanged (writeup stands alone).
    """
    thin = _thin_phases(phases)
    if not thin:
        return phases  # every phase substantively covered — nothing to supplement
    grouped = retrieve(by_id, goal, target_type, search_fn, ctx, profile)
    grouped = {p: t for p, t in grouped.items() if p in thin}  # offer library only for thin phases
    covered = {p["phase"]: [s["title"] for s in p["steps"]] for p in phases}
    user = build_augment_prompt(goal, ctx, covered, grouped, thin)
    raw = llm.chat(_AUGMENT_SYSTEM, user, cfg)
    parsed = llm.extract_json(raw)
    supp = _ground(parsed, by_id, target)
    # deterministic backstop: keep supplements ONLY for genuinely thin phases, so a
    # substantively-covered phase gets nothing even if the model tried to add there.
    supp = [ph for ph in supp if ph["phase"] in thin]
    return _merge_phases(phases, supp)


# --------------------------------------------------------------------------- #
# public entry point
# --------------------------------------------------------------------------- #
def compose(
    by_id: dict[str, dict],
    goal: str,
    target_type: str | None,
    search_fn: SearchFn,
    scope_text: str | None = None,
) -> dict[str, Any]:
    """Compose an attack path for the goal. Two modes:

    1. **Writeup-first (+ augmentation)** — if the goal names a box we have a
       writeup for, build the path from that writeup's real ordered walkthrough
       (trusted, PRIMARY), then best-effort AUGMENT it with grounded KB
       supplements and clearly-marked ai_suggested gap steps for what the writeup
       is missing or too terse on. If the LLM is unreachable the writeup stands
       alone.
    2. **KB-first + AI-suggested fallback** — otherwise retrieve grounded KB
       techniques (weighted by box-type context) and let the LLM order them and
       add clearly-marked ai_suggested steps for genuine gaps.

    Raises ``llm.LLMError`` (only in mode 2) if the LLM is unreachable / produces
    no usable path — the API layer maps that to a clean 503.
    """
    cfg = llm.load_config()
    target = extract_target(goal)
    ctx = parse_goal_context(goal)
    # Profile the target FIRST (safe empty profile on any LLM failure) — it steers
    # both retrieval and composition, and supplies out-of-scope paths to drop.
    profile = profile_target(goal, scope_text, cfg)
    oos = profile.get("out_of_scope") or []
    box_writeup = find_box_writeup(by_id, goal)

    # (1) WRITEUP-FIRST (+ augmentation)
    if box_writeup and box_writeup["id"] in by_id:
        wu = by_id[box_writeup["id"]]
        phases = build_writeup_path(wu, target)
        if phases:
            augmented = False
            try:  # best-effort supplements; the writeup stands alone on failure
                merged = _augment_writeup(
                    phases, by_id, goal, target_type, ctx, target, search_fn, cfg,
                    profile,
                )
                augmented = any(
                    s.get("from_writeup") is False
                    for ph in merged
                    for s in ph["steps"]
                )
                phases = merged
            except llm.LLMError:
                pass
            phases, scoped = _filter_out_of_scope(phases, oos)
            damaged = bool((wu.get("meta") or {}).get("source_damaged"))
            return {
                "goal": goal,
                "target_type": target_type,
                "target": target,
                "phases": phases,
                "profile": profile,
                "scoped": scoped,
                "box_writeup": box_writeup,
                "origin": "writeup",
                "origin_label": f"from your writeup: {wu['title']}",
                "origin_note": (
                    "source formatting damaged — some commands may be mangled; "
                    "open the writeup to verify"
                )
                if damaged
                else None,
                "augmented": augmented,
                "model_used": cfg["model"] if augmented else "your writeup",
                "provider": cfg["provider"] if augmented else "writeup",
            }

    # (2) KB-FIRST + AI-SUGGESTED FALLBACK
    grouped = retrieve(by_id, goal, target_type, search_fn, ctx, profile)
    user = build_user_prompt(goal, target_type, grouped, ctx, profile)
    raw = llm.chat(_SYSTEM, user, cfg)
    parsed = llm.extract_json(raw)
    phases = _ground(parsed, by_id, target)

    if not phases:
        raise llm.LLMError("the model did not produce any usable steps")

    phases, scoped = _filter_out_of_scope(phases, oos)
    if not phases:
        raise llm.LLMError("all composed steps were out of scope")

    return {
        "goal": goal,
        "target_type": target_type,
        "target": target,
        "phases": phases,
        "profile": profile,
        "scoped": scoped,
        "box_writeup": box_writeup,
        "origin": "composed",
        "origin_label": None,
        "origin_note": None,
        "model_used": cfg["model"],
        "provider": cfg["provider"],
    }
