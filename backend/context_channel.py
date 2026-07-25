"""Channel 2 — CONTEXT grounding: what the planner READS, never what it RUNS.

HackPit retrieves from the KB on **two separate channels**, and keeping them
separate is the whole design:

* **Channel 1 — STEP grounding** (``attack_path.retrieve`` / ``_ground``, NOT
  touched by this module). Writeups and CTF indexes are excluded from the step
  pool; methodology / meta / tools-arsenal / grab-bag docs are step-INELIGIBLE.
  They must never become literal steps — a writeup step overfits one box, a
  methodology step is un-runnable.
* **Channel 2 — CONTEXT** (this module). The *content* of the relevant writeup
  and of the matching methodology/workflow docs is injected into the composer
  PROMPT as background the model reasons from. It shapes technique choice and
  the plan's flow. It is never emitted as a step, and nothing here changes what
  is step-eligible.

Everything this module produces is bounded (hard char caps, see the budget
constants) so the injected background can't blow the context window, and it is a
pure NO-OP when nothing matches: no writeup, no methodology doc → empty block →
the prompt is byte-for-byte what it was before Channel 2 existed.
"""

from __future__ import annotations

import re
from typing import Any, Callable

# --------------------------------------------------------------------------- #
# token budget — the hard ceiling on injected background
# --------------------------------------------------------------------------- #
WRITEUP_CHARS = 2800        # one writeup excerpt
METHODOLOGY_CHARS = 1200    # one methodology/workflow doc excerpt
METHODOLOGY_DOCS = 2        # how many methodology docs are ever injected
TOTAL_CONTEXT_CHARS = 6000  # excerpt BODY across all sources, together
# Absolute ceiling on the rendered block (bodies + the fixed headers + titles).
# build_context_block() slices to this, so no combination of sources — however
# long, however many — can push the prompt past a known bound.
MAX_BLOCK_CHARS = TOTAL_CONTEXT_CHARS + 1600

_SECTION_CHARS = 900        # one excerpted section
_CODE_PREVIEW_LINES = 2     # keep a code block's first lines (which TOOL), not a dump

# goal words too generic to select a relevant section on
_STOP = {
    "the", "and", "for", "with", "this", "that", "from", "into", "your", "you",
    "get", "box", "machine", "target", "host", "htb", "thm", "hackthebox",
    "tryhackme", "vulnhub", "root", "user", "flag", "flags", "exploit", "attack",
    "hack", "pwn", "compromise", "http", "https", "www", "com", "org", "net",
    "shell", "access", "find", "how", "what", "run", "use", "using", "via",
}

_HEADING_RE = re.compile(r"^\s{0,3}#{1,6}\s+\S", re.M)
_FENCE_RE = re.compile(r"```[^\n]*\n(.*?)```", re.S)


def _salient(text: str) -> set[str]:
    """Content words from the goal, used to pick which sections are relevant."""
    return {
        w
        for w in re.findall(r"[a-z0-9][a-z0-9._-]{2,}", (text or "").lower())
        if w not in _STOP
    }


def _trim_code(section: str) -> str:
    """Shrink fenced code to its first lines.

    A writeup's commands say WHICH TOOL was used — useful background — but the
    full block is a box-specific dump. Keeping the head preserves the technique
    signal at a fraction of the budget (and of the leakage surface).
    """

    def _cut(m: re.Match[str]) -> str:
        lines = [ln for ln in m.group(1).splitlines() if ln.strip()]
        head = lines[:_CODE_PREVIEW_LINES]
        more = " …" if len(lines) > len(head) else ""
        return "`" + " ; ".join(x.strip() for x in head)[:200] + more + "`"

    return _FENCE_RE.sub(_cut, section)


def _split_sections(body: str) -> list[str]:
    """Split a body into markdown sections (heading-led), else into paragraphs."""
    body = (body or "").strip()
    if not body:
        return []
    if _HEADING_RE.search(body):
        parts: list[str] = []
        buf: list[str] = []
        for line in body.splitlines():
            if _HEADING_RE.match(line) and buf:
                parts.append("\n".join(buf).strip())
                buf = [line]
            else:
                buf.append(line)
        if buf:
            parts.append("\n".join(buf).strip())
        return [p for p in parts if p]
    return [p.strip() for p in re.split(r"\n\s*\n", body) if p.strip()]


def excerpt(body: str, goal: str, cap: int, *, lead: bool = True) -> str:
    """A bounded, RELEVANT excerpt of a document body — never the whole file.

    Sections are scored on overlap with the goal's content words; the highest
    scoring ones are kept **in their original order** (so the document's own flow
    survives) until ``cap`` is reached. ``lead`` keeps the opening section even
    when it scores nothing — for a methodology doc that opening is the flow.
    """
    sections = _split_sections(body)
    if not sections:
        return ""
    terms = _salient(goal)
    scored: list[tuple[int, int, str]] = []
    for i, sec in enumerate(sections):
        words = _salient(sec)
        score = len(terms & words)
        if lead and i == 0:
            score += 2  # the opening frames the approach — worth keeping
        scored.append((score, i, sec))

    scored.sort(key=lambda t: (-t[0], t[1]))
    keep: list[tuple[int, str]] = []
    used = 0
    for score, i, sec in scored:
        if score <= 0 and keep:
            break  # nothing relevant left; don't pad the budget with noise
        text = _trim_code(sec)[:_SECTION_CHARS]
        if used + len(text) > cap:
            if keep:
                break
            text = text[:cap]  # first section alone exceeds the cap — hard cut
        keep.append((i, text))
        used += len(text)
        if used >= cap:
            break
    keep.sort(key=lambda t: t[0])
    return "\n\n".join(t for _i, t in keep)[:cap]


# --------------------------------------------------------------------------- #
# CH1 — writeup CONTEXT (approach, never literals)
# --------------------------------------------------------------------------- #
def writeup_context(entry: dict, goal: str, cap: int = WRITEUP_CHARS) -> dict[str, Any] | None:
    """Bounded excerpt of a matched box WRITEUP, as reasoning background.

    ``entry`` is the writeup ``find_box_writeup`` already matched (Channel 1's
    link) — this module never widens that match. Returns None when the writeup
    has no usable body, so a missing body is a clean no-op.
    """
    text = excerpt(entry.get("body_md") or "", goal, cap)
    if not text:
        return None
    return {
        "kind": "writeup",
        "id": entry.get("id", ""),
        "title": entry.get("title") or "",
        "excerpt": text,
        "chars": len(text),
    }


# --------------------------------------------------------------------------- #
# CH2 — methodology / workflow CONTEXT (the flow, never a step)
# --------------------------------------------------------------------------- #
# The meta-docs Channel 1 keeps OUT of the step pool (or hard-deprioritizes as
# broad references) because they are un-runnable process guidance: recon
# methodology, pentest / bug-bounty workflow, threat modeling, the "how to
# approach a machine" notes. Un-runnable is exactly why they make good CONTEXT —
# they describe the flow and the bug-class prioritisation a plan should follow.
# NB: "pentesting <something>" is deliberately NOT here — it would match every
# HackTricks per-service page ("500/udp - Pentesting IPsec/IKE VPN"), which is a
# technique, not a methodology. Only the explicit process words qualify.
_METHODOLOGY_TITLE_RE = re.compile(
    r"\b(?:methodolog(?:y|ies)|workflow|mindset|playbook|"
    r"(?:machine|general|overall)\s+approach|attack\s?paths?|"
    r"threat\s+model(?:ing)?|testing\s+checklist)\b",
    re.I,
)
_METHODOLOGY_QUERY = "methodology workflow approach process phases prioritisation"


def is_methodology_doc(entry: dict) -> bool:
    """True when the entry is a METHODOLOGY / workflow / process doc.

    Decided on the TITLE, deliberately — the KB's ``methodology`` CATEGORY is the
    HackTricks section name, and two thirds of what sits in it are ordinary
    technique pages ("Docker Forensics", "Telecom Network Exploitation"). Reading
    one of those as "the methodology to follow" would frame a single technique as
    the plan's shape. The process words are the reliable signal.

    This is a Channel-2 SELECTION predicate only. It decides what may be read as
    background; it does not (and must not) feed step-eligibility — that stays
    entirely with ``attack_path.is_step_eligible``.
    """
    return bool(_METHODOLOGY_TITLE_RE.search(entry.get("title") or ""))


def methodology_context(
    by_id: dict[str, dict],
    goal: str,
    search_fn: Callable[[str, int, str], list[dict]],
    profile: dict[str, Any] | None = None,
    target_context: str = "",
    exclude: set[str] | None = None,
    limit: int = METHODOLOGY_DOCS,
    cap: int = METHODOLOGY_CHARS,
) -> list[dict[str, Any]]:
    """Retrieve the methodology/workflow docs that match this goal, as background.

    Reuses the KB's existing hybrid search (same callable Channel 1 uses), then
    keeps only methodology docs — so a technique can never arrive here, and a
    methodology doc can never leave here as a step. Empty list when nothing
    matches, which makes Channel 2 a no-op.
    """
    prof = profile or {}
    bias = " ".join(prof.get("priority_bug_classes") or []) or target_context
    query = " ".join(
        x for x in (goal, bias, prof.get("target_class") or "", _METHODOLOGY_QUERY) if x
    ).strip()
    skip = exclude or set()

    seen: dict[str, float] = {}
    for hit in search_fn(query, 24, "hybrid"):
        eid = hit.get("id")
        if not eid or eid in skip or eid not in by_id:
            continue
        if not is_methodology_doc(by_id[eid]):
            continue
        score = float(hit.get("score") or 0.0)
        if eid not in seen or score > seen[eid]:
            seen[eid] = score

    out: list[dict[str, Any]] = []
    for eid, _score in sorted(seen.items(), key=lambda kv: -kv[1]):
        e = by_id[eid]
        text = excerpt(e.get("body_md") or "", goal, cap)
        if not text:
            continue
        out.append(
            {
                "kind": "methodology",
                "id": eid,
                "title": e.get("title") or "",
                "excerpt": text,
                "chars": len(text),
            }
        )
        if len(out) >= limit:
            break
    return out


# --------------------------------------------------------------------------- #
# the injected block
# --------------------------------------------------------------------------- #
_WRITEUP_HEADER = (
    "REFERENCE — here is how this (or a closely similar) box was approached. "
    "Use it to inform the APPROACH and technique choice for the NAMED target: "
    "which classes of technique to reach for, in what order, and what tends to "
    "follow what. It is BACKGROUND, not a script:\n"
    "- Do NOT copy any box-specific literal from it — no IP, hostname, "
    "credential, path, port-to-service assumption or flag. Those belong to that "
    "box, not to this engagement.\n"
    "- Do NOT turn it into steps verbatim; adapt the approach to THIS target and "
    "still cite library entry_ids for grounded steps."
)


_METHODOLOGY_HEADER = (
    "METHODOLOGY — follow this flow and bug-class prioritisation when you "
    "structure the plan. It shapes the ORDER and SHAPE of the path (recon → "
    "enumeration → exploitation → privesc → post-exploitation, and which classes "
    "to probe first for this kind of target). It is BACKGROUND, not content:\n"
    "- Do NOT emit any of it as a step — it is process guidance, not something "
    "the operator can run.\n"
    "- Every step still comes from the technique library (cite entry_id) or is a "
    "clearly-marked ai_suggested gap step."
)


def build_context_block(sources: list[dict[str, Any]]) -> str:
    """Render the Channel-2 sources as prompt background, under the total cap.

    Returns "" when there are no sources — the caller then appends nothing and
    the prompt is unchanged (the no-op guarantee). Each KIND gets its header
    once, and the shared ``TOTAL_CONTEXT_CHARS`` budget is spent in order, so a
    long writeup can never crowd the window: it just leaves less for the rest.
    """
    if not sources:
        return ""
    lines: list[str] = []
    budget = TOTAL_CONTEXT_CHARS
    headed: set[str] = set()
    for src in sources:
        if budget <= 0:
            break
        body = src["excerpt"][:budget]
        if not body:
            continue
        if src["kind"] not in headed:
            headed.add(src["kind"])
            lines.append("")
            lines.append(
                _WRITEUP_HEADER if src["kind"] == "writeup" else _METHODOLOGY_HEADER
            )
        lines.append(f"### {src['kind']}: {src['title'][:120]}")
        lines.append(body)
        budget -= len(body)
    return "\n".join(lines)[:MAX_BLOCK_CHARS]


# --------------------------------------------------------------------------- #
# CH3 — the LEAKAGE guard
# --------------------------------------------------------------------------- #
# Injected background carries box-specific literals: the writeup's 10.10.11.x,
# its `dev.forest.htb`, its cracked password, its /home/svc-alfresco path, its
# flag. A model reasoning from that text can echo one into a generated step, and
# a step aimed at another box's host is a WRONG step.
#
# This is a PLAN-QUALITY guard, not the safety boundary. The safety boundary is
# the executor: every command goes through the target-lock / scope-lock, so a
# leaked off-target host is REFUSED at execution time whether or not this guard
# catches it (backend/cockpit — see docs/CHANNEL2-GROUNDING.md). What this guard
# buys is a plan that doesn't waste the operator's time pointing at the wrong
# machine, and one that never surfaces another box's credential as if it were
# an asset of this engagement.
_LEAK_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_LEAK_HOST_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:htb|thm|local|lan|internal|corp|box|vuln|[a-z]{2,24})\b",
    re.I,
)
_LEAK_CRED_RE = re.compile(
    r"(?:pass(?:word|wd)?|pwd|creds?|secret|api[_-]?key|token)\s*[:=]\s*"
    r"(?P<v>[^\s'\"`,;<>]{4,64})",
    re.I,
)
_LEAK_PAIR_RE = re.compile(
    r"\b(?P<v>[A-Za-z][\w.$-]{2,32}:[^\s'\"`,;<>]{4,48})\b"
)
_LEAK_FLAG_RE = re.compile(r"\b(?:HTB|THM|FLAG|flag)\{[^}\n]{1,120}\}")
_LEAK_PATH_RE = re.compile(
    r"(?:/(?:home|root|Users)/[\w.$-]+(?:/[\w.$-]+)*|"
    r"[A-Za-z]:\\\\?Users\\\\?[\w.$-]+(?:\\\\?[\w.$-]+)*)"
)

# Public infrastructure and non-routable addresses that appear in ANY notes and
# are never a box's identity. Rewriting these would corrupt a legitimate command
# (a `git clone` of a tool, a loopback listener, a 0.0.0.0 bind).
_BENIGN_HOSTS = {
    "github.com", "raw.githubusercontent.com", "gist.github.com", "gitlab.com",
    "bitbucket.org", "pypi.org", "files.pythonhosted.org", "npmjs.com",
    "registry.npmjs.org", "example.com", "example.org", "example.net",
    "localhost", "google.com", "microsoft.com", "live.com", "windows.com",
    "portswigger.net", "hackthebox.com", "hackthebox.eu", "app.hackthebox.com",
    "tryhackme.com", "exploit-db.com", "cve.mitre.org", "attack.mitre.org",
    "owasp.org", "kali.org", "docker.io", "hub.docker.com", "python.org",
    "crackstation.net", "virustotal.com", "shodan.io", "wikipedia.org",
}
_BENIGN_IPS = {"127.0.0.1", "0.0.0.0", "255.255.255.0", "255.255.0.0", "8.8.8.8"}
# suffixes that only ever name a lab/CTF machine, never public infrastructure
_LAB_TLDS = {"htb", "thm", "local", "lan", "internal", "corp", "box", "vuln"}

# fields on a step that are MODEL PROSE — the model's own words, so the place a
# read literal can resurface. A grounded step's commands are copied verbatim from
# the KB entry and are never model output, so they are not scanned here.
_PROSE_FIELDS = ("why", "target_adaptation", "on_success", "on_blocked")


def _host_literals(text: str) -> set[str]:
    """Box-identity hosts/IPs in the text (benign public infra excluded)."""
    out: set[str] = set()
    for ip in _LEAK_IP_RE.findall(text):
        parts = ip.split(".")
        if all(p.isdigit() and int(p) <= 255 for p in parts) and ip not in _BENIGN_IPS:
            out.add(ip)
    for host in _LEAK_HOST_RE.findall(text):
        h = host.lower().strip(".")
        if _LEAK_IP_RE.fullmatch(h):
            continue
        # benign by itself or by parent (docs.github.com is github.com's)
        labels = h.split(".")
        if any(
            ".".join(labels[i:]) in _BENIGN_HOSTS for i in range(len(labels) - 1)
        ):
            continue
        # a bare "file.txt"-shaped token is not a host
        if h.rsplit(".", 1)[-1] in {"txt", "md", "py", "sh", "js", "json", "yml",
                                    "yaml", "php", "asp", "aspx", "exe", "dll",
                                    "zip", "log", "conf", "ini", "xml", "html"}:
            continue
        out.add(h)
        # a lab domain's PARENT is the same box's identity: seeing
        # "dev.forest.htb" also makes "forest.htb" a literal of that box, and the
        # model routinely writes the parent (a realm, an /etc/hosts line) even
        # when only the subdomain was in the text.
        labels = h.split(".")
        if len(labels) > 2 and labels[-1] in _LAB_TLDS:
            out.add(".".join(labels[-2:]))
    return out


def _secret_literals(text: str) -> set[str]:
    """Credentials, tokens and flags in the text — never substitutable, only dropped."""
    out: set[str] = set()
    for m in _LEAK_CRED_RE.finditer(text):
        out.add(m.group("v"))
    for m in _LEAK_PAIR_RE.finditer(text):
        v = m.group("v")
        if "://" in v or v.split(":", 1)[0].lower() in {"http", "https", "ftp", "smb"}:
            continue
        out.add(v)
    out.update(_LEAK_FLAG_RE.findall(text))
    out.update(_LEAK_PATH_RE.findall(text))
    return {v for v in out if len(v) >= 4}


def collect_literals(
    sources: list[dict[str, Any]], facts: str | None = None
) -> tuple[set[str], set[str]]:
    """Literals carried by the INJECTED background, split by how they can be fixed.

    Returns ``(hosts, secrets)``: hosts/IPs can be re-pointed at the real target;
    credentials, flags and box-specific paths cannot be — they can only be
    dropped. Anything that also appears in ``facts`` (the goal / pasted scope) is
    NOT a leak: it is this engagement's own identifier, and the operator named it.
    """
    text = "\n".join(s.get("excerpt") or "" for s in sources)
    if not text:
        return set(), set()
    hay = (facts or "").lower()
    hosts = {h for h in _host_literals(text) if h.lower() not in hay}
    secrets = {s for s in _secret_literals(text) if s.lower() not in hay}
    return hosts, secrets


def _scrub_text(
    text: str, hosts: set[str], secrets: set[str], target_host: str | None
) -> tuple[str, int]:
    """Re-point leaked hosts at the real target; return ("", n) if a secret leaked."""
    hits = 0
    low = text.lower()
    if any(s.lower() in low for s in secrets):
        return "", 1  # a credential/flag/box path from another box — drop it whole
    out = text
    for h in sorted(hosts, key=len, reverse=True):
        if re.search(re.escape(h), out, re.I):
            if not target_host:
                return "", hits + 1  # nothing to re-point at — drop rather than mislead
            out = re.sub(re.escape(h), target_host, out, flags=re.I)
            hits += 1
    return out, hits


def scrub_phases(
    phases: list[dict[str, Any]],
    hosts: set[str],
    secrets: set[str],
    target: str | None,
) -> tuple[list[dict[str, Any]], int]:
    """POST-generation scan: no literal read on Channel 2 survives into a step.

    Scanned surfaces are exactly the MODEL's own output — every step's prose
    fields, and an ai_suggested step's commands. A grounded step's commands come
    verbatim from the cited KB entry (Channel 1) and a writeup step's come from
    the user's own writeup, so neither is model output and neither is touched:
    this guard cannot alter Channel-1 behaviour.

    Leaked hosts are re-pointed at the real target; leaked credentials, flags and
    box paths are dropped (there is nothing to re-point them to). Returns the
    phases and the number of scrubbed literals. A no-op when nothing was injected.
    """
    if not hosts and not secrets:
        return phases, 0
    host_only = re.sub(r"^https?://", "", target or "", flags=re.I).split("/", 1)[0]
    leaks = 0
    for ph in phases:
        for step in ph.get("steps") or []:
            if step.get("from_writeup"):
                continue  # the user's own writeup for THIS box — not model output
            for field in _PROSE_FIELDS:
                val = step.get(field)
                if not val:
                    continue
                cleaned, n = _scrub_text(val, hosts, secrets, host_only)
                if n:
                    leaks += n
                    if cleaned:
                        step[field] = cleaned
                    else:
                        step.pop(field, None)
            if not step.get("ai_suggested"):
                continue  # grounded commands are the KB's, never the model's
            kept: list[dict[str, Any]] = []
            for cmd in step.get("commands") or []:
                cleaned, n = _scrub_text(cmd.get("cmd") or "", hosts, secrets, host_only)
                leaks += n
                if cleaned:
                    kept.append({**cmd, "cmd": cleaned})
            step["commands"] = kept
    return phases, leaks


def provenance(sources: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Compact, user-facing record of what Channel 2 fed the planner."""
    return [
        {"kind": s["kind"], "id": s["id"], "title": s["title"], "chars": s["chars"]}
        for s in sources
    ]
