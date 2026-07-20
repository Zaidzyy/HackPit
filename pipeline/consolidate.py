"""Consolidating enrichment: fold an external source into the KB WITHOUT
creating duplicate techniques.

This is the reusable consolidation engine used for every enrichment batch.
Where the plain ingesters (`ingest.py`, `ingest_notes.py`) each own a `source`
block and rewrite it wholesale, this module instead MATCHES every candidate
against the entries already in the KB and either:

  * MERGES it into the existing entry (best-content-wins, structural — no
    per-entry LLM): the existing entry stays canonical (its id/title/source/
    tier are preserved so links never break), the new source is recorded in
    ``meta.also_covered_in``, and the candidate's distinct payloads are folded
    in as clearly-LABELLED variant steps + an appended, marked body section.
  * or CREATES a NEW entry (source-tagged, reference tier) when nothing in the
    KB confidently covers that technique.

Matching is deliberately CONSERVATIVE (spec: "merge only on confident match,
else create new"): a candidate merges only when BOTH
  (a) its canonical vulnerability/technique class — resolved through a curated
      alias map via contiguous token-subsequence matching, so ``nosql
      injection`` never collapses into ``sql injection`` — equals an existing
      entry's class, AND
  (b) the semantic cosine (local nomic-embed-text document vectors) to that
      entry clears ``SEM_FLOOR``.
The alias map is the authority; the embedding is a high-confidence sanity gate.

A batch is a `SourceSpec` = (name, label, tier, category, path, discover()).
`discover()` returns fully-parsed candidate Entries — which is also where a
source folds its own same-technique splits together (e.g. OSCP's
``kerberoasting-from-linux`` + ``-from-windows`` become ONE candidate with
labelled Linux/Windows variants, so they can't spawn two duplicate entries).

Re-runs are IDEMPOTENT: prior contributions from a source (new entries, and the
marked body block / labelled steps / added refs on merged entries) are reverted
first, so running twice yields the same KB.

Nothing raw or proprietary is written to the repo: outputs live under ``/data``
(gitignored) and source files are read from an EXTERNAL path, never copied.
Adaptation, not copy — payloads are capped into key structured blocks.

Usage:
    uv run python consolidate.py --source patt          # PayloadsAllTheThings
    uv run python consolidate.py --source oscp          # oscp-cpts-notes
    uv run python consolidate.py --source oscp --dry-run
    uv run python embed.py                               # re-embed (incremental)
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import subprocess
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import embed  # composite_doc, embed_document, load_index, OllamaUnavailable
from schema import SCHEMA_VERSION, Code, Entry, Step, emit_json_schema

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = REPO_ROOT / "data" / "kb"

# Human-readable source labels for the "also covered in" line / merge report.
SOURCE_LABELS = {
    "peh-notes": "your notes",
    "some-hacking-resources": "some hacking resources",
    "payloadsallthethings": "PayloadsAllTheThings",
    "oscp-cpts-notes": "oscp-cpts-notes",
    "htb-academy": "HTB Academy",
    "madstuff": "x3m1Sec's notes",  # José Miguel Romero, x3m1sec.gitbook.io (used with permission)
    "htb-my-resources": "your notes (htb my resources)",
    "claude-red": "claude-red skills",
    "hacktricks": "HackTricks",
    "claude-bug-bounty": "claude-bug-bounty",
    "galaxy-checklist": "Galaxy Bug Bounty Checklist",
    "htb-cheatsheets": "HTB Academy cheat sheet",
    "shodan-dorks": "shodan-dorks",
}

# Zaid's OWN notes — the trusted tier-1 sources. When one of these is the
# INCOMING side of a merge, its content is the trusted/primary variant and the
# entry is marked "from your notes" (its tested commands are preferred).
# NOTE: madstuff is x3m1Sec's public notes, NOT Zaid's own — it is a tier-3
# reference source and is deliberately NOT listed here.
PERSONAL_SOURCES = {"peh-notes", "htb-my-resources"}

# --------------------------------------------------------------------------- #
# matching knobs
# --------------------------------------------------------------------------- #
# Cosine is a SANITY gate, not the authority — the curated alias-key equality
# is. Thin single-lab candidates (e.g. a one-payload bugforge writeup) embed
# sparsely and score only ~0.64 against a rich existing entry of the SAME class;
# the floor sits at 0.60 so those true matches still consolidate rather than
# duplicating the technique. The specific token-subsequence keys make a
# coincidental key collision at this range effectively impossible.
SEM_FLOOR = 0.60
# A merge target must be a SUBSTANTIAL entry, not a one-line checklist/pointer
# stub: folding a full technique into a stub would bury it under a misleading
# title. If a candidate's only same-class match is a stub, it becomes a new
# entry instead (the stub keeps its recon-reminder role — not a duplicate).
MIN_TARGET_LEN = 300

# Curated canonical technique classes. Each key lists alias token-sequences; a
# title matches the key when one alias appears as a CONTIGUOUS run of its tokens
# (so "nosql injection" != "sql injection"). Both candidate titles and existing
# KB titles/tags resolve through this same map, which is how an abbreviation
# ("xss resource") and its full name ("Cross Site Scripting") land on one key.
# Extend this map as later batches introduce new overlaps.
CANON: dict[str, list[list[str]]] = {
    # --- web / appsec (batch 1: PayloadsAllTheThings) ---
    "sql-injection": [["sql", "injection"]],
    "command-injection": [["command", "injection"], ["os", "command", "injection"]],
    "xss": [["xss"], ["cross", "site", "scripting"]],
    "csrf": [["csrf"], ["cross", "site", "request", "forgery"]],
    "file-inclusion": [
        ["file", "inclusion"], ["lfi"], ["rfi"],
        ["local", "file", "inclusion"], ["remote", "file", "inclusion"],
    ],
    "file-upload": [
        ["file", "upload"], ["insecure", "file", "upload"],
        ["upload", "insecure", "files"], ["unrestricted", "file", "upload"],
    ],
    "xxe": [["xxe"], ["xml", "external", "entity"], ["xml", "injection"]],
    # web classes that gained their first KB home as batch-1 reference entries,
    # so batch-2 lab writeups consolidate into them instead of duplicating.
    "idor": [["idor"], ["insecure", "direct", "object", "reference"],
             ["insecure", "direct", "object", "references"]],
    "ssrf": [["ssrf"], ["server", "side", "request", "forgery"]],
    "mass-assignment": [["mass", "assignment"]],
    "race-condition": [["race", "condition"], ["race", "conditions"]],
    "jwt": [["jwt"], ["json", "web", "token"]],
    # web classes first homed as batch-6 reference entries (claude-red skills),
    # also the overlap targets for the HackTricks fold (batch 7).
    "ssti": [["ssti"], ["server", "side", "template", "injection"],
             ["template", "injection"]],
    "open-redirect": [["open", "redirect"], ["open", "redirects"]],
    "request-smuggling": [["request", "smuggling"],
                          ["http", "request", "smuggling"], ["desync"]],
    "deserialization": [["deserialization"], ["deserialisation"],
                        ["insecure", "deserialization"]],
    "graphql": [["graphql"]],
    "waf-bypass": [["waf", "bypass"], ["waf", "bypasses"]],
    "business-logic": [["business", "logic"]],
    "parameter-pollution": [["parameter", "pollution"], ["hpp"]],
    "oauth": [["oauth"], ["oauth2"]],
    "clickjacking": [["clickjacking"]],
    "cors": [["cors"], ["cross", "origin", "resource", "sharing"]],
    "osint": [["osint"], ["open", "source", "intelligence"]],
    # --- active directory / OSCP (batch 2: oscp-cpts-notes) ---
    "kerberoasting": [["kerberoasting"]],
    "asrep-roasting": [["asreproasting"], ["asrep", "roasting"], ["as", "rep", "roasting"]],
    "password-spraying": [["password", "spraying"], ["password", "spray"]],
    "credentialed-enumeration": [["credentialed", "enumeration"]],
    "dcsync": [["dcsync"]],
    "pass-the-hash": [["pass", "the", "hash"], ["pth"]],
    "pass-the-ticket": [["pass", "the", "ticket"], ["ptt"]],
}

# --------------------------------------------------------------------------- #
# adaptation caps — extract key payloads, never dump huge verbatim lists
# --------------------------------------------------------------------------- #
MAX_CODE_CHARS = 500        # per copyable block
MAX_SECTIONS = 14           # technique subheadings walked per document
MAX_CODE_PER_SECTION = 3    # key payload blocks kept per subheading
MAX_STEPS_NEW = 14          # steps on a brand-new entry
MAX_STEPS_MERGE = 8         # source steps folded into an existing entry
MAX_ADAPTED_BODY = 3000     # adapted body / appended-section length

_TOKEN_RE = re.compile(r"[a-z0-9]+")
_SKIP_HEADINGS = {"summary", "table of contents", "toc", "tools", "labs", "lab",
                  "references", "reference", "some popular tools"}


# --------------------------------------------------------------------------- #
# canonical-key resolution (source-agnostic)
# --------------------------------------------------------------------------- #
def _tokens(text: str) -> list[str]:
    return _TOKEN_RE.findall((text or "").lower())


def _is_subseq(alias: list[str], toks: list[str]) -> bool:
    """True if `alias` appears as a CONTIGUOUS run inside `toks`."""
    n = len(alias)
    return any(toks[i:i + n] == alias for i in range(len(toks) - n + 1))


def canonical_keys(text: str) -> set[str]:
    """All curated technique keys a piece of text (a title) resolves to."""
    toks = _tokens(text)
    return {k for k, aliases in CANON.items()
            if any(_is_subseq(a, toks) for a in aliases)}


def entry_keys(e: dict) -> set[str]:
    """Canonical classes an existing KB entry belongs to (title + tags + id)."""
    hay = " ".join([e.get("title", ""), " ".join(e.get("tags", []) or []),
                    e.get("id", "")])
    return canonical_keys(hay)


def slugify(text: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return re.sub(r"-{2,}", "-", s)


def _dedup(seq) -> list[str]:
    out, seen = [], set()
    for x in seq:
        x = str(x).strip()
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out


def content_len(e: dict) -> int:
    """Rough 'completeness' measure: body + all step text/code."""
    n = len(e.get("body_md", "") or "")
    for s in e.get("steps", []) or []:
        n += len(s.get("text", "") or "")
        for c in s.get("code", []) or []:
            n += len(c.get("cmd", "") or "")
    return n


def _norm_code(cmd: str) -> str:
    return re.sub(r"\s+", " ", (cmd or "").strip()).lower()


# --------------------------------------------------------------------------- #
# shared markdown helpers
# --------------------------------------------------------------------------- #
_IMG_RE = re.compile(r"!\[[^\]]*\]\([^)]+\)")
_LINK_RE = re.compile(r"\[([^\]]+)\]\((https?://[^)]+)\)")
_BARE_URL_RE = re.compile(r"(?<!\()(https?://[^\s)\]]+)")
_FIGURE_RE = re.compile(r"<figure[\s\S]*?</figure>", re.IGNORECASE)
_HTMLTAG_RE = re.compile(r"</?(?:figure|figcaption|img|mark|details|summary)\b[^>]*>",
                         re.IGNORECASE)
_HINT_RE = re.compile(r"\{%[^%]*%\}")
# mdBook directives HackTricks uses instead of GitBook hints, e.g.
# `{{#include ../banners/hacktricks-training.md}}` / `{{#ref …}}` — noise.
_MDBOOK_RE = re.compile(r"\{\{#[^}]*\}\}")

ACRONYMS = {
    "sql": "SQL", "sqli": "SQLi", "idor": "IDOR", "ssrf": "SSRF", "xxe": "XXE",
    "lfi": "LFI", "rfi": "RFI", "jwt": "JWT", "xss": "XSS", "csrf": "CSRF",
    "rce": "RCE", "api": "API", "graphql": "GraphQL", "ad": "AD", "smb": "SMB",
    "ntlm": "NTLM", "spn": "SPN", "suid": "SUID", "nfs": "NFS", "dns": "DNS",
    "rdp": "RDP", "ld": "LD", "os": "OS", "crlf": "CRLF", "iis": "IIS",
    "dos": "DoS", "2fa": "2FA", "cors": "CORS", "ssti": "SSTI", "ssrf": "SSRF",
    "waf": "WAF", "oauth": "OAuth", "hpp": "HPP", "iot": "IoT", "ble": "BLE",
}


def humanize(slug: str) -> str:
    words = re.split(r"[-_ ]+", slug)
    return " ".join(ACRONYMS.get(w.lower(), w.capitalize()) for w in words if w)


def _adapted_body(title: str, summary: str, steps: list[Step]) -> str:
    """Compact, restructured digest (capped) — never the verbatim source."""
    parts = [f"# {title}", ""]
    if summary:
        parts += [f"> {summary}", ""]
    parts.append("## Key payloads & methodology")
    for s in steps:
        parts.append(f"\n### {s.text}" if s.text else "")
        for c in s.code:
            parts.append(f"```{c.lang}\n{c.cmd}\n```")
    body = "\n".join(parts).strip()
    return body[:MAX_ADAPTED_BODY]


# =========================================================================== #
#  SOURCE 1 — PayloadsAllTheThings (template README per technique folder)
# =========================================================================== #
def _clean_summary(text: str) -> str:
    """A PATT `>` blockquote is `desc - [ref](url)`; keep the prose."""
    s = re.sub(r"\s*[-–—]\s*\[.*$", "", text)
    s = _LINK_RE.sub(r"\1", s)
    s = _IMG_RE.sub("", s)
    return " ".join(s.split())[:300].rstrip()


def _walk_sections(lines: list[str]) -> list[dict]:
    """Split a markdown body into sections keyed by heading, each carrying its
    raw non-heading lines, prose-only lines, and fenced code blocks."""
    sections: list[dict] = []
    cur = {"heading": "", "level": 1, "raw": [], "prose": [], "code": []}
    in_fence = False
    lang = ""
    buf: list[str] = []
    for line in lines:
        st = line.strip()
        if in_fence:
            if st.startswith("```"):
                code = "\n".join(buf).strip()
                if code:
                    cur["code"].append((lang or "text", code))
                in_fence = False
                buf = []
            else:
                buf.append(line)
            continue
        if st.startswith("```"):
            in_fence, lang, buf = True, st[3:].strip(), []
            continue
        hm = re.match(r"^(#{1,6})\s+(.*)$", line)
        if hm:
            sections.append(cur)
            cur = {"heading": hm.group(2).strip(), "level": len(hm.group(1)),
                   "raw": [], "prose": [], "code": []}
            continue
        if st:
            cur["raw"].append(st)
            if not st.startswith(("*", "-", "|", ">")):
                cur["prose"].append(st)
    sections.append(cur)
    return sections


def _parse_tools(lines: list[str]) -> tuple[list[str], list[str]]:
    names, urls = [], []
    for line in lines:
        st = line.strip()
        if not st.startswith(("*", "-")):
            continue
        m = _LINK_RE.search(st)
        if m:
            names.append(m.group(1).split("/")[-1].strip())
            urls.append(m.group(2))
        else:
            txt = st.lstrip("*- ").split(" - ")[0].strip()
            if txt:
                names.append(txt)
    return _dedup(names)[:12], _dedup(urls)


def _section_urls(lines: list[str]) -> list[str]:
    urls: list[str] = []
    for line in lines:
        urls += [u for _, u in _LINK_RE.findall(line)]
        urls += _BARE_URL_RE.findall(line)
    return [u.rstrip(".,);") for u in urls]


def parse_patt(path: Path, root: Path) -> Entry:
    """Adapt one PayloadsAllTheThings technique README into a canonical Entry."""
    rel = path.relative_to(root).as_posix()
    folder = Path(rel).parts[0]
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()

    title = folder
    for line in lines:
        if line.startswith("# "):
            title = line[2:].strip()
            break

    summary = ""
    for line in lines:
        if line.strip().startswith(">"):
            summary = _clean_summary(line.strip().lstrip(">").strip())
            break

    sections = _walk_sections(lines)
    tool_names: list[str] = []
    refs: list[str] = []
    method: list[dict] = []
    for sec in sections:
        h = sec["heading"].strip()
        low = h.lower()
        if not summary and not method and sec["prose"] and sec["level"] <= 1:
            summary = " ".join(sec["prose"])[:300].rstrip()
        if low == "tools":
            names, urls = _parse_tools(sec["raw"])
            tool_names += names
            refs += urls
            continue
        if low in ("labs", "lab", "references", "reference"):
            refs += _section_urls(sec["raw"])
            continue
        if low in _SKIP_HEADINGS or not h:
            continue
        if sec["code"] or sec["prose"]:
            method.append(sec)

    steps: list[Step] = []
    for sec in method[:MAX_SECTIONS]:
        prose = " ".join(sec["prose"]).strip()
        text = f"{sec['heading']} — {prose}"[:600] if prose else sec["heading"]
        code = [Code(lang=(lg or "text"), cmd=cd[:MAX_CODE_CHARS])
                for lg, cd in sec["code"][:MAX_CODE_PER_SECTION]]
        if code or prose:
            steps.append(Step(n=len(steps) + 1, text=text.strip(), code=code))
        if len(steps) >= MAX_STEPS_NEW:
            break

    keys = sorted(canonical_keys(title))
    return Entry(
        id="patt-" + slugify(folder), title=title, category="web",
        source="payloadsallthethings", tier=3,
        tags=_dedup(["web"] + keys + [slugify(title)]),
        tools=_dedup(tool_names), summary=summary or title, steps=steps,
        body_md=_adapted_body(title, summary, steps), references=_dedup(refs),
        meta={"src_file": rel, "kind": "reference",
              "source_label": SOURCE_LABELS["payloadsallthethings"],
              "canonical_keys": keys, "also_covered_in": ["payloadsallthethings"]},
        schema_version=SCHEMA_VERSION,
    )


def discover_patt(root: Path, failures: list | None = None,
                  flagged: list | None = None) -> list[Entry]:
    out: list[Entry] = []
    for p in sorted(root.rglob("README.md")):
        rel = p.relative_to(root)
        if len(rel.parts) != 2 or rel.parts[0].startswith("_template"):
            continue
        out.append(parse_patt(p, root))
    return out


# =========================================================================== #
#  SOURCE 2 — oscp-cpts-notes (GitBook: per-technique md, OS/lab splits)
# =========================================================================== #
OSCP_CATEGORY = {
    "active-directory-attacks": "active-directory",
    "linux-privilege-escalation": "privesc",
    "windows-privilege-escalation": "privesc",
    "pivoting-and-tunneling": "pivoting",
    "web-app": "web",
    "beyond-oscp-cpts": "post-exploitation",
}
BUGFORGE_TITLES = {
    "sql-injection-sqli": "SQL Injection",
    "idor-insecure-direct-object-reference": "Insecure Direct Object References",
    "ssrf-server-side-request-forgery": "Server-Side Request Forgery",
    "local-file-inclusion-lfi": "Local File Inclusion",
    "jwt-none-algorithm-attack": "JWT None Algorithm Attack",
    "broken-access-control": "Broken Access Control",
    "business-logic-flaw": "Business Logic Flaw",
    "graphql-idor": "GraphQL IDOR",
    "mass-assignment": "Mass Assignment",
    "race-condition": "Race Condition",
    "xxe": "XXE",
}
_OS_SUFFIX_RE = re.compile(r"[-_ ]from[-_ ](linux|windows)$|[-_](linux|windows)$", re.I)
# a shell prompt to strip from an inline command bullet
_PROMPT_RE = re.compile(r"^\s*(?:PS\s+[^>]*>|[^\s$#>]+@[^\s$#>]+[^$#>]*[$#>#])\s*")
_INLINE_CMD_RE = re.compile(r"^\s*[*\-]\s+`([^`]+)`")


def _strip_gitbook(text: str) -> tuple[str, int]:
    """Remove GitBook figure/hint/html noise; return (clean_text, n_images)."""
    n_images = len(_FIGURE_RE.findall(text)) + len(_IMG_RE.findall(text))
    text = _FIGURE_RE.sub("", text)
    text = _HINT_RE.sub("", text)
    text = _MDBOOK_RE.sub("", text)
    text = _HTMLTAG_RE.sub("", text)
    return text, n_images


def _oscp_group(path: Path, root: Path) -> tuple[str, str, str | None]:
    """Return (group_key, group_title, variant_label) for one GitBook file.

    Same-technique files fold into one group: OS splits (…-from-linux /
    …-from-windows) group by base technique; per-lab bugforge writeups group by
    their vuln-class folder. Everything else is its own singleton group.
    """
    rel = path.relative_to(root)
    parts = rel.parts
    stem = path.stem

    if "bugforge" in parts:
        i = parts.index("bugforge")
        vuln = parts[i + 1] if i + 1 < len(parts) - 1 else parts[-2]
        title = BUGFORGE_TITLES.get(vuln, humanize(vuln))
        return f"bugforge/{vuln}", title, humanize(stem)

    m = _OS_SUFFIX_RE.search(stem)
    if m:
        base = _OS_SUFFIX_RE.sub("", stem)
        os_name = (m.group(1) or m.group(2)).capitalize()
        parent = "/".join(parts[:-1])
        return f"{parent}/{base}", humanize(base), os_name

    return rel.as_posix(), "", None  # singleton (title from the file heading)


_GIT_ROOT_CACHE: dict[str, Path | None] = {}


def _git_root(path: Path) -> Path | None:
    """Nearest ancestor containing a .git (memoised per directory)."""
    d = path.parent
    key = str(d)
    if key in _GIT_ROOT_CACHE:
        return _GIT_ROOT_CACHE[key]
    root = None
    for anc in [d, *d.parents]:
        if (anc / ".git").exists():
            root = anc
            break
    _GIT_ROOT_CACHE[key] = root
    return root


def _git_recover(path: Path) -> str | None:
    """Recover a file's committed content when its on-disk copy is a dehydrated
    OneDrive placeholder (present in `git ls-files`, empty/unreadable on disk).
    Returns None if the file isn't git-tracked or git isn't available."""
    repo = _git_root(path)
    if repo is None:
        return None
    try:
        rel = path.relative_to(repo).as_posix()
    except ValueError:
        return None
    try:
        out = subprocess.run(["git", "-C", str(repo), "show", f"HEAD:{rel}"],
                             capture_output=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0 or not out.stdout:
        return None
    return out.stdout.decode("utf-8", "replace")


def _safe_read(path: Path) -> str | None:
    """Read text, tolerating the odd unreadable Windows/OneDrive placeholder
    (OSError 22) — a bad file is skipped, never aborts the run. When the on-disk
    copy is missing/unreadable or dehydrated to whitespace, fall back to the
    file's git-committed content (these sources are all git repos)."""
    disk: str | None
    try:
        disk = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        try:
            disk = path.read_bytes().decode("utf-8", "replace")
        except OSError:
            disk = None
    if disk is not None and disk.strip():
        return disk
    return _git_recover(path) or disk


def _all_md(root: Path, name: str = "*.md") -> list[Path]:
    """Every markdown file under `root`: the UNION of the on-disk tree (rglob)
    and the git index (`git ls-files`). OneDrive can dehydrate a file so far it
    vanishes from directory listings — rglob then can't see it, but it's still
    in git, and _safe_read git-recovers its content. Non-git sources fall back
    to rglob alone."""
    found: dict[str, Path] = {}
    for p in root.rglob(name):
        found[p.as_posix().lower()] = p
    repo = None
    for anc in [root, *root.parents]:
        if (anc / ".git").exists():
            repo = anc
            break
    if repo is not None:
        try:
            out = subprocess.run(["git", "-C", str(repo), "ls-files", "*.md"],
                                 capture_output=True, timeout=30)
            if out.returncode == 0:
                import fnmatch
                for line in out.stdout.decode("utf-8", "replace").splitlines():
                    rel = line.strip()
                    if not rel or not fnmatch.fnmatch(Path(rel).name, name):
                        continue
                    fp = repo / rel
                    try:
                        fp.relative_to(root)
                    except ValueError:
                        continue  # tracked file outside this source subtree
                    found.setdefault(fp.as_posix().lower(), fp)
        except (OSError, subprocess.SubprocessError):
            pass
    return sorted(found.values(), key=lambda p: p.as_posix())


def _parse_oscp_file(path: Path, root: Path) -> dict | None:
    """Parse one GitBook technique/lab file into structured parts (None if the
    file cannot be read)."""
    text = _safe_read(path)
    if text is None:
        return None
    raw, n_images = _strip_gitbook(text)
    lines = raw.splitlines()

    title = ""
    for line in lines:
        if line.startswith("# "):
            title = line[2:].strip()
            break

    summary = ""
    for para in raw.split("\n\n"):
        p = " ".join(para.split())
        if p and not p.startswith(("#", ">", "```", "|", "*", "-", "!")):
            summary = p[:300].rstrip()
            break

    sections = _walk_sections(lines)
    steps: list[Step] = []
    for sec in sections:
        if sec["heading"].strip().lower() in _SKIP_HEADINGS:
            continue
        # copyable code: fenced blocks + inline-backtick command bullets
        blocks: list[Code] = []
        for lg, cd in sec["code"]:
            blocks.append(Code(lang=(lg or "text"), cmd=cd[:MAX_CODE_CHARS]))
        for ln in sec["raw"]:
            m = _INLINE_CMD_RE.match(ln)
            if m:
                cmd = _PROMPT_RE.sub("", m.group(1).strip())
                if cmd:
                    blocks.append(Code(lang="bash", cmd=cmd[:MAX_CODE_CHARS]))
        blocks = blocks[:MAX_CODE_PER_SECTION]
        prose = " ".join(sec["prose"]).strip()
        text = f"{sec['heading']} — {prose}"[:600] if prose else sec["heading"]
        if blocks or (sec["heading"] and prose):
            steps.append(Step(n=len(steps) + 1, text=text.strip(), code=blocks))

    refs = _dedup(_section_urls(lines))
    tools = _oscp_tools(raw)
    return {"title": title or humanize(path.stem), "summary": summary,
            "steps": steps, "refs": refs, "tools": tools, "n_images": n_images}


_OSCP_TOOLS = {
    "impacket", "getuserspns", "secretsdump", "crackmapexec", "netexec", "kerbrute",
    "hashcat", "john", "rubeus", "mimikatz", "bloodhound", "sharphound", "powerview",
    "evil-winrm", "responder", "ligolo", "chisel", "sshuttle", "proxychains",
    "ldapsearch", "smbclient", "smbmap", "enum4linux", "rpcclient", "nmap", "ffuf",
    "sqlmap", "wpscan", "gobuster", "feroxbuster", "linpeas", "winpeas", "pspy",
}


def _oscp_tools(text: str) -> list[str]:
    low = text.lower()
    return sorted({t for t in _OSCP_TOOLS
                   if re.search(rf"(?<![a-z0-9]){re.escape(t)}(?![a-z0-9])", low)})[:12]


def _oscp_candidate(group_key: str, members: list[tuple[Path, str, str | None]],
                    root: Path, failures: list | None = None) -> Entry | None:
    """Consolidate one group's files into a single candidate Entry, labelling
    each member (OS name / lab name) as a variant so no group ever spawns two
    duplicate entries. Returns None if no member could be read."""
    parsed = []
    for p, title, variant in members:
        pf = _parse_oscp_file(p, root)
        if pf is None:
            if failures is not None:
                failures.append(p.relative_to(root).as_posix())
            continue
        parsed.append((pf, title, variant))
    if not parsed:
        return None
    # primary = the fullest member (its title/summary lead the entry)
    parsed.sort(key=lambda t: content_len({"body_md": "", "steps":
                [s.model_dump() for s in t[0]["steps"]]}), reverse=True)
    primary, grp_title, _ = parsed[0]
    rel0 = members[0][0].relative_to(root).as_posix()
    top = rel0.split("/", 1)[0]
    category = OSCP_CATEGORY.get(top, "misc")
    title = grp_title or primary["title"]

    steps: list[Step] = []
    variants: list[str] = []
    refs: list[str] = []
    tools: list[str] = []
    for parts, _t, variant in parsed:
        if variant:
            variants.append(variant)
        for s in parts["steps"]:
            label = f"{variant} — {s.text}" if variant else s.text
            steps.append(Step(n=len(steps) + 1, text=label[:600], code=s.code))
            if len(steps) >= MAX_STEPS_NEW:
                break
        refs += parts["refs"]
        tools += parts["tools"]
        if len(steps) >= MAX_STEPS_NEW:
            break

    summary = primary["summary"] or title
    keys = sorted(canonical_keys(title))
    meta = {"src_file": rel0, "kind": "reference",
            "source_label": SOURCE_LABELS["oscp-cpts-notes"],
            "canonical_keys": keys, "also_covered_in": ["oscp-cpts-notes"]}
    if variants:
        meta["variants"] = _dedup(variants)
    return Entry(
        id="oscp-" + slugify(title), title=title, category=category,
        source="oscp-cpts-notes", tier=3,
        tags=_dedup([category] + keys + [slugify(title)]),
        tools=_dedup(tools), summary=summary, steps=steps,
        body_md=_adapted_body(title, summary, steps), references=_dedup(refs),
        meta=meta, schema_version=SCHEMA_VERSION,
    )


def discover_oscp(root: Path, failures: list | None = None,
                  flagged: list | None = None) -> list[Entry]:
    """Group the GitBook files (skipping index/nav READMEs + SUMMARY) and emit
    one consolidated candidate per technique group."""
    groups: dict[str, list[tuple[Path, str, str | None]]] = defaultdict(list)
    order: list[str] = []
    for p in sorted(root.rglob("*.md")):
        if p.name.lower() in ("readme.md", "summary.md"):
            continue  # GitBook dir index / nav — not a technique page
        gk, title, variant = _oscp_group(p, root)
        if gk not in groups:
            order.append(gk)
        groups[gk].append((p, title, variant))
    cands = [_oscp_candidate(gk, groups[gk], root, failures) for gk in order]
    return [c for c in cands if c is not None]


# =========================================================================== #
#  SOURCE 3 — HTB Academy (proprietary module notes: adapt-only, HARD cap)
# =========================================================================== #
# HTB Academy is PAID curriculum. We synthesise a minimal adapted digest and
# cap hard — never store large verbatim proprietary text (and never commit it;
# the KB lives under gitignored /data).
HTB_MAX_STEPS = 6
HTB_MAX_CODE_PER_SECTION = 2
HTB_MAX_CODE_CHARS = 300
HTB_MAX_PROSE = 140
HTB_MAX_BODY = 1200


def _section_code(sec: dict, max_blocks: int, code_cap: int) -> list[Code]:
    """Fenced blocks + inline-backtick command bullets from one section."""
    blocks: list[Code] = []
    for lg, cd in sec["code"]:
        blocks.append(Code(lang=(lg or "text"), cmd=cd[:code_cap]))
    for ln in sec["raw"]:
        m = _INLINE_CMD_RE.match(ln)
        if m:
            cmd = _PROMPT_RE.sub("", m.group(1).strip())
            if cmd:
                blocks.append(Code(lang="bash", cmd=cmd[:code_cap]))
    return blocks[:max_blocks]


def _htb_body(title: str, summary: str, steps: list[Step]) -> str:
    """A hard-capped SYNTHESISED digest (headings + capped code, prose dropped)
    — deliberately not the source's verbatim prose."""
    parts = [f"# {title}"]
    if summary:
        parts.append(f"> {summary}")
    parts.append("\n## Key techniques (adapted digest)")
    for s in steps:
        head = s.text.split(" — ", 1)[0]
        parts.append(f"\n### {head}")
        for c in s.code:
            parts.append(f"```{c.lang}\n{c.cmd}\n```")
    return "\n".join(parts).strip()[:HTB_MAX_BODY]


def parse_htb(path: Path, root: Path) -> Entry | None:
    """Adapt one HTB Academy module README into a canonical Entry (None if the
    file is unreadable or empty). Hard-capped, synthesised — not a raw dump."""
    text = _safe_read(path)
    if text is None or not text.strip():
        return None
    text, _n = _strip_gitbook(text)
    lines = text.splitlines()
    folder = path.relative_to(root).parts[0]
    title = humanize(folder.replace("&", " and "))

    first_heading = ""
    for line in lines:
        if line.startswith("#"):
            first_heading = line.lstrip("#").strip()
            break

    summary = ""
    for para in text.split("\n\n"):
        p = " ".join(para.split())
        if p and not p.startswith(("#", ">", "```", "|", "*", "-", "!")):
            summary = p[:200].rstrip()
            break

    steps: list[Step] = []
    for sec in _walk_sections(lines):
        if not sec["heading"] or sec["heading"].lower() in _SKIP_HEADINGS:
            continue
        code = _section_code(sec, HTB_MAX_CODE_PER_SECTION, HTB_MAX_CODE_CHARS)
        prose = " ".join(sec["prose"]).strip()[:HTB_MAX_PROSE]
        text_i = f"{sec['heading']} — {prose}" if prose else sec["heading"]
        if code or sec["heading"]:
            steps.append(Step(n=len(steps) + 1, text=text_i.strip()[:400], code=code))
        if len(steps) >= HTB_MAX_STEPS:
            break

    # keys from folder title + the module's opening topic (its primary subject),
    # so e.g. "Server-Side Attacks" + "Identifying SSRF" resolves to ssrf.
    keys = sorted(canonical_keys(f"{title} {first_heading}"))
    return Entry(
        id="htb-" + slugify(folder), title=title, category="web",
        source="htb-academy", tier=3,
        tags=_dedup(["reference"] + keys + [slugify(title)]),
        tools=_oscp_tools(text), summary=summary or title, steps=steps,
        body_md=_htb_body(title, summary, steps),
        references=_dedup(_section_urls(lines)),
        meta={"src_file": path.relative_to(root).parts[0], "kind": "reference",
              "source_label": SOURCE_LABELS["htb-academy"],
              "canonical_keys": keys, "also_covered_in": ["htb-academy"]},
        schema_version=SCHEMA_VERSION,
    )


def discover_htb(root: Path, failures: list | None = None,
                 flagged: list | None = None) -> list[Entry]:
    """One candidate per HTB module README; skip empty/unreadable (recorded)."""
    out: list[Entry] = []
    for p in sorted(root.rglob("README.md")):
        e = parse_htb(p, root)
        if e is None:
            if failures is not None:
                failures.append(p.relative_to(root).as_posix())
            continue
        out.append(e)
    return out


# =========================================================================== #
#  SOURCE 4 — madstuff (x3m1Sec's public Obsidian/GitBook notes; tier 3 ref)
# =========================================================================== #
# x3m1Sec = José Miguel Romero (x3m1sec.gitbook.io), used with permission — a
# REFERENCE source, not Zaid's own notes (so tier 3, no "from your notes" mark).
# Every note ships as a PAIR: `<name>.md` (rendered, no title) and
# `<name>-md.md` (raw source, has the `# title`, ~2.6x fuller, backslash-escaped
# markdown). We dedupe each pair to the titled `-md.md` and unescape it.
_MD_UNESCAPE_RE = re.compile(r"\\([\\`*_{}\[\]()#+.!|>~=-])")
_WIKILINK_RE = re.compile(r"\[\[([^\]|]+)(?:\|([^\]]+))?\]\]")
_MAD_BOILER_RE = re.compile(
    r"^\s*>?\s*For the complete documentation index.*$", re.MULTILINE)
_MAD_SELFHOST = "x3m1sec.gitbook.io"


def _mad_category(base: str) -> str:
    low = base.lower()
    if "active-directory" in low or "kerberos" in low or "/ad-" in low:
        return "active-directory"
    if low.startswith("ctfs/") or "/ctfs/" in low:
        return "ctf"
    if "privilege-escalation" in low or "privesc" in low:
        return "privesc"
    if "pivot" in low or "tunnel" in low:
        return "pivoting"
    if "web" in low:
        return "web"
    if "cheat" in low or low.startswith("resources/"):
        return "reference"
    return "reference"


def parse_madstuff(path: Path, notes_root: Path, base: str) -> Entry | None:
    """Adapt one madstuff note (the chosen member of a pair) into an Entry."""
    text = _safe_read(path)
    if text is None:
        return None
    text = _MD_UNESCAPE_RE.sub(r"\1", text)
    text = _WIKILINK_RE.sub(lambda m: m.group(2) or m.group(1), text)
    text = _MAD_BOILER_RE.sub("", text)
    text, _n = _strip_gitbook(text)
    if not text.strip():
        return None
    lines = text.splitlines()

    stem = Path(base).name
    title = humanize(stem)
    for line in lines:
        if line.startswith("# "):
            title = line[2:].strip()
            break

    summary = ""
    for para in text.split("\n\n"):
        p = " ".join(para.split())
        if p and not p.startswith(("#", ">", "```", "|", "*", "-", "!")):
            summary = p[:300].rstrip()
            break

    steps: list[Step] = []
    for sec in _walk_sections(lines):
        if not sec["heading"] or sec["heading"].lower() in _SKIP_HEADINGS:
            continue
        code = _section_code(sec, MAX_CODE_PER_SECTION, MAX_CODE_CHARS)
        prose = " ".join(sec["prose"]).strip()
        text_i = f"{sec['heading']} — {prose}"[:600] if prose else sec["heading"]
        if code or prose:
            steps.append(Step(n=len(steps) + 1, text=text_i.strip(), code=code))
        if len(steps) >= MAX_STEPS_NEW:
            break

    # external refs only — drop the author's own gitbook self-index links
    refs = [u for u in _dedup(_section_urls(lines)) if _MAD_SELFHOST not in u]
    keys = sorted(canonical_keys(title))
    category = _mad_category(base)
    n_code = sum(len(s.code) for s in steps)
    entry = Entry(
        id="mad-" + slugify(base), title=title, category=category,
        source="madstuff", tier=3,  # x3m1Sec's public notes — reference tier
        tags=_dedup([category] + keys + [slugify(title)]),
        tools=_oscp_tools(text), summary=summary or title, steps=steps,
        body_md=_adapted_body(title, summary, steps), references=refs,
        meta={"src_file": "notes/" + base + ".md", "canonical_keys": keys,
              "source_label": SOURCE_LABELS["madstuff"],
              "also_covered_in": ["madstuff"]},
        schema_version=SCHEMA_VERSION,
    )
    # low-value flag (still ingested — Zaid's rule: never silently drop)
    if n_code == 0 and (len(refs) >= 3 or len(text.strip()) < 250):
        entry.meta["flag_reason"] = "prose/link-only, no commands — low technique value"
    return entry


def _group_madstuff_by_class(cands: list[Entry]) -> list[Entry]:
    """Fold madstuff notes that resolve to the SAME canonical class into one
    candidate (fullest primary + the rest as labelled variants), so a whole
    course module — e.g. the file-inclusion notes — consolidates into ONE merge
    instead of spawning many duplicate-class entries. Notes with no class are
    left as individual candidates."""
    keyed: dict[tuple, list[Entry]] = defaultdict(list)
    singles: list[Entry] = []
    for c in cands:
        ck = entry_keys(c.model_dump())
        if ck:
            keyed[tuple(sorted(ck))].append(c)
        else:
            singles.append(c)
    out: list[Entry] = list(singles)
    for keys, members in keyed.items():
        if len(members) == 1:
            out.append(members[0])
            continue
        members.sort(key=lambda c: content_len(c.model_dump()), reverse=True)
        primary = members[0]
        steps = list(primary.steps)
        variants, refs, tools = [], list(primary.references), list(primary.tools)
        for m in members[1:]:
            variants.append(m.title)
            for s in m.steps:
                if len(steps) >= MAX_STEPS_NEW:
                    break
                steps.append(Step(n=len(steps) + 1,
                                  text=f"{m.title} — {s.text}"[:600], code=s.code))
            refs += m.references
            tools += m.tools
        primary.steps = steps[:MAX_STEPS_NEW]
        primary.references = _dedup(refs)
        primary.tools = _dedup(tools)
        primary.meta["variants"] = _dedup(variants)
        primary.meta["canonical_keys"] = list(keys)
        primary.body_md = _adapted_body(primary.title, primary.summary, primary.steps)
        out.append(primary)
    return out


def discover_madstuff(root: Path, failures: list | None = None,
                      flagged: list | None = None) -> list[Entry]:
    """Dedupe each note pair (prefer the titled `-md.md`), skip+flag index/nav/
    folder-review pages, emit one tier-1 candidate per note, then consolidate
    same-class notes. Nothing is silently dropped: skipped pages and low-value
    notes are recorded in `flagged`."""
    notes = root / "notes" if (root / "notes").is_dir() else root
    groups: dict[str, dict] = {}
    for p in sorted(notes.rglob("*.md")):
        rel = p.relative_to(notes).as_posix()
        base = rel[:-6] if rel.endswith("-md.md") else rel[:-3]
        g = groups.setdefault(base, {})
        g["md" if rel.endswith("-md.md") else "plain"] = p

    parsed: list[Entry] = []
    for base, g in sorted(groups.items()):
        chosen = g.get("md") or g.get("plain")
        parts = Path(base).parts
        is_root_index = len(parts) == 1
        is_folder_index = len(parts) > 1 and slugify(parts[-1]) == slugify(parts[-2])
        if is_root_index or is_folder_index:
            if flagged is not None:
                flagged.append({"file": "notes/" + base + ".md",
                                "reason": "index / nav / folder-review page (not ingested)"})
            continue
        e = parse_madstuff(chosen, notes, base)
        if e is None:
            if failures is not None:
                failures.append("notes/" + base + ".md")
            continue
        if flagged is not None and e.meta.get("flag_reason"):
            flagged.append({"file": e.meta["src_file"], "reason": e.meta["flag_reason"],
                            "ingested": True, "id": e.id})
        parsed.append(e)
    return _group_madstuff_by_class(parsed)


# =========================================================================== #
#  SOURCE 5 — htb my resources (Zaid's own Notion export; tier 1)
# =========================================================================== #
# 5 monolithic Notion pages (50-400 KB, hundreds of `#` headings — real topics
# mixed with command-comment "headings"). The format does NOT split cleanly into
# per-technique entries without producing junk, and hard caps would DROP most of
# Zaid's content. Compromise: one entry per page with the FULL cleaned body
# preserved (lexically searchable — nothing dropped) + capped key-command steps,
# and EVERY page flagged for morning refinement (split into per-technique
# entries). Coarse but honest; never forces bad structure, never drops his notes.
_NOTION_HASH_RE = re.compile(r"\s+[0-9a-f]{32}$")
_NBSP_RE = re.compile(r"[\xa0​]")


def _clean_notion(text: str) -> str:
    text = _NBSP_RE.sub(" ", text)
    text, _n = _strip_gitbook(text)  # drops ![]() images + html tags
    text = _MD_UNESCAPE_RE.sub(r"\1", text)
    return text


def parse_htb_my_resources(path: Path, root: Path) -> Entry | None:
    text = _safe_read(path)
    if text is None or not text.strip():
        return None
    text = _clean_notion(text)
    lines = text.splitlines()
    stem = _NOTION_HASH_RE.sub("", path.stem).strip()

    # page title = the page (file) name; only for a bare "Untitled" page do we
    # fall back to its first meaningful H1.
    title = humanize(stem)
    if stem.lower() == "untitled":
        for line in lines:
            m = re.match(r"^#\s+(.*)$", line)
            if m:
                h = m.group(1).strip().strip("*").strip()
                if h and h.lower() != "untitled":
                    title = h
                    break

    summary = ""
    for para in text.split("\n\n"):
        p = " ".join(para.split())
        if p and not p.startswith(("#", ">", "```", "|", "*", "-", "!")):
            summary = p[:300].rstrip()
            break

    steps: list[Step] = []
    for sec in _walk_sections(lines):
        code = _section_code(sec, MAX_CODE_PER_SECTION, MAX_CODE_CHARS)
        if not code:
            continue
        head = sec["heading"] or "commands"
        steps.append(Step(n=len(steps) + 1, text=head[:300], code=code))
        if len(steps) >= MAX_STEPS_NEW:
            break

    refs = [u for u in _dedup(_section_urls(lines)) if _MAD_SELFHOST not in u]
    low = (title + " " + stem).lower()
    category = "web" if any(w in low for w in ("wordpress", "word press", "web")) else "reference"
    keys = sorted(canonical_keys(title))
    # full cleaned body preserved (searchable) — strip only the leading title echo
    body = re.sub(r"^#\s+.*?\n", "", text, count=1).strip()
    return Entry(
        id="htbmine-" + slugify(stem), title=title, category=category,
        source="htb-my-resources", tier=1,
        tags=_dedup([category] + keys + [slugify(title)]),
        tools=_oscp_tools(text), summary=summary or title, steps=steps,
        body_md=body, references=refs,
        meta={"src_file": path.name, "canonical_keys": keys,
              "source_label": SOURCE_LABELS["htb-my-resources"],
              "also_covered_in": ["htb-my-resources"],
              "flag_reason": "large multi-topic Notion page — coarse one-per-page "
                             "ingestion (full body preserved); review for splitting "
                             "into per-technique entries"},
        schema_version=SCHEMA_VERSION,
    )


def discover_htb_my_resources(root: Path, failures: list | None = None,
                              flagged: list | None = None) -> list[Entry]:
    out: list[Entry] = []
    for p in sorted(root.rglob("*.md")):
        e = parse_htb_my_resources(p, root)
        if e is None:
            if failures is not None:
                failures.append(p.name)
            continue
        if flagged is not None:
            flagged.append({"file": e.meta["src_file"], "reason": e.meta["flag_reason"],
                            "ingested": True, "id": e.id})
        out.append(e)
    return out


# =========================================================================== #
#  SOURCE 6 — claude-red (offensive skill packs; two markdown layouts, tier 3)
# =========================================================================== #
# Each skill is Skills/<category>/<folder>/SKILL.md in ONE of two layouts:
#   A) templated: "# SKILL: <title>" + ## Metadata/Description/Trigger Phrases/
#      Instructions + "---" + "## Full Methodology" (the real content).
#   B) frontmatter: a YAML "---\nname:…\ndescription:…\n---" header then a
#      "# <title>" and the content directly (no Full-Methodology wrapper).
# The parser normalises both to (title, summary, methodology-body) and adapts.
# Category comes from the top folder; canonical class from the folder+title, so
# offensive-idor/ssti/ssrf/… fold into their existing KB homes while AD / cloud
# / wireless / exploit-dev / etc. become new tier-3 entries.
CLAUDERED_CATEGORY = {
    "web": "web", "auth": "web", "active-directory": "active-directory",
    "cloud": "cloud", "recon": "recon", "exploit-dev": "exploit-dev",
    "fuzzing": "fuzzing", "infrastructure": "post-exploitation", "iot": "iot",
    "mobile": "mobile", "wireless": "wireless", "ai": "ai", "utility": "reference",
}
_FM_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.S)
_MERMAID_HEADS = ("flowchart", "graph ", "graph\n", "graph t", "graph l",
                  "sequencediagram", "statediagram", "classdiagram", "erdiagram",
                  "gantt", "pie ", "mindmap", "journey", "gitgraph", "%%{")


def _frontmatter(text: str) -> tuple[dict, str]:
    """Split a leading YAML `--- … ---` block into (fields, remaining-body)."""
    m = _FM_RE.match(text)
    if not m:
        return {}, text
    fields: dict = {}
    for line in m.group(1).splitlines():
        mm = re.match(r"^(\w[\w-]*):\s*(.*)$", line)
        if mm:
            fields[mm.group(1)] = mm.group(2).strip().strip('"').strip("'").strip()
    return fields, text[m.end():]


def _is_mermaid(lang: str, code: str) -> bool:
    if (lang or "").lower() == "mermaid":
        return True
    head = code.strip().lower()[:24]
    return any(head.startswith(h) for h in _MERMAID_HEADS)


def _cred_code(sec: dict) -> list[Code]:
    """Section code = fenced blocks (mermaid diagrams dropped) + inline command
    bullets, capped like every other reference source."""
    blocks: list[Code] = []
    for lg, cd in sec["code"]:
        if _is_mermaid(lg, cd):
            continue
        blocks.append(Code(lang=(lg or "text"), cmd=cd[:MAX_CODE_CHARS]))
    for ln in sec["raw"]:
        m = _INLINE_CMD_RE.match(ln)
        if m:
            cmd = _PROMPT_RE.sub("", m.group(1).strip())
            if cmd:
                blocks.append(Code(lang="bash", cmd=cmd[:MAX_CODE_CHARS]))
    return blocks[:MAX_CODE_PER_SECTION]


_CRED_SKIP = _SKIP_HEADINGS | {"metadata", "trigger phrases",
                               "instructions for claude", "overview", "shortcut",
                               "mechanisms"}


def parse_claudered(path: Path, root: Path) -> Entry | None:
    """Adapt one claude-red SKILL.md (either layout) into a canonical Entry."""
    raw_text = _safe_read(path)
    if raw_text is None or not raw_text.strip():
        return None
    fm, after_fm = _frontmatter(raw_text)

    # source URL + templated title come from the metadata block (layout A)
    src_url = None
    ms = re.search(r"\*\*Source\*\*:\s*(\S+)", raw_text)
    if ms:
        src_url = ms.group(1).strip()
    skill_title = None
    mt = re.search(r"^#\s*SKILL:\s*(.+)$", raw_text, re.M)
    if mt:
        skill_title = mt.group(1).strip()

    # methodology body: after "## Full Methodology" (A) else the post-frontmatter
    # text (B); strip GitBook/html noise either way
    if "## Full Methodology" in raw_text:
        body_src = raw_text.split("## Full Methodology", 1)[1]
    else:
        body_src = after_fm
    body_src, _n = _strip_gitbook(body_src)
    lines = body_src.splitlines()
    sections = _walk_sections(lines)  # fence-aware: headings only, not code comments

    folder = path.relative_to(root).parts[-2]
    category_folder = path.relative_to(root).parts[0]
    first_h1 = ""
    for sec in sections:
        h = sec["heading"].strip()
        if sec["level"] == 1 and h and not h.upper().startswith("SKILL"):
            first_h1 = h
            break
    title = skill_title or first_h1 or humanize(fm.get("name") or folder)
    title = re.sub(r"^Week\s+\d+:\s*", "", title).strip() or humanize(folder)

    summary = ""
    md = re.search(r"^##\s*Description\s*\n+(.+)$", raw_text, re.M)
    if md:
        summary = " ".join(md.group(1).split())[:300].rstrip()
    elif fm.get("description"):
        summary = " ".join(fm["description"].split())[:300].rstrip()
    else:
        for para in body_src.split("\n\n"):
            p = " ".join(para.split())
            if p and not p.startswith(("#", ">", "```", "|", "*", "-", "!", "_")):
                summary = p[:300].rstrip()
                break

    steps: list[Step] = []
    for sec in sections:
        h = sec["heading"].strip()
        if not h or h.lower() in _CRED_SKIP:
            continue
        code = _cred_code(sec)
        prose = " ".join(sec["prose"]).strip()
        text_i = f"{h} — {prose}"[:600] if prose else h
        if code or prose:
            steps.append(Step(n=len(steps) + 1, text=text_i.strip(), code=code))
        if len(steps) >= MAX_STEPS_NEW:
            break

    category = CLAUDERED_CATEGORY.get(category_folder, "reference")
    keys = sorted(canonical_keys(f"{title} {folder}"))
    refs = _dedup(([src_url] if src_url else []) + _section_urls(lines))
    return Entry(
        id="cred-" + slugify(folder.replace("offensive-", "") or folder),
        title=title, category=category, source="claude-red", tier=3,
        tags=_dedup([category] + keys + [slugify(title)]),
        tools=_oscp_tools(body_src), summary=summary or title, steps=steps,
        body_md=_adapted_body(title, summary, steps), references=refs,
        meta={"src_file": path.relative_to(root).as_posix(), "kind": "reference",
              "source_label": SOURCE_LABELS["claude-red"], "canonical_keys": keys,
              "also_covered_in": ["claude-red"], "skill_folder": folder},
        schema_version=SCHEMA_VERSION,
    )


def discover_claudered(root: Path, failures: list | None = None,
                       flagged: list | None = None) -> list[Entry]:
    """One candidate per SKILL.md (skip empty/unreadable — recorded), then fold
    same-class skills (e.g. the two OSINT skills) into one candidate."""
    out: list[Entry] = []
    for p in _all_md(root, "SKILL.md"):
        e = parse_claudered(p, root)
        if e is None:
            if failures is not None:
                failures.append(p.relative_to(root).as_posix())
            continue
        out.append(e)
    return _group_madstuff_by_class(out)


# =========================================================================== #
#  SOURCE 7 — HackTricks (811-page GitBook; non-commercial → adapt/cap, tier 3)
# =========================================================================== #
# Same GitBook markdown as oscp-cpts-notes, so _parse_oscp_file does the heavy
# lifting. The directory tree IS the SUMMARY.md taxonomy — the top folder gives
# the category. UNLIKE oscp, a `<topic>/README.md` here is the topic's MAIN
# content page (sql-injection/README.md = the SQLi page), so READMEs are KEPT;
# only SUMMARY.md and content-free nav stubs are skipped (and recorded). Same-
# class sub-pages (mysql-/mssql-/postgresql-injection …) fold into ONE candidate
# so a whole class consolidates once instead of piling onto its target. Non-
# commercial licensed: adapted/capped digests only, never raw (data/ gitignored).
HACKTRICKS_CATEGORY = {
    "pentesting-web": "web",
    "network-services-pentesting": "network-services",
    "windows-hardening": "windows",
    "linux-hardening": "linux",
    "binary-exploitation": "pwn",
    "generic-methodologies-and-resources": "methodology",
    "generic-hacking": "reference",
    "reversing": "reversing",
    "stego": "stego",
    "AI": "ai",
    "todo": "reference",
}


def parse_hacktricks(path: Path, root: Path) -> Entry | None:
    """Adapt one HackTricks page into a canonical Entry. Returns None for an
    unreadable file or a content-free nav stub (skipped, recorded upstream)."""
    pf = _parse_oscp_file(path, root)  # generic GitBook -> structured parts
    if pf is None:
        return None
    steps = pf["steps"][:MAX_STEPS_NEW]
    summary = pf["summary"]
    # a page with no copyable steps and only a stub summary is a nav/index page
    if not steps and len(summary) < 40:
        return None

    rel = path.relative_to(root)
    top = rel.parts[0]
    category = HACKTRICKS_CATEGORY.get(top, "reference")
    stem = path.stem
    base = path.parent.name if stem.lower() == "readme" else stem
    title = (pf["title"] or "").lstrip("#").strip() or humanize(base)
    keys = sorted(canonical_keys(f"{title} {base}"))
    return Entry(
        id="ht-" + slugify(base), title=title, category=category,
        source="hacktricks", tier=3,
        tags=_dedup([category] + keys + [slugify(title)]),
        tools=pf["tools"], summary=summary or title, steps=steps,
        body_md=_adapted_body(title, summary, steps),
        references=_dedup(pf["refs"]),
        meta={"src_file": rel.as_posix(), "kind": "reference",
              "source_label": SOURCE_LABELS["hacktricks"], "canonical_keys": keys,
              "also_covered_in": ["hacktricks"]},
        schema_version=SCHEMA_VERSION,
    )


def discover_hacktricks(root: Path, failures: list | None = None,
                        flagged: list | None = None) -> list[Entry]:
    """Parse every page (skip SUMMARY.md + unreadable + nav stubs, all recorded),
    then fold same-class sub-pages into one candidate each."""
    out: list[Entry] = []
    for p in sorted(root.rglob("*.md")):
        if p.name.lower() == "summary.md":
            continue
        text = _safe_read(p)
        if text is None:
            if failures is not None:
                failures.append(p.relative_to(root).as_posix())
            continue
        e = parse_hacktricks(p, root)
        if e is None:
            if flagged is not None:
                flagged.append({"file": p.relative_to(root).as_posix(),
                                "reason": "nav/index stub or empty — skipped"})
            continue
        out.append(e)
    return _group_madstuff_by_class(out)


# =========================================================================== #
#  SOURCE 8 — claude-bug-bounty (methodology docs only; skip scaffolding)
# =========================================================================== #
# A bug-bounty plugin repo. Only the technique/methodology docs are ingested —
# skills/ (YAML-frontmatter SKILL.md packs), web3/ (smart-contract KB), and the
# technique command docs under commands/. Agent/tooling scaffolding (agents/,
# hooks/, mcp/, rules/, docs/, tools/, root meta) and pure session-utility
# commands are skipped (recorded). Same YAML-frontmatter layout as claude-red's
# format B, so the same helpers apply.
_BB_DIRS = ("skills", "web3", "commands")
# commands that are session/tooling utilities, not security technique
_BB_SKIP_CMD = {"readme", "memory-gc", "pickup", "remember", "intel",
                "scope", "scope-aggregate", "arsenal"}
_BB_NAV = {"00-start-here", "readme", "summary", "index"}


def parse_bugbounty(path: Path, root: Path) -> Entry | None:
    raw_text = _safe_read(path)
    if raw_text is None or not raw_text.strip():
        return None
    fm, body_src = _frontmatter(raw_text)
    body_src, _n = _strip_gitbook(body_src)
    lines = body_src.splitlines()
    sections = _walk_sections(lines)

    parts = path.relative_to(root).parts
    top = parts[0]
    # skill packs live one folder deep (skills/<name>/SKILL.md); everything else
    # is named by its own stem
    if top == "skills" and len(parts) > 2:
        base = parts[1] if path.name == "SKILL.md" else f"{parts[1]}-{path.stem}"
    else:
        base = path.stem

    first_h1 = ""
    for sec in sections:
        h = sec["heading"].strip()
        if sec["level"] == 1 and h:
            first_h1 = h
            break
    # command pages title as "# /hunt" — normalise to the technique name
    title = (first_h1 or humanize(fm.get("name") or base)).lstrip("/#").strip()
    title = title or humanize(base)

    summary = ""
    if fm.get("description"):
        summary = " ".join(fm["description"].split())[:300].rstrip()
    else:
        for para in body_src.split("\n\n"):
            p = " ".join(para.split())
            if p and not p.startswith(("#", ">", "```", "|", "*", "-", "!", "_")):
                summary = p[:300].rstrip()
                break

    steps: list[Step] = []
    for sec in sections:
        h = sec["heading"].strip()
        if not h or h.lower() in _CRED_SKIP:
            continue
        code = _cred_code(sec)
        prose = " ".join(sec["prose"]).strip()
        text_i = f"{h} — {prose}"[:600] if prose else h
        if code or prose:
            steps.append(Step(n=len(steps) + 1, text=text_i.strip(), code=code))
        if len(steps) >= MAX_STEPS_NEW:
            break
    if not steps and len(summary) < 40:
        return None  # nav/index stub

    keys = sorted(canonical_keys(f"{title} {base}"))
    low = (base + " " + "/".join(parts)).lower()
    category = "web3" if ("web3" in low or "token" in low or "smart-contract" in low
                          or top == "web3") else ("web" if keys else "reference")
    refs = _dedup(_section_urls(lines))
    return Entry(
        id="cbb-" + slugify(base), title=title, category=category,
        source="claude-bug-bounty", tier=3,
        tags=_dedup([category] + keys + [slugify(title)]),
        tools=_oscp_tools(body_src), summary=summary or title, steps=steps,
        body_md=_adapted_body(title, summary, steps), references=refs,
        meta={"src_file": path.relative_to(root).as_posix(), "kind": "reference",
              "source_label": SOURCE_LABELS["claude-bug-bounty"],
              "canonical_keys": keys, "also_covered_in": ["claude-bug-bounty"]},
        schema_version=SCHEMA_VERSION,
    )


def discover_bugbounty(root: Path, failures: list | None = None,
                       flagged: list | None = None) -> list[Entry]:
    """Ingest skills/ + web3/ + technique command docs; skip scaffolding dirs and
    pure-utility commands (recorded), then fold same-class docs."""
    out: list[Entry] = []
    for p in _all_md(root):
        parts = p.relative_to(root).parts
        if parts[0] not in _BB_DIRS:
            continue  # scaffolding dir or root meta file — not methodology
        stem = p.stem.lower()
        if stem in _BB_NAV or (parts[0] == "commands" and stem in _BB_SKIP_CMD):
            if flagged is not None:
                flagged.append({"file": p.relative_to(root).as_posix(),
                                "reason": "index/nav or session-utility doc — skipped"})
            continue
        e = parse_bugbounty(p, root)
        if e is None:
            if flagged is not None:
                flagged.append({"file": p.relative_to(root).as_posix(),
                                "reason": "empty/nav stub — skipped"})
            continue
        out.append(e)
    return _group_madstuff_by_class(out)


# =========================================================================== #
#  SOURCE 9 — Galaxy-Bugbounty-Checklist (per-class checklists, tier 3)
# =========================================================================== #
# 22 plain-markdown checklists, one per `<Topic>/README.md`. The FOLDER NAME is
# the technique (and the reliable canonical class), so titles/keys come from it,
# not from the sometimes-typo'd inner headings. Many are bare numbered lists
# with no code — so the full cleaned body is PRESERVED (searchable, nothing
# lost) plus payload blocks lifted into steps. Class checklists (SQLi/CSRF/SSRF/
# file-upload/oauth/xss/…) fold into their existing homes; the rest are new.
_GALAXY_CATEGORY = {"osint": "recon", "wordpress": "web",
                    "internet-information-services-iis": "web", "dos": "web"}
_GALAXY_BODY_CAP = 3500


def parse_galaxy(path: Path, root: Path) -> Entry | None:
    text = _safe_read(path)
    if text is None:
        return None
    text = _IMG_RE.sub("", text)
    text, _n = _strip_gitbook(text)
    text = text.strip()
    lines = text.splitlines()

    folder = path.relative_to(root).parts[0]
    title = humanize(folder)

    summary = ""
    for para in text.split("\n\n"):
        p = " ".join(para.split())
        if p and not p.startswith(("#", ">", "```", "|", "!")):
            summary = p[:300].rstrip()
            break

    steps: list[Step] = []
    for sec in _walk_sections(lines):
        code = _section_code(sec, MAX_CODE_PER_SECTION, MAX_CODE_CHARS)
        prose = " ".join(sec["prose"]).strip()
        head = sec["heading"].strip() or "checklist"
        text_i = f"{head} — {prose}"[:600] if prose else head
        if code or prose:
            steps.append(Step(n=len(steps) + 1, text=text_i.strip(), code=code))
        if len(steps) >= MAX_STEPS_NEW:
            break

    # a genuinely empty stub (e.g. an unfinished to-do page) — skip + record
    if not steps and len(text) < 80:
        return None

    keys = sorted(canonical_keys(f"{title} {folder}"))
    category = _GALAXY_CATEGORY.get(slugify(folder), "web")
    refs = _dedup(_section_urls(lines))
    return Entry(
        id="galaxy-" + slugify(folder), title=title, category=category,
        source="galaxy-checklist", tier=3,
        tags=_dedup([category, "checklist"] + keys + [slugify(title)]),
        tools=_oscp_tools(text), summary=summary or title, steps=steps,
        body_md=text[:_GALAXY_BODY_CAP],  # full checklist preserved (searchable)
        references=refs,
        meta={"src_file": path.relative_to(root).as_posix(), "kind": "checklist",
              "source_label": SOURCE_LABELS["galaxy-checklist"],
              "canonical_keys": keys, "also_covered_in": ["galaxy-checklist"]},
        schema_version=SCHEMA_VERSION,
    )


def discover_galaxy(root: Path, failures: list | None = None,
                    flagged: list | None = None) -> list[Entry]:
    """One candidate per topic checklist (skip the root index + empty stubs,
    recorded), then fold same-class checklists."""
    out: list[Entry] = []
    for p in _all_md(root):
        rel = p.relative_to(root)
        if len(rel.parts) == 1:  # root README = repo index/nav
            continue
        e = parse_galaxy(p, root)
        if e is None:
            if flagged is not None:
                flagged.append({"file": rel.as_posix(),
                                "reason": "empty/unfinished checklist stub — skipped"})
            continue
        out.append(e)
    return _group_madstuff_by_class(out)


# =========================================================================== #
#  SOURCE 10 — HTB Academy cheat-sheet PDFs (image-only; OCR, adapt, HARD cap)
# =========================================================================== #
# Two proprietary HTB cheat sheets, each an image-per-page PDF (no text layer).
# We OCR the page images, adapt the "label: payload" pairs into a hard-capped
# digest, and let them MERGE into the existing file-inclusion / sql-injection
# entries. PROPRIETARY: OCR'd, restructured, capped — never the raw PDF, never
# committed (data/ is gitignored). Deps (pypdf, pytesseract, tesseract on PATH)
# are imported lazily so the rest of the engine never needs them.
PDF_MAX_STEPS = 8
PDF_CODE_CAP = 400
PDF_BODY_CAP = 1600
_PDF_CODE_RE = re.compile(
    r"(SELECT|UNION|INSERT|UPDATE|ALTER|DROP|CREATE|SHOW\s|DESCRIBE|FROM\s|WHERE\s|"
    r"mysql|sqlmap|LOAD_FILE|OUTFILE|information_schema|GROUP_CONCAT|SLEEP\(|"
    r"php://|data://|file://|expect://|zip://|/etc/passwd|\.\./|base64|<\?php|"
    r"include\(|allow_url|LIMIT\s|ORDER\s+BY|--\s|@@version|xp_cmdshell)", re.I)
_PDF_BANNER_RE = re.compile(r"hack\s?the\s?box|cheat\s?sheet|htb\s?academy", re.I)


def _clean_ocr(text: str) -> list[str]:
    """Drop OCR garbage lines (mostly non-alphanumeric decoration) and the
    repeated HTB/CHEAT-SHEET banner; return the usable lines."""
    out: list[str] = []
    for ln in text.splitlines():
        s = " ".join(ln.split())
        if len(s) < 3 or _PDF_BANNER_RE.search(s):
            continue
        good = sum(c.isalnum() or c.isspace() or c in "_./:-()<>?=*,'\";" for c in s)
        if good / len(s) < 0.7:
            continue
        out.append(s)
    return out


def _ocr_image(im) -> str:
    """OCR a PIL image via tesseract. Uses a subprocess with a controlled temp
    dir (pytesseract's own temp handling intermittently hits OSError 22 when
    OneDrive/AV locks the temp file); retries a couple of times."""
    import tempfile
    for _ in range(3):
        try:
            with tempfile.TemporaryDirectory() as d:
                ip = Path(d) / "page.png"
                im.save(ip)
                out = subprocess.run(["tesseract", str(ip), "stdout"],
                                     capture_output=True, timeout=120)
                if out.returncode == 0:
                    return out.stdout.decode("utf-8", "replace")
        except (OSError, subprocess.SubprocessError):
            continue
    return ""


def parse_htb_pdf(path: Path, lang: str) -> Entry | None:
    try:
        import pypdf  # noqa: F401
    except ImportError:
        return None
    try:
        reader = pypdf.PdfReader(str(path))
        pages: list[str] = []
        for pg in reader.pages:
            for img in pg.images:
                pages.append(_ocr_image(img.image))
    except Exception:
        return None
    lines = _clean_ocr("\n".join(pages))
    if len(lines) < 5:
        return None

    # pair descriptive labels with the payload lines that follow
    steps: list[Step] = []
    label, buf = "", []

    def flush():
        if buf and len(steps) < PDF_MAX_STEPS:
            cmd = "\n".join(buf)[:PDF_CODE_CAP]
            steps.append(Step(n=len(steps) + 1, text=(label or "commands")[:200],
                              code=[Code(lang=lang, cmd=cmd)]))

    for ln in lines:
        if _PDF_CODE_RE.search(ln):
            buf.append(ln)
        else:
            flush()
            buf = []
            label = ln.rstrip(":")
        if len(steps) >= PDF_MAX_STEPS:
            break
    flush()

    stem = path.stem.replace("cheatsheet-", "")
    title = humanize(stem.replace("-fundamentals", ""))
    keys = sorted(canonical_keys(f"{title} {stem}"))
    summary = (f"HTB Academy {title} cheat sheet — key commands and payloads "
               f"(OCR-adapted digest of the proprietary PDF).")
    body = _htb_body(title, summary, steps)[:PDF_BODY_CAP]
    return Entry(
        id="htbcs-" + slugify(stem), title=f"{title} Cheat Sheet", category="web",
        source="htb-cheatsheets", tier=3,
        tags=_dedup(["web", "cheatsheet"] + keys + [slugify(title)]),
        tools=_oscp_tools(" ".join(lines)), summary=summary, steps=steps,
        body_md=body, references=[],
        meta={"src_file": path.name, "kind": "cheatsheet",
              "source_label": SOURCE_LABELS["htb-cheatsheets"],
              "canonical_keys": keys, "also_covered_in": ["htb-cheatsheets"]},
        schema_version=SCHEMA_VERSION,
    )


_HTB_PDF_LANG = {"cheatsheet-sql-injection-fundamentals": "sql",
                 "cheatsheet-file-inclusion": "bash"}


def discover_htb_pdf(root: Path, failures: list | None = None,
                     flagged: list | None = None) -> list[Entry]:
    """OCR each cheat-sheet PDF into one candidate (skip if OCR yields nothing —
    recorded). `root` is the folder holding the two PDFs."""
    out: list[Entry] = []
    for p in sorted(root.glob("cheatsheet-*.pdf")):
        lang = _HTB_PDF_LANG.get(p.stem, "text")
        e = parse_htb_pdf(p, lang)
        if e is None:
            if failures is not None:
                failures.append(p.name)
            continue
        out.append(e)
    return out


# =========================================================================== #
#  SOURCE 11 — shodan-dorks (a ~2000-line dork list -> ONE reference entry)
# =========================================================================== #
# A flat list of Shodan search queries. Per the "don't explode into hundreds of
# tiny entries" rule, this folds into a SINGLE reference entry: the dorks are
# bucketed by query type into a handful of capped, copyable blocks. Kept
# standalone (no canonical class) so it never merges into the OSINT entry.
_SHODAN_BUCKETS = [
    ("CPE / version dorks", re.compile(r"^'?\"?cpe:", re.I)),
    ("HTTP title dorks", re.compile(r"\b(http\.)?title:", re.I)),
    ("HTTP html/body dorks", re.compile(r"\bhttp\.(html|favicon|component)", re.I)),
    ("Product / app dorks", re.compile(r"\b(product:|app=|http\.component:)", re.I)),
    ("SSL / TLS certificate dorks", re.compile(r"\bssl", re.I)),
    ("Port / service dorks", re.compile(r"\b(port:|has_screenshot|net:|org:)", re.I)),
]
_SHODAN_NOISE_RE = re.compile(r"^[0-9a-f]{20,}$|^<|</|requested resource")
_SHODAN_PER_BLOCK = 40      # example dorks kept per bucket block
_SHODAN_BODY_CAP = 8000


def _shodan_bucket(dork: str) -> str:
    for name, rx in _SHODAN_BUCKETS:
        if rx.search(dork):
            return name
    return "Banner / keyword dorks"


def parse_shodan(txt_path: Path, readme: Path | None) -> Entry | None:
    text = _safe_read(txt_path)
    if text is None:
        return None
    dorks: list[str] = []
    seen: set[str] = set()
    for ln in text.splitlines():
        s = ln.strip()
        if len(s) < 2 or _SHODAN_NOISE_RE.search(s) or s in seen:
            continue
        seen.add(s)
        dorks.append(s)
    if len(dorks) < 10:
        return None

    buckets: dict[str, list[str]] = defaultdict(list)
    for d in dorks:
        buckets[_shodan_bucket(d)].append(d)

    summary = ("Curated Shodan search queries ('dorks') for discovering "
               "internet-exposed devices, services, and known-vulnerable "
               f"software versions — {len(dorks)} queries across "
               f"{len(buckets)} categories.")
    order = [n for n, _ in _SHODAN_BUCKETS] + ["Banner / keyword dorks"]
    steps: list[Step] = []
    body_parts = [f"# Shodan Dorks\n\n> {summary}\n"]
    for name in order:
        items = buckets.get(name)
        if not items:
            continue
        sample = items[:_SHODAN_PER_BLOCK]
        block = "\n".join(sample)
        steps.append(Step(n=len(steps) + 1,
                          text=f"{name} ({len(items)} queries)",
                          code=[Code(lang="text", cmd=block[:MAX_CODE_CHARS * 3])]))
        body_parts.append(f"\n## {name} ({len(items)})\n\n```\n{block}\n```")
    body = "\n".join(body_parts)[:_SHODAN_BODY_CAP]
    return Entry(
        id="shodan-dorks", title="Shodan Dorks", category="recon",
        source="shodan-dorks", tier=3,
        tags=_dedup(["recon", "shodan", "dorks", "attack-surface",
                     "asset-discovery", "reconnaissance"]),
        tools=["shodan"], summary=summary, steps=steps, body_md=body,
        references=["https://www.shodan.io/", "https://github.com/humblelad/Shodan-Dorks"],
        meta={"src_file": txt_path.name, "kind": "reference",
              "source_label": SOURCE_LABELS["shodan-dorks"], "canonical_keys": [],
              "also_covered_in": ["shodan-dorks"], "total_dorks": len(dorks)},
        schema_version=SCHEMA_VERSION,
    )


def discover_shodan(root: Path, failures: list | None = None,
                    flagged: list | None = None) -> list[Entry]:
    """Fold the whole dork list into ONE reference entry."""
    txt = root / "dorks.txt"
    if not txt.exists():
        cands = list(root.rglob("*.txt"))
        txt = cands[0] if cands else txt
    e = parse_shodan(txt, root / "README.md")
    if e is None:
        if failures is not None:
            failures.append(txt.name)
        return []
    return [e]


# --------------------------------------------------------------------------- #
# source registry
# --------------------------------------------------------------------------- #
@dataclass
class SourceSpec:
    name: str
    label: str
    default_path: str
    discover: Callable[..., list[Entry]]


SPECS: dict[str, SourceSpec] = {
    "patt": SourceSpec(
        "payloadsallthethings", SOURCE_LABELS["payloadsallthethings"],
        r"C:\Users\zaid_\Downloads\hacks\new resources\PayloadsAllTheThings",
        discover_patt),
    "oscp": SourceSpec(
        "oscp-cpts-notes", SOURCE_LABELS["oscp-cpts-notes"],
        r"C:\Users\zaid_\Downloads\hacks\new resources\oscp-cpts-notes",
        discover_oscp),
    "htb": SourceSpec(
        "htb-academy", SOURCE_LABELS["htb-academy"],
        r"C:\Users\zaid_\Downloads\hacks\new resources\HTB_academy",
        discover_htb),
    "madstuff": SourceSpec(
        "madstuff", SOURCE_LABELS["madstuff"],
        r"C:\Users\zaid_\Downloads\hacks\new resources\madstuff",
        discover_madstuff),
    "htbmine": SourceSpec(
        "htb-my-resources", SOURCE_LABELS["htb-my-resources"],
        r"C:\Users\zaid_\Downloads\hacks\new resources\htb my resources",
        discover_htb_my_resources),
    "claudered": SourceSpec(
        "claude-red", SOURCE_LABELS["claude-red"],
        r"C:\Users\zaid_\cyber\claude-red\Skills",
        discover_claudered),
    "hacktricks": SourceSpec(
        "hacktricks", SOURCE_LABELS["hacktricks"],
        r"C:\Users\zaid_\Downloads\hacks\hackdic",
        discover_hacktricks),
    "bugbounty": SourceSpec(
        "claude-bug-bounty", SOURCE_LABELS["claude-bug-bounty"],
        r"C:\Users\zaid_\cyber\claude-bug-bounty",
        discover_bugbounty),
    "galaxy": SourceSpec(
        "galaxy-checklist", SOURCE_LABELS["galaxy-checklist"],
        r"C:\Users\zaid_\cyber\Galaxy-Bugbounty-Checklist",
        discover_galaxy),
    "htbpdf": SourceSpec(
        "htb-cheatsheets", SOURCE_LABELS["htb-cheatsheets"],
        r"C:\Users\zaid_\Downloads\hacks\new resources",
        discover_htb_pdf),
    "shodan": SourceSpec(
        "shodan-dorks", SOURCE_LABELS["shodan-dorks"],
        r"C:\Users\zaid_\Downloads\hacks\new resources\shodan-dorks",
        discover_shodan),
}


# --------------------------------------------------------------------------- #
# matching (source-agnostic core)
# --------------------------------------------------------------------------- #
def match_candidate(cand: dict, cand_vec, existing: list[dict],
                    unit_vecs, id_order: list[str]):
    """Return (target_id, cosine, signals) or (None, best_cosine, signals).

    Confident match := shared canonical class AND cosine >= SEM_FLOOR. Among all
    existing entries sharing a class, the FULLEST is chosen as the merge target
    — so a technique lands in its richest home — with cosine as the tie-break.
    """
    import numpy as np

    # Key on the WHOLE candidate (title + tags + id/path), identical to how
    # entry_keys() classifies existing entries — so a note whose class shows in
    # its path but not its terse title (e.g. .../file-inclusion/php-filters.md)
    # still consolidates instead of duplicating the class.
    ck = entry_keys(cand) | set((cand.get("meta") or {}).get("canonical_keys", []))
    idx_by_id = {eid: i for i, eid in enumerate(id_order)}
    v = np.asarray(cand_vec, dtype=np.float32)
    v = v / max(float(np.linalg.norm(v)), 1e-9)

    best_any = (-1.0, None)
    keyed: list[tuple[int, float, str]] = []
    for e in existing:
        row = idx_by_id.get(e["id"])
        cos = float(unit_vecs[row] @ v) if row is not None else 0.0
        if cos > best_any[0]:
            best_any = (cos, e["id"])
        if (ck and (ck & entry_keys(e)) and cos >= SEM_FLOOR
                and content_len(e) >= MIN_TARGET_LEN):
            keyed.append((content_len(e), cos, e["id"]))

    signals = {"canonical_keys": sorted(ck), "best_cosine": round(best_any[0], 3),
               "best_id": best_any[1]}
    if not keyed:
        return None, best_any[0], signals
    keyed.sort(key=lambda t: (t[0], t[1]), reverse=True)  # fullest, then cosine
    _clen, cos, target_id = keyed[0]
    signals["shared_class"] = True
    return target_id, cos, signals


# --------------------------------------------------------------------------- #
# merge (structural, best-content-wins) + idempotent revert
# --------------------------------------------------------------------------- #
def _mark(name: str) -> str:
    return f"<!-- merged:{name} -->"


def _prefix(label: str) -> str:
    return f"[{label} · "


def revert_source(entry: dict, name: str, label: str) -> dict:
    """Remove any prior contribution from THIS source, so a re-run is clean."""
    ms = (entry.get("meta") or {}).get("merged_sources", {})
    rec = ms.get(name)
    if not rec:
        return entry
    mark, prefix = _mark(name), _prefix(label)
    body = entry.get("body_md", "") or ""
    sep = "\n\n---\n\n"
    start = body.find(sep + mark)
    if start != -1:
        # excise ONLY this source's section (from its `---`+mark up to the next
        # merged-source section or EOF). Splitting on the mark alone would drop
        # every later source's section too — a re-run of an early source must
        # not delete the body a later source contributed.
        nxt = body.find(sep + "<!-- merged:", start + len(sep + mark))
        if nxt == -1:
            entry["body_md"] = body[:start].rstrip()
        else:
            entry["body_md"] = (body[:start] + body[nxt:]).rstrip()
    kept = [s for s in entry.get("steps", [])
            if not (s.get("text", "") or "").startswith(prefix)]
    for i, s in enumerate(kept, 1):
        s["n"] = i
    entry["steps"] = kept
    added_refs = set(rec.get("added_refs", []))
    added_tools = set(rec.get("added_tools", []))
    entry["references"] = [r for r in entry.get("references", []) if r not in added_refs]
    entry["tools"] = [t for t in entry.get("tools", []) if t not in added_tools]
    meta = entry["meta"]
    if name in meta.get("also_covered_in", []):
        meta["also_covered_in"].remove(name)
    for log_key in ("merge_log",):
        meta[log_key] = [x for x in meta.get(log_key, []) if x.get("source") != name]
        if not meta[log_key]:
            meta.pop(log_key, None)
    ms.pop(name, None)
    if not ms:
        meta.pop("merged_sources", None)
    if not meta.get("also_covered_in"):
        meta.pop("also_covered_in", None)
    # author_notes is legitimate only on an entry whose SPINE is Zaid's own
    # notes. On any other spine it can only be a stale transient from an
    # incoming-personal merge, so clear it; on a personal spine, clear only once
    # no merges remain.
    if entry.get("source") in PERSONAL_SOURCES:
        if not meta.get("merged_sources"):
            meta.pop("author_notes", None)
    else:
        meta.pop("author_notes", None)
    return entry


def merge_into(target: dict, cand: dict, name: str, label: str) -> dict:
    """Fold `cand` into existing `target` in place (structural, best-content-
    wins). Target stays canonical; cand's distinct payloads become LABELLED
    variant steps, an attributed marked body section is appended, refs/tools are
    unioned, and provenance is recorded for a clean revert."""
    meta = target.setdefault("meta", {})
    pre_len = content_len(target)
    also = meta.setdefault("also_covered_in", [target.get("source")])
    if name not in also:
        also.append(name)

    prefix = _prefix(label)
    seen = {_norm_code(c.get("cmd", ""))
            for s in target.get("steps", []) for c in s.get("code", [])}
    existing_first: dict[str, str] = {}
    for s in target.get("steps", []):
        for c in s.get("code", []):
            head = _norm_code(c.get("cmd", "")).split(" ", 1)[0]
            if head:
                existing_first.setdefault(head, c.get("cmd", ""))

    added_steps = 0
    conflicts: list[dict] = []
    n = len(target.get("steps", []))
    for s in cand.get("steps", []):
        code = [c for c in s.get("code", []) if _norm_code(c["cmd"]) not in seen]
        if not code and not s.get("text"):
            continue
        for c in code:
            seen.add(_norm_code(c["cmd"]))
            head = _norm_code(c["cmd"]).split(" ", 1)[0]
            if head in existing_first and existing_first[head] != c["cmd"]:
                conflicts.append({"tool": head, "resolution": "kept both (labelled variant)"})
        n += 1
        head_label = f"{prefix}{s.get('text', '').split(' — ')[0][:60]}]"
        target.setdefault("steps", []).append({
            "n": n, "text": f"{head_label} {s.get('text', '')}".strip()[:600],
            "code": code, "images": [],
        })
        added_steps += 1
        if added_steps >= MAX_STEPS_MERGE:
            break

    before_refs = set(target.get("references", []))
    before_tools = set(target.get("tools", []))
    target["references"] = _dedup(list(target.get("references", [])) + cand.get("references", []))
    target["tools"] = _dedup(list(target.get("tools", [])) + cand.get("tools", []))
    added_refs = [r for r in target["references"] if r not in before_refs]
    added_tools = [t for t in target["tools"] if t not in before_tools]

    primary_target = pre_len >= content_len(cand)
    src_label = SOURCE_LABELS.get(target.get("source"), target.get("source"))
    personal = name in PERSONAL_SOURCES
    if personal:
        note = (f"_The following are YOUR OWN tested commands, folded in from "
                f"{label} — prefer these._")
    else:
        note = (f"_Primary content above is from {src_label}; the key payloads "
                f"below are adapted from {label}._")
    section = "\n\n---\n\n" + _mark(name) + "\n" + \
        f"## Also covered in — {label}\n\n{note}\n\n" + cand.get("body_md", "")
    target["body_md"] = target.get("body_md", "") + section

    # author_notes is tied to the entry's SPINE being Zaid's own notes — an
    # incoming personal source's trustedness is conveyed by the body note above,
    # not a top-level mark (which would be hard to revert cleanly).
    if target.get("source") in PERSONAL_SOURCES:
        meta["author_notes"] = "preserved — primary content is your own notes"

    # Accumulate — several candidates of one source can merge into the same
    # target in a single run (e.g. "IDOR" and "GraphQL IDOR"); revert must be
    # able to undo ALL of their contributions, not just the last.
    rec = meta.setdefault("merged_sources", {}).setdefault(
        name, {"added_steps": 0, "added_refs": [], "added_tools": [],
               "primary": "existing" if primary_target else name})
    rec["added_steps"] += added_steps
    rec["added_refs"] = _dedup(rec["added_refs"] + added_refs)
    rec["added_tools"] = _dedup(rec["added_tools"] + added_tools)
    meta.setdefault("merge_log", []).append({
        "source": name, "cand_id": cand.get("id"), "cand_title": cand.get("title"),
        "added_steps": added_steps, "added_refs": len(added_refs),
        "primary": "existing" if primary_target else name,
        "target_len": pre_len, "cand_len": content_len(cand),
        "variants": (cand.get("meta") or {}).get("variants", []),
        "conflicts": conflicts,
    })
    # deterministic order so a re-run (which reverts then re-appends this source's
    # rows) yields a byte-identical log regardless of source run order.
    meta["merge_log"].sort(key=lambda x: (x.get("source", ""), x.get("cand_id", "")))
    return target


# --------------------------------------------------------------------------- #
# orchestrator
# --------------------------------------------------------------------------- #
def load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as fh:
        return [json.loads(l) for l in fh if l.strip()]


def run(spec: SourceSpec, source_path: Path, out_dir: Path, host: str,
        model: str, dry_run: bool) -> dict:
    kb_path = out_dir / "entries.jsonl"
    entries = load_jsonl(kb_path)
    if not entries:
        raise SystemExit(f"KB not found / empty: {kb_path}. Run the ingesters first.")

    # start clean: revert any prior run of THIS source (idempotent)
    entries = [e for e in entries if e.get("source") != spec.name]
    for e in entries:
        revert_source(e, spec.name, spec.label)
    by_id = {e["id"]: e for e in entries}

    ids_order, vectors, _meta = embed.load_index()
    if ids_order is None:
        raise SystemExit("No embeddings. Build them first: uv run python embed.py")
    import numpy as np
    unit = vectors / np.clip(np.linalg.norm(vectors, axis=1, keepdims=True), 1e-9, None)

    failures: list[str] = []
    flagged: list[dict] = []
    candidates = spec.discover(source_path, failures, flagged)

    merged_rows: list[dict] = []
    created: list[dict] = []
    new_entries: list[dict] = []
    used_ids = set(by_id)

    for cand in candidates:
        cd = cand.model_dump()
        try:
            cvec = embed.embed_document(embed.composite_doc(cd), host, model)
        except embed.OllamaUnavailable as exc:
            raise SystemExit(f"ERROR embedding candidate '{cand.title}': {exc}")
        target_id, cos, signals = match_candidate(cd, cvec, entries, unit, ids_order)

        if target_id is not None:
            target = by_id[target_id]
            pre_len = content_len(target)
            merge_into(target, cd, spec.name, spec.label)
            merged_rows.append({
                "candidate": cand.title,
                "variants": (cand.meta or {}).get("variants", []),
                "into_id": target_id, "into_title": target["title"],
                "into_source": target["source"], "cosine": round(cos, 3),
                "canonical_keys": signals["canonical_keys"],
                "primary": "existing" if pre_len >= content_len(cd) else spec.name,
                "target_len": pre_len, "cand_len": content_len(cd),
            })
        else:
            eid = cand.id
            k = 2
            while eid in used_ids:
                eid = f"{cand.id}-{k}"
                k += 1
            cand.id = eid
            used_ids.add(eid)
            new_entries.append(cand.model_dump())
            created.append({
                "id": eid, "title": cand.title, "category": cand.category,
                "variants": (cand.meta or {}).get("variants", []),
                "n_steps": len(cand.steps), "best_cosine": signals["best_cosine"],
                "nearest": signals["best_id"],
            })

    merged_kb = entries + new_entries
    result = {
        "generated_at": _now(), "source": spec.name,
        "source_path": str(source_path), "dry_run": dry_run,
        "parsed": len(candidates), "merged_count": len(merged_rows),
        "created_count": len(created), "kb_before": len(entries),
        "kb_after": len(merged_kb),
        "kb_by_source": dict(Counter(e.get("source") for e in merged_kb)),
        "unreadable_files": failures,
        "flagged_for_review": flagged,
        "merged_into_existing": merged_rows, "created_new": created,
    }

    if not dry_run:
        with kb_path.open("w", encoding="utf-8") as fh:
            for e in merged_kb:
                fh.write(json.dumps(e, ensure_ascii=False) + "\n")
        (out_dir / f"merge_report.{spec.name}.json").write_text(
            json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        emit_json_schema(Path(__file__).with_name("entry.schema.json"))
    return result


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def main() -> None:
    ap = argparse.ArgumentParser(description="Consolidating enrichment into the KB.")
    ap.add_argument("--source", choices=sorted(SPECS), default="patt")
    ap.add_argument("--source-path", default=None)
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    ap.add_argument("--host", default=embed.OLLAMA_HOST)
    ap.add_argument("--model", default=embed.EMBED_MODEL)
    ap.add_argument("--dry-run", action="store_true", help="report only; don't write KB")
    args = ap.parse_args()

    spec = SPECS[args.source]
    source_path = Path(args.source_path or spec.default_path)
    if not source_path.is_dir():
        raise SystemExit(f"Source path not found: {source_path}")

    r = run(spec, source_path, Path(args.out), args.host, args.model, args.dry_run)
    tag = " (DRY RUN — KB not modified)" if args.dry_run else ""
    print(f"\nConsolidated {spec.name}{tag}")
    print(f"  parsed={r['parsed']}  merged={r['merged_count']}  new={r['created_count']}")
    print(f"  KB: {r['kb_before']} -> {r['kb_after']}  by_source={r['kb_by_source']}")
    print("\n  merged into existing:")
    for m in r["merged_into_existing"]:
        v = f" {m['variants']}" if m["variants"] else ""
        print(f"    - {m['candidate']}{v}  ->  {m['into_title']} [{m['into_id']}]"
              f"  (cos {m['cosine']}, primary={m['primary']})")
    print(f"\n  created new: {r['created_count']} entries")
    if r.get("unreadable_files"):
        print(f"  unreadable/skipped: {len(r['unreadable_files'])}")
    if r.get("flagged_for_review"):
        print(f"  flagged for review: {len(r['flagged_for_review'])}")
    if not args.dry_run:
        print("\n  Re-embed incrementally:  uv run python embed.py")


if __name__ == "__main__":
    main()
