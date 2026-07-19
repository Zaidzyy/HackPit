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
}

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
    "race-condition": [["race", "condition"]],
    "jwt": [["jwt"], ["json", "web", "token"]],
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

ACRONYMS = {
    "sql": "SQL", "sqli": "SQLi", "idor": "IDOR", "ssrf": "SSRF", "xxe": "XXE",
    "lfi": "LFI", "rfi": "RFI", "jwt": "JWT", "xss": "XSS", "csrf": "CSRF",
    "rce": "RCE", "api": "API", "graphql": "GraphQL", "ad": "AD", "smb": "SMB",
    "ntlm": "NTLM", "spn": "SPN", "suid": "SUID", "nfs": "NFS", "dns": "DNS",
    "rdp": "RDP", "ld": "LD", "os": "OS",
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


def discover_patt(root: Path, failures: list | None = None) -> list[Entry]:
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


def _safe_read(path: Path) -> str | None:
    """Read text, tolerating the odd unreadable Windows/OneDrive placeholder
    (OSError 22) — a bad file is skipped, never aborts the run."""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        try:
            return path.read_bytes().decode("utf-8", "replace")
        except OSError:
            return None


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


def discover_oscp(root: Path, failures: list | None = None) -> list[Entry]:
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

    ck = canonical_keys(cand.get("title", "")) | set(
        (cand.get("meta") or {}).get("canonical_keys", []))
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
    if mark in body:
        entry["body_md"] = body.split("\n\n---\n\n" + mark, 1)[0].rstrip()
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
    if not meta.get("merged_sources") and meta.get("author_notes"):
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
    note = (f"_Primary content above is from {src_label}; the key payloads "
            f"below are adapted from {label}._")
    section = "\n\n---\n\n" + _mark(name) + "\n" + \
        f"## Also covered in — {label}\n\n{note}\n\n" + cand.get("body_md", "")
    target["body_md"] = target.get("body_md", "") + section

    if target.get("source") == "peh-notes":
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
    candidates = spec.discover(source_path, failures)

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
    if not args.dry_run:
        print("\n  Re-embed incrementally:  uv run python embed.py")


if __name__ == "__main__":
    main()
