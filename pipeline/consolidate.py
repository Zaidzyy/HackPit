"""Consolidating enrichment: fold an external source into the KB WITHOUT
creating duplicate techniques.

This is the reusable consolidation engine used for every enrichment batch
(PayloadsAllTheThings is the first). Where the plain ingesters (`ingest.py`,
`ingest_notes.py`) each own a `source` block and rewrite it wholesale, this
module instead MATCHES every candidate against the entries already in the KB
and either:

  * MERGES it into the existing entry (best-content-wins, structural — no
    per-entry LLM): the existing entry stays canonical (its id/title/source/
    tier are preserved so links never break), the new source is recorded in
    ``meta.also_covered_in``, and the candidate's distinct payloads are folded
    in as clearly-LABELLED variant steps + an appended, marked body section.
  * or CREATES a NEW entry (source-tagged, reference tier) when nothing in the
    KB confidently covers that technique.

Matching is deliberately CONSERVATIVE (spec: "merge only on confident match,
else create new"): a candidate merges only when BOTH
  (a) its canonical vulnerability-class — resolved through a curated alias map
      via contiguous token-subsequence matching, so ``nosql injection`` never
      collapses into ``sql injection`` — equals an existing entry's class, AND
  (b) the semantic cosine (local nomic-embed-text document vectors) to that
      entry clears ``SEM_FLOOR``.
The alias map is the authority; the embedding is a high-confidence sanity gate.
This pair was calibrated on the real KB: it captures abbreviation matches that
raw token overlap misses (Cross Site Scripting -> "xss resource", cosine 0.78)
while rejecting near-neighbours that raw semantics would wrongly merge
(Server-Side Request Forgery -> "CSRF resource", cosine 0.80).

Re-runs are IDEMPOTENT: prior contributions from this source (new entries, and
the marked body block / labelled steps / added refs on merged entries) are
reverted first, so running twice yields the same KB.

Nothing raw or proprietary is ever written to the repo: outputs live under
``/data`` (gitignored). Source files are read from an EXTERNAL path and never
copied. Adaptation, not copy — payload lists are capped into key structured
blocks, never dumped verbatim.

Usage:
    uv run python consolidate.py                 # PayloadsAllTheThings
    uv run python consolidate.py --dry-run       # report only, don't write KB
    uv run python consolidate.py --source-path "C:\\path\\to\\PayloadsAllTheThings"
    # then re-embed incrementally:
    uv run python embed.py
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
from collections import Counter
from pathlib import Path

import embed  # composite_doc, embed_document, load_index, OllamaUnavailable
from schema import SCHEMA_VERSION, Code, Entry, Step, emit_json_schema

# --------------------------------------------------------------------------- #
# batch config (PayloadsAllTheThings — later batches swap these + the parser)
# --------------------------------------------------------------------------- #
SOURCE_NAME = "payloadsallthethings"
REF_TIER = 3  # reference tier: below tier-1 notes and tier-2 curated resources.
DEFAULT_CATEGORY = "web"  # PATT is entirely web/appsec technique material.
DEFAULT_SOURCE_PATH = r"C:\Users\zaid_\Downloads\hacks\new resources\PayloadsAllTheThings"

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = REPO_ROOT / "data" / "kb"

# Human-readable source labels for the "also covered in" line / merge report.
SOURCE_LABELS = {
    "peh-notes": "your notes",
    "some-hacking-resources": "some hacking resources",
    "payloadsallthethings": "PayloadsAllTheThings",
}

# --------------------------------------------------------------------------- #
# matching knobs
# --------------------------------------------------------------------------- #
SEM_FLOOR = 0.70  # cosine sanity gate; the alias-key equality is the authority.

# Curated canonical vulnerability classes. Each key lists alias token-sequences;
# a title matches the key when one alias appears as a CONTIGUOUS run of its
# tokens (so "nosql injection" != "sql injection"). Both candidate titles and
# existing KB titles/tags are resolved through this same map, which is how an
# abbreviation ("xss resource") and its full name ("Cross Site Scripting") land
# on the same key. Extend this map as later batches introduce new overlaps.
CANON: dict[str, list[list[str]]] = {
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
}

# --------------------------------------------------------------------------- #
# adaptation caps — extract key payloads, never dump huge verbatim lists
# --------------------------------------------------------------------------- #
MAX_CODE_CHARS = 500        # per copyable block
MAX_SECTIONS = 14           # technique subheadings walked per README
MAX_CODE_PER_SECTION = 1    # first payload block per subheading (the key one)
MAX_STEPS_NEW = 12          # steps on a brand-new entry
MAX_STEPS_MERGE = 8         # PATT steps folded into an existing entry
MAX_ADAPTED_BODY = 3000     # adapted body / appended-section length

MERGE_MARK = f"<!-- merged:{SOURCE_NAME} -->"
STEP_PREFIX = f"[{SOURCE_LABELS[SOURCE_NAME]} · "  # provenance-label on variant steps

_TOKEN_RE = re.compile(r"[a-z0-9]+")
_SKIP_HEADINGS = {"summary", "table of contents", "toc", "tools", "labs", "lab",
                  "references", "reference"}


def _tokens(text: str) -> list[str]:
    return _TOKEN_RE.findall((text or "").lower())


def _is_subseq(alias: list[str], toks: list[str]) -> bool:
    """True if `alias` appears as a CONTIGUOUS run inside `toks`."""
    n = len(alias)
    return any(toks[i:i + n] == alias for i in range(len(toks) - n + 1))


def canonical_keys(text: str) -> set[str]:
    """All curated vuln-class keys a piece of text (a title) resolves to."""
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
# PayloadsAllTheThings parser  (the only source-specific part)
# --------------------------------------------------------------------------- #
_IMG_RE = re.compile(r"!\[[^\]]*\]\([^)]+\)")
_LINK_RE = re.compile(r"\[([^\]]+)\]\((https?://[^)]+)\)")
_BARE_URL_RE = re.compile(r"(?<!\()(https?://[^\s)\]]+)")


def _clean_summary(text: str) -> str:
    """A PATT `>` blockquote is `desc - [ref](url)`; keep the prose."""
    s = re.sub(r"\s*[-–—]\s*\[.*$", "", text)     # drop trailing " - [ref](url)"
    s = _LINK_RE.sub(r"\1", s)                     # unwrap any inline links
    s = _IMG_RE.sub("", s)
    return " ".join(s.split())[:300].rstrip()


def _walk_sections(lines: list[str]) -> list[dict]:
    """Split a PATT README body into sections keyed by ## / ### heading, each
    carrying its raw non-heading lines, prose-only lines, and fenced code
    blocks (all in document order)."""
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
    """From a `## Tools` section: (tool_names, tool_urls)."""
    names, urls = [], []
    for line in lines:
        st = line.strip()
        if not st.startswith(("*", "-")):
            continue
        m = _LINK_RE.search(st)
        if m:
            name = m.group(1).split("/")[-1].strip()
            names.append(name)
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
    """Adapt one PayloadsAllTheThings technique README into a canonical Entry.

    Restructures — it does NOT copy: payloads are capped into key blocks, the
    Summary TOC is dropped, Tools/Labs/References are lifted into their schema
    fields, and the body is a compact structured digest (<= MAX_ADAPTED_BODY).
    """
    rel = path.relative_to(root).as_posix()
    folder = Path(rel).parts[0]
    raw = path.read_text(encoding="utf-8", errors="replace")
    lines = raw.splitlines()

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
        if low in ("tools",):
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
        text = sec["heading"]
        if prose:
            text = f"{sec['heading']} — {prose}"[:600]
        code = [Code(lang=(lg or "text"), cmd=cd[:MAX_CODE_CHARS])
                for lg, cd in sec["code"][:MAX_CODE_PER_SECTION]]
        if code or prose:
            steps.append(Step(n=len(steps) + 1, text=text.strip(), code=code))
        if len(steps) >= MAX_STEPS_NEW:
            break

    body_md = _adapted_body(title, summary, steps)
    keys = sorted(canonical_keys(title))
    tags = _dedup([DEFAULT_CATEGORY] + keys + [slugify(title)])

    return Entry(
        id="patt-" + slugify(folder),
        title=title,
        category=DEFAULT_CATEGORY,
        subcategory=None,
        source=SOURCE_NAME,
        tier=REF_TIER,
        tags=tags,
        tools=_dedup(tool_names),
        summary=summary or title,
        steps=steps,
        body_md=body_md,
        references=_dedup(refs),
        meta={
            "src_file": rel,          # folder path only — no proprietary content
            "kind": "reference",
            "source_label": SOURCE_LABELS[SOURCE_NAME],
            "canonical_keys": keys,
            "also_covered_in": [SOURCE_NAME],
        },
        schema_version=SCHEMA_VERSION,
    )


def _adapted_body(title: str, summary: str, steps: list[Step]) -> str:
    """Compact, restructured digest (capped) — never the verbatim README."""
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


# --------------------------------------------------------------------------- #
# matching (source-agnostic core)
# --------------------------------------------------------------------------- #
def match_candidate(cand: dict, cand_vec, existing: list[dict],
                    unit_vecs, id_order: list[str]):
    """Return (target_id, cosine, signals) or (None, best_cosine, signals).

    Confident match := shared canonical vuln-class AND cosine >= SEM_FLOOR.
    Among all existing entries sharing a class, the FULLEST (most complete) is
    chosen as the merge target — so a technique lands in its richest home, not
    a terse tool stub — with cosine as the tie-break.
    """
    import numpy as np

    ck = canonical_keys(cand.get("title", "")) | set(
        (cand.get("meta") or {}).get("canonical_keys", []))
    idx_by_id = {eid: i for i, eid in enumerate(id_order)}
    v = np.asarray(cand_vec, dtype=np.float32)
    v = v / max(float(np.linalg.norm(v)), 1e-9)

    best_any = (-1.0, None)
    keyed: list[tuple[int, float, str]] = []  # (content_len, cosine, id)
    for e in existing:
        eid = e["id"]
        row = idx_by_id.get(eid)
        cos = float(unit_vecs[row] @ v) if row is not None else 0.0
        if cos > best_any[0]:
            best_any = (cos, eid)
        if ck and (ck & entry_keys(e)) and cos >= SEM_FLOOR:
            keyed.append((content_len(e), cos, eid))

    signals = {"canonical_keys": sorted(ck),
               "best_cosine": round(best_any[0], 3),
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
def revert_source(entry: dict) -> dict:
    """Remove any prior contribution from THIS source, so a re-run is clean."""
    ms = (entry.get("meta") or {}).get("merged_sources", {})
    rec = ms.get(SOURCE_NAME)
    if not rec:
        return entry
    # 1) drop the appended, marked body block
    body = entry.get("body_md", "") or ""
    if MERGE_MARK in body:
        entry["body_md"] = body.split("\n\n---\n\n" + MERGE_MARK, 1)[0].rstrip()
    # 2) drop provenance-labelled variant steps, renumber
    kept = [s for s in entry.get("steps", [])
            if not (s.get("text", "") or "").startswith(STEP_PREFIX)]
    for i, s in enumerate(kept, 1):
        s["n"] = i
    entry["steps"] = kept
    # 3) remove added refs / tools
    added_refs = set(rec.get("added_refs", []))
    added_tools = set(rec.get("added_tools", []))
    entry["references"] = [r for r in entry.get("references", []) if r not in added_refs]
    entry["tools"] = [t for t in entry.get("tools", []) if t not in added_tools]
    # 4) clean meta bookkeeping
    meta = entry["meta"]
    also = meta.get("also_covered_in", [])
    if SOURCE_NAME in also:
        also.remove(SOURCE_NAME)
    meta.pop("merge_log", None)
    meta.pop("author_notes", None)
    ms.pop(SOURCE_NAME, None)
    if not ms:
        meta.pop("merged_sources", None)
    if not meta.get("also_covered_in"):
        meta.pop("also_covered_in", None)
    return entry


def merge_into(target: dict, cand: dict) -> dict:
    """Fold `cand` (a candidate Entry dict) into existing `target` in place.

    The target stays canonical (id/title/source/tier untouched). The candidate's
    distinct payloads become LABELLED variant steps; a marked, adapted body
    section is appended; refs/tools are unioned; provenance is recorded. Primary
    content = whichever side is more complete (reported, target stays the spine).
    """
    meta = target.setdefault("meta", {})
    pre_len = content_len(target)
    also = meta.setdefault("also_covered_in", [target.get("source")])
    if SOURCE_NAME not in also:
        also.append(SOURCE_NAME)

    # distinct steps only (dedup against target's existing command bodies)
    seen = {_norm_code(c.get("cmd", ""))
            for s in target.get("steps", []) for c in s.get("code", [])}
    added_steps = 0
    conflicts: list[dict] = []
    existing_first = {}
    for s in target.get("steps", []):
        for c in s.get("code", []):
            head = _norm_code(c.get("cmd", "")).split(" ", 1)[0]
            if head:
                existing_first.setdefault(head, c.get("cmd", ""))

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
        label = f"{STEP_PREFIX}{s.get('text', '').split(' — ')[0][:60]}]"
        rest = s.get("text", "")
        target.setdefault("steps", []).append({
            "n": n,
            "text": f"{label} {rest}".strip()[:600],
            "code": code,
            "images": [],
        })
        added_steps += 1
        if added_steps >= MAX_STEPS_MERGE:
            break

    # union references / tools, tracking what we added (for clean revert)
    before_refs = set(target.get("references", []))
    before_tools = set(target.get("tools", []))
    target["references"] = _dedup(list(target.get("references", [])) + cand.get("references", []))
    target["tools"] = _dedup(list(target.get("tools", [])) + cand.get("tools", []))
    added_refs = [r for r in target["references"] if r not in before_refs]
    added_tools = [t for t in target["tools"] if t not in before_tools]

    # appended, marked body section (adapted digest) — clearly attributed.
    # cand.body_md is already capped at MAX_ADAPTED_BODY, so no extra slice needed.
    primary_target = pre_len >= content_len(cand)
    src_label = SOURCE_LABELS.get(target.get("source"), target.get("source"))
    note = (f"_Primary content above is from {src_label}; the key payloads "
            f"below are adapted from {SOURCE_LABELS[SOURCE_NAME]}._")
    section = "\n\n---\n\n" + MERGE_MARK + "\n" + \
        f"## Also covered in — {SOURCE_LABELS[SOURCE_NAME]}\n\n{note}\n\n" + \
        cand.get("body_md", "")
    target["body_md"] = target.get("body_md", "") + section

    if target.get("source") == "peh-notes":
        meta["author_notes"] = "preserved — primary content is your own notes"

    meta.setdefault("merged_sources", {})[SOURCE_NAME] = {
        "added_steps": added_steps,
        "added_refs": added_refs,
        "added_tools": added_tools,
        "primary": "existing" if primary_target else SOURCE_NAME,
    }
    meta.setdefault("merge_log", []).append({
        "source": SOURCE_NAME,
        "cand_id": cand.get("id"),
        "cand_title": cand.get("title"),
        "added_steps": added_steps,
        "added_refs": len(added_refs),
        "primary": "existing" if primary_target else SOURCE_NAME,
        "target_len": pre_len,
        "cand_len": content_len(cand),
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


def run(source_path: Path, out_dir: Path, host: str, model: str,
        dry_run: bool) -> dict:
    kb_path = out_dir / "entries.jsonl"
    entries = load_jsonl(kb_path)
    if not entries:
        raise SystemExit(f"KB not found / empty: {kb_path}. Run the ingesters first.")

    # start clean: revert any prior run of THIS source (idempotent)
    entries = [e for e in entries if e.get("source") != SOURCE_NAME]
    for e in entries:
        revert_source(e)
    by_id = {e["id"]: e for e in entries}

    # existing vectors (built from the pre-enrichment entries)
    ids_order, vectors, ix_meta = embed.load_index()
    if ids_order is None:
        raise SystemExit("No embeddings. Build them first: uv run python embed.py")
    import numpy as np
    unit = vectors / np.clip(np.linalg.norm(vectors, axis=1, keepdims=True), 1e-9, None)

    # parse candidates
    readmes = sorted(source_path.rglob("README.md"))
    candidates: list[Entry] = []
    for p in readmes:
        rel = p.relative_to(source_path)
        if len(rel.parts) != 2 or rel.parts[0].startswith("_template"):
            continue
        candidates.append(parse_patt(p, source_path))

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
            merge_into(target, cd)
            merged_rows.append({
                "candidate": cand.title,
                "candidate_folder": cand.meta["src_file"].split("/")[0],
                "into_id": target_id,
                "into_title": target["title"],
                "into_source": target["source"],
                "cosine": round(cos, 3),
                "canonical_keys": signals["canonical_keys"],
                "primary": "existing" if pre_len >= content_len(cd) else SOURCE_NAME,
                "target_len": pre_len,
                "cand_len": content_len(cd),
            })
        else:
            eid = cand.id
            k = 2
            while eid in used_ids:
                eid = f"{cand.id}-{k}"
                k += 1
            cand.id = eid
            used_ids.add(eid)
            row = cand.model_dump()
            new_entries.append(row)
            created.append({
                "id": eid, "title": cand.title,
                "folder": cand.meta["src_file"].split("/")[0],
                "category": cand.category, "n_steps": len(cand.steps),
                "best_cosine": signals["best_cosine"],
                "nearest": signals["best_id"],
            })

    merged_kb = entries + new_entries
    result = {
        "generated_at": _now(),
        "source": SOURCE_NAME,
        "source_path": str(source_path),
        "dry_run": dry_run,
        "parsed": len(candidates),
        "merged_count": len(merged_rows),
        "created_count": len(created),
        "kb_before": len(entries) + 0,  # entries already excludes prior PATT
        "kb_after": len(merged_kb),
        "kb_by_source": dict(Counter(e.get("source") for e in merged_kb)),
        "merged_into_existing": merged_rows,
        "created_new": created,
    }

    if not dry_run:
        with kb_path.open("w", encoding="utf-8") as fh:
            for e in merged_kb:
                fh.write(json.dumps(e, ensure_ascii=False) + "\n")
        (out_dir / "merge_report.json").write_text(
            json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        emit_json_schema(Path(__file__).with_name("entry.schema.json"))
    return result


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def main() -> None:
    ap = argparse.ArgumentParser(description="Consolidating enrichment into the KB.")
    ap.add_argument("--source-path", default=DEFAULT_SOURCE_PATH)
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    ap.add_argument("--host", default=embed.OLLAMA_HOST)
    ap.add_argument("--model", default=embed.EMBED_MODEL)
    ap.add_argument("--dry-run", action="store_true",
                    help="report only; do not modify the KB")
    args = ap.parse_args()

    source_path = Path(args.source_path)
    if not source_path.is_dir():
        raise SystemExit(f"Source path not found: {source_path}")

    r = run(source_path, Path(args.out), args.host, args.model, args.dry_run)
    tag = " (DRY RUN — KB not modified)" if args.dry_run else ""
    print(f"\nConsolidated {SOURCE_NAME}{tag}")
    print(f"  parsed={r['parsed']}  merged={r['merged_count']}  new={r['created_count']}")
    print(f"  KB: {r['kb_before']} -> {r['kb_after']}  by_source={r['kb_by_source']}")
    print("\n  merged into existing:")
    for m in r["merged_into_existing"]:
        print(f"    - {m['candidate']}  ->  {m['into_title']} [{m['into_id']}]"
              f"  (cos {m['cosine']}, primary={m['primary']})")
    print(f"\n  created new: {r['created_count']} entries")
    if not args.dry_run:
        print("\n  Re-embed incrementally:  uv run python embed.py")


if __name__ == "__main__":
    main()
