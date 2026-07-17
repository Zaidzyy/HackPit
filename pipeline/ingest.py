"""Ingester for the "some hacking resources" markdown knowledge source.

Reads markdown-with-YAML-frontmatter files from an EXTERNAL absolute path
(the source is never copied into the repo), normalizes each into the canonical
`Entry` schema, and writes:

    data/kb/entries.jsonl   one Entry per line
    data/kb/index.json      manifest (counts, failures, lightweight entry list)

Both outputs live under /data which is gitignored — no source content is ever
committed.

Usage:
    python pipeline/ingest.py
    python pipeline/ingest.py --source-path "C:\\path\\to\\source" --out data/kb
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
from collections import Counter
from pathlib import Path

import yaml

from schema import SCHEMA_VERSION, Code, Entry, Step, emit_json_schema

# Default external source location (NOT in the repo).
DEFAULT_SOURCE_PATH = r"C:\Users\zaid_\Downloads\hacks\some hacking resources"
SOURCE_NAME = "some-hacking-resources"
DEFAULT_TIER = 2

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = REPO_ROOT / "data" / "kb"

FRONTMATTER_RE = re.compile(r"^\s*---\s*\n(.*?)\n---\s*\n?(.*)$", re.DOTALL)
NUM_ITEM_RE = re.compile(r"^\s*(\d+)\.\s+(.*)$")

# Map source folder / phase to a canonical category.
FOLDER_CATEGORY = {
    "ad-attacks": "active-directory",
    "services": "services",
    "tools": "tools",
}
PHASE_CATEGORY = {
    "recon": "recon",
    "enumeration": "recon",
    "privesc": "privesc",
    "credentials": "credentials",
    "exploitation": "exploitation",
    "pivoting": "pivoting",
    "persistence": "persistence",
}


def split_frontmatter(text: str) -> tuple[dict, str]:
    """Return (frontmatter_dict, body_markdown)."""
    m = FRONTMATTER_RE.match(text)
    if not m:
        return {}, text.strip()
    fm = yaml.safe_load(m.group(1)) or {}
    if not isinstance(fm, dict):
        fm = {}
    return fm, m.group(2).strip()


def derive_category(top_folder: str, phase: str | None) -> str:
    if top_folder in FOLDER_CATEGORY:
        return FOLDER_CATEGORY[top_folder]
    # workflows/ (checklists) and anything else -> derive from phase
    p = (phase or "").lower()
    if p.startswith("ad-"):
        return "active-directory"
    return PHASE_CATEGORY.get(p, p or "misc")


def parse_fences(body: str) -> list[tuple[str, str]]:
    """Extract fenced code blocks as (lang, code) in document order."""
    blocks: list[tuple[str, str]] = []
    inside = False
    lang = "text"
    buf: list[str] = []
    for line in body.splitlines():
        st = line.strip()
        if not inside and st.startswith("```"):
            inside, lang, buf = True, (st[3:].strip() or "text"), []
        elif inside and st.startswith("```"):
            inside = False
            blocks.append((lang, "\n".join(buf).strip()))
        elif inside:
            buf.append(line)
    return blocks


def first_comment(cmd: str) -> str:
    for line in cmd.splitlines():
        s = line.strip()
        if s.startswith("#"):
            return s.lstrip("#").strip()
    return ""


def build_steps(fm_commands, body: str) -> list[Step]:
    """Frontmatter commands become copyable code steps; extra body fences are
    appended; if neither exists, numbered prose lines become text-only steps."""
    steps: list[Step] = []
    seen_cmds: set[str] = set()
    n = 0

    for c in fm_commands or []:
        if not isinstance(c, dict):
            continue
        cmd = (c.get("cmd") or "").strip()
        if not cmd:
            continue
        n += 1
        lang = c.get("shell") or "bash"
        text = c.get("description") or first_comment(cmd)
        steps.append(
            Step(n=n, text=text, code=[Code(lang=lang, cmd=cmd, copyable=True)])
        )
        seen_cmds.add(cmd)

    for lang, code in parse_fences(body):
        if not code or code in seen_cmds:
            continue
        n += 1
        steps.append(Step(n=n, code=[Code(lang=lang or "bash", cmd=code)]))
        seen_cmds.add(code)

    if not steps:
        for line in body.splitlines():
            m = NUM_ITEM_RE.match(line)
            if m:
                n += 1
                steps.append(Step(n=n, text=m.group(2).strip()))

    return steps


def make_summary(notes, body: str) -> str:
    if isinstance(notes, str) and notes.strip():
        s = " ".join(notes.split())
    else:
        s = ""
        for para in body.split("\n\n"):
            p = " ".join(para.split())
            if p and not p.startswith(("#", ">", "```")):
                s = p
                break
    return s[:300].rstrip()


def dedup(seq) -> list[str]:
    out, seen = [], set()
    for x in seq:
        x = str(x).strip()
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out


def collect_tags(fm: dict) -> list[str]:
    tags: list[str] = []
    for key in ("tags", "techniques", "ad_primitives", "services"):
        v = fm.get(key)
        if isinstance(v, list):
            tags += [str(x) for x in v]
        elif isinstance(v, str):
            tags.append(v)
    return dedup(tags)


def parse_references(fm: dict) -> tuple[list[str], list[str]]:
    """Return (urls, related_ids)."""
    r = fm.get("references")
    if isinstance(r, dict):
        return dedup(r.get("urls") or []), dedup(r.get("related") or [])
    if isinstance(r, list):
        return dedup(r), []
    return [], []


def normalize(path: Path, source_root: Path) -> Entry:
    rel = path.relative_to(source_root).as_posix()
    top_folder = rel.split("/", 1)[0]
    fm, body = split_frontmatter(path.read_text(encoding="utf-8"))

    fm_id = str(fm.get("id") or path.stem).strip()
    phase = fm.get("phase")
    urls, related = parse_references(fm)

    meta = {"src_file": rel}
    for key in ("os", "phase", "type", "order", "ports", "techniques", "ad_primitives"):
        if fm.get(key) not in (None, [], ""):
            meta[key] = fm[key]
    if related:
        meta["related"] = related
    if fm.get("source"):
        meta["src_source"] = fm["source"]

    return Entry(
        id=fm_id,
        title=str(fm.get("title") or fm_id),
        category=derive_category(top_folder, phase),
        subcategory=(str(phase) if phase else None),
        source=SOURCE_NAME,
        tier=DEFAULT_TIER,
        tags=collect_tags(fm),
        tools=dedup(fm.get("tools") or []),
        summary=make_summary(fm.get("notes"), body),
        steps=build_steps(fm.get("commands"), body),
        body_md=body,
        references=urls,
        meta=meta,
        schema_version=SCHEMA_VERSION,
    )


def ingest(source_path: Path, out_dir: Path) -> dict:
    files = sorted(source_path.rglob("*.md"))
    entries: list[Entry] = []
    failed: list[dict] = []
    ids: dict[str, str] = {}

    for f in files:
        rel = f.relative_to(source_path).as_posix()
        try:
            e = normalize(f, source_path)
            if e.id in ids:  # keep global uniqueness stable + explicit
                e.id = f"{e.id}--{Path(rel).parent.name}"
            ids[e.id] = rel
            entries.append(e)
        except Exception as exc:  # noqa: BLE001 - report, don't abort the run
            failed.append({"file": rel, "error": f"{type(exc).__name__}: {exc}"})

    out_dir.mkdir(parents=True, exist_ok=True)
    jsonl = out_dir / "entries.jsonl"
    with jsonl.open("w", encoding="utf-8") as fh:
        for e in entries:
            fh.write(json.dumps(e.model_dump(), ensure_ascii=False) + "\n")

    by_cat = Counter(e.category for e in entries)
    by_type = Counter(e.meta.get("type") for e in entries)
    by_phase = Counter(e.subcategory for e in entries)

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "source": SOURCE_NAME,
        "source_path": str(source_path),
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "total": len(entries),
        "failed_count": len(failed),
        "counts": {
            "by_category": dict(sorted(by_cat.items())),
            "by_type": dict(sorted((str(k), v) for k, v in by_type.items())),
            "by_phase": dict(sorted((str(k), v) for k, v in by_phase.items())),
        },
        "failed": failed,
        "entries": [
            {
                "id": e.id,
                "title": e.title,
                "category": e.category,
                "subcategory": e.subcategory,
                "source": e.source,
                "tier": e.tier,
                "order": e.meta.get("order"),
                "n_steps": len(e.steps),
            }
            for e in entries
        ],
    }
    (out_dir / "index.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    # Keep the emitted JSON Schema (committed spec artifact) fresh.
    emit_json_schema(Path(__file__).with_name("entry.schema.json"))
    return manifest


def main() -> None:
    ap = argparse.ArgumentParser(description="Ingest the markdown knowledge source.")
    ap.add_argument("--source-path", default=DEFAULT_SOURCE_PATH)
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    args = ap.parse_args()

    source_path = Path(args.source_path)
    if not source_path.is_dir():
        raise SystemExit(f"Source path not found: {source_path}")

    manifest = ingest(source_path, Path(args.out))
    print(f"Ingested {manifest['total']} entries "
          f"({manifest['failed_count']} failed) -> {args.out}")
    print("By category:", manifest["counts"]["by_category"])


if __name__ == "__main__":
    main()
