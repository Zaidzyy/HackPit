"""Ingester for the personal "Practical Ethical Hacking" course notes.

This is the FIRST tier-1 source: the author's own notes, a Notion markdown
export whose knowledge lives in prose, fenced commands, AND screenshots. It
normalizes into the exact same canonical `Entry` schema as every other source
(`schema.Entry`) and MERGES into `data/kb/entries.jsonl` alongside the existing
`some-hacking-resources` entries — kept distinguishable by `source`/`tier`.

    source = "peh-notes"
    tier   = 1            # most-trusted tier (author's own notes)

What it does per note file:
  * Reads markdown from an EXTERNAL absolute path (never copied into the repo).
  * Derives `category` from the top folder / page, `subcategory` = the note's
    own section (page) name.
  * Extracts fenced code blocks into `steps[].code` (copyable). Obviously-wrong
    language tags on shell blocks (```c / ```jsx) are retagged to ```bash. Prose
    / typos are left FAITHFUL (voice cleanup is a later, reviewed pass).
  * For every `![image](path)` reference, looks the image up in
    `data/images/captions.json` and:
      - attaches the image path to the relevant step's `images[]`,
      - folds its OCR text into the searchable `body_md` (OCR is real content),
      - stores the caption in `meta` as a SOFT scene-label ONLY. Unverified
        (llava) captions are NEVER indexed. The one exception is a hand-authored
        override from `manual_captions.json` — that is our own verified text, so
        it is treated as trusted, searchable content and folded into `body_md`.
  * Never drops a file. A file that is essentially external links / reading
    material (no runnable commands, no captured screenshots) is still ingested
    but tagged `meta.kind = "reference"` and reported for the author's triage.

Usage:
    uv run python ingest_notes.py
    uv run python ingest_notes.py --notes-path "C:\\path" --captions ../data/images/captions.json
    uv run python ingest_notes.py --out ../data/kb
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import urllib.parse
from collections import Counter
from pathlib import Path

from images import load_manual_captions
from schema import SCHEMA_VERSION, Code, Entry, Step, emit_json_schema

DEFAULT_NOTES_PATH = r"C:\Users\zaid_\Downloads\hacks\PRACTICAL ETHICAL HACKING COMPLETE NOTES"
SOURCE_NAME = "peh-notes"
TIER = 1  # author's own notes — the most-trusted tier.

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = REPO_ROOT / "data" / "kb"
DEFAULT_CAPTIONS = REPO_ROOT / "data" / "images" / "captions.json"

# Notion appends " <32-hex-id>" to every exported page filename.
NOTION_HASH_RE = re.compile(r"\s+[0-9a-f]{32}$")
IMAGE_REF_RE = re.compile(r"!\[([^\]]*)\]\(([^)]+)\)")
HEADING_RE = re.compile(r"^(#{1,6})\s+(.*)$")
LINK_RE = re.compile(r"\[[^\]]*\]\((https?://[^)]+)\)")
BARE_URL_RE = re.compile(r"(?<!\()(https?://[^\s)\]]+)")
IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tif", ".tiff"}

# Shell blocks in these notes are routinely mistagged by Notion as ```c / ```jsx
# (there is no real C or JSX in the course). Retag those to bash. An empty fence
# is treated as a copyable shell block too. Everything else is left as-authored.
SHELL_MISTAGS = {"c", "jsx"}


def strip_hash(name: str) -> str:
    """`sql injection resource 39ee...` -> `sql injection resource`."""
    return NOTION_HASH_RE.sub("", name).strip()


# --------------------------------------------------------------------------- #
# categorization
# --------------------------------------------------------------------------- #
# Ordered (prefix, category) — first match wins. "post exploitation" MUST be
# checked before "exploitation".
CATEGORY_RULES: list[tuple[str, str]] = [
    ("active directory", "active-directory"),
    ("finding and exploiting", "web"),
    ("web application enumeration", "web"),
    ("scanning and enumeration", "recon"),
    ("info gathering", "recon"),
    ("post exploitation", "post-exploitation"),
    ("exploitation", "exploitation"),
    ("burpsuite", "tools"),
    ("wireless network hacking", "wireless"),
    ("extra resources", "reference"),
    ("practical ethical hacking complete notes", "reference"),  # root index page
]


def top_name(rel: str) -> str:
    """The categorizing key: the top folder, or (for a root-level page) the
    page's own name with the Notion hash stripped."""
    parts = rel.split("/")
    if len(parts) > 1:
        return parts[0]
    return strip_hash(Path(parts[0]).stem)


def derive_category(top: str) -> tuple[str, bool]:
    """Return (category, matched). `matched=False` flags an unmapped top."""
    t = top.strip().lower()
    for prefix, cat in CATEGORY_RULES:
        if t.startswith(prefix):
            return cat, True
    return "misc", False


# --------------------------------------------------------------------------- #
# image reference resolution -> captions.json key
# --------------------------------------------------------------------------- #
def build_caption_index(captions: dict) -> tuple[dict, dict]:
    """Return (by_key, root_by_basename). `root_by_basename` maps a bare
    filename to a root-level caption key, used to recover Notion refs that point
    at a per-page asset folder that got flattened to the export root."""
    by_key = captions.get("images", {})
    root_by_basename = {
        Path(k).name: k for k in by_key if "/" not in k
    }
    return by_key, root_by_basename


def resolve_image(url: str, md_path: Path, notes_root: Path,
                  by_key: dict, root_by_basename: dict) -> str | None:
    """Resolve an image URL from a note into a captions.json key, or None if it
    is an external (http) image or cannot be matched locally."""
    url = url.strip()
    if url.startswith(("http://", "https://")):
        return None
    dec = urllib.parse.unquote(url)
    try:
        abs_img = (md_path.parent / dec).resolve()
        rel = abs_img.relative_to(notes_root.resolve()).as_posix()
    except Exception:
        rel = None
    if rel and rel in by_key:
        return rel
    # Notion sometimes writes `<PageName>/image.png` for assets that were
    # flattened to the export root. Fall back to a unique root-level basename.
    base = Path(dec).name
    if base in root_by_basename:
        return root_by_basename[base]
    return None


# --------------------------------------------------------------------------- #
# code / language handling
# --------------------------------------------------------------------------- #
def fix_lang(lang: str) -> str:
    lang = (lang or "").strip().lower()
    if lang in SHELL_MISTAGS or lang == "":
        return "bash"
    return lang


# --------------------------------------------------------------------------- #
# per-note block walk: sections -> steps, plus OCR-folded body + image meta
# --------------------------------------------------------------------------- #
def caption_for(key: str, rec: dict, manual: dict[str, str]) -> tuple[str, str]:
    """Return (caption_text, source) for an image. Manual authored override
    beats the stored (llava) caption."""
    if key in manual:
        return manual[key], "manual"
    return (rec.get("caption") or "").strip(), (rec.get("caption_source") or "llava")


def parse_note(
    md_path: Path,
    notes_root: Path,
    by_key: dict,
    root_by_basename: dict,
    manual: dict[str, str],
):
    """Walk a note's markdown once, producing:
        title, summary, steps[], augmented body_md, images_meta[],
        external_image_urls[], stats(n_code, n_local_images).
    """
    raw = md_path.read_text(encoding="utf-8", errors="replace")
    lines = raw.splitlines()

    title = ""
    steps: list[Step] = []
    images_meta: list[dict] = []
    external_images: list[str] = []
    seen_img_keys: set[str] = set()
    n_code = 0

    # A section accumulates prose + code + images between headings.
    section = {"heading": "", "text": [], "code": [], "images": [], "ocr": []}

    def flush():
        nonlocal steps
        has_content = section["code"] or section["images"]
        if not has_content:
            return
        n = len(steps) + 1
        text_bits = []
        if section["heading"]:
            text_bits.append(section["heading"])
        prose = " ".join(" ".join(section["text"]).split()).strip()
        if prose:
            text_bits.append(prose)
        text_bits.extend(section["ocr"])  # fold OCR into step text too
        steps.append(
            Step(
                n=n,
                text=" \n".join(text_bits).strip()[:4000],
                code=section["code"],
                images=section["images"],
            )
        )

    def new_section(heading: str):
        nonlocal section
        flush()
        section = {"heading": heading, "text": [], "code": [],
                   "images": [], "ocr": []}

    i = 0
    in_fence = False
    fence_lang = ""
    fence_buf: list[str] = []
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        if in_fence:
            if stripped.startswith("```"):
                code_text = "\n".join(fence_buf).strip()
                if code_text:
                    section["code"].append(
                        Code(lang=fix_lang(fence_lang), cmd=code_text)
                    )
                in_fence = False
                fence_buf = []
            else:
                fence_buf.append(line)
            i += 1
            continue

        if stripped.startswith("```"):
            in_fence = True
            fence_lang = stripped[3:].strip()
            fence_buf = []
            n_code += 1
            i += 1
            continue

        hm = HEADING_RE.match(line)
        if hm:
            heading_text = hm.group(2).strip()
            if not title:  # first heading is the page title
                title = heading_text
                section["heading"] = ""  # title isn't a section body
            else:
                new_section(heading_text)
            i += 1
            continue

        # image references on this line
        for m in IMAGE_REF_RE.finditer(line):
            alt, url = m.group(1), m.group(2)
            if url.strip().startswith(("http://", "https://")):
                external_images.append(url.strip())
                continue
            key = resolve_image(url, md_path, notes_root, by_key, root_by_basename)
            if not key:
                continue
            rec = by_key.get(key, {})
            ocr = (rec.get("ocr_text") or "").strip()
            caption, src = caption_for(key, rec, manual)
            if key not in section["images"]:
                section["images"].append(key)
            if ocr:
                section["ocr"].append(ocr)
            # Authored (manual) caption is trusted -> also searchable via step text.
            if src == "manual" and caption:
                section["ocr"].append(caption)
            if key not in seen_img_keys:
                seen_img_keys.add(key)
                images_meta.append({
                    "path": key,
                    "kind": rec.get("kind"),
                    "char_count": rec.get("char_count", 0),
                    "ocr_len": len(ocr),
                    "caption": caption,            # SOFT scene-label (meta only)
                    "caption_source": src,         # "manual" (trusted) | "llava"
                })
            continue

        # plain prose line
        if stripped:
            section["text"].append(line)
        i += 1

    flush()

    # Summary: first meaningful prose paragraph (skip headings/quotes/fences).
    summary = ""
    for para in raw.split("\n\n"):
        p = " ".join(para.split())
        if p and not p.startswith(("#", ">", "```", "![", "<aside", "|")):
            summary = p
            break

    body_md = build_body(raw, md_path, notes_root, by_key, root_by_basename, manual)

    return {
        "title": title or strip_hash(md_path.stem),
        "summary": summary[:300].rstrip(),
        "steps": steps,
        "body_md": body_md,
        "images_meta": images_meta,
        "external_images": _dedup(external_images),
        "n_code": n_code,
        "n_local_images": len(seen_img_keys),
    }


def build_body(raw: str, md_path: Path, notes_root: Path,
               by_key: dict, root_by_basename: dict,
               manual: dict[str, str]) -> str:
    """Return the note's markdown, faithful to the author's prose, but with each
    local image reference augmented with its OCR text (real, searchable content)
    and — only for authored overrides — the verified caption. Unverified llava
    captions are deliberately NOT injected, so they never become search facts."""
    def repl(m: re.Match) -> str:
        alt, url = m.group(1), m.group(2)
        original = m.group(0)
        if url.strip().startswith(("http://", "https://")):
            return original
        key = resolve_image(url, md_path, notes_root, by_key, root_by_basename)
        if not key:
            return original
        rec = by_key.get(key, {})
        ocr = (rec.get("ocr_text") or "").strip()
        caption, src = caption_for(key, rec, manual)
        block = [original, "", f"<!-- image:{key} -->"]
        if ocr:
            block.append(f"[screenshot OCR] {ocr}")
        if src == "manual" and caption:
            block.append(f"[verified caption] {caption}")
        return "\n".join(block)

    return IMAGE_REF_RE.sub(repl, raw).strip()


# --------------------------------------------------------------------------- #
# tools / references / helpers
# --------------------------------------------------------------------------- #
# Curated pentest tool lexicon — factual (present in the text), so safe to index.
TOOL_LEXICON = {
    "nmap", "masscan", "rustscan", "sqlmap", "burpsuite", "burp", "metasploit",
    "msfvenom", "msfconsole", "meterpreter", "responder", "hashcat", "john",
    "hydra", "netexec", "crackmapexec", "impacket", "mimikatz", "bloodhound",
    "sharphound", "rubeus", "kerbrute", "getuserspns", "secretsdump",
    "evil-winrm", "smbclient", "smbmap", "enum4linux", "ldapsearch", "rpcclient",
    "nuclei", "gobuster", "ffuf", "feroxbuster", "dirb", "wfuzz", "wpscan",
    "nikto", "aircrack-ng", "airmon-ng", "airodump-ng", "aireplay-ng",
    "wireshark", "tcpdump", "hcxdumptool", "powerview", "powerup", "winpeas",
    "linpeas", "certutil", "proxychains", "netcat", "socat", "gpp-decrypt",
    "setoolkit", "gophish", "wpscan", "amass", "subfinder", "httpx", "katana",
    "owasp zap", "zaproxy", "curl", "wget", "hping3", "theharvester",
}


def extract_tools(text: str) -> list[str]:
    low = text.lower()
    found = []
    for tool in TOOL_LEXICON:
        # whole-token-ish match
        if re.search(rf"(?<![a-z0-9]){re.escape(tool)}(?![a-z0-9])", low):
            found.append(tool)
    return sorted(set(found))


def extract_references(raw: str, external_images: list[str]) -> list[str]:
    urls = LINK_RE.findall(raw) + BARE_URL_RE.findall(raw) + list(external_images)
    return _dedup(u.rstrip(".,);") for u in urls)


def _dedup(seq) -> list[str]:
    out, seen = [], set()
    for x in seq:
        x = str(x).strip()
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out


def slugify(text: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return re.sub(r"-{2,}", "-", s)


# --------------------------------------------------------------------------- #
# normalize one file -> Entry
# --------------------------------------------------------------------------- #
def normalize(path: Path, notes_root: Path, by_key: dict,
              root_by_basename: dict, manual: dict[str, str]) -> tuple[Entry, dict]:
    rel = path.relative_to(notes_root).as_posix()
    top = top_name(rel)
    category, matched = derive_category(top)
    section_name = strip_hash(path.stem)

    parsed = parse_note(path, notes_root, by_key, root_by_basename, manual)
    raw = path.read_text(encoding="utf-8", errors="replace")

    tools = extract_tools(parsed["body_md"])
    references = extract_references(raw, parsed["external_images"])

    # A note is "reference" when it carries no runnable commands and no captured
    # screenshots — its value is reading / links, not reproducible steps.
    is_root_index = top.lower().startswith("practical ethical hacking complete notes")
    is_reference = is_root_index or (
        parsed["n_code"] == 0 and parsed["n_local_images"] == 0
    )

    meta: dict = {
        "src_file": rel,
        "top": top,
        "section": section_name,
        "n_code": parsed["n_code"],
        "n_images": parsed["n_local_images"],
        "n_external_images": len(parsed["external_images"]),
    }
    if parsed["images_meta"]:
        meta["images"] = parsed["images_meta"]
    if parsed["external_images"]:
        meta["external_images"] = parsed["external_images"]
    if is_reference:
        meta["kind"] = "reference"
    if not matched:
        meta["category_unmatched"] = True

    entry = Entry(
        id=slugify(NOTION_HASH_RE.sub("", rel.rsplit(".", 1)[0])),
        title=parsed["title"],
        category=category,
        subcategory=section_name,
        source=SOURCE_NAME,
        tier=TIER,
        tags=_dedup([category] + tools),
        tools=tools,
        summary=parsed["summary"],
        steps=parsed["steps"],
        body_md=parsed["body_md"],
        references=references,
        meta=meta,
        schema_version=SCHEMA_VERSION,
    )
    report_row = {
        "file": rel,
        "id": entry.id,
        "category": category,
        "section": section_name,
        "n_code": parsed["n_code"],
        "n_images": parsed["n_local_images"],
        "n_refs": len(references),
        "words": len(re.findall(r"\w+", raw)),
        "reference": is_reference,
        "unmatched_category": not matched,
    }
    return entry, report_row


# --------------------------------------------------------------------------- #
# merge into data/kb (preserve other sources)
# --------------------------------------------------------------------------- #
def load_existing(jsonl: Path) -> list[dict]:
    if not jsonl.exists():
        return []
    with jsonl.open(encoding="utf-8") as fh:
        return [json.loads(l) for l in fh if l.strip()]


def ingest(notes_path: Path, out_dir: Path, captions_path: Path) -> dict:
    captions = json.loads(captions_path.read_text(encoding="utf-8")) if captions_path.exists() else {"images": {}}
    by_key, root_by_basename = build_caption_index(captions)
    manual = load_manual_captions()

    files = sorted(notes_path.rglob("*.md"))
    entries: list[Entry] = []
    rows: list[dict] = []
    failed: list[dict] = []
    ids: dict[str, str] = {}

    for f in files:
        rel = f.relative_to(notes_path).as_posix()
        try:
            e, row = normalize(f, notes_path, by_key, root_by_basename, manual)
            base = e.id
            k = 2
            while e.id in ids:  # keep ids globally unique + explicit
                e.id = f"{base}-{k}"
                k += 1
            ids[e.id] = rel
            row["id"] = e.id
            entries.append(e)
            rows.append(row)
        except Exception as exc:  # noqa: BLE001 - report, never abort the run
            failed.append({"file": rel, "error": f"{type(exc).__name__}: {exc}"})

    # ---- merge with other sources (drop any prior peh-notes, keep the rest) ----
    out_dir.mkdir(parents=True, exist_ok=True)
    jsonl = out_dir / "entries.jsonl"
    existing = load_existing(jsonl)
    kept = [r for r in existing if r.get("source") != SOURCE_NAME]
    merged = kept + [e.model_dump() for e in entries]
    with jsonl.open("w", encoding="utf-8") as fh:
        for r in merged:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")

    # ---- manifest for this source ----
    by_cat = Counter(e.category for e in entries)
    ref_files = [r["file"] for r in rows if r["reference"]]
    unmatched = [r["file"] for r in rows if r["unmatched_category"]]
    n_img_attached = sum(len(e.meta.get("images", [])) for e in entries)

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "source": SOURCE_NAME,
        "tier": TIER,
        "source_path": str(notes_path),
        "captions_path": str(captions_path),
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "total": len(entries),
        "failed_count": len(failed),
        "images_attached": n_img_attached,
        "manual_overrides_available": len(manual),
        "counts": {"by_category": dict(sorted(by_cat.items()))},
        "reference_tagged": ref_files,
        "unmatched_category": unmatched,
        "failed": failed,
        "files": rows,
        "kb_total_after_merge": len(merged),
        "kb_by_source": dict(Counter(r.get("source") for r in merged)),
    }
    (out_dir / "index.notes.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    emit_json_schema(Path(__file__).with_name("entry.schema.json"))
    return manifest


def main() -> None:
    ap = argparse.ArgumentParser(description="Ingest the personal PEH course notes.")
    ap.add_argument("--notes-path", default=DEFAULT_NOTES_PATH)
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    ap.add_argument("--captions", default=str(DEFAULT_CAPTIONS))
    args = ap.parse_args()

    notes_path = Path(args.notes_path)
    if not notes_path.is_dir():
        raise SystemExit(f"Notes path not found: {notes_path}")

    m = ingest(notes_path, Path(args.out), Path(args.captions))
    print(f"Ingested {m['total']} note entries ({m['failed_count']} failed); "
          f"{m['images_attached']} image attachments.")
    print("By category:", m["counts"]["by_category"])
    print("KB after merge:", m["kb_total_after_merge"], m["kb_by_source"])
    print("Reference-tagged:", len(m["reference_tagged"]), "files")
    if m["unmatched_category"]:
        print("UNMATCHED category:", m["unmatched_category"])


if __name__ == "__main__":
    main()
