"""Ingester for HTB box-writeup PDFs.

Reads machine/box writeup PDFs from an EXTERNAL absolute path (default
``~/Downloads/hacks/htb boxes``), extracts and normalizes each into the canonical
``Entry`` schema as a ``category="writeup"`` entry, and MERGES into
``data/kb/entries.jsonl`` alongside the other sources (mirrors ``ingest_notes.py``:
drop any prior rows from this source, keep everything else).

These are HTB proprietary "Official" writeups. Like ``htb-academy``, they are
indexed LOCALLY only: ``data/kb/*`` is gitignored and never committed, and the
PDFs themselves are never copied into the repo. This module (code) is committable;
the extracted content is not. Run AFTER the other ingesters and BEFORE ``embed.py``:

    python pipeline/ingest.py
    python pipeline/ingest_notes.py
    python pipeline/ingest_authored.py
    python pipeline/ingest_box_pdfs.py     # <-- this
    python pipeline/embed.py               # incremental

A parsed writeup becomes an ordered list of steps (each a heading/instruction +
its command blocks), which is exactly what ``attack_path.build_writeup_path``
consumes to drive the writeup-first attack-path mode. ``find_box_writeup`` matches
the goal to a box by the entry TITLE, so the title is set to the box name.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections import Counter
from pathlib import Path

from pypdf import PdfReader

from schema import Entry, Step, Code

REPO_ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = REPO_ROOT / "data" / "kb"
SOURCE_NAME = "htb-box-pdfs"
_SRC_ROOT = Path(os.environ.get("HACKPIT_BOX_PDFS") or (Path.home() / "Downloads" / "hacks" / "htb boxes"))

# lines that look like shell/commands vs prose
_CMD_START = re.compile(
    r"^\s*(?:\$|#|>|PS[ >]|sudo\b|nmap\b|ffuf\b|gobuster\b|feroxbuster\b|curl\b|wget\b|"
    r"nc\b|ncat\b|ssh\b|scp\b|smbclient\b|smbmap\b|crackmapexec\b|nxc\b|impacket-\w+|"
    r"python[23]?\b|php\b|bash\b|sh\b|powershell\b|hydra\b|john\b|hashcat\b|sqlmap\b|"
    r"nikto\b|whatweb\b|enum4linux\b|rustscan\b|masscan\b|evil-winrm\b|kerbrute\b|"
    r"GetUserSPNs|secretsdump|psexec|wmiexec|bloodhound|netexec|dig\b|host\b|openssl\b|"
    r"echo\b|cat\b|ls\b|cd\b|chmod\b|export\b|git\b|docker\b|kubectl\b)",
    re.I,
)
_CMD_HINT = re.compile(r"[|;>]|--\w|\$\(|\b10\.10\.\d{1,3}\.\d{1,3}\b|/etc/|http://|https://")
# section headings HTB writeups use — become step boundaries / phase seeds
_HEADING = re.compile(
    r"^(?:enumeration|nmap|foothold|initial access|user|shell|exploitation|exploit|"
    r"privilege escalation|privesc|root|lateral movement|post[- ]?exploitation|"
    r"persistence|web|smb|ldap|kerberos|reconnaissance|recon|scanning|discovery|"
    r"gaining access|cracking|password|credential)s?\b.*$",
    re.I,
)
_BOX_TYPE = {
    "windows": re.compile(r"\b(windows|active directory|domain controller|kerberos|ntlm|smb)\b", re.I),
    "linux": re.compile(r"\b(linux|ubuntu|debian|suid|sudo|capabilit)\b", re.I),
}


def _looks_command(line: str) -> bool:
    s = line.strip()
    if len(s) < 2 or len(s) > 400:
        return False
    return bool(_CMD_START.search(s) or (_CMD_HINT.search(s) and not s.endswith(".")))


def extract_text(pdf_path: Path) -> str:
    reader = PdfReader(str(pdf_path))
    return "\n".join((pg.extract_text() or "") for pg in reader.pages)


# a box name is the leading alphabetic token(s) before any digit/date — pypdf
# sometimes glues the name to the date line ("Principal11th March 2026").
_NAME_LEAD = re.compile(r"^([A-Za-z][A-Za-z '\-]{0,38}?)(?=\s*\d|\s*$)")


def box_name(text: str, fallback: str) -> str:
    for line in text.splitlines():
        s = line.strip()
        if not s or s.lower().startswith(("prepared", "document", "classification", "machine author")):
            continue
        m = _NAME_LEAD.match(s)
        name = (m.group(1).strip() if m else s).strip()
        if name and len(name) <= 40:
            return name
    return fallback


# the walkthrough starts here; everything before (title, metadata, synopsis,
# skills required/learned) is summary and must NOT become steps — otherwise its
# prose ("...gain foothold...", "...escalate to root...") pushes the monotonic
# phase index forward before the real recon step and mislabels the whole path.
_WALKTHROUGH_START = re.compile(
    r"^(?:enumeration|reconnaissance|recon|scanning|nmap|discovery|information gathering)\b",
    re.I,
)


def parse_steps(text: str) -> list[Step]:
    """Group the writeup into ordered steps: a heading (or the first block) starts
    a step; command-looking lines become that step's code, prose becomes its text.
    Skips the summary preamble before the first walkthrough heading."""
    lines = text.splitlines()
    start = 0
    for i, ln in enumerate(lines):
        if _WALKTHROUGH_START.match(ln.strip()):
            start = i
            break
    text = "\n".join(lines[start:]) if start else text

    steps: list[Step] = []
    cur_text: list[str] = []
    cur_cmds: list[str] = []
    n = 0

    def flush():
        nonlocal n, cur_text, cur_cmds
        if not cur_text and not cur_cmds:
            return
        n += 1
        code = [Code(lang="bash", cmd="\n".join(cur_cmds))] if cur_cmds else []
        steps.append(Step(n=n, text=" ".join(cur_text).strip()[:600], code=code))
        cur_text, cur_cmds = [], []

    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        if _HEADING.match(line.strip()):
            flush()
            cur_text = [line.strip()]
            continue
        if _looks_command(line):
            cur_cmds.append(line.strip())
        else:
            # a prose line after commands closes the current command group into a step
            if cur_cmds:
                flush()
            cur_text.append(line.strip())
    flush()
    # keep only steps that carry something runnable OR a real heading
    return [s for s in steps if s.code or _HEADING.match((s.text or "")[:40])] or steps


def normalize(pdf_path: Path) -> tuple[Entry, str]:
    text = extract_text(pdf_path)
    name = box_name(text, pdf_path.stem)
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "box"
    btype = next((k for k, rx in _BOX_TYPE.items() if rx.search(text)), None)
    steps = parse_steps(text)
    entry = Entry(
        id=f"htb-box-{slug}",
        title=name,
        category="writeup",
        subcategory="htb-machine",
        source=SOURCE_NAME,
        tier=3,
        tags=[t for t in ["writeup", "htb", "box", btype] if t],
        tools=[],
        summary=(f"HTB machine writeup: {name}." + (f" {btype.title()} box." if btype else ""))[:280],
        steps=steps,
        body_md=text,
        references=[],
        meta={"box_type": btype, "proprietary": True, "source_pdf": pdf_path.name},
    )
    content_hash = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
    return entry, content_hash


def load_existing(jsonl: Path) -> list[dict]:
    if not jsonl.exists():
        return []
    with jsonl.open(encoding="utf-8") as fh:
        return [json.loads(l) for l in fh if l.strip()]


def main() -> None:
    if not _SRC_ROOT.exists():
        raise SystemExit(f"box PDF source not found: {_SRC_ROOT}")
    pdfs = sorted(_SRC_ROOT.glob("*.pdf"))
    entries: list[dict] = []
    seen_hash: set[str] = set()
    seen_id: dict[str, int] = {}
    skipped_dupes = 0
    for p in pdfs:
        try:
            e, h = normalize(p)
        except Exception as exc:  # never abort the batch on one bad PDF
            print(f"  FAILED {p.name}: {type(exc).__name__}: {exc}")
            continue
        if h in seen_hash:
            skipped_dupes += 1
            continue
        seen_hash.add(h)
        if e.id in seen_id:  # same box name, different content -> disambiguate
            seen_id[e.id] += 1
            e.id = f"{e.id}-{seen_id[e.id]}"
        else:
            seen_id[e.id] = 1
        entries.append(e.model_dump())

    jsonl = OUT_DIR / "entries.jsonl"
    existing = load_existing(jsonl)
    kept = [r for r in existing if r.get("source") != SOURCE_NAME]
    merged = kept + entries
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    with jsonl.open("w", encoding="utf-8") as fh:
        for r in merged:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")

    print(f"box PDFs: {len(pdfs)} files, {len(entries)} entries ({skipped_dupes} exact dupes skipped)")
    print(f"merged: {len(kept)} kept + {len(entries)} box -> {len(merged)} total")
    for r in entries:
        print(f"  - {r['id']}: {r['title']}  ({len(r['steps'])} steps, box_type={r['meta'].get('box_type')})")
    print("NEXT: run  python pipeline/embed.py  to vectorize the new rows.")


if __name__ == "__main__":
    main()
