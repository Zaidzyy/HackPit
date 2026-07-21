"""Ingester for HackPit-AUTHORED knowledge entries.

Unlike the other ingesters (which read EXTERNAL, third-party sources that are
never committed), this one ingests Zaid's OWN original entries — synthesized
methodology written for HackPit — which live IN the repo at
``pipeline/authored/authored_entries.jsonl`` and are safe to commit.

It MERGES them into ``data/kb/entries.jsonl`` alongside the existing sources,
mirroring ``ingest_notes.py``: any prior rows from this source are dropped and
replaced, every other source is preserved. Run it AFTER the other ingesters
(``ingest.py`` then ``ingest_notes.py``) and BEFORE ``embed.py``:

    python pipeline/ingest.py
    python pipeline/ingest_notes.py
    python pipeline/ingest_authored.py     # <-- this
    python pipeline/embed.py               # incremental: only embeds the new rows

The authored file is validated against the canonical schema on load, so a
malformed entry aborts loudly instead of corrupting the KB.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from schema import Entry  # canonical pydantic model — validates each row

REPO_ROOT = Path(__file__).resolve().parents[1]
AUTHORED = REPO_ROOT / "pipeline" / "authored" / "authored_entries.jsonl"
OUT_DIR = REPO_ROOT / "data" / "kb"
SOURCE_NAME = "hackpit-authored"


def load_authored(path: Path) -> list[dict]:
    if not path.exists():
        raise SystemExit(f"authored entries not found: {path}")
    rows: list[dict] = []
    with path.open(encoding="utf-8") as fh:
        for i, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            raw = json.loads(line)
            raw.setdefault("source", SOURCE_NAME)
            # validate + normalize through the canonical schema, then dump back
            entry = Entry.model_validate(raw)
            row = entry.model_dump()
            if row.get("source") != SOURCE_NAME:
                raise SystemExit(
                    f"{path}:{i} source must be '{SOURCE_NAME}', got {row.get('source')!r}"
                )
            rows.append(row)
    # ids must be unique within the authored set
    ids = [r["id"] for r in rows]
    dupes = [k for k, v in Counter(ids).items() if v > 1]
    if dupes:
        raise SystemExit(f"duplicate authored ids: {dupes}")
    return rows


def load_existing(jsonl: Path) -> list[dict]:
    if not jsonl.exists():
        return []
    with jsonl.open(encoding="utf-8") as fh:
        return [json.loads(l) for l in fh if l.strip()]


def main() -> None:
    authored = load_authored(AUTHORED)
    jsonl = OUT_DIR / "entries.jsonl"
    existing = load_existing(jsonl)
    kept = [r for r in existing if r.get("source") != SOURCE_NAME]
    merged = kept + authored

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    with jsonl.open("w", encoding="utf-8") as fh:
        for r in merged:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")

    print(
        f"merged {len(authored)} authored entries "
        f"({len(kept)} kept from other sources) -> {len(merged)} total"
    )
    print("authored ids:", ", ".join(r["id"] for r in authored))
    print("NEXT: run  python pipeline/embed.py  to vectorize the new rows.")


if __name__ == "__main__":
    main()
