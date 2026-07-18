"""HackPit backend — FastAPI service.

Exposes the built knowledge base (data/kb/) and the existing hybrid search
(pipeline/search.py) to the frontend. Read-only over the *built* KB, plus one
read-only exception: GET /image serves note screenshots straight from the
external notes folder (they are never copied into the repo), strictly
sandboxed to that folder.

Design notes
------------
* The KB is loaded once at startup and held in memory (`STATE`). Excluded
  entries (pipeline/exclude.json) are dropped up-front, so they can never
  surface from any endpoint — search re-applies the same filter defensively.
* Search is delegated to `pipeline/search.py` unchanged. If the vector half
  is unavailable (Ollama down / no embeddings), hybrid and vector requests
  fall back to lexical BM25 instead of failing.
* Response shapes are documented as Pydantic models so the frontend has a
  stable contract; the full Entry uses the canonical `pipeline/schema.py`.
"""

from __future__ import annotations

import json
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

# --------------------------------------------------------------------------- #
# reuse the pipeline (search + canonical schema) without reimplementing it
# --------------------------------------------------------------------------- #
REPO_ROOT = Path(__file__).resolve().parents[1]
PIPELINE_DIR = REPO_ROOT / "pipeline"
if str(PIPELINE_DIR) not in sys.path:
    # search.py does a bare `import embed`, so the pipeline dir must be importable.
    sys.path.insert(0, str(PIPELINE_DIR))

import search as kb_search  # noqa: E402  (pipeline/search.py)
from schema import Entry  # noqa: E402  (pipeline/schema.py — canonical entry model)

DATA_KB = REPO_ROOT / "data" / "kb" / "entries.jsonl"
CAPTIONS_PATH = REPO_ROOT / "data" / "images" / "captions.json"


# --------------------------------------------------------------------------- #
# note screenshots live ONLY in the external notes folder (never copied into
# the repo). The /image route serves them read-only, strictly sandboxed.
# --------------------------------------------------------------------------- #
IMAGE_EXTS = {".png", ".jpg", ".jpeg"}


def _resolve_notes_dir() -> Path | None:
    """Notes folder: env override → captions.json meta → None (route 503s)."""
    env = os.environ.get("HACKPIT_NOTES_DIR")
    if env:
        return Path(env)
    if CAPTIONS_PATH.exists():
        try:
            meta = json.loads(CAPTIONS_PATH.read_text(encoding="utf-8")).get("meta", {})
            if meta.get("notes_path"):
                return Path(meta["notes_path"])
        except Exception:
            pass
    return None


NOTES_DIR = _resolve_notes_dir()

# --------------------------------------------------------------------------- #
# category -> display name / accent colour / glyph.
# Colours + icons mirror the approved design mock so the frontend cards render
# with the same per-category palette. Categories beyond the mock's six cards
# still get a sensible restrained colour rather than falling through unstyled.
# --------------------------------------------------------------------------- #
CATEGORY_META: dict[str, tuple[str, str, str]] = {
    # (display name, accent colour, icon) — first six match the mock exactly
    "active-directory": ("Active Directory", "#5dd3aa", "⬡"),      # ⬡
    "web": ("Web & bug bounty", "#5aa9f0", "⚑"),                   # ⚑
    "recon": ("Recon & enum", "#a996f5", "◈"),                     # ◈
    "privesc": ("Privilege escalation", "#e88a5a", "▲"),           # ▲
    "tools": ("Tools", "#e0c15a", "⚒"),                            # ⚒
    "post-exploitation": ("Post-exploitation", "#6ad39a", "⌂"),    # ⌂
    # extras
    "services": ("Services", "#4fd0c0", "⚙"),                      # ⚙
    "credentials": ("Credentials", "#f0c94f", "⚷"),               # ⚷
    "persistence": ("Persistence", "#c98af0", "⟲"),               # ⟲
    "exploitation": ("Exploitation", "#f07a6a", "✷"),            # ✷
    "reference": ("Reference", "#8b938d", "≡"),                   # ≡
    "wireless": ("Wireless", "#5ad3c8", "⌁"),                     # ⌁
}
FALLBACK_META = ("#8b938d", "◆")  # grey diamond


def category_meta(slug: str) -> tuple[str, str, str]:
    if slug in CATEGORY_META:
        return CATEGORY_META[slug]
    name = slug.replace("-", " ").title()
    return (name, *FALLBACK_META)


# --------------------------------------------------------------------------- #
# in-memory KB state, populated at startup
# --------------------------------------------------------------------------- #
class _State:
    entries: list[dict] = []
    by_id: dict[str, dict] = {}
    by_category: dict[str, list[dict]] = {}
    stats: dict[str, int] = {}


STATE = _State()


def _load_stats(entries: list[dict]) -> dict[str, int]:
    """Derive the home-counter numbers from the built KB (+ image captions)."""
    tools = sum(1 for e in entries if e.get("category") == "tools")
    # "workflows / checklists" == the ordered checklist steps carried in the KB.
    workflows = sum(
        1
        for e in entries
        if (e.get("meta") or {}).get("type") == "checklist-step"
    )

    screenshots = 0
    if CAPTIONS_PATH.exists():
        try:
            cap = json.loads(CAPTIONS_PATH.read_text(encoding="utf-8"))
            meta = cap.get("meta", {}) if isinstance(cap, dict) else {}
            screenshots = int(meta.get("total_images") or 0)
            if not screenshots and isinstance(cap.get("images"), dict):
                screenshots = len(cap["images"])
        except Exception:
            screenshots = 0

    return {
        # `techniques` == every non-excluded entry (matches the mock's counter).
        "techniques": len(entries),
        "tools": tools,
        "workflows": workflows,
        "screenshots_ocr": screenshots,
        "total_entries": len(entries),
        "categories": len({e.get("category") for e in entries}),
    }


@asynccontextmanager
async def lifespan(app: FastAPI):
    raw = kb_search.load_entries(DATA_KB)
    # Drop excluded/hidden entries once, at the door — they can't leak anywhere.
    entries = kb_search.filter_excluded(raw)

    STATE.entries = entries
    STATE.by_id = {e["id"]: e for e in entries}
    by_cat: dict[str, list[dict]] = {}
    for e in entries:
        by_cat.setdefault(e.get("category", "uncategorized"), []).append(e)
    STATE.by_category = by_cat
    STATE.stats = _load_stats(entries)
    yield
    STATE.entries = []
    STATE.by_id = {}
    STATE.by_category = {}
    STATE.stats = {}


app = FastAPI(
    title="HackPit API",
    version="0.1.0",
    description="Knowledge base + hybrid search for the HackPit companion.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_methods=["GET"],
    allow_headers=["*"],
)


# --------------------------------------------------------------------------- #
# response models (the frontend contract)
# --------------------------------------------------------------------------- #
class StatsResponse(BaseModel):
    techniques: int = Field(description="Total non-excluded entries.")
    tools: int = Field(description="Entries in the 'tools' category.")
    workflows: int = Field(description="Ordered checklist / workflow steps.")
    screenshots_ocr: int = Field(description="Screenshots OCR'd into the KB.")
    total_entries: int
    categories: int


class CategoryOut(BaseModel):
    slug: str
    name: str
    count: int
    color: str = Field(description="Per-category accent hex (mock palette).")
    icon: str = Field(description="Glyph shown on the category card.")


class EntrySummary(BaseModel):
    id: str
    title: str
    summary: str
    tags: list[str]
    tier: int
    source: str
    category: str


class SearchHit(BaseModel):
    rank: int
    score: float
    id: str
    title: str
    category: str
    source: str
    tier: int | None = None
    snippet: str


class SearchResponse(BaseModel):
    query: str
    mode: str = Field(description="Search mode actually used.")
    requested_mode: str
    fell_back: bool = Field(
        description="True if the requested mode degraded to lexical (e.g. Ollama down)."
    )
    count: int
    results: list[SearchHit]


# --------------------------------------------------------------------------- #
# endpoints
# --------------------------------------------------------------------------- #
@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "entries": str(len(STATE.entries))}


@app.get("/stats", response_model=StatsResponse)
def stats() -> dict[str, int]:
    """Home-page counters, derived from the built KB."""
    return STATE.stats


@app.get("/categories", response_model=list[CategoryOut])
def categories() -> list[CategoryOut]:
    """All categories present in the KB, with real counts + card styling."""
    out: list[CategoryOut] = []
    for slug, items in STATE.by_category.items():
        name, color, icon = category_meta(slug)
        out.append(
            CategoryOut(slug=slug, name=name, count=len(items), color=color, icon=icon)
        )
    out.sort(key=lambda c: c.count, reverse=True)
    return out


@app.get("/categories/{slug}", response_model=list[EntrySummary])
def category_entries(slug: str) -> list[EntrySummary]:
    """Lightweight listing of the entries in one category (no full body)."""
    items = STATE.by_category.get(slug)
    if items is None:
        raise HTTPException(status_code=404, detail=f"unknown category: {slug}")
    return [
        EntrySummary(
            id=e["id"],
            title=e["title"],
            summary=e.get("summary", ""),
            tags=e.get("tags", []),
            tier=int(e.get("tier", 2)),
            source=e.get("source", ""),
            category=e.get("category", slug),
        )
        for e in items
    ]


@app.get("/search", response_model=SearchResponse)
def search(
    q: str = Query(..., min_length=1, description="Search query."),
    mode: str = Query("hybrid", pattern="^(hybrid|lexical|vector)$"),
    top: int = Query(20, ge=1, le=100),
) -> SearchResponse:
    """Ranked hybrid (BM25 + vector) search over the KB.

    Falls back to lexical BM25 if the vector half is unavailable (Ollama down
    or embeddings missing) so a query never 500s on infrastructure state.
    """
    used_mode = mode
    fell_back = False
    try:
        hits = kb_search.search(STATE.entries, q, top, mode=mode)
    except (Exception, SystemExit):
        # search.py raises SystemExit when it can't embed the query / load the
        # index. Degrade non-lexical modes to lexical rather than erroring.
        if mode == "lexical":
            raise HTTPException(status_code=500, detail="lexical search failed")
        used_mode = "lexical"
        fell_back = True
        hits = kb_search.search(STATE.entries, q, top, mode="lexical")

    results = [
        SearchHit(
            rank=h["rank"],
            score=h["score"],
            id=h["id"],
            title=h["title"],
            category=h["category"],
            source=h["source"],
            tier=h.get("tier"),
            snippet=h["snippet"],
        )
        for h in hits
    ]
    return SearchResponse(
        query=q,
        mode=used_mode,
        requested_mode=mode,
        fell_back=fell_back,
        count=len(results),
        results=results,
    )


@app.get("/entry/{entry_id}", response_model=Entry)
def entry(entry_id: str) -> dict[str, Any]:
    """The full canonical Entry (steps, copyable commands, body, refs, meta)."""
    e = STATE.by_id.get(entry_id)
    if e is None:
        raise HTTPException(status_code=404, detail=f"unknown entry: {entry_id}")
    return e


@app.get("/image")
def image(path: str = Query(..., description="Notes-relative screenshot path")):
    """Serve a note screenshot from inside the notes folder — nowhere else.

    Hardening: the path must be notes-relative (no drive, no leading slash, no
    ``..`` segment), the resolved target must stay within the notes folder, and
    only image extensions are served. Any violation is rejected before touching
    the filesystem beyond a stat.
    """
    if NOTES_DIR is None:
        raise HTTPException(status_code=503, detail="notes directory not configured")

    base = NOTES_DIR.resolve()
    rel = path.strip().replace("\\", "/")
    parts = rel.split("/")

    # reject empty, absolute (leading slash), drive-qualified, or traversal paths
    if (
        not rel
        or rel.startswith("/")
        or (len(rel) >= 2 and rel[1] == ":")
        or ".." in parts
    ):
        raise HTTPException(status_code=400, detail="invalid path")

    target = (base / rel).resolve()

    # defence in depth: the resolved path must live inside the notes folder
    try:
        target.relative_to(base)
    except ValueError:
        raise HTTPException(status_code=403, detail="path escapes notes directory")

    if target.suffix.lower() not in IMAGE_EXTS:
        raise HTTPException(status_code=415, detail="unsupported media type")
    if not target.is_file():
        raise HTTPException(status_code=404, detail="image not found")

    return FileResponse(target, headers={"Cache-Control": "public, max-age=86400"})
