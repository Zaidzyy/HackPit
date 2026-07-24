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

from fastapi import Body, FastAPI, HTTPException, Query
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

import consolidate  # noqa: E402  (pipeline/consolidate.py — SOURCE_LABELS, PERSONAL_SOURCES)
import search as kb_search  # noqa: E402  (pipeline/search.py)
from schema import Code, Entry  # noqa: E402  (pipeline/schema.py — canonical models)

# generative layer (backend/llm.py + backend/attack_path.py) — provider-swappable
import attack_path  # noqa: E402
import chat as chat_assistant  # noqa: E402  (backend/chat.py — engagement assistant)
import llm  # noqa: E402
import orchestrator  # noqa: E402  (backend/orchestrator.py — the loop's propose step)
import report as report_gen  # noqa: E402  (backend/report.py — LLM report drafting)
import sessions as sessions_db  # noqa: E402  (backend/sessions.py — SQLite store)
from cockpit import runstore as cockpit_runstore  # noqa: E402
from cockpit.router import router as cockpit_router  # noqa: E402

DATA_KB = REPO_ROOT / "data" / "kb" / "entries.jsonl"
CAPTIONS_PATH = REPO_ROOT / "data" / "images" / "captions.json"
SCRIPTS_PATH = REPO_ROOT / "data" / "kb" / "scripts.json"  # built by pipeline/scripts_index.py


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
    # categories introduced by the round-2/3 enrichment batches — each gets a
    # distinct on-theme icon+colour so no card falls through to the grey diamond.
    "network-services": ("Network services", "#3fb0c9", "⇆"),
    "pwn": ("Binary exploitation", "#e05563", "⊗"),
    "windows": ("Windows", "#6d8ef2", "⊞"),
    "methodology": ("Methodology", "#b7a3f0", "❖"),
    "writeup": ("Writeups", "#f0a24a", "▤"),
    "ctf": ("CTF", "#7ec98a", "⌖"),
    "linux": ("Linux", "#edb64a", "⊙"),
    "ai": ("AI / LLM", "#57d1cf", "✧"),
    "web3": ("Web3", "#9d8cf5", "⬢"),
    "reversing": ("Reversing", "#cf9a55", "↺"),
    "exploit-dev": ("Exploit dev", "#e0785a", "⟐"),
    "stego": ("Steganography", "#74aee6", "◑"),
    "pivoting": ("Pivoting", "#4fd0b8", "⤳"),
    "fuzzing": ("Fuzzing", "#c3d15a", "⁘"),
    "cloud": ("Cloud", "#62b6ef", "⌬"),
    "iot": ("IoT", "#5ec7ad", "⎔"),
    "mobile": ("Mobile", "#94cf68", "▢"),
    "forensics": ("Forensics", "#aab3bd", "⌕"),
    "ics": ("ICS / OT", "#e0a35c", "⎓"),
    "phishing": ("Phishing", "#dd8ac2", "◗"),
    "supply-chain": ("Supply chain", "#9aa4ac", "⧟"),
}
FALLBACK_META = ("#8b938d", "◆")  # grey diamond (last-resort only)


def category_meta(slug: str) -> tuple[str, str, str]:
    if slug in CATEGORY_META:
        return CATEGORY_META[slug]
    name = slug.replace("-", " ").title()
    return (name, *FALLBACK_META)


# --------------------------------------------------------------------------- #
# source provenance — friendly labels for the consolidation richness.
# We reuse the pipeline's SOURCE_LABELS / PERSONAL_SOURCES rather than keeping a
# divergent copy, so a slug renamed in the ingester stays in sync on the API.
# --------------------------------------------------------------------------- #
def source_label(slug: str) -> str:
    """Short friendly chip label for a source slug ("madstuff" -> "sec")."""
    return consolidate.SOURCE_LABELS.get(slug, slug)


def source_full(slug: str) -> str:
    """Full attribution for a source whose chip is a short alias (tooltip). Falls
    back to the friendly label when no distinct full form is registered."""
    full = getattr(consolidate, "SOURCE_LABELS_FULL", {})
    return full.get(slug, source_label(slug))


def source_facets(e: dict) -> dict[str, Any]:
    """Derive the consolidation-provenance facets the entry view surfaces.

    * ``primary_source_label`` — the spine source's friendly label.
    * ``also_covered_in_labels`` — friendly labels for the OTHER sources folded
      in (``meta.also_covered_in`` minus the spine, order-preserving, deduped).
    * ``source_count`` — distinct sources covering this entry (>=1).
    * ``from_your_notes`` — the entry's tested content is Zaid's own (spine is a
      personal source, or a personal source was folded in as trusted content).
    * ``variants`` — any labelled technique variants recorded during merge.
    """
    meta = e.get("meta") or {}
    spine = e.get("source", "")
    also = meta.get("also_covered_in") or []

    others: list[str] = []
    seen = {spine}
    for slug in also:
        if slug not in seen:
            seen.add(slug)
            others.append(source_label(slug))

    distinct = len(dict.fromkeys(also)) if also else 1
    from_notes = bool(meta.get("author_notes")) or spine in consolidate.PERSONAL_SOURCES
    variants = meta.get("variants") or []

    return {
        "primary_source_label": source_label(spine),
        "primary_source_full": source_full(spine),
        "also_covered_in_labels": others,
        "source_count": max(distinct, 1),
        "from_your_notes": from_notes,
        "variants": [str(v) for v in variants],
    }


# --------------------------------------------------------------------------- #
# in-memory KB state, populated at startup
# --------------------------------------------------------------------------- #
class _State:
    entries: list[dict] = []
    by_id: dict[str, dict] = {}
    by_category: dict[str, list[dict]] = {}
    stats: dict[str, int] = {}
    scripts: dict = {}  # the Scripts Arsenal index (pipeline/scripts_index.py)


STATE = _State()


def _load_scripts() -> dict:
    """Load the built Scripts Arsenal index (empty skeleton if not built yet)."""
    if SCRIPTS_PATH.exists():
        try:
            return json.loads(SCRIPTS_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"total": 0, "kb_entries": 0, "groups": []}


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
    STATE.scripts = _load_scripts()

    # engagement sessions live in a local SQLite file (gitignored).
    sessions_db.init_db()
    # cockpit run-records share that SQLite file (gitignored).
    cockpit_runstore.init_db()
    yield
    STATE.entries = []
    STATE.by_id = {}
    STATE.by_category = {}
    STATE.stats = {}
    STATE.scripts = {}


app = FastAPI(
    title="HackPit API",
    version="0.1.0",
    description="Knowledge base + hybrid search for the HackPit companion.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["*"],
)

# Cockpit — live, human-approved execution against the isolated lab (see cockpit/).
app.include_router(cockpit_router)


# --------------------------------------------------------------------------- #
# search helper shared by /search and the attack-path retrieval: degrade a
# non-lexical mode to lexical if the vector half is unavailable (Ollama down)
# rather than failing the whole request.
# --------------------------------------------------------------------------- #
def _resilient_search(q: str, top: int, mode: str) -> list[dict]:
    try:
        return kb_search.search(STATE.entries, q, top, mode=mode)
    except (Exception, SystemExit):
        if mode == "lexical":
            raise
        return kb_search.search(STATE.entries, q, top, mode="lexical")


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


class ScriptSource(BaseModel):
    id: str
    title: str
    category: str = ""


class ScriptItem(BaseModel):
    id: str = Field(description="Stable per-group id ({type}-{n}).")
    label: str = Field(description="Short human label ('bash · reverse shell').")
    lang: str
    code: str = Field(description="The copyable script/payload, verbatim.")
    type: str
    reuse: int = Field(description="How many entries this script appears in.")
    sources: list[ScriptSource] = Field(description="Entries it was lifted from (capped).")
    source_total: int = Field(description="Total distinct source entries (>= len(sources)).")


class ScriptGroup(BaseModel):
    type: str
    label: str
    icon: str
    color: str
    count: int = Field(description="Distinct scripts of this type.")
    shown: int = Field(description="Scripts included (may be < count under the cap).")
    scripts: list[ScriptItem] = Field(default_factory=list)


class ScriptsResponse(BaseModel):
    total: int
    kb_entries: int = Field(default=0, description="Entries scanned to build the arsenal.")
    groups: list[ScriptGroup] = Field(default_factory=list)


class ScriptGroupSummary(BaseModel):
    type: str
    label: str
    icon: str
    color: str
    count: int


class ScriptsSummary(BaseModel):
    total: int
    groups: list[ScriptGroupSummary] = Field(default_factory=list)


class EntrySummary(BaseModel):
    id: str
    title: str
    summary: str
    tags: list[str]
    tier: int
    source: str
    source_label: str = Field(default="", description="Short friendly source label (chip text).")
    category: str
    source_count: int = Field(
        default=1, description="Distinct sources consolidated into this entry (>=1)."
    )


class EntryOut(Entry):
    """The canonical Entry plus the resolved source-provenance facets the entry
    view renders (friendly labels, source count, from-your-notes)."""

    primary_source_label: str = Field(description="Short friendly label for the spine source (chip).")
    primary_source_full: str = Field(
        default="", description="Full attribution for the spine source (tooltip)."
    )
    also_covered_in_labels: list[str] = Field(
        default_factory=list,
        description="Friendly labels for the other sources folded in (spine excluded).",
    )
    source_count: int = Field(default=1, description="Distinct sources covering this entry.")
    from_your_notes: bool = Field(
        default=False, description="True when the entry's tested content is your own notes."
    )
    variants: list[str] = Field(
        default_factory=list, description="Labelled technique variants recorded on merge."
    )


class SearchHit(BaseModel):
    rank: int
    score: float
    id: str
    title: str
    category: str
    source: str
    source_label: str = Field(default="", description="Short friendly source label (chip text).")
    tier: int | None = None
    snippet: str
    source_count: int = Field(
        default=1, description="Distinct sources consolidated into this entry (>=1)."
    )


class SearchResponse(BaseModel):
    query: str
    mode: str = Field(description="Search mode actually used.")
    requested_mode: str
    fell_back: bool = Field(
        description="True if the requested mode degraded to lexical (e.g. Ollama down)."
    )
    count: int
    results: list[SearchHit]


# ---- LLM config (guided attack paths) ------------------------------------ #
class LLMConfigOut(BaseModel):
    provider: str = Field(
        description="ollama | openai | anthropic | openrouter | claude-agent-sdk."
    )
    model: str
    has_key: bool = Field(
        description="Whether a key is stored (never the key itself). Always false "
        "for local providers (ollama, claude-agent-sdk)."
    )


class LLMConfigIn(BaseModel):
    provider: str
    model: str | None = None
    api_key: str | None = Field(default=None, description="Never returned or logged.")


# ---- attack path --------------------------------------------------------- #
class AttackPathIn(BaseModel):
    goal: str = Field(min_length=3, description="Free-text target/goal description.")
    target_type: str | None = Field(
        default=None, description="Optional chip: pentest | bugbounty | ctf | ad."
    )
    scope_text: str | None = Field(
        default=None,
        description="Optional pasted scope / Rules of Engagement. Fed to the target "
        "profiler; forbidden paths/hosts are dropped from the composed path.",
    )


class AttackStep(BaseModel):
    id: str = Field(description="Stable per-step id ({phase}-{n}) for engagement state.")
    title: str
    entry_id: str = Field(
        default="",
        description="Cited KB entry — links to /entry/{id}. Empty for an "
        "AI-suggested step (no KB citation).",
    )
    why: str = Field(description="1–2 line rationale for this step.")
    commands: list[Code] = Field(
        description="Commands for this step. For grounded/writeup steps these are "
        "the entry's real commands; for AI-suggested steps they are the model's "
        "own, unverified."
    )
    ai_suggested: bool = Field(
        default=False,
        description="True = general-knowledge gap-fill (not from the KB), render "
        "distinctly with a 'verify' badge. False = grounded in the KB / writeup.",
    )
    from_writeup: bool = Field(
        default=False,
        description="True = a PRIMARY step lifted from the user's own box writeup "
        "(trusted). False = a composed/supplement step.",
    )
    target_adaptation: str | None = Field(
        default=None,
        description="Optional one-line guidance (grounded steps only) bridging the "
        "technique's generic example commands to THIS target, naming only real "
        "hosts/endpoints/accounts from the goal/scope. Prose, never a runnable "
        "command; the step's real commands are unchanged. Absent when it can't be "
        "adapted confidently.",
    )
    on_success: str | None = Field(
        default=None,
        description="Optional branch hint — what this finding unlocks / the next "
        "action or step to jump to. Present only where a real branch exists.",
    )
    on_blocked: str | None = Field(
        default=None,
        description="Optional branch hint — the pivot if this step 403s or fails. "
        "Present only where a real branch exists.",
    )


class AttackPhase(BaseModel):
    phase: str
    label: str
    steps: list[AttackStep]


class BoxWriteup(BaseModel):
    id: str = Field(description="Writeup entry id — links to /entry/{id}.")
    title: str
    tier: int


class TargetProfile(BaseModel):
    """What KIND of target this is — steers retrieval + composition and drives the
    'why these steps' chips. All fields empty when the profiler was unavailable."""

    target_class: str | None = Field(
        default=None, description="Short label, e.g. 'multi-tenant SaaS'."
    )
    tech_signals: list[str] = Field(default_factory=list)
    priority_bug_classes: list[str] = Field(
        default_factory=list,
        description="Target-specific bug classes to probe first (drives the query "
        "bias and the 'why these steps' chips).",
    )
    out_of_scope: list[str] = Field(
        default_factory=list, description="Paths/hosts the RoE forbids."
    )


class AttackPathOut(BaseModel):
    goal: str
    target_type: str | None
    target: str | None = Field(
        default=None,
        description="Target (IP/host/URL) parsed from the goal and substituted "
        "into step commands; null if none was detectable.",
    )
    phases: list[AttackPhase]
    profile: TargetProfile = Field(
        default_factory=TargetProfile,
        description="Inferred target profile that steered this path (target class + "
        "priority bug classes). Empty when the profiler was unavailable.",
    )
    scoped: bool = Field(
        default=False,
        description="True when one or more steps were dropped for touching an "
        "out-of-scope path/host from the pasted RoE.",
    )
    box_writeup: BoxWriteup | None = Field(
        default=None,
        description="A full writeup for the named box, surfaced as a link; also "
        "the source when origin=='writeup'. Null when the goal doesn't name a box "
        "we have a writeup for.",
    )
    origin: str = Field(
        default="composed",
        description="'writeup' = path built from the user's own box walkthrough; "
        "'composed' = KB-grounded + AI-suggested composition.",
    )
    origin_label: str | None = Field(
        default=None,
        description="Banner label when origin=='writeup', e.g. 'from your "
        "writeup: <box>'.",
    )
    origin_note: str | None = Field(
        default=None,
        description="Caveat for the origin, e.g. a 'source formatting damaged' "
        "note when the writeup's export was mangled.",
    )
    augmented: bool = Field(
        default=False,
        description="Writeup origin only: True when the LLM added grounded/"
        "AI-suggested supplement steps beyond the writeup's own steps.",
    )
    model_used: str
    provider: str


# ---- engagement sessions ------------------------------------------------- #
class SessionCreateIn(BaseModel):
    goal: str = Field(min_length=1)
    target_type: str | None = None
    path: dict = Field(description="A composed attack-path (the /attack-path output).")


class SessionCreateOut(BaseModel):
    id: str


class SessionSummary(BaseModel):
    id: str
    label: str
    goal: str
    target_type: str | None
    checked: int
    total: int
    created_at: str
    updated_at: str


class ChatTurn(BaseModel):
    role: str = Field(description='"user" | "assistant".')
    content: str
    ts: str
    cited_entry_ids: list[str] = Field(
        default_factory=list,
        description="KB entries the assistant cited (assistant turns only).",
    )


class SessionDetail(BaseModel):
    id: str
    label: str
    goal: str
    target_type: str | None
    created_at: str
    updated_at: str
    checked: int
    total: int
    # the composed path with per-step `checked` + `result_text` merged in
    path: dict
    # the last generated report (Markdown) + when, if any
    report_md: str | None = None
    report_generated_at: str | None = None
    # the engagement assistant's persisted conversation
    chat_history: list[ChatTurn] = Field(default_factory=list)


class ChatIn(BaseModel):
    message: str = Field(min_length=1, description="The tester's chat message.")


class ChatOut(BaseModel):
    reply: str = Field(description="The assistant's reply, as Markdown.")
    cited_entry_ids: list[str] = Field(
        default_factory=list,
        description="Grounded KB entries the reply drew on (link to /entry/{id}).",
    )
    model_used: str
    ts: str


class ReportOut(BaseModel):
    report_md: str = Field(description="The generated report as Markdown.")
    report_generated_at: str
    model_used: str


class StepUpdateIn(BaseModel):
    checked: bool | None = None
    result: str | None = None


class StepStateOut(BaseModel):
    checked: bool
    result_text: str


class SessionRenameIn(BaseModel):
    label: str = Field(min_length=1)


# --- the orchestrator loop: propose the NEXT single command (no execution) ---
class LoopProposeIn(BaseModel):
    avoid: list[str] = Field(
        default_factory=list,
        description="Command lines the operator skipped — propose something different.",
    )


class LoopProposal(BaseModel):
    command: str = Field(description="Proposed allowlisted command (e.g. 'nmap').")
    args: list[str] = Field(description="Proposed argv tokens (targeting the lab).")
    rationale: str = Field(description="Why the agent proposes this as the next step.")
    step_id: str | None = Field(
        None, description="The plan step id this realizes, if any."
    )
    gate_ok: bool = Field(
        description="Advisory pre-check: does this pass the M1 allowlist + target-lock? "
        "The executor re-checks all gates at run time; a false proposal is never auto-run."
    )
    gate_reason: str = Field(
        description="Why the pre-check failed (empty when gate_ok)."
    )
    dangerous_flags: list[str] = Field(
        default_factory=list,
        description="Escalation flags DETECTED in this proposal (never blocked). When "
        "non-empty the UI shows them RED and approve requires an explicit confirmation; "
        "the executor's danger gate re-checks this at run time.",
    )


class LoopProposeOut(BaseModel):
    done: bool = Field(description="True when the agent proposes no further step.")
    proposal: LoopProposal | None = Field(
        None, description="The next proposed command — NOT executed; awaits human approval."
    )
    reason: str | None = Field(None, description="Why the loop is done, when done.")


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
            source_label=source_label(e.get("source", "")),
            category=e.get("category", slug),
            source_count=source_facets(e)["source_count"],
        )
        for e in items
    ]


@app.get("/scripts", response_model=ScriptsResponse)
def scripts() -> dict[str, Any]:
    """The full Scripts Arsenal — every runnable script/payload extracted and
    deduped from the KB, grouped by type, with per-script source attribution."""
    data = STATE.scripts or {"total": 0, "kb_entries": 0, "groups": []}
    # kb_entries is a build-time count over the raw entries file (pre-exclusion).
    # Report the actual *served* KB size so the arsenal's "deduped from N entries"
    # line always matches /stats total_entries and the home counter, regardless of
    # when the arsenal index was last built.
    return {**data, "kb_entries": len(STATE.entries)}


@app.get("/scripts/summary", response_model=ScriptsSummary)
def scripts_summary() -> dict[str, Any]:
    """Lightweight arsenal counts (no script bodies) — feeds the home card."""
    groups = [
        {"type": g["type"], "label": g["label"], "icon": g["icon"],
         "color": g["color"], "count": g["count"]}
        for g in (STATE.scripts.get("groups") or [])
    ]
    return {"total": STATE.scripts.get("total", 0), "groups": groups}


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
        try:
            hits = kb_search.search(STATE.entries, q, top, mode="lexical")
        except (Exception, SystemExit):
            raise HTTPException(status_code=500, detail="lexical search failed")

    results = [
        SearchHit(
            rank=h["rank"],
            score=h["score"],
            id=h["id"],
            title=h["title"],
            category=h["category"],
            source=h["source"],
            source_label=source_label(h["source"]),
            tier=h.get("tier"),
            snippet=h["snippet"],
            source_count=source_facets(STATE.by_id[h["id"]])["source_count"]
            if h["id"] in STATE.by_id
            else 1,
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


@app.get("/entry/{entry_id}", response_model=EntryOut)
def entry(entry_id: str) -> dict[str, Any]:
    """The full canonical Entry (steps, copyable commands, body, refs, meta) plus
    resolved source-provenance facets (friendly labels, source count, from-your-
    notes) so the entry view can surface the consolidation richness."""
    e = STATE.by_id.get(entry_id)
    if e is None:
        raise HTTPException(status_code=404, detail=f"unknown entry: {entry_id}")
    return {**e, **source_facets(e)}


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


# --------------------------------------------------------------------------- #
# generative: LLM config + guided attack paths
# --------------------------------------------------------------------------- #
@app.get("/llm-config", response_model=LLMConfigOut)
def get_llm_config() -> dict[str, Any]:
    """Current LLM provider/model + whether a key is stored. NEVER the key."""
    return llm.public_config()


@app.post("/llm-config", response_model=LLMConfigOut)
def set_llm_config(cfg: LLMConfigIn = Body(...)) -> dict[str, Any]:
    """Persist provider/model (+ optional key) to the gitignored config file.

    The key is written to disk only and never returned. Default stays local
    Ollama, which needs no key.
    """
    try:
        return llm.save_config(cfg.provider, cfg.model, cfg.api_key)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


class OllamaModelsOut(BaseModel):
    """Model names pulled in the local Ollama, for the settings model picker."""

    models: list[str] = Field(default_factory=list)


@app.get("/ollama-models", response_model=OllamaModelsOut)
def get_ollama_models() -> dict[str, Any]:
    """Names of models pulled locally (proxies Ollama /api/tags), so the settings
    picker offers what's actually installed. Returns an empty list on any error
    (Ollama down) — never 500 — so the UI degrades to a free-text input."""
    return {"models": llm.list_ollama_models()}


@app.post("/attack-path", response_model=AttackPathOut)
def attack_path_compose(req: AttackPathIn = Body(...)) -> dict[str, Any]:
    """Compose an ordered, KB-grounded attack walkthrough for a goal.

    Retrieval uses the existing hybrid search across phases; composition uses
    the configured LLM (default local Ollama). Every returned step cites a real
    KB entry and carries that entry's real commands — steps the model invents or
    miscites are dropped in the grounding pass.
    """
    goal = req.goal.strip()
    if not goal:
        raise HTTPException(status_code=400, detail="goal is required")
    try:
        return attack_path.compose(
            STATE.by_id, goal, req.target_type, _resilient_search, req.scope_text
        )
    except llm.LLMError as e:
        # Ollama offline / no key / unparseable output / nothing grounded.
        raise HTTPException(status_code=503, detail=str(e))


# --------------------------------------------------------------------------- #
# engagement sessions — save a composed path and work it interactively
# --------------------------------------------------------------------------- #
@app.post("/sessions", response_model=SessionCreateOut, status_code=201)
def create_session(req: SessionCreateIn = Body(...)) -> dict[str, str]:
    """Create a saved engagement from a composed attack-path. Returns its id."""
    if not req.path.get("phases"):
        raise HTTPException(status_code=400, detail="path has no phases")
    sid = sessions_db.create_session(req.goal.strip(), req.target_type, req.path)
    return {"id": sid}


@app.get("/sessions", response_model=list[SessionSummary])
def list_sessions() -> list[dict[str, Any]]:
    """All saved engagements (newest-updated first) with checked/total progress."""
    return sessions_db.list_sessions()


@app.get("/sessions/{session_id}", response_model=SessionDetail)
def get_session(session_id: str) -> dict[str, Any]:
    """Full engagement: metadata + the path with per-step state merged in."""
    s = sessions_db.get_session(session_id)
    if s is None:
        raise HTTPException(status_code=404, detail="session not found")
    return s


@app.patch("/sessions/{session_id}/steps/{step_id}", response_model=StepStateOut)
def update_session_step(
    session_id: str, step_id: str, req: StepUpdateIn = Body(...)
) -> dict[str, Any]:
    """Partially update one step's state (checked and/or pasted result)."""
    if req.checked is None and req.result is None:
        raise HTTPException(status_code=400, detail="nothing to update")
    res = sessions_db.update_step(session_id, step_id, req.checked, req.result)
    if res is None:
        raise HTTPException(
            status_code=404, detail="session or step not found"
        )
    return res


@app.patch("/sessions/{session_id}", response_model=SessionSummary)
def rename_session(
    session_id: str, req: SessionRenameIn = Body(...)
) -> dict[str, Any]:
    """Rename an engagement (its label)."""
    if not sessions_db.rename_session(session_id, req.label):
        raise HTTPException(status_code=404, detail="session not found")
    s = sessions_db.get_session(session_id)
    assert s is not None  # just renamed it
    return s


@app.delete("/sessions/{session_id}", status_code=204)
def delete_session(session_id: str) -> None:
    """Delete an engagement and all its step state."""
    if not sessions_db.delete_session(session_id):
        raise HTTPException(status_code=404, detail="session not found")


@app.post("/sessions/{session_id}/report", response_model=ReportOut)
def generate_report(session_id: str) -> dict[str, Any]:
    """Draft a pentest report from the session, persist it, and return it.

    Grounded in the session's completed steps + pasted evidence (see
    ``report.py``). Long-form output, so this is slower on the local model.
    """
    session = sessions_db.get_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="session not found")
    # Fold in any recorded cockpit sandbox runs so the report reflects what was
    # actually executed (commands + captured output), not just checked-off steps.
    runs = cockpit_runstore.list_runs_for_session(session_id)
    if runs:
        session["execution_runs"] = [r.model_dump() for r in runs]
    try:
        report_md, model_used = report_gen.compose_report(session)
    except llm.LLMError as e:
        raise HTTPException(status_code=503, detail=str(e))

    ts = sessions_db.save_report(session_id, report_md)
    if ts is None:  # deleted between fetch and save — unlikely
        raise HTTPException(status_code=404, detail="session not found")
    return {
        "report_md": report_md,
        "report_generated_at": ts,
        "model_used": model_used,
    }


@app.post("/sessions/{session_id}/loop/propose", response_model=LoopProposeOut)
def loop_propose(session_id: str, req: LoopProposeIn = Body(default=None)) -> dict[str, Any]:
    """Propose the NEXT single recon command for the guided loop — does NOT execute.

    Reads the session's composed plan + its recorded cockpit runs (the results so far)
    and asks the LLM for the one next allowlisted command against the isolated lab. The
    returned proposal is a SUGGESTION only: it is not run here, and it advances nothing.
    Execution happens separately through POST /cockpit/exec (the M1 executor, all four
    gates), only after a human approves. See docs/cockpit-loop.md.
    """
    session = sessions_db.get_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="session not found")
    plan = session.get("path") or {}
    runs = [r.model_dump() for r in cockpit_runstore.list_runs_for_session(session_id)]
    avoid = list(req.avoid) if req and req.avoid else []
    try:
        return orchestrator.propose_next(plan, runs, llm.load_config(), avoid)
    except llm.LLMError as e:
        raise HTTPException(status_code=503, detail=str(e))


@app.post("/sessions/{session_id}/chat", response_model=ChatOut)
def session_chat(session_id: str, req: ChatIn = Body(...)) -> dict[str, Any]:
    """One assistant turn for an engagement: answer the tester's message, grounded
    in the session context + the KB, then persist both turns on the session.

    Retrieval reuses the hybrid search; composition uses the configured LLM
    (default local Ollama). The reply reuses real KB commands and cites real
    entries — nothing is invented (see ``chat.py``).
    """
    message = req.message.strip()
    if not message:
        raise HTTPException(status_code=400, detail="message is required")
    session = sessions_db.get_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="session not found")
    try:
        reply, cited, model_used = chat_assistant.answer(
            STATE.by_id, session, message, _resilient_search
        )
    except llm.LLMError as e:
        # Ollama offline / no key / unparseable output.
        raise HTTPException(status_code=503, detail=str(e))

    ts = sessions_db.append_chat(session_id, message, reply, cited)
    if ts is None:  # deleted between fetch and append — unlikely
        raise HTTPException(status_code=404, detail="session not found")
    return {
        "reply": reply,
        "cited_entry_ids": cited,
        "model_used": model_used,
        "ts": ts,
    }
