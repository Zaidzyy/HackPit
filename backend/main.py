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
from cockpit import engagement as cockpit_engagement  # noqa: E402
from cockpit import reconcile as cockpit_reconcile  # noqa: E402
from cockpit import loot as cockpit_loot  # noqa: E402
from cockpit import winprofiles as cockpit_winprofiles  # noqa: E402  (Windows target store)
# The two evasion/exfil surfaces. Their ROUTES live here, not in cockpit/router.py, and NOT in
# any orchestrator/loop module: see the "Sliver C2 + DNS-tunnel obfuscation" section below.
from cockpit import sliver as cockpit_sliver  # noqa: E402  (Sliver C2 — human-only + gated gen)
from cockpit import obfuscation as cockpit_obfuscation  # noqa: E402  (DNS tunnel — human-only)
from evasion import engine as evasion_engine  # noqa: E402  (generate-only artifact producer)
import state as engagement_state  # noqa: E402
from state import store as state_store  # noqa: E402
from state import tasks as state_tasks  # noqa: E402
from state import credvault  # noqa: E402
from cockpit.router import router as cockpit_router  # noqa: E402
from adgraph import store as ad_store  # noqa: E402  (backend/adgraph — AD attack-path graph)
from adgraph.router import (  # noqa: E402
    router as ad_router,
    set_grounder,
    set_scope_resolver as set_ad_scope_resolver,
)
from detection.router import (  # noqa: E402  (backend/detection — purple-team footprint)
    router as detection_router,
    set_run_lookup as set_detection_run_lookup,
    set_runs_lookup as set_detection_runs_lookup,
)
from codescan.router import (  # noqa: E402  (backend/codescan — STATIC AppSec analysis)
    router as codescan_router,
    set_kb as set_codescan_kb,
)
from arsenal import loader as arsenal_loader  # noqa: E402  (backend/arsenal — tool catalog)
from arsenal.router import (  # noqa: E402
    router as arsenal_router,
    set_arsenal as set_arsenal_catalog,
)
from exploits.router import router as exploits_router  # noqa: E402  (backend/exploits — CVE index)

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
    # engagement-mode records (deliberate real-target entry) share it too.
    cockpit_engagement.init_db()
    # saved Windows-target connection profiles (WinRM driver) share it too.
    cockpit_winprofiles.init_db()
    # parsed AD attack-path graphs share it too.
    ad_store.init_db()
    # structured engagement state (hosts/services/endpoints/credentials/findings) + the
    # task tree share it too. This is what the orchestrator reasons over instead of
    # re-reading stdout tails.
    engagement_state.init_db()
    # :code scan — hand the KB to the SAST panel so a finding can point at the technique
    # behind it. Optional by design: with no KB the scan runs identically, just unlinked.
    set_codescan_kb(
        STATE.by_id,
        _resilient_search,
        attack_path.is_step_eligible,
        lambda e: not attack_path.is_broad_reference(e),
    )
    # Tool arsenal — load the catalog once and resolve its KB links against the live KB, so
    # a step's arsenal tag can point at the entry that documents that tool. Best-effort: a
    # catalog problem leaves an empty arsenal and composition behaves as it did before.
    try:
        loaded = arsenal_loader.load()
        arsenal_loader.link_kb(loaded, STATE.by_id, attack_path.is_step_eligible)
        attack_path.set_arsenal(loaded)
        set_arsenal_catalog(loaded)
        # STARTUP RECONCILIATION (D7): ask the sandbox which catalogued tools it actually
        # has. This is what closes the loop that let the catalog claim 73 tools while the
        # image shipped 7 — the planner's prompt block is filtered by the answer, so it can
        # no longer propose a tool that is not installed. Runs on a background thread: the
        # probe shells out to Docker, which can be slow or absent, and app start must never
        # wait on it. Until it lands, availability reads as "unknown" and nothing is filtered.
        cockpit_reconcile.check_in_background(loaded)
    except Exception:  # noqa: BLE001 - never fail startup over the catalog
        pass
    yield
    set_codescan_kb(None, None, None, None)
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
# AD attack-path graph (see adgraph/). Read-only graph/parse/path/technique endpoints; every
# abuse command it surfaces still runs ONLY through the cockpit executor above.
app.include_router(ad_router)
# Detection footprint (see detection/). READ-ONLY purple-team annotation: what a DEFENDER would
# see for a command/step/run — ATT&CK tag, telemetry, the Sigma rule that would fire, loudness.
# It executes nothing and changes no gate; it only describes.
app.include_router(detection_router)
# :code scan (see codescan/). STATIC application-security analysis: it READS a codebase with
# Semgrep/Bandit and reports what they find. It never executes the scanned code, takes no
# target, and shares nothing with the engagement/executor/target-lock/scope/isolation model —
# a self-contained analysis utility that happens to live in the same backend.
app.include_router(codescan_router)
# Tool arsenal (see arsenal/). READ-ONLY catalog: tool descriptions + invocation TEMPLATES the
# planner draws on. It executes nothing and restricts nothing — a rendered invocation is a
# string, and it runs only through the gated cockpit executor with an explicit human approval.
app.include_router(arsenal_router)
# CVE -> exploit index (see exploits/). READ-ONLY keyed lookup over the sandbox's local
# exploit-db catalogue: service+version -> CVE -> public exploit, the OSCP inner loop. It
# is deliberately NOT a KB source — that query wants an exact table, not prose retrieval.
# A hit is information plus a path inside the sandbox; running it is a separate, gated,
# human-approved command like every other.
app.include_router(exploits_router)


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


# Only these KB categories may GROUND an AD abuse edge — so a network-scan / web entry can
# never supply the command for an ACL/delegation/DCSync abuse (that would look authoritative
# but be wrong). If nothing AD-relevant matches, the technique's own catalog template is used
# (ai_suggested), exactly like the kill-chain map falls back to general knowledge.
_AD_GROUND_CATEGORIES = frozenset({"active-directory", "windows"})


def _ad_kb_grounder(seeds: str) -> dict | None:
    """Ground an AD abuse edge in the KB: the best AD-relevant entry (with commands) for the
    technique's seed terms, via the SAME hybrid search + entry_commands the attack-path composer
    uses. Returns ``{id, title, commands}`` or None (→ the catalog fallback / ai_suggested).
    Restricted to AD/Windows entries so an off-topic hit can't mis-ground the abuse. The AD
    graph router calls this via set_grounder so adgraph has no import cycle with the app.
    """
    try:
        hits = _resilient_search(seeds, 8, "hybrid")
    except Exception:
        return None
    for h in hits:
        e = STATE.by_id.get(h.get("id"))
        if not e or e.get("category") not in _AD_GROUND_CATEGORIES:
            continue
        cmds = attack_path.entry_commands(e)
        if cmds:
            return {"id": e["id"], "title": e.get("title") or e["id"], "commands": cmds}
    return None


# Wire the KB grounder into the AD graph router (technique endpoint uses it for grounding).
set_grounder(_ad_kb_grounder)


def _detection_run_lookup(run_id: str) -> dict | None:
    """Read one recorded cockpit run for the detection panel to ANNOTATE. Read-only."""
    rec = cockpit_runstore.get_run(run_id)
    return rec.model_dump() if rec is not None else None


def _detection_runs_lookup(session_id: str) -> list[dict]:
    """Read an engagement's recorded runs for the detection panel to TAG. Read-only."""
    return [r.model_dump() for r in cockpit_runstore.list_runs_for_session(session_id)]


# Wire the run lookups into the detection router (so /detection/footprint/run/{id} and
# /detection/runs can describe what runs left behind). READ path only — the detection package
# never executes anything, and the cockpit package is untouched by this feature.
set_detection_run_lookup(_detection_run_lookup)
set_detection_runs_lookup(_detection_runs_lookup)


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


class ScriptFile(BaseModel):
    """A tool FILE on disk rather than a copyable snippet (D12 — `oscp_tools`).

    Present only on rows the corpus ingester contributed. The row's `code` is a short
    preview, never the whole file, so the UI shows a path to copy instead of a payload.
    """

    name: str
    rel_path: str = Field(description="Path within the source tool tree.")
    host_path: str = Field(description="Absolute path on this machine.")
    bytes: int
    sha256: str
    platform: str = Field(description="windows | linux | any.")
    runs_here: bool = Field(description="False for Windows-only tooling (D9) — kept, marked.")
    source: str


class ScriptItem(BaseModel):
    id: str = Field(description="Stable per-group id ({type}-{n}).")
    label: str = Field(description="Short human label ('bash · reverse shell').")
    lang: str
    code: str = Field(description="The copyable script/payload, verbatim.")
    type: str
    reuse: int = Field(description="How many entries this script appears in.")
    sources: list[ScriptSource] = Field(description="Entries it was lifted from (capped).")
    source_total: int = Field(description="Total distinct source entries (>= len(sources)).")
    file: ScriptFile | None = Field(
        default=None, description="Set when this row is a tool file, not a snippet."
    )


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
    tool_files: int = Field(default=0, description="Rows backed by a file on disk (D12).")
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
    attck: dict[str, Any] | None = Field(
        default=None,
        description="DETECTION FOOTPRINT TAG (purple-team, read-only). The MITRE ATT&CK "
        "technique(s) + tactic this step's first command maps to, plus a loud-vs-quiet "
        "rating — i.e. what a DEFENDER would see if this step ran. Derived deterministically "
        "from the curated ATT&CK/SigmaHQ map (no LLM); null when the command is not in that "
        "map. Describes detection only — it is never guidance on avoiding it.",
    )
    arsenal: dict[str, Any] | None = Field(
        default=None,
        description="TOOL ARSENAL PROVENANCE. Which catalogued tool this step actually runs "
        "({tool, category, purpose, kb_entry_id, docs}), read deterministically from the "
        "command's own program name — never from anything the model claimed. Null when the "
        "step runs no catalogued tool. Informational: it does NOT mean the command was "
        "verified, and it changes nothing about how the step runs — every command still "
        "clears the same executor gates.",
    )
    foreign_refs: list[str] | None = Field(
        default=None,
        description="HONESTY MARKER. Hosts / AD domains still named in this step's commands "
        "that are NOT this engagement's target and could not be confidently rewritten — a "
        "KB command written for another environment (MARVEL.local, 192.168.1.10). The step "
        "needs adjusting before it is run against your target. Nothing is ever guessed in "
        "their place: a fabricated domain would be worse than a visible gap. Null when the "
        "step's commands reference nothing foreign. Plan quality only — the executor's "
        "target/scope lock is what actually refuses a foreign host.",
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


class ContextSource(BaseModel):
    """CHANNEL 2 — a document the planner READ as background (see
    backend/context_channel.py). Its content shaped technique choice and the
    plan's flow; it never became a step, and its presence here changes no step's
    grounded/ai_suggested label."""

    kind: str = Field(description="'writeup' | 'methodology'.")
    id: str = Field(description="KB entry id — links to /entry/{id}.")
    title: str
    chars: int = Field(description="Size of the injected excerpt (budgeted).")


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
    context_sources: list[ContextSource] = Field(
        default_factory=list,
        description="Channel 2: the writeup / methodology docs whose CONTENT was "
        "injected as reasoning background. Empty when nothing matched (Channel 2 "
        "was then a no-op and the composition is identical to pre-Channel-2).",
    )
    context_leaks: int = Field(
        default=0,
        description="How many box-specific literals from that background were "
        "caught in the model's output and re-pointed at the target or dropped. "
        "Plan quality only — the executor's target/scope lock is the backstop.",
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
    # the model that actually generated the persisted report (for correct
    # attribution after the active LLM config changes); null for old reports
    report_model: str | None = None
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
    engagement_id: str | None = Field(
        None,
        description="When set to an ACTIVE engagement id, the loop drafts against THAT "
        "engagement's real target + authorized program scope instead of the isolated lab. "
        "An unknown/exited id is refused (409) — never silently downgraded to lab. The "
        "proposal is still only a draft: nothing runs until the operator approves it, and "
        "the executor re-checks every gate then.",
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


@app.get("/sessions/{session_id}/state")
def session_state(session_id: str) -> dict[str, Any]:
    """The accumulated engagement state — hosts, services, endpoints, credentials, findings
    — plus the live task tree.

    This is what the orchestrator reasons over. Secrets are included: they are already in
    the run records this was parsed from, and the operator needs them to drive the tools.
    """
    summary = state_store.load(session_id)
    return {
        **summary.to_dict(include_secrets=True),
        "tasks": [t.to_dict() for t in state_tasks.load(session_id)],
        "task_progress": state_tasks.progress(session_id),
    }


class CredFillIn(BaseModel):
    """Fill a command's credential placeholders from one captured credential."""

    command: str = Field(..., description="The command draft, with <user>/<password>/… placeholders.")
    kind: str = Field(..., description="Credential kind (password / ntlm / …).")
    principal: str = Field(..., description="Account name.")
    domain: str = Field("", description="Domain / realm, if any.")


@app.post("/sessions/{session_id}/credentials/fill")
def fill_credential(session_id: str, req: CredFillIn = Body(...)) -> dict[str, Any]:
    """Substitute a captured credential's values into a command's placeholders (step 14).

    The operator picks a credential and a command; this returns the command with
    <user>/<password>/<hash>/<domain> filled from that credential — one click instead of
    retyping a hash. The placeholder→field mapping lives server-side (state/credvault.py) so
    it cannot drift from what the loop/planner would use. Fills credential placeholders only;
    <target> and operational placeholders are left untouched. Nothing runs — this returns a
    string; the filled command still goes through the executor's gates like any other.
    """
    cred = next(
        (
            c
            for c in state_store.load(session_id).credentials
            if c.kind.lower() == req.kind.strip().lower()
            and c.principal.lower() == req.principal.strip().lower()
            and c.domain.lower() == req.domain.strip().lower()
        ),
        None,
    )
    if cred is None:
        raise HTTPException(status_code=404, detail="no such credential in this engagement")
    filled, used = credvault.fill(req.command, cred)
    return {"command": filled, "filled": used}


class ProofIn(BaseModel):
    """Set a host's local.txt / proof.txt flag by hand (the operator pastes it)."""

    address: str = Field(..., description="The host the flag belongs to (IP or hostname).")
    kind: str = Field(..., description="'local' (user foothold) or 'proof' (root/SYSTEM).")
    value: str = Field("", description="The flag. Empty clears it.")


@app.post("/sessions/{session_id}/state/proof")
def set_proof(session_id: str, req: ProofIn = Body(...)) -> dict[str, Any]:
    """Record a captured local.txt/proof.txt flag against a host (Phase 4 item 5).

    Flags are also captured automatically when a command reads a flag file (state/parsers.py);
    this is the manual paste path. The flag drives the OSCP report's per-host proof table, so it
    never has to be retyped at report time — the transcription the project already refuses to let
    the model do. Nothing runs.
    """
    try:
        host = state_store.set_proof(session_id, req.address, req.kind, req.value)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return {"address": host.address, "local_txt": host.local_txt,
            "proof_txt": host.proof_txt, "ownership": host.ownership()}


@app.post("/sessions/{session_id}/state/tasks/seed")
def seed_session_tasks(session_id: str) -> dict[str, Any]:
    """Seed the task tree from the composed plan's phases.

    Idempotent per session: a session that already has tasks is left alone, so re-plotting
    the attack path can never wipe the progress recorded against the existing tree.
    """
    session = sessions_db.get_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="session not found")
    plan = session.get("path") or {}
    titles: list[str] = []
    for phase in plan.get("phases") or []:
        name = str(phase.get("name") or phase.get("phase") or "").strip()
        if name:
            titles.append(name)
    if not titles:
        titles = ["Recon", "Enumeration", "Exploitation", "Privilege escalation", "Post-exploitation"]
    made = state_tasks.seed(session_id, titles)
    return {"tasks": [t.to_dict() for t in made], "progress": state_tasks.progress(session_id)}


@app.get("/tools")
def tool_reconciliation(
    refresh: bool = False, windows_profile_id: str | None = None
) -> dict[str, Any]:
    """Which catalogued tools the sandbox ACTUALLY has (D7).

    Per-target: pass ``windows_profile_id`` to reconcile against a selected WINDOWS box
    instead of the Linux sandbox — Windows-only tools become runnable and Linux-only ones N/A
    (availability is per active target, never a global flip). Omit it for the Linux view.

    This is the check that would have caught the 73-catalogued / 7-installed gap on day one,
    and it keeps catching it every time the image changes. The same answer filters the
    planner's prompt block, so a catalogued-but-missing tool can never be proposed.

    * ``missing``      catalogued Linux tools the sandbox does not have — a real gap.
    * ``windows_only`` PowerShell/.NET entries that cannot run on a Linux sandbox by
      construction (D9). NOT a gap to close: they stay catalogued because HackPit still
      helps plan and write up that work, and they are excluded from the planner's prompt.
    * ``available: false`` means the probe could not run (e.g. Docker down), so availability
      is UNKNOWN — not that the tools are absent. Nothing is filtered in that state.

    Served from main rather than the cockpit or arsenal router on purpose. The cockpit must
    stay arsenal-blind (the execution gates can never be catalog-aware) and the arsenal must
    never import the execution layer; test_arsenal_safety enforces BOTH directions. main is
    the composition root that is already allowed to know about both.
    """
    if windows_profile_id:
        profile = cockpit_winprofiles.get_public(windows_profile_id)
        if profile is None:
            raise HTTPException(status_code=404, detail="no such Windows target profile")
        view = cockpit_reconcile.windows_target_view(attack_path._arsenal(), profile["host"])
        return {**view, "loot": cockpit_loot.describe()}
    if refresh:
        try:
            cockpit_reconcile.check(attack_path._arsenal())
        except Exception as exc:  # noqa: BLE001 - a status endpoint must not 500
            raise HTTPException(status_code=503, detail=f"probe failed: {exc}") from exc
    return {**cockpit_reconcile.current().to_dict(), "loot": cockpit_loot.describe()}


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
def generate_report(
    session_id: str,
    template: str = Query("standard", description="standard | oscp | cpts | bugbounty."),
    include_opsec: bool = Query(
        False, description="Append the red-team OPSEC assessment (D10) — for detection-scoped work."
    ),
) -> dict[str, Any]:
    """Draft a pentest report from the session, persist it, and return it.

    Grounded in the session's completed steps + pasted evidence (see ``report.py``). The
    ``template`` selects an exam/format mode: OSCP (per-host + proof.txt table), CPTS
    (professional format), or bugbounty (H1/Bugcrowd single-vuln + CVSS). Long-form output, so
    this is slower on the local model.
    """
    session = sessions_db.get_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="session not found")
    # Fold in any recorded cockpit sandbox runs so the report reflects what was
    # actually executed (commands + captured output), not just checked-off steps.
    runs = cockpit_runstore.list_runs_for_session(session_id)
    if runs:
        session["execution_runs"] = [r.model_dump() for r in runs]
    # Fold in the structured engagement state so the OSCP template can render the per-host
    # proof table straight from state — no hash retyped at report time.
    session["state_hosts"] = state_store.load(session_id).to_dict(include_secrets=True)["hosts"]
    try:
        report_md, model_used = report_gen.compose_report(
            session, template=template, include_opsec=include_opsec
        )
    except llm.LLMError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except ValueError as e:  # unknown template
        raise HTTPException(status_code=422, detail=str(e))

    ts = sessions_db.save_report(session_id, report_md, model_used)
    if ts is None:  # deleted between fetch and save — unlikely
        raise HTTPException(status_code=404, detail="session not found")
    return {
        "report_md": report_md,
        "report_generated_at": ts,
        "model_used": model_used,
    }


def _loop_scope_context(engagement_id: str | None) -> orchestrator.ScopeContext | None:
    """Resolve the loop's mode: None = the isolated lab; a ScopeContext = a real engagement.

    The MODE RESOLUTION lives here, not in the orchestrator — the proposer has no capability
    to enter or look up an engagement (regression-locked); it only ever receives an inert,
    read-only description of what it may target. An id that is set but not ACTIVE fails
    CLOSED with 409: the loop is never silently downgraded to lab against a real-target id.
    """
    if not engagement_id:
        return None
    record = cockpit_engagement.get_active(engagement_id)
    if record is None:
        raise HTTPException(
            status_code=409,
            detail="engagement mode is not active for this id — enter engagement mode first "
            "(POST /cockpit/engagement/enter); an unknown or exited engagement cannot drive "
            "the loop",
        )
    matcher = cockpit_engagement.resolved_scope(record)
    return orchestrator.ScopeContext(
        target=record.target,
        scope=record.scope or record.target,
        include=tuple(record.scope_include),
        exclude=tuple(record.scope_exclude),
        allowed_hosts=tuple(record.allowed_hosts),
        out_of_scope_seen=tuple(record.discovered_out_of_scope),
        in_scope=matcher.in_scope,
    )


# Wire that SAME resolver into the AD orchestrator. Mode resolution lives here, so the AD
# proposer — like the cockpit loop's — has no capability to enter or look up an engagement; it
# only ever receives an inert, read-only description of what it may target, and an id that is
# set but not active fails CLOSED with 409 rather than silently degrading to lab mode.
set_ad_scope_resolver(_loop_scope_context)


@app.post("/sessions/{session_id}/loop/propose", response_model=LoopProposeOut)
def loop_propose(session_id: str, req: LoopProposeIn = Body(default=None)) -> dict[str, Any]:
    """Propose the NEXT single command for the guided loop — does NOT execute.

    Reads the session's composed plan + its recorded cockpit runs (the results so far) and
    asks the LLM for the one next command. WHICH TARGET depends on the mode:

    * no ``engagement_id`` → the ISOLATED LAB, exactly as before (unchanged).
    * an ACTIVE ``engagement_id`` → that engagement's REAL target and authorized PROGRAM
      SCOPE, including any in-scope hosts recon has discovered. An unknown/exited id is
      refused with 409 — it is never downgraded to lab.

    The returned proposal is a SUGGESTION only: it is not run here, and it advances nothing.
    Execution happens separately through POST /cockpit/exec (the executor, all of the mode's
    gates), only after a human approves THAT command. There is no batch and no approve-all in
    either mode. See docs/cockpit-loop.md + docs/ENGAGEMENT-LOOP-REAL-TARGET.md.
    """
    session = sessions_db.get_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="session not found")
    plan = session.get("path") or {}
    runs = [r.model_dump() for r in cockpit_runstore.list_runs_for_session(session_id)]
    avoid = list(req.avoid) if req and req.avoid else []
    scope_ctx = _loop_scope_context(req.engagement_id if req else None)
    try:
        # session_id is what grounds the proposal in accumulated STATE (hosts, services,
        # credentials, findings) and the live task tree, instead of stdout tails alone.
        return orchestrator.propose_next(
            plan, runs, llm.load_config(), avoid, scope_ctx, session_id
        )
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


# --------------------------------------------------------------------------- #
# Sliver C2 + DNS-tunnel obfuscation — the HUMAN surface for two cockpit modules
# --------------------------------------------------------------------------- #
# WHY THESE ROUTES LIVE HERE AND NOWHERE ELSE
# -------------------------------------------
# Both surfaces are HUMAN-ONLY by construction: the orchestrator / loop / agent / executor /
# adgraph packages have ZERO code path to either module, and that is regression-locked by a
# source scan over the whole backend tree (test_sliver.py, test_obfuscation.py and the two
# safety suites test_sliver_safety.py / test_obfuscation_safety.py). Those scans allow exactly
# TWO files to reference each module: the module itself and *this file*. Putting the routes in
# an orchestrator-reachable module would break the scan — deliberately, because a C2 server or
# a covert channel an agent could raise is an autonomous C2 / an autonomous covert channel.
#
# The two footings, unchanged from the modules:
#   SERVER / LISTENER LIFECYCLE  -> *** HUMAN-ONLY ***. A human clicking Start IS the approval:
#       this is OPERATOR INFRASTRUCTURE on the operator's own sandbox, with no target. There is
#       nothing to scope-check, so there is no gate and no red-confirm.
#   IMPLANT GENERATION           -> a GATED COMMAND. POST /api/sliver/implants runs the REAL
#       executor gates (target/scope -> approval -> heuristic danger -> isolation). A payload
#       generator trips the heuristic, so ``dangerous_ack`` is required in practice. A refused
#       build produces NOTHING and returns 403 naming the gate.
#
# *** THE SECRET NEVER CROSSES THIS BOUNDARY. *** ObfuscationListener carries the operator's
# pre-shared tunnel key on the model (and embedded inside ``client_command``), because
# start_listener has to hand it to the server process. The RunRecord redaction covers the audit
# trail only — an HTTP route is a second, independent export path, so it gets its own redaction:
# :class:`ObfuscationListenerOut` has no ``secret`` field at all AND the one-liner is masked on
# the way out (see :func:`_listener_public`). The operator chose that key and knows it; HackPit
# re-emits it nowhere. Pinned by test_obfuscation_safety.py::test_secret_never_crosses_the_http_boundary.
#
# NOTHING HERE DELIVERS ANYTHING. The Sliver routes generate an artifact and stop; the
# obfuscation routes hand back a string the operator carries across BY HAND. There is no
# delivery route, and there must never be one.


def _sliver_http_error(exc: "cockpit_sliver.SliverRefused") -> HTTPException:
    """Map a Sliver refusal to a status code. A GATE refusal is 403; availability is 409."""
    status = 409 if exc.gate in {"unavailable", "limit"} else 404 if exc.gate == "unknown" else 403
    return HTTPException(status_code=status, detail={"gate": exc.gate, "reason": exc.reason})


@app.get("/api/sliver/status")
def sliver_status() -> dict[str, Any]:
    """Engage-sandbox availability + live/built counts — drives the panel banner. Read-only."""
    return cockpit_sliver.status()


@app.get("/api/sliver/servers", response_model=list[cockpit_sliver.SliverServer])
def sliver_list_servers() -> list[cockpit_sliver.SliverServer]:
    """Every Sliver server this backend started, with liveness refreshed. Read-only."""
    return cockpit_sliver.list_servers()


@app.post("/api/sliver/servers", response_model=cockpit_sliver.SliverServer)
def sliver_start_server(
    req: cockpit_sliver.SliverServerRequest | None = Body(default=None),
) -> cockpit_sliver.SliverServer:
    """Start the operator's OWN Sliver server in the engage sandbox. *** HUMAN-ONLY. ***

    No target, therefore no target gate: the daemon listens on the operator's box and touches
    nothing belonging to the client. 409 if the sandbox is down, the live cap is hit, or the
    docker CLI is missing — and in each case NOTHING runs.
    """
    try:
        return cockpit_sliver.start_server(req or cockpit_sliver.SliverServerRequest())
    except cockpit_sliver.SliverRefused as exc:
        raise _sliver_http_error(exc)


@app.delete("/api/sliver/servers/{sid}", response_model=cockpit_sliver.SliverServer)
def sliver_stop_server(sid: str) -> cockpit_sliver.SliverServer:
    """Stop a Sliver server. *** HUMAN-ONLY. *** Idempotent; 404 on an unknown id."""
    try:
        return cockpit_sliver.stop_server(sid)
    except cockpit_sliver.SliverRefused as exc:
        raise _sliver_http_error(exc)


@app.post("/api/sliver/implants/preview")
def sliver_preview_implant(req: cockpit_sliver.ImplantRequest = Body(...)) -> dict[str, Any]:
    """PURE PREVIEW: the exact argv a build would run, plus the gate verdict. Runs NOTHING.

    This is what makes the red-confirm honest — the operator sees the literal argv and which
    gate would refuse it BEFORE approving. ``_implant_argv`` does no I/O and no execution, and
    ``validate_generate`` only evaluates gates. A refusal here is DATA (200 with
    ``rejected``), not an error: the panel renders it next to the confirm button.
    """
    rejected = cockpit_sliver.validate_generate(req)
    return {
        "argv": cockpit_sliver._implant_argv(req),
        "listener": req.listener,
        "rejected": None if rejected is None else rejected.model_dump(),
    }


@app.post("/api/sliver/implants", response_model=cockpit_sliver.Implant)
def sliver_generate_implant(req: cockpit_sliver.ImplantRequest = Body(...)) -> cockpit_sliver.Implant:
    """Generate ONE implant artifact — a GATED command that happens to produce a file.

    Runs the REAL ``executor.validate_request`` first. 403 naming the gate on any refusal
    (target/scope, approval, danger red-confirm, engagement, isolation) with NOTHING built;
    409 if docker is unavailable. A build that runs and FAILS is not a refusal — it comes back
    200 with ``status='failed'``, because a tool failure is not a safety event.

    IT ONLY GENERATES. Delivering the artifact to a host and executing it are separate,
    separately-approved concerns and are DEFERRED — there is no route for either.
    """
    try:
        return cockpit_sliver.generate_implant(req)
    except cockpit_sliver.SliverRefused as exc:
        raise _sliver_http_error(exc)


@app.get("/api/sliver/implants", response_model=list[cockpit_sliver.Implant])
def sliver_list_implants() -> list[cockpit_sliver.Implant]:
    """Every implant built by this process, oldest first. Read-only."""
    return cockpit_sliver.list_implants()


class ObfuscationListenerOut(BaseModel):
    """A DNS-tunnel listener AS THE HTTP BOUNDARY SEES IT — *** with no secret on it. ***

    Deliberately NOT ``cockpit.obfuscation.ObfuscationListener``: that model carries the
    operator's pre-shared tunnel key, because the module has to hand it to the server process.
    This one has no ``secret`` field at all, and ``client_command`` arrives already masked —
    masked *at source*, inside the module (``start_listener`` renders it from a
    ``_mask_secret`` copy), not scrubbed here on the way out. So the key cannot leave the
    process through an API response, and that holds for routes nobody has written yet.
    """

    id: str
    kind: str
    status: str
    container: str
    zone: str
    tunnel_net: str | None = None
    run_id: str
    client_command: str = Field(
        "", description="The CLIENT half for the operator to run BY HAND, with the pre-shared "
        "key MASKED. HackPit never delivers or executes it."
    )
    setup_note: str = ""
    started_at: str
    stopped_at: str | None = None
    engagement_id: str | None = None


def _listener_public(lis: "cockpit_obfuscation.ObfuscationListener") -> dict[str, Any]:
    """The listener minus its ``secret`` field. Drops — it does NOT scrub.

    *** THE BOUNDARY IS NOT HERE ANY MORE, AND THAT IS THE POINT. *** ``client_command``
    arrives already masked: ``cockpit.obfuscation.start_listener`` builds it from a
    ``_mask_secret`` copy, so the operator's key is never embedded in it at all. A future route
    that returns the raw model therefore cannot leak the key through the one-liner even if it
    never calls this helper — the guarantee is structural, in the module, not a discipline the
    HTTP layer has to remember.

    This function now does exactly one thing — drop the ``secret`` field — which
    ``response_model=ObfuscationListenerOut`` also does independently. Two cheap, overlapping
    drops of a field is the right amount of redundancy; a string-substitution pass here was
    not, because ``str.replace`` is over-broad (a key that is a substring of the zone would
    have eaten the zone). Pinned by test_obfuscation_safety.py.
    """
    return lis.model_dump(exclude={"secret"})


@app.get("/api/obfuscation/status")
def obfuscation_status() -> dict[str, Any]:
    """Engage-sandbox availability + live listener count. Read-only."""
    return cockpit_obfuscation.status()


@app.get("/api/obfuscation/listeners", response_model=list[ObfuscationListenerOut])
def obfuscation_list_listeners() -> list[dict[str, Any]]:
    """Every DNS-tunnel listener, secrets stripped. Read-only."""
    return [_listener_public(l) for l in cockpit_obfuscation.list_listeners()]


@app.post("/api/obfuscation/listeners", response_model=ObfuscationListenerOut)
def obfuscation_start_listener(
    req: cockpit_obfuscation.ObfuscationRequest = Body(...),
) -> dict[str, Any]:
    """Start a dnscat2/iodine listener in the engage sandbox. *** HUMAN-ONLY. ***

    Operator infrastructure for a zone the OPERATOR owns and has had delegated — no target, so
    no gate beyond a human clicking Start. 409 if the sandbox is down, the cap is hit or docker
    is missing (nothing runs); 422 if the zone/secret/tunnel-net bounds reject the request.

    The response carries the CLIENT one-liner with the key masked. Carrying that line to the
    far side is the operator's own manual step — HackPit cannot reach a machine it has not
    compromised, and there is no route here that tries.
    """
    try:
        return _listener_public(cockpit_obfuscation.start_listener(req))
    except cockpit_obfuscation.ObfuscationRefused as exc:
        status = 404 if exc.gate == "unknown" else 409
        raise HTTPException(status_code=status, detail={"gate": exc.gate, "reason": exc.reason})


@app.delete("/api/obfuscation/listeners/{lid}", response_model=ObfuscationListenerOut)
def obfuscation_stop_listener(lid: str) -> dict[str, Any]:
    """Stop a DNS-tunnel listener. *** HUMAN-ONLY. *** Idempotent; 404 on an unknown id."""
    try:
        return _listener_public(cockpit_obfuscation.stop_listener(lid))
    except cockpit_obfuscation.ObfuscationRefused as exc:
        status = 404 if exc.gate == "unknown" else 409
        raise HTTPException(status_code=status, detail={"gate": exc.gate, "reason": exc.reason})


# --------------------------------------------------------------------------- #
# The bespoke evasion engine (build #4, item C)
# --------------------------------------------------------------------------- #
# GENERATE-ONLY. These two routes build an artifact and stop. There is deliberately NO route
# that delivers or executes one — that is a separate, separately-approved concern and it is
# not built. The orchestrator has no path here; a human calls these or nothing does.
#
# FORCED HONESTY: `EvasionResult` carries the blue-team footprint and the OPSEC note in the
# SAME object as the artifact path, and both fields are required on the model. The UI cannot
# render the artifact without also receiving what a defender would see — there is no flag,
# query parameter or response shape that returns one without the other.
def _evasion_http_error(exc: "evasion_engine.EvasionRefused") -> HTTPException:
    """A gate refusal is 403 naming the gate; an inactive engagement is 409."""
    status = 409 if exc.gate in {"engagement", "sandbox", "unavailable"} else 403
    return HTTPException(status_code=status, detail={"gate": exc.gate, "reason": exc.reason})


@app.get("/api/evasion/techniques")
def evasion_techniques() -> dict[str, Any]:
    """The techniques this engine can emit, each with the detection spec that describes it.

    Read-only. Exposed so the panel can never offer a technique whose blue-view footprint
    would not resolve at generate time.
    """
    return {"techniques": [{"technique": t, "detection_spec": k}
                           for t, k in sorted(evasion_engine.TECHNIQUES.items())]}


@app.post("/api/evasion/preview")
def evasion_preview(req: evasion_engine.EvasionRequest = Body(...)) -> dict[str, Any]:
    """PURE PREVIEW: the gate verdict and the honest footprint, building NOTHING.

    Mirrors the Sliver preview route so the red-confirm is honest: the operator sees which
    gate would refuse, AND the defender's view of what they are about to build, before they
    approve it. A refusal is DATA (200 with ``rejected``), not an error.
    """
    rejected = evasion_engine.validate_build(req)
    try:
        footprint, opsec = evasion_engine._honest_footprint(req.techniques)
    except evasion_engine.EvasionError as exc:
        raise HTTPException(status_code=409, detail={"gate": "honesty", "reason": str(exc)})
    return {
        "rejected": None if rejected is None else rejected.model_dump(),
        "footprint": footprint,
        "opsec_note": opsec,
    }


@app.post("/api/evasion/generate", response_model=evasion_engine.EvasionResult)
def evasion_generate(
    req: evasion_engine.EvasionRequest = Body(...),
) -> evasion_engine.EvasionResult:
    """Build ONE evasion artifact — a GATED command that happens to produce a file.

    Runs the REAL ``executor.validate_request`` first: 403 naming the gate on any refusal
    (target/scope, approval, danger red-confirm, engagement, isolation) with NOTHING built.
    A generator that runs and FAILS is not a refusal — it returns 200 with a non-zero
    ``exit_code``, because a tool failure is not a safety event.

    409 with ``gate='honesty'`` if the engine cannot produce the blue-view footprint for the
    requested technique. That is the forced-honesty contract failing closed: no footprint,
    no artifact.
    """
    try:
        return evasion_engine.generate(req)
    except evasion_engine.EvasionRefused as exc:
        raise _evasion_http_error(exc)
    except evasion_engine.EvasionError as exc:
        raise HTTPException(status_code=409, detail={"gate": "honesty", "reason": str(exc)})
