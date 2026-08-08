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

import hashlib
import json
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import Body, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, Field

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
import alternatives  # noqa: E402  (backend/alternatives.py — second-opinion engine, executes nothing)
import attack_path  # noqa: E402
import chat as chat_assistant  # noqa: E402  (backend/chat.py — engagement assistant)
import llm  # noqa: E402
import operator_identity  # noqa: E402  (operator byline / report identity)
import orchestrator  # noqa: E402  (backend/orchestrator.py — the loop's propose step)
import reasoning  # noqa: E402  (backend/reasoning/ — deeper proposer; propose-only, no exec)
import report as report_gen  # noqa: E402  (backend/report.py — LLM report drafting)
import sessions as sessions_db  # noqa: E402  (backend/sessions.py — SQLite store)
from cockpit import runstore as cockpit_runstore  # noqa: E402
from cockpit import engagement as cockpit_engagement  # noqa: E402
from cockpit import reconcile as cockpit_reconcile  # noqa: E402
from cockpit import loot as cockpit_loot  # noqa: E402
from cockpit import winprofiles as cockpit_winprofiles  # noqa: E402  (Windows target store)
from cockpit import sandbox as cockpit_sandbox  # noqa: E402  (read-only container probes)
# The two evasion/exfil surfaces. Their ROUTES live here, not in cockpit/router.py, and NOT in
# any orchestrator/loop module: see the "Sliver C2 + DNS-tunnel obfuscation" section below.
from cockpit import sliver as cockpit_sliver  # noqa: E402  (Sliver C2 — human-only + gated gen)
from cockpit import obfuscation as cockpit_obfuscation  # noqa: E402  (DNS tunnel — human-only)
from evasion import engine as evasion_engine  # noqa: E402  (generate-only artifact producer)
import state as engagement_state  # noqa: E402
from state import store as state_store  # noqa: E402
# backend/findings/ — the finding pipeline (dynamic schema, dedup, pluggable rankers,
# post-scripts). PURE DATA: it executes nothing and imports no cockpit/executor/state, so the
# coupling (dict -> state.Finding, command post-script -> gated executor) lives HERE in the app
# layer, exactly like the codescan sink. See backend/findings/__init__.py.
from findings import pipeline as finding_pipeline  # noqa: E402
from findings import postscripts as finding_postscripts  # noqa: E402
from findings import rankers as finding_rankers  # noqa: E402
from findings import schema as finding_schema  # noqa: E402
from state import tasks as state_tasks  # noqa: E402
from state import credvault  # noqa: E402
# Formal engagement governance (RoE / ConOps / Deconfliction / OPPLAN). The data model + the
# OPPLAN status state machine live in the executes-nothing state package (state/governance.py);
# the propose-only drafter (governance_draft.py) is the generative layer, like attack_path.py.
# The RoE-vs-scope ADVISORY check is wired HERE in the app layer — that is the only place
# cockpit.scope may be imported from — and it flags, it never blocks. Governance adds NO gate.
from state import governance as gov  # noqa: E402
import governance_draft  # noqa: E402
from cockpit import scope as cockpit_scope  # noqa: E402
from cockpit.router import router as cockpit_router  # noqa: E402
from adgraph import store as ad_store  # noqa: E402  (backend/adgraph — AD attack-path graph)
from adgraph.router import (  # noqa: E402
    router as ad_router,
    set_grounder,
    set_scope_resolver as set_ad_scope_resolver,
)
from cloudgraph import store as cloud_store  # noqa: E402  (backend/cloudgraph — cloud IAM graph)
from cloudgraph import imds as cloud_imds  # noqa: E402  (SSRF→IMDS bridge: pure parser, seeds owned)
from cloudgraph.router import (  # noqa: E402
    router as cloud_router,
    set_grounder as set_cloud_grounder,
    set_scope_resolver as set_cloud_scope_resolver,
)
from detection.router import (  # noqa: E402  (backend/detection — purple-team footprint)
    router as detection_router,
    set_run_lookup as set_detection_run_lookup,
    set_runs_lookup as set_detection_runs_lookup,
)
from codescan.router import (  # noqa: E402  (backend/codescan — STATIC AppSec analysis)
    router as codescan_router,
    set_kb as set_codescan_kb,
    set_findings_sink as set_codescan_findings_sink,
    set_diff_provider as set_codescan_diff_provider,
)
from arsenal import loader as arsenal_loader  # noqa: E402  (backend/arsenal — tool catalog)
from arsenal.router import (  # noqa: E402
    router as arsenal_router,
    set_arsenal as set_arsenal_catalog,
)
from exploits.router import router as exploits_router  # noqa: E402  (backend/exploits — CVE index)
from oob import config as oob_config  # noqa: E402  (backend/oob — the canary's one configuration)
from oob import tokens as oob_tokens  # noqa: E402  (canary token minting + correlation)
from oob import interactsh as oob_interactsh  # noqa: E402  (interact.sh second OOB backend)
from oob import settings as oob_settings  # noqa: E402  (OOB auto-poll setting)
from oob import autopoll as oob_autopoll  # noqa: E402  (read-only background callback sweep)
from oob.router import router as oob_router  # noqa: E402  (out-of-band canary panel)

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
    # parsed cloud IAM privilege-escalation graphs share it too.
    cloud_store.init_db()
    # out-of-band canary: minted tokens and the one canary configuration share it too. The
    # LISTENER those tokens are for is a separate deployable (oob/server.py) that runs on a
    # VPS; nothing started here opens a socket.
    oob_tokens.init_db()
    oob_config.init_db()
    # the interact.sh second OOB backend: its session/map/seen tables and the auto-poll setting
    # share the same file. Registering a session opens outbound sockets; init here does not.
    oob_interactsh.init_db()
    oob_settings.init_db()
    # structured engagement state (hosts/services/endpoints/credentials/findings) + the
    # task tree share it too. This is what the orchestrator reasons over instead of
    # re-reading stdout tails.
    engagement_state.init_db()
    # reasoning copilot — the tried/failed ledger's dead-lead table and the candidate frontier
    # share the same file. Propose-only: these are the proposer's memory, never an exec path.
    reasoning.init_db()
    # 2.7 — wire the KB retriever so the loop's fingerprint block can surface case-based
    # exploitation writeups for the exact service+version in state. get_entry hydrates the full
    # entry (the search index is lightweight) so the structured fingerprint's version RANGE
    # matches. Read-only: retrieves, never runs.
    orchestrator.set_kb_retriever(
        lambda q: _resilient_search(q, 5, "hybrid"),
        lambda eid: STATE.by_id.get(eid) if eid else None,
    )
    # :code scan — hand the KB to the SAST panel so a finding can point at the technique
    # behind it. Optional by design: with no KB the scan runs identically, just unlinked.
    set_codescan_kb(
        STATE.by_id,
        _resilient_search,
        attack_path.is_step_eligible,
        lambda e: not attack_path.is_broad_reference(e),
    )
    # :code scan AI audit — the two cross-cutting seams codescan cannot own itself (it stays
    # orthogonal to state and runs no subprocess of its own). The sink lands ranked audit findings
    # in engagement state; the diff provider backs 'patched-since'. Both are plain callbacks, so
    # codescan gains no import of state / git — the capability arrives as data, like the KB above.
    set_codescan_findings_sink(_persist_codescan_findings)
    set_codescan_diff_provider(_git_changed_since)
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
    # OOB auto-poll: a read-only background sweep that files callbacks from both canary backends
    # without a click. It reaches poll_all -> ingest -> state and NO execution surface, so it does
    # not cross the propose-only invariant. Daemon thread; sleeps first, so start is never blocked.
    oob_autopoll.start(app)
    yield
    set_codescan_kb(None, None, None, None)
    set_codescan_findings_sink(None)
    set_codescan_diff_provider(None)
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
# Cloud IAM privilege-escalation graph (see cloudgraph/). ENUMERATION is a gated job (the
# recon/nuclei shape); the graph/path/technique/orchestrate routes are read-only and every abuse
# command they surface still runs ONLY through the cockpit executor above.
app.include_router(cloud_router)
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
# Out-of-band canary (see backend/oob/ + oob/server.py). Mints the tokens that go into blind
# SSRF/XXE/RCE/SQLi/JNDI payloads, correlates the callbacks back to the step that caused them,
# and files them as findings. The DEPLOY route is the only one that executes anything, and it
# goes through the cockpit executor host-locked to the configured VPS — it is passed no
# destination, because it has no parameter for one.
app.include_router(oob_router)


# --------------------------------------------------------------------------- #
# :code scan AI-audit seams — the two capabilities codescan cannot own (it is
# orthogonal to state and runs no subprocess). Injected via set_findings_sink /
# set_diff_provider so the coupling lives HERE, in the app layer, not in codescan.
# --------------------------------------------------------------------------- #
def _persist_codescan_findings(session_id: str, items: list[dict]) -> int:
    """Upsert AI-audit findings into engagement state. codescan hands plain dicts; this builds the
    Finding records and writes them, so codescan never imports state (orthogonality)."""
    from state.models import Finding

    records = [
        Finding(
            session_id=session_id,
            title=str(it.get("title") or "")[:300],
            severity=str(it.get("severity") or "info"),
            target=str(it.get("target") or ""),
            evidence=str(it.get("evidence") or ""),
            tool=str(it.get("tool") or "ai-audit"),
            reference=str(it.get("reference") or ""),
            source_run_id=it.get("source_run_id"),
        )
        for it in items
        if str(it.get("title") or "").strip()
    ]
    return state_store.upsert_findings(records)


def _git_changed_since(root: Path, ref: str) -> set | None:
    """Repo-relative paths changed since a git ref (the 'patched-since' scope). Read-only: it runs
    `git diff --name-only` in the repo and never touches the working tree. Returns None when the
    path is not a git repo or git is unavailable — the audit then degrades to a full pass."""
    import re
    import subprocess  # local: a read-only git query, kept out of codescan by design

    ref = (ref or "").strip()
    if not ref or not re.match(r"^[\w./@^~-]{1,120}$", ref):
        return None
    try:
        proc = subprocess.run(  # noqa: S603 - argv list, shell=False, ref validated above
            ["git", "-C", str(root), "diff", "--name-only", f"{ref}...", "--"],
            capture_output=True, text=True, timeout=30, shell=False,
        )
        if proc.returncode != 0:
            # fall back to a two-dot diff (ref may not share history for a three-dot merge base)
            proc = subprocess.run(  # noqa: S603
                ["git", "-C", str(root), "diff", "--name-only", ref, "--"],
                capture_output=True, text=True, timeout=30, shell=False,
            )
        if proc.returncode != 0:
            return None
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    return {line.strip().replace("\\", "/") for line in proc.stdout.splitlines() if line.strip()}


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


# Only cloud KB categories may GROUND a cloud IAM abuse edge — so an AD/web entry can never supply
# the command for an IAM privesc abuse. If nothing cloud-relevant matches, the technique's own
# catalog template is used (ai_suggested), exactly like the AD grounder falls back.
_CLOUD_GROUND_CATEGORIES = frozenset({"cloud"})


# A grounded cloud command is only useful if it is an actual CLI invocation — the cloud KB is
# prose-heavy and its code blocks are often JSON policy documents or output samples, which are not
# runnable and would render worse than the precise catalog template. So a KB hit only GROUNDS an
# edge when at least one of its commands starts with a cloud CLI verb; otherwise we fall back to the
# catalog (ai_suggested), exactly as an unmatched seed would.
_CLOUD_CLI_HEADS = ("aws", "az", "gcloud", "gsutil", "pacu", "cloudfox", "kubectl", "curl")


def _looks_like_cloud_cli(cmd: str) -> bool:
    line = next((ln.strip() for ln in (cmd or "").splitlines()
                 if ln.strip() and not ln.strip().startswith("#")), "")
    head = line.split(" ", 1)[0].rsplit("/", 1)[-1].lower()
    return head in _CLOUD_CLI_HEADS


def _cloud_kb_grounder(seeds: str) -> dict | None:
    """Ground a cloud IAM abuse edge in the KB (the 534-entry hacktricks-cloud corpus): the best
    cloud-relevant entry whose commands include a real CLI invocation for the technique's seed
    terms, via the SAME hybrid search + entry_commands the AD grounder uses. Returns
    ``{id, title, commands}`` or None (→ the catalog fallback / ai_suggested)."""
    try:
        hits = _resilient_search(seeds, 8, "hybrid")
    except Exception:
        return None
    for h in hits:
        e = STATE.by_id.get(h.get("id"))
        if not e or e.get("category") not in _CLOUD_GROUND_CATEGORIES:
            continue
        cmds = [c for c in attack_path.entry_commands(e) if _looks_like_cloud_cli(c.get("cmd", ""))]
        if cmds:
            return {"id": e["id"], "title": e.get("title") or e["id"], "commands": cmds}
    return None


# Wire the cloud KB grounder into the cloud graph router.
set_cloud_grounder(_cloud_kb_grounder)


# --------------------------------------------------------------------------- #
# The web ↔ cloud SEAM: SSRF/RCE → IMDS → seed an OWNED cloud principal.
#
# CROSS-CUTTING, so it lives here and not in cloudgraph/router.py: it joins the cloud IAM graph
# (cloud_store) to the pure IMDS parser (cloudgraph.imds), to engagement state (findings + the
# credential vault), and to the loot mount (cockpit.loot) — and cloudgraph must not import cockpit
# (the decoupling rule). The bridge EXECUTES NOTHING: the request that actually touched
# 169.254.169.254 already ran through the human-approved repeater / nuclei / executor (or arrived as
# an OOB callback); this route only PARSES a captured response and SEEDS the graph. There is no gate
# because there is nothing to gate — no command, no spawn, no network. The captured secret goes to
# the vault/loot and never into the Finding text.
# --------------------------------------------------------------------------- #
class SeedImdsIn(BaseModel):
    session_id: str = Field(..., description="Session whose cloud graph the identity seeds into.")
    provider: str = Field("aws", description="aws | azure | gcp.")
    response_body: str = Field(..., description="The captured IMDS response body (paste / repeater "
                                                "exchange / OOB callback body).")
    source: str = Field("paste", description="Where the body came from: repeater | oob | paste.")
    role_hint: str | None = Field(None, description="The <role> from the IMDS URL (AWS) or the SA "
                                                    "email (GCP), so the identity matches its "
                                                    "enumerated node.")
    engagement_id: str | None = Field(None, description="Engagement, when captured in engagement "
                                                        "mode (enables a loot-file copy of the "
                                                        "secret).")


@app.post("/cockpit/cloud/seed-imds")
def cloud_seed_imds(req: SeedImdsIn) -> dict[str, Any]:
    """Parse a captured IMDS response into an OWNED cloud principal and seed it into the session's
    :cloud graph. Records a high-severity Finding (no secret in it) and stores the secret in the
    engagement credential vault (+ a loot file in engagement mode). Executes nothing — the IMDS
    fetch already went through the human-approved repeater/executor. Returns the seeded node id and
    a suggested next step (enumerate AS this identity), which is NOT auto-run."""
    import re

    from state.models import Credential, Finding

    src = (req.source or "paste").strip().lower()
    if src not in {"repeater", "oob", "paste"}:
        src = "paste"
    try:
        result = cloud_imds.parse(req.response_body, req.provider, req.role_hint)
    except cloud_imds.ImdsParseError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    if result.node is None:
        # A role listing / bare IMDSv2 token / identity doc — no credential to own yet. Return the
        # guidance (warnings) so the operator fetches the actual creds next, but seed nothing.
        raise HTTPException(status_code=422, detail={
            "reason": "the body carried no credential to own — "
                      + (result.warnings[0] if result.warnings else "nothing recognised"),
            "imds_version": result.imds_version, "warnings": result.warnings,
        })

    node_dict = result.node.to_dict()
    node_dict.setdefault("props", {})["source"] = src
    seeded = cloud_store.seed_owned_node(
        req.session_id, node_dict, result.aliases, provider=result.provider,
        account=result.account or None, engagement_id=req.engagement_id,
    )
    if seeded is None:
        raise HTTPException(status_code=422, detail="could not seed — a session_id is required")

    # SECRET → vault (the gitignored sessions.db credential store, like every captured credential).
    secret_blob = json.dumps(result.creds, sort_keys=True)
    try:
        state_store.upsert_credentials([Credential(
            session_id=req.session_id, kind=result.cred_kind,
            principal=result.cred_principal or result.identity or seeded["node_id"],
            secret=secret_blob, domain=result.provider, note=result.cred_note,
            source_run_id=seeded["graph_id"],
        )])
        vault = "vault"
    except Exception:  # noqa: BLE001 — vault write is best-effort; the finding still records it
        vault = "none"

    # SECRET → loot file too, when captured in an engagement (mirrors :credentials → loot).
    loot_path = None
    if req.engagement_id:
        try:
            host_dir = cockpit_loot.host_dir(req.engagement_id)
            host_dir.mkdir(parents=True, exist_ok=True)
            safe = re.sub(r"[^A-Za-z0-9_.-]", "_", seeded["node_id"])[:80]
            fp = host_dir / f"imds-{result.provider}-{safe}.json"
            fp.write_text(secret_blob, encoding="utf-8")
            loot_path = cockpit_loot.container_dir(req.engagement_id) + "/" + fp.name
            vault = "loot"
        except Exception:  # noqa: BLE001 — loot is a convenience, never a gate
            loot_path = None

    # FINDING → engagement state. Built ONLY from the non-secret fields (finding_evidence excludes
    # the key/token by construction). High severity: stolen cloud credentials.
    finding_recorded = False
    try:
        state_store.upsert_findings([Finding(
            session_id=req.session_id, title=result.finding_title, severity="high",
            target=result.identity or seeded["node_id"], evidence=result.finding_evidence,
            tool="cloudgraph-imds", reference="ssrf-imds", source_run_id=seeded["graph_id"],
        )])
        finding_recorded = True
    except Exception:  # noqa: BLE001 — finding is best-effort
        finding_recorded = False

    return {
        **result.to_response(),
        "graph_id": seeded["graph_id"],
        "node_id": seeded["node_id"],
        "matched_existing": seeded["matched_existing"],
        "graph_created": seeded["created"],
        "source": src,
        "secret_stored": vault,
        "loot_path": loot_path,
        "finding_recorded": finding_recorded,
        "next_step": {
            "action": "enumerate as this identity",
            "endpoint": "POST /cockpit/cloud/enumerate",
            "note": "Optional and GATED — run a cloud enumeration AS the stolen identity to expand "
                    "the graph. Not auto-run; you approve it like every command.",
        },
        "note": "SEEDED ONLY — nothing was executed. The IMDS fetch went through the human-approved "
                "repeater/executor; this parsed the captured body and marked the principal owned.",
    }


@app.get("/cockpit/cloud/imds-catalog")
def cloud_imds_catalog(provider: str = Query("aws")) -> dict[str, Any]:
    """The per-provider IMDS request cheat-set — curl / gopher templates the operator copies into
    the repeater and approves-and-sends. Read-only data; the bridge never fires these."""
    return {"provider": (provider or "aws").strip().lower(),
            "requests": cloud_imds.request_catalog(provider)}


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


class OperatorOut(BaseModel):
    """Operator identity for the BROWSER. Name and handle only, by construction —
    the OSID and email in operator.json are report-only and never appear here."""

    name: str = Field(description="Display name, or '' when unconfigured.")
    handle: str = Field(description="Platform handle, or ''.")


class HomeRail(BaseModel):
    """The launcher status rail. Answers "why is that surface refusing?" at a glance.

    Every field is a STATUS, never a secret. `llm_model` is the model NAME (the key
    is never included — see `llm.public_config`), and `windows_profile` is the
    profile's display name, never its stored credential.
    """

    sandbox_up: bool | None = Field(description="Lab sandbox running; None if undeterminable.")
    engage_sandbox_up: bool | None = Field(description="Engagement sandbox running.")
    llm_provider: str
    llm_model: str
    windows_profile: str | None = Field(description="Newest WinRM profile's display name.")
    engagement_id: str | None = None
    engagement_target: str | None = None


class HomeSummary(BaseModel):
    """Launcher payload: the rail plus per-surface counts.

    Deliberately SEPARATE from /stats so the hero's counters render immediately —
    this endpoint runs docker probes and must never be on the hero's critical path.
    """

    rail: HomeRail
    surfaces: dict[str, int] = Field(description="Surface id -> count for the tile badges.")


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
    # extra="forbid": a field this model does not know is a 422, not a shrug. `target`
    # below used to be one of those — callers passed it, Pydantic dropped it silently, and
    # the plan came back pointed at nothing while looking like the request had been honoured.
    # Rejecting an unknown field is the only answer that cannot be mistaken for success.
    model_config = ConfigDict(extra="forbid")

    goal: str = Field(min_length=3, description="Free-text target/goal description.")
    target_type: str | None = Field(
        default=None, description="Optional chip: pentest | bugbounty | ctf | ad."
    )
    target: str | None = Field(
        default=None,
        description="Optional explicit target (host / IP / URL) for this path. Overrides "
        "the target parsed from the goal, and is what example hosts in KB commands are "
        "rewritten to. When omitted the target is taken from the goal, and failing that "
        "from the first concrete host in scope_text.",
    )
    scope_text: str | None = Field(
        default=None,
        description="Optional pasted scope / Rules of Engagement. Fed to the target "
        "profiler; forbidden paths/hosts are dropped from the composed path. Also parsed "
        "as the PROGRAM SCOPE every composed command is checked against.",
    )


class PlannedCode(Code):
    """A command as the PLANNER hands it back — the KB's ``Code`` plus what composition
    learned about it.

    A subclass rather than extra fields on ``Code``: that model is the canonical KB entry
    shape (pipeline/schema.py) and these facts are true of a planned command, not of a
    stored one. It also repairs a silent loss — ``unverified`` and ``truncated`` were
    already being set by attack_path.py and then dropped by this response_model, because
    a field a response model does not declare does not reach the client. That is the same
    trap ``scoped``/``foreign_refs`` had to be added here to avoid, and it is why a new
    per-command fact needs a change in three files, not one.
    """

    unverified: bool = Field(
        default=False,
        description="True = the model's own command (an ai_suggested step), not lifted "
        "from a KB entry. Nothing has checked that it is correct.",
    )
    truncated: bool = Field(
        default=False,
        description="True = the command was capped for display; open the cited entry for "
        "the full text.",
    )
    runnable: bool | None = Field(
        default=None,
        description="THE SCOPE CHECK. False = this command cannot run as written against "
        "this engagement — see unrunnable_reason. Null = there was no declared scope to "
        "check it against, or the command names an in-scope host and is fine. Plan quality "
        "only: it refuses nothing, and the executor's target/scope lock is the real bound.",
    )
    unrunnable_reason: str | None = Field(
        default=None,
        description="Why this command cannot run as written — either it points at a host "
        "outside the engagement scope, or it names no host at all. Null when runnable is "
        "not False.",
    )
    original_cmd: str | None = Field(
        default=None,
        description="The command as the KB stored it, present ONLY when HackPit repointed it "
        "at your target. Kept so a rewrite is visible rather than silent — you can see that "
        "the entry said tesla.com and this now says your host.",
    )
    repointed_from: list[str] | None = Field(
        default=None,
        description="The out-of-scope host(s) replaced to produce `cmd`. Done automatically "
        "only for TARGET-DIRECTED tools (nmap, ffuf, nuclei, sqlmap…), where the host "
        "argument is by definition the thing being assessed.",
    )
    suggested_cmd: str | None = Field(
        default=None,
        description="What this command would look like pointed at your target — offered for "
        "a FLAGGED command that the automatic pass declined to rewrite. NEVER applied: it is "
        "shown beside the original, never in place of it. The automatic pass declines for "
        "fetch-capable tools (curl, wget, nc, ssh…) because a host in their argument may be a "
        "tool download or your own listener, and only a human can tell which. Null when "
        "there is no host to swap.",
    )
    suggested_from: list[str] | None = Field(
        default=None, description="The host(s) `suggested_cmd` would replace."
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
    commands: list[PlannedCode] = Field(
        description="Commands for this step. For grounded/writeup steps these are "
        "the entry's real commands; for AI-suggested steps they are the model's "
        "own, unverified. Each carries its own scope verdict — see PlannedCode."
    )
    unrunnable_commands: int | None = Field(
        default=None,
        description="How many of this step's commands failed the scope check — a badge "
        "count so a step can be seen to need work without expanding it. Null when none did.",
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
        description="Target (IP/host/URL) substituted into step commands; null if none "
        "could be determined from the request or the scope.",
    )
    target_source: str | None = Field(
        default=None,
        description="Where that target came from: 'caller' (the request's own target "
        "field), 'goal' (parsed out of the goal text), or 'scope' (the first concrete "
        "in-scope host — HackPit chose it for you). Null when there is no target, in "
        "which case no example host was rewritten and most commands will be unrunnable.",
    )
    scope_checked: bool = Field(
        default=False,
        description="True when a usable scope was supplied and every command was judged "
        "against it. False = no scope, so nothing was checked. Reported separately from "
        "commands_unrunnable because 0-of-0-checked and 0-of-32-bad are the same number "
        "and very different facts; without this the UI would render 'unchecked' as 'clean'.",
    )
    commands_total: int = Field(
        default=0, description="How many commands this path returned, across every step."
    )
    commands_repointed: int = Field(
        default=0,
        description="How many commands were automatically repointed at your target — an "
        "out-of-scope host replaced in a TARGET-DIRECTED tool's argument. Fetch-capable "
        "tools are never repointed automatically; those get a `suggested_cmd` instead.",
    )
    commands_unrunnable: int = Field(
        default=0,
        description="How many of them cannot run as written against this engagement — "
        "they point at a host outside the scope, or name no host at all. THE HEADLINE "
        "HONESTY NUMBER: a plan whose commands are mostly the KB's own examples used to "
        "be indistinguishable from one that had been adapted to the target. Always 0 "
        "when no scope_text was supplied, because then there is nothing to check against "
        "— that is 'unchecked', not 'clean'.",
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


# ---- second-opinion (dual-candidate) ------------------------------------- #
class AltVerdict(BaseModel):
    recommendation: str = Field(
        description='"primary" | "alternative" | "situational" — ADVISORY only, never a gate.'
    )
    summary: str = Field(default="", description="Which candidate is better and why. Prose only.")
    factors: list[str] = Field(default_factory=list, description="Optional tradeoff bullets.")
    model_used: str = ""
    provider: str = ""


class Alternative(BaseModel):
    kind: str = Field(
        description='"grounded" (verbatim KB entry) | "ai_suggested" (model, unverified).'
    )
    entry_id: str = Field(
        default="", description="Cited KB entry — set + real when grounded, else empty."
    )
    entry_title: str = ""
    title: str
    commands: list[PlannedCode] = Field(default_factory=list)
    foreign_refs: list[str] | None = Field(
        default=None,
        description="Foreign hosts still named after scope adaptation — the same annotation a "
        "primary step carries. Null when the command names only in-scope hosts. Declared here "
        "so the response model does not strip it (the per-command-fact three-files trap).",
    )


class AlternativeOut(BaseModel):
    alternative: Alternative | None = None
    verdict: AltVerdict


class AltStepIn(BaseModel):
    goal: str
    target: str | None = None
    scope_text: str | None = None
    step_title: str = ""
    step_cmd: str = ""
    step_entry_id: str = ""


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
    # SUBMISSION FIELDS — what the bug-bounty report renders alongside the finding.
    cvss_vector: str | None = Field(
        default=None,
        description="CVSS 3.1 vector string. The SCORE is computed from it at report time, "
        "never asserted by the model.",
    )
    vrt_category: str | None = Field(
        default=None,
        description="Bugcrowd VRT category key (see GET /vrt-categories). Maps to a P1–P5 "
        "priority by LOOKUP — the priority is never derived from the CVSS score, because the "
        "two genuinely disagree and a triager acts on the VRT one.",
    )
    known_issues: str | None = Field(
        default=None,
        description="The program's published known-issues list, pasted verbatim from the "
        "brief. At report time each finding is compared against it and possible matches are "
        "FLAGGED. Nothing is ever auto-suppressed: a false match that silently dropped a "
        "real finding would cost far more than a warning the operator dismisses.",
    )
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
    # --- reasoning copilot (Task 2) — advisory only; the proposal still runs nothing --- #
    hypothesis: str = Field("", description="What the proposer believes it is testing (2.2).")
    expected_signal: str = Field(
        "", description="What output would confirm or refute the hypothesis (2.2)."
    )
    citations: list[dict[str, str]] = Field(
        default_factory=list,
        description="KB entry ids + state facts the proposal rests on (invariant 3).",
    )
    schema_valid: bool = Field(
        True, description="Does the proposal carry hypothesis + expected_signal + citations?"
    )
    schema_problems: list[str] = Field(
        default_factory=list, description="Why the reasoning schema check failed, if it did."
    )
    critique: dict[str, Any] = Field(
        default_factory=dict,
        description="The skeptic pass (2.5): ok / downrank / confidence / concerns / checks.",
    )
    specialist: str = Field(
        "generalist", description="The domain lens this situation routed to (2.6)."
    )
    frontier: dict[str, Any] = Field(
        default_factory=dict,
        description="Candidate-frontier state (2.3): open lead count + how many were just pushed.",
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


# --------------------------------------------------------------------------- #
# finding pipeline — dynamic schema, de-dup, pluggable rankers, post-scripts
# (backend/findings/). Pure data operations execute nothing; a command post-script
# is an approve-each PROPOSAL the operator fires through the already-gated executor,
# exactly like a drafted web exploit. NO new gate — spec §0.
# --------------------------------------------------------------------------- #
def _finding_to_payload(f: Any) -> dict[str, Any]:
    """A state.Finding -> the pipeline's finding dict (carrying its fingerprint)."""
    return {
        "fingerprint": f.fingerprint(),
        "title": f.title, "severity": f.severity, "target": f.target,
        "evidence": f.evidence, "tool": f.tool, "reference": f.reference,
        "attacker_path": f.attacker_path, "source_refs": list(f.source_refs or []),
        "cvss": f.cvss, "vuln_class": f.vuln_class, "extra": dict(f.extra or {}),
        "merged_count": f.merged_count,
    }


def _payload_to_finding(session_id: str, d: dict[str, Any], run_id: str | None = None) -> Any:
    """A validated/ranked pipeline dict -> a state.Finding, ready to upsert."""
    from state.models import Finding

    return Finding(
        session_id=session_id, title=str(d.get("title") or "")[:300],
        severity=finding_schema.normalize_severity(d.get("severity")),
        target=str(d.get("target") or ""), evidence=str(d.get("evidence") or ""),
        tool=str(d.get("tool") or ""), reference=str(d.get("reference") or ""),
        attacker_path=str(d.get("attacker_path") or ""),
        source_refs=[str(x) for x in (d.get("source_refs") or [])],
        cvss=str(d.get("cvss") or ""), vuln_class=str(d.get("vuln_class") or ""),
        extra=dict(d.get("extra") or {}), merged_count=int(d.get("merged_count") or 0),
        ranker=str(d.get("ranker") or ""), source_run_id=run_id,
    )


@app.get("/findings/rankers")
def finding_rankers_list() -> dict[str, Any]:
    """The pluggable severity rankers available to any engagement (data only)."""
    return {"rankers": finding_rankers.list_rankers(),
            "default": finding_rankers.DEFAULT_RANKER_ID}


@app.get("/findings/postscripts")
def finding_postscripts_list() -> dict[str, Any]:
    """The built-in post-finding scripts. ``needs_approval`` marks the command ones."""
    return {"postscripts": finding_postscripts.list_postscripts()}


@app.get("/findings/schema")
def finding_schema_view() -> dict[str, Any]:
    """The structured finding schema (base field set) — what every producer emits."""
    return {"fields": finding_schema.DEFAULT_FIELDS, "schema": finding_schema.output_schema()}


class PipelineIn(BaseModel):
    """Run the finding pipeline over an engagement's findings."""

    ranker_id: str | None = Field(None, description="Severity ranker id; null/blank = default.")
    persist: bool = Field(
        False,
        description="When true, WRITE the collapsed + rescored findings back to engagement "
        "state (absorbed duplicates are removed, survivors keep the worst severity and the "
        "ranker's score) and remember the ranker choice. A pure data operation — nothing runs.",
    )


@app.post("/sessions/{session_id}/findings/pipeline")
def run_finding_pipeline(session_id: str, req: PipelineIn = Body(...)) -> dict[str, Any]:
    """De-duplicate + rank an engagement's findings, optionally persisting the collapse.

    Returns the assembled view (ranked findings, the "merged N duplicates" note, severity
    counts). Executes nothing. Deliberately returns a plain dict (no response_model) so the
    structured-schema fields survive the round-trip — the 3-schema-places rule.
    """
    ranker_id = (req.ranker_id or "").strip() or state_store.get_finding_ranker(session_id) \
        or finding_rankers.DEFAULT_RANKER_ID
    findings = state_store.load(session_id).findings
    payloads = [_finding_to_payload(f) for f in findings]
    result = finding_pipeline.run_pipeline(payloads, ranker_id)

    if req.persist:
        # collapse in the store: for each dedup group keep one representative fingerprint,
        # delete the others, and write the survivor's rescored severity/rank/merge count.
        state_store.set_finding_ranker(session_id, ranker_id)
        groups: dict[tuple, list[Any]] = {}
        for f in findings:
            groups.setdefault(finding_pipeline.dedup_key(_finding_to_payload(f)), []).append(f)
        survivor_by_key = {finding_pipeline.dedup_key(d): d for d in result["findings"]}
        absorbed: list[str] = []
        keepers: list[Any] = []
        for key, members in groups.items():
            surv = survivor_by_key.get(key)
            if surv is None:
                continue
            members_sorted = sorted(
                members, key=lambda m: finding_pipeline._IMPACT_RANK.get(m.severity, 99))
            keep_fp = members_sorted[0].fingerprint()
            absorbed += [m.fingerprint() for m in members_sorted[1:]]
            rec = _payload_to_finding(session_id, surv)
            # pin the representative identity so the upsert updates in place, not inserts anew
            rec.title = members_sorted[0].title
            rec.target = members_sorted[0].target
            rec.reference = members_sorted[0].reference
            keepers.append(rec)
        if absorbed:
            state_store.delete_findings(session_id, absorbed)
        if keepers:
            state_store.upsert_findings(keepers)
        result["persisted"] = True
        result["removed_duplicates"] = len(absorbed)

    result["session_id"] = session_id
    return result


@app.get("/findings/pipeline/sample")
def finding_pipeline_sample(ranker: str | None = None) -> dict[str, Any]:
    """A deterministic SYNTHETIC run of the pipeline — the offline demo the /engagements panel
    renders (and the screenshot uses). No engagement, no DB write: pure data over a fixed set of
    fabricated findings so the ranker picker + merged badges + post-scripts panel have content."""
    samples = [
        {"title": "SQL injection in /api/orders?id=1", "severity": "high", "vuln_class": "sqli",
         "target": "https://shop.example.com/api/orders?id=1",
         "attacker_path": "Send id=1 OR 1=1-- ; the ORDER BY clause concatenates it unescaped, "
         "dumping every customer's orders.", "source_refs": ["api/orders.py:88"],
         "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "reference": "CWE-89",
         "tool": "ai-audit"},
        {"title": "SQL Injection in the orders endpoint", "severity": "critical",
         "vuln_class": "sqli", "target": "https://shop.example.com/api/orders",
         "attacker_path": "Same ORDER BY sink, reached via the sort= parameter.",
         "source_refs": ["api/orders.py:88"], "reference": "CWE-89", "tool": "nuclei"},
        {"title": "SSRF in the avatar image proxy", "severity": "medium", "vuln_class": "ssrf",
         "target": "https://shop.example.com/proxy?url=",
         "attacker_path": "url=http://169.254.169.254/latest/meta-data/ reaches the cloud IMDS; "
         "the response is returned to the attacker.", "source_refs": ["proxy/fetch.py:34"],
         "reference": "CWE-918", "tool": "ai-audit"},
        {"title": "Reflected XSS in search", "severity": "medium", "vuln_class": "stored-xss",
         "target": "https://shop.example.com/search?q=",
         "attacker_path": "q= is echoed into the results title unencoded.",
         "source_refs": ["web/search.tsx:12"], "reference": "CWE-79", "tool": "dalfox"},
        {"title": "Missing Strict-Transport-Security header", "severity": "info",
         "vuln_class": "missing-header", "target": "https://shop.example.com/",
         "attacker_path": "", "source_refs": [], "reference": "best-practice", "tool": "nuclei"},
        {"title": "Missing security header (HSTS) on the API host", "severity": "low",
         "vuln_class": "missing-header", "target": "https://api.example.com/",
         "attacker_path": "", "source_refs": [], "reference": "missing-header", "tool": "nuclei"},
    ]
    ranker_id = (ranker or "").strip() or finding_rankers.DEFAULT_RANKER_ID
    result = finding_pipeline.run_pipeline(samples, ranker_id)
    result["sample"] = True
    return result


class PostScriptRunIn(BaseModel):
    """Run a post-script over a finding. Pass a session + fingerprint to run against a stored
    finding, or an inline finding (the /engagements demo does the latter with synthetic data)."""

    postscript_id: str = Field(..., description="Which post-script (see GET /findings/postscripts).")
    fingerprint: str | None = Field(None, description="A finding already in engagement state.")
    finding: dict[str, Any] | None = Field(
        None, description="An inline finding dict when not persisting (preview / demo).")


@app.post("/sessions/{session_id}/findings/postscript")
def run_finding_postscript(session_id: str, req: PostScriptRunIn = Body(...)) -> dict[str, Any]:
    """Run a post-finding script. DATA post-scripts (validate / report) run in-process and
    return their result; the COMMAND post-script (PoC) returns an APPROVE-EACH proposal — a
    command string with ``needs_approval: true`` that the operator fires through the gated
    executor. Nothing is executed here. A per-(session, finding, script) lock refuses a
    concurrent double-run.
    """
    script = finding_postscripts.get_postscript(req.postscript_id)
    if script is None:
        raise HTTPException(status_code=404, detail="no such post-script")

    finding = req.finding
    fingerprint = (req.fingerprint or "").strip()
    if finding is None and fingerprint:
        finding = next(
            (_finding_to_payload(f) for f in state_store.load(session_id).findings
             if f.fingerprint() == fingerprint),
            None,
        )
    if not finding:
        raise HTTPException(
            status_code=404,
            detail="no such finding (pass a fingerprint in state or an inline finding)")
    lock_fp = fingerprint or hashlib.sha256(
        str(finding.get("title") or "").encode("utf-8")).hexdigest()[:16]
    try:
        with finding_postscripts.LOCKS.guard(session_id, lock_fp, script.id):
            result = finding_postscripts.run(script, finding)
    except finding_postscripts.PostScriptLocked as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return {"postscript": script.meta(), "result": result}


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


@app.get("/operator", response_model=OperatorOut)
def operator_profile() -> dict[str, str]:
    """Who is running this HackPit — NAME AND HANDLE ONLY.

    `operator_identity.public_profile()` is the masked accessor; the raw `load()`
    also carries an OSID and an email, which belong in a report handed to an
    examiner and have no business on a web page. `test_operator.py` asserts on the
    AST that this endpoint calls the masked one, and checks the real configured
    OSID/email never appear in the response.
    """
    return operator_identity.public_profile()


@app.get("/home-summary", response_model=HomeSummary)
def home_summary() -> dict[str, Any]:
    """The launcher's status rail + per-surface counts.

    CROSS-CUTTING BY CONSTRUCTION, so it lives here rather than in any package —
    it reads the sandbox probe, the LLM config, the Windows profile store, the
    engagement store and the KB counters, and `cockpit` and `arsenal` may not
    reference each other (see backend/AGENTS.md).

    NO SECRETS. Every accessor used below is the masked/public variant:
    `llm.public_config()` reduces the API key to a boolean and
    `winprofiles.list_profiles()` returns `_public` rows. The raw
    `llm.load_config()` and `winprofiles.get_secret()` must never appear in this
    function — `test_home_summary.py` asserts that on the source AND proves the
    check can fail by planting a call.

    READ-ONLY. It probes and counts; it starts nothing and runs no user input.
    The docker probes are best-effort: a status endpoint that 500s because the
    stack is down is worse than one that reports "down", so every probe is
    wrapped.
    """
    def _probe(fn: Any) -> bool | None:
        """Run a docker probe, returning None when it cannot be determined."""
        try:
            return bool(fn())
        except Exception:  # noqa: BLE001 - a status endpoint must never 500
            return None

    llm_cfg = llm.public_config()
    profiles = cockpit_winprofiles.list_profiles()
    engagements = cockpit_engagement.list_active()

    active = engagements[0] if engagements else None
    rail = {
        "sandbox_up": _probe(cockpit_sandbox.is_sandbox_up),
        "engage_sandbox_up": _probe(cockpit_sandbox.is_engage_sandbox_up),
        "llm_provider": llm_cfg["provider"],
        "llm_model": llm_cfg["model"],
        "windows_profile": (profiles[0]["name"] or profiles[0]["host"]) if profiles else None,
        "engagement_id": active.engagement_id if active else None,
        "engagement_target": active.target if active else None,
    }

    return {
        "rail": rail,
        "surfaces": {
            "library": STATE.stats.get("total_entries", 0),
            "arsenal": len(attack_path._arsenal().tools),
            "scripts": STATE.scripts.get("total", 0),
            "sessions": len(sessions_db.list_sessions()),
            "engagements": len(engagements),
            "windows_profiles": len(profiles),
        },
    }


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

    Those real commands are the KB author's, written against the KB author's target. Two
    passes make that fact visible rather than letting it read as a finished plan: example
    hosts and placeholders are rewritten to this engagement's target (taken from ``target``,
    else the goal, else the first concrete host in ``scope_text``), and then EVERY command
    is checked against the declared scope, with the ones that still cannot run marked
    ``runnable: false`` and given a reason. ``commands_unrunnable`` is the count. With no
    ``scope_text`` there is nothing to check against and the count is 0 — unchecked, not clean.
    """
    goal = req.goal.strip()
    if not goal:
        raise HTTPException(status_code=400, detail="goal is required")
    try:
        return attack_path.compose(
            STATE.by_id, goal, req.target_type, _resilient_search, req.scope_text,
            req.target,
        )
    except llm.LLMError as e:
        # Ollama offline / no key / unparseable output / nothing grounded.
        raise HTTPException(status_code=503, detail=str(e))


@app.post("/attack-path/alternative", response_model=AlternativeOut)
def attack_path_alternative(req: AltStepIn = Body(...)) -> dict[str, Any]:
    """On-demand SECOND OPINION for one attack-path step. Returns one alternative candidate
    (a grounded KB technique, or an AI-tuned command marked unverified) plus an advisory
    verdict. EXECUTES NOTHING; the primary step is untouched. Soft-fails (alternative null)
    when the LLM is unreachable, so the plan view never breaks."""
    goal = req.goal.strip()
    if not goal:
        raise HTTPException(status_code=400, detail="goal is required")
    return alternatives.best_alternative(
        {"title": req.step_title, "cmd": req.step_cmd, "entry_id": req.step_entry_id},
        goal=goal, target=req.target, scope=req.scope_text,
        by_id=STATE.by_id,
        # the engine's search_fn contract is one-arg; _resilient_search needs (q, top, mode)
        search_fn=lambda q: _resilient_search(q, 8, "hybrid"),
    )


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


class SubmissionIn(BaseModel):
    """The submission fields the bug-bounty report renders. Each is optional; only the ones
    supplied are written, and an EMPTY STRING clears one (a field that can only ever be set
    eventually carries something wrong)."""

    model_config = ConfigDict(extra="forbid")

    cvss_vector: str | None = Field(
        default=None, description="CVSS 3.1 vector, e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    )
    vrt_category: str | None = Field(
        default=None, description="Bugcrowd VRT key from GET /vrt-categories, e.g. 'xss-stored'."
    )
    known_issues: str | None = Field(
        default=None,
        description="The program's published known-issues list, pasted verbatim (one per line).",
    )


@app.get("/vrt-categories")
def list_vrt_categories() -> dict[str, Any]:
    """The Bugcrowd VRT categories HackPit can map to a P1–P5 priority.

    A CURATED SUBSET of the taxonomy at its default priorities — not the full VRT, and any
    program's own brief overrides it. Read-only reference data for a picker; the priority is
    a lookup on the category, never a function of the CVSS score.
    """
    return {"categories": report_gen.vrt_categories()}


@app.patch("/sessions/{session_id}/submission", response_model=SessionDetail)
def set_submission(session_id: str, req: SubmissionIn = Body(...)) -> dict[str, Any]:
    """Set the CVSS vector, VRT category and/or known-issues list for an engagement.

    PATCH, not PUT, and the distinction is load-bearing: only the fields you send are
    written, so this is a partial update rather than a replacement. It shipped as PUT for
    about an hour and the browser refused it — the CORS allow-list names GET/POST/PATCH/
    DELETE, so the preflight failed. Widening that list would have been the easy fix and the
    wrong one: the verb was what did not fit, not the policy.

    Stored verbatim and unvalidated on purpose: an unparseable vector and an unrecognised VRT
    key are both reported IN THE REPORT, where the operator sees them, rather than rejected
    here where the typed text would be lost.
    """
    if not sessions_db.set_submission(
        session_id,
        cvss_vector=req.cvss_vector,
        vrt_category=req.vrt_category,
        known_issues=req.known_issues,
    ):
        raise HTTPException(status_code=404, detail="session not found")
    s = sessions_db.get_session(session_id)
    assert s is not None  # just written to it
    return s


@app.delete("/sessions/{session_id}", status_code=204)
def delete_session(session_id: str) -> None:
    """Delete an engagement and all its step state."""
    if not sessions_db.delete_session(session_id):
        raise HTTPException(status_code=404, detail="session not found")


# ---- engagement governance: RoE / ConOps / Deconfliction / OPPLAN -------- #
# The formal governance package. Everything here is authored + human-approved documentation
# plus a formalised scope frame; it EXECUTES NOTHING and adds NO gate. Generation is
# propose-only (the drafter drafts, the human edits + approves). The RoE FORMALISES the scope
# handrail — it is advisory to the human, never a machine veto. Per-command human approval
# stays THE bound (matching the standing "target lock is a handrail" decision).

def _require_session(session_id: str) -> dict[str, Any]:
    s = sessions_db.get_session(session_id)
    if s is None:
        raise HTTPException(status_code=404, detail="engagement not found")
    return s


def _live_scope_spec(session_id: str) -> str:
    """The program scope of any ACTIVE engagement bound to this session, or '' when the
    session is a plain saved engagement with no live scope. Read-only lookup — used to seed
    the RoE draft and to compute the (advisory) RoE-vs-scope flag."""
    try:
        for rec in cockpit_engagement.list_active():
            if getattr(rec, "session_id", None) == session_id:
                return (getattr(rec, "scope_spec", "") or "").strip()
    except Exception:  # pragma: no cover - a registry read must never break governance
        return ""
    return ""


def _roe_scope_advisory(session_id: str, roe_payload: dict[str, Any]) -> dict[str, Any]:
    """The RoE-vs-scope check. ADVISORY ONLY — it describes, it never blocks. Surfaces whether
    the RoE's declared scope parses, whether it is unbounded ('*'), and whether it MATCHES the
    live engagement scope the executor's handrail actually uses. A mismatch is flagged in the
    UI so the operator reconciles it; the human gate remains the real bound either way."""
    declared = (roe_payload.get("scope_spec") or "").strip()
    live = _live_scope_spec(session_id)
    out: dict[str, Any] = {
        "declared_scope": declared,
        "live_scope": live,
        "status": "ok",
        "notes": [],
        "unbounded": False,
        "advisory": True,   # this can only advise; it never machine-blocks a command
    }
    if not declared:
        out["status"] = "undeclared"
        out["notes"].append("The RoE declares no scope — set it to formalise the handrail.")
        return out
    try:
        resolved = cockpit_scope.parse_scope(declared, resolve=False)
    except ValueError as exc:
        out["status"] = "invalid"
        out["notes"].append(f"RoE scope does not parse: {exc}")
        return out
    out["describe"] = resolved.describe()
    out["unbounded"] = resolved.unbounded()
    if resolved.unbounded():
        out["notes"].append("The RoE scope is '*' (unbounded) — every host is authorized by choice.")
    if live and _norm_scope(live) != _norm_scope(declared):
        out["status"] = "mismatch"
        out["notes"].append(
            "The RoE scope differs from the live engagement scope the handrail uses — reconcile "
            "them. This is flagged, not enforced; human approval stays the bound."
        )
    return out


def _norm_scope(spec: str) -> frozenset[str]:
    return frozenset(t for t in re.split(r"[\s,;]+", (spec or "").strip().lower()) if t)


class GovDraftIn(BaseModel):
    """Optional overrides for a propose-only draft. When omitted, the drafter seeds from the
    session's goal + the live engagement scope."""

    model_config = ConfigDict(extra="forbid")
    scope_spec: str | None = None
    target: str | None = None
    target_type: str | None = None


class GovDocIn(BaseModel):
    """An edited governance-document body. The shape depends on the doc type; stored verbatim
    as versioned JSON. Saving RESETS approval — an edited frame must be re-approved."""

    model_config = ConfigDict(extra="allow")
    payload: dict[str, Any] = Field(default_factory=dict)


class GovApproveIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    approved_by: str | None = Field(default="operator")


class ObjectiveIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = Field(min_length=1)
    parent_id: str | None = None
    phase: str | None = None
    technique_ids: list[str] | None = None
    opsec: str | None = None
    c2_tier: str | None = None
    notes: str | None = None


class ObjectiveUpdateIn(BaseModel):
    """A partial update. A ``status`` change is validated against the OPPLAN state machine —
    an illegal transition is a 400, and NOTHING is written."""

    model_config = ConfigDict(extra="forbid")
    status: str | None = None
    title: str | None = None
    phase: str | None = None
    technique_ids: list[str] | None = None
    opsec: str | None = None
    c2_tier: str | None = None
    notes: str | None = None
    evidence_run_id: str | None = None
    finding_fingerprints: list[str] | None = None


class ExpandIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    child_titles: list[str] = Field(default_factory=list)


class OpplanSeedIn(BaseModel):
    """Create objectives from a drafted OPPLAN's proposed list. Every objective lands PENDING
    for the human to edit — this is the propose-only draft becoming editable rows, not a run."""

    model_config = ConfigDict(extra="forbid")
    objectives: list[dict[str, Any]] = Field(default_factory=list)


def _governance_view(session_id: str) -> dict[str, Any]:
    pkg = gov.package(session_id)
    pkg["scope_check"] = _roe_scope_advisory(session_id, pkg["roe"]["payload"])
    pkg["phases"] = list(gov.OBJECTIVE_PHASES)
    pkg["opsec_levels"] = list(gov.OPSEC_LEVELS)
    pkg["c2_tiers"] = list(gov.C2_TIERS)
    pkg["statuses"] = list(gov.OBJECTIVE_STATUSES)
    return pkg


@app.get("/engagement/{session_id}/governance")
def get_governance(session_id: str) -> dict[str, Any]:
    """The whole governance package — RoE / ConOps / Deconfliction / OPPLAN + objectives +
    ATT&CK coverage + the advisory RoE-vs-scope check. Read-only; executes nothing."""
    _require_session(session_id)
    return _governance_view(session_id)


@app.get("/governance/techniques")
def governance_techniques() -> dict[str, Any]:
    """The MITRE ATT&CK techniques the reference knows about — an objective/RoE picker. Pure
    reference data; not a whitelist (an operator may map an objective to any technique)."""
    return {"techniques": governance_draft.known_techniques()}


@app.post("/engagement/{session_id}/governance/{doc_type}/draft")
def draft_governance_doc(
    session_id: str, doc_type: str, req: GovDraftIn = Body(default=GovDraftIn())
) -> dict[str, Any]:
    """PROPOSE-ONLY: draft one governance document from the scope + target. Returns the drafted
    payload (and whether it came from the LLM or the deterministic fallback) for the human to
    review and PUT. It saves NOTHING and runs NOTHING — the human edits then approves."""
    session = _require_session(session_id)
    dt = (doc_type or "").strip().lower()
    if dt not in gov.DOC_TYPES:
        raise HTTPException(status_code=404, detail=f"unknown governance document '{doc_type}'")
    scope_spec = (req.scope_spec or _live_scope_spec(session_id) or "").strip()
    target = (req.target or session.get("goal") or "").strip()
    target_type = (req.target_type or session.get("target_type") or "").strip()
    # Ground the draft in what the engagement already knows (hosts/services) when available —
    # read-only, and truncated so a huge state cannot blow the prompt budget.
    try:
        state_block = state_store.load(session_id).to_dict().__str__()[:1500]
    except Exception:  # pragma: no cover
        state_block = ""
    if dt == gov.DOC_ROE:
        return draft_governance_doc_result(governance_draft.draft_roe(scope_spec, target, target_type, state_block))
    if dt == gov.DOC_CONOPS:
        return draft_governance_doc_result(governance_draft.draft_conops(scope_spec, target, target_type, state_block))
    if dt == gov.DOC_DECONFLICTION:
        return draft_governance_doc_result(
            governance_draft.draft_deconfliction(session_id, scope_spec, target, target_type, state_block))
    return draft_governance_doc_result(governance_draft.draft_opplan(scope_spec, target, target_type, state_block))


def draft_governance_doc_result(drafted: dict[str, Any]) -> dict[str, Any]:
    return {"payload": drafted.get("payload", {}), "source": drafted.get("source", "fallback")}


@app.patch("/engagement/{session_id}/governance/{doc_type}")
def save_governance_doc(
    session_id: str, doc_type: str, req: GovDocIn = Body(...)
) -> dict[str, Any]:
    """Save an edited document body (versioned; resets approval). Executes nothing.

    PATCH, not PUT — the CORS allow-list is GET/POST/PATCH/DELETE, and a PUT preflight fails so
    the browser cannot call the route at all (the same lesson set_submission learned). The verb
    is what did not fit, not the policy."""
    _require_session(session_id)
    try:
        gov.save_doc(session_id, doc_type, req.payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return _governance_view(session_id)


@app.post("/engagement/{session_id}/governance/{doc_type}/approve")
def approve_governance_doc(
    session_id: str, doc_type: str, req: GovApproveIn = Body(default=GovApproveIn())
) -> dict[str, Any]:
    """The human sign-off on a document version. Records a decision — grants no capability,
    gates nothing, runs nothing. This is what turns the scope handrail into a written RoE the
    operator agreed to, without making it a machine veto."""
    _require_session(session_id)
    try:
        gov.approve_doc(session_id, doc_type, req.approved_by or "operator")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return _governance_view(session_id)


@app.get("/engagement/{session_id}/objectives")
def list_objectives(session_id: str) -> dict[str, Any]:
    """The OPPLAN — versioned objectives + summary + ATT&CK coverage. Read-only."""
    _require_session(session_id)
    return gov.opplan_payload(session_id)


@app.post("/engagement/{session_id}/objectives")
def add_objective(session_id: str, req: ObjectiveIn = Body(...)) -> dict[str, Any]:
    """Add an OPPLAN objective (or a sub-objective under ``parent_id``). Starts PENDING."""
    _require_session(session_id)
    try:
        obj = gov.add_objective(
            session_id, req.title, parent_id=req.parent_id,
            phase=req.phase or gov.OBJECTIVE_PHASES[0],
            technique_ids=req.technique_ids or [],
            opsec=req.opsec or gov.OPSEC_STANDARD, c2_tier=req.c2_tier or gov.C2_NONE,
            notes=req.notes or "",
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"objective": obj.to_dict(), "opplan": gov.opplan_payload(session_id)}


@app.patch("/engagement/{session_id}/objectives/{obj_id}")
def update_objective(session_id: str, obj_id: str, req: ObjectiveUpdateIn = Body(...)) -> dict[str, Any]:
    """Update an objective. A ``status`` change is validated against the OPPLAN state machine —
    an illegal transition (e.g. out of the terminal ``completed`` state) is a 400 and nothing
    is written. ``evidence_run_id`` records the approved, exit-0 run that advanced it (the same
    advance-evidence model the graph orchestrator uses)."""
    _require_session(session_id)
    try:
        obj = gov.update_objective(
            session_id, obj_id, status=req.status, title=req.title, phase=req.phase,
            technique_ids=req.technique_ids, opsec=req.opsec, c2_tier=req.c2_tier,
            notes=req.notes, evidence_run_id=req.evidence_run_id,
            finding_fingerprints=req.finding_fingerprints,
        )
    except gov.TransitionError as exc:
        raise HTTPException(status_code=400, detail={"gate": "state-machine", "reason": str(exc)})
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"objective": obj.to_dict(), "opplan": gov.opplan_payload(session_id)}


@app.post("/engagement/{session_id}/objectives/{obj_id}/expand")
def expand_objective(session_id: str, obj_id: str, req: ExpandIn = Body(...)) -> dict[str, Any]:
    """Expand an objective into sub-objectives (opplan expand)."""
    _require_session(session_id)
    made = gov.expand_objective(session_id, obj_id, req.child_titles)
    return {"created": [o.to_dict() for o in made], "opplan": gov.opplan_payload(session_id)}


@app.post("/engagement/{session_id}/objectives/{obj_id}/collapse")
def collapse_objective(session_id: str, obj_id: str) -> dict[str, Any]:
    """Collapse an objective (opplan collapse): delete its sub-objectives, keep the objective."""
    _require_session(session_id)
    removed = gov.collapse_objective(session_id, obj_id)
    return {"removed": removed, "opplan": gov.opplan_payload(session_id)}


@app.delete("/engagement/{session_id}/objectives/{obj_id}")
def delete_objective(session_id: str, obj_id: str) -> dict[str, Any]:
    """Delete an objective and its sub-objectives."""
    _require_session(session_id)
    removed = gov.delete_objective(session_id, obj_id)
    if not removed:
        raise HTTPException(status_code=404, detail="objective not found")
    return {"removed": removed, "opplan": gov.opplan_payload(session_id)}


@app.post("/engagement/{session_id}/opplan/seed")
def seed_opplan(session_id: str, req: OpplanSeedIn = Body(...)) -> dict[str, Any]:
    """Create objectives from a drafted OPPLAN's proposed list. Each becomes a PENDING
    objective for the human to edit — the propose-only draft turning into editable rows."""
    _require_session(session_id)
    created = []
    for spec in req.objectives:
        title = str(spec.get("title") or "").strip()
        if not title:
            continue
        try:
            obj = gov.add_objective(
                session_id, title, phase=spec.get("phase") or gov.OBJECTIVE_PHASES[0],
                technique_ids=spec.get("technique_ids") or [],
                opsec=spec.get("opsec") or gov.OPSEC_STANDARD,
                c2_tier=spec.get("c2_tier") or gov.C2_NONE, notes=spec.get("notes") or "",
            )
            created.append(obj.to_dict())
        except ValueError:
            break  # OPPLAN full — keep what landed
    return {"created": created, "opplan": gov.opplan_payload(session_id)}


def _governance_report_md(session_id: str) -> str:
    """Render the engagement's governance package as a Markdown appendix for the report. Pure
    string building over the governance records — executes nothing. Returns '' when there is
    no governance to report, so a report on an engagement without one is byte-identical."""
    pkg = gov.package(session_id)
    objectives = pkg["opplan"]["objectives"]
    roe, conops, decon = pkg["roe"], pkg["conops"], pkg["deconfliction"]
    coverage = pkg["opplan"]["attack_coverage"]
    has_docs = any(d["version"] > 0 for d in (roe, conops, decon))
    if not objectives and not has_docs:
        return ""
    out: list[str] = ["\n\n---\n\n## Engagement Governance\n"]

    def _doc_status(d: dict[str, Any]) -> str:
        if d["approved"]:
            return f"**approved**{(' · ' + d['approved_by']) if d['approved_by'] else ''} (v{d['version']})"
        if d["version"] > 0:
            return f"drafted, awaiting approval (v{d['version']})"
        return "not drafted"

    if has_docs:
        out.append("\n### Rules of Engagement\n")
        out.append(f"- Status: {_doc_status(roe)}\n")
        rp = roe["payload"]
        if rp.get("scope_spec"):
            out.append(f"- Authorized scope: `{rp['scope_spec']}`\n")
        if rp.get("opsec_level"):
            out.append(f"- OPSEC level: {rp['opsec_level']}\n")
        for label, key in (("Forbidden techniques", "forbidden_techniques"),
                           ("Stop conditions", "stop_conditions")):
            vals = rp.get(key) or []
            if vals:
                out.append(f"- {label}: {', '.join(str(v) for v in vals)}\n")
        out.append(f"\n### Concept of Operations\n- Status: {_doc_status(conops)}\n")
        if conops["payload"].get("approach"):
            out.append(f"- Approach: {conops['payload']['approach']}\n")
        out.append(f"\n### Deconfliction Plan\n- Status: {_doc_status(decon)}\n")
        if decon["payload"].get("engagement_signature"):
            out.append(f"- Engagement signature: `{decon['payload']['engagement_signature']}`\n")

    if objectives:
        s = pkg["opplan"]["summary"]
        out.append(
            f"\n### OPPLAN — Objectives ({s['completed']}/{s['total']} completed)\n\n"
            "| # | Objective | Phase | Status | ATT&CK | Evidence |\n"
            "|---|-----------|-------|--------|--------|----------|\n"
        )
        for o in objectives:
            techs = ", ".join(o["technique_ids"]) or "—"
            out.append(
                f"| {o['obj_id']} | {o['title']} | {o['phase']} | {o['status']} | "
                f"{techs} | {o['evidence_run_id'] or '—'} |\n"
            )
        c = coverage["counts"]
        out.append(
            f"\n### MITRE ATT&CK Coverage\n\n"
            f"- Tactics exercised: {c['tactics_touched']} / {c['tactics_total']}\n"
            f"- Techniques exercised: {c['techniques_covered']} / {c['techniques_total']}\n"
        )
        covered = [
            f"{t['tactic_name']} ({', '.join(x['id'] for x in t['techniques'] if x['covered'])})"
            for t in coverage["grid"] if t["covered"]
        ]
        if covered:
            out.append("- " + "; ".join(covered) + "\n")
    return "".join(out)


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
    engagement_state = state_store.load(session_id).to_dict(include_secrets=True)
    session["state_hosts"] = engagement_state["hosts"]
    # ...and the findings, so the known-issue check has something to compare the program's
    # published list against. Read-only: the check FLAGS a possible match and never removes
    # a finding.
    session["state_findings"] = engagement_state["findings"]
    try:
        report_md, model_used = report_gen.compose_report(
            session, template=template, include_opsec=include_opsec
        )
    except llm.LLMError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except ValueError as e:  # unknown template
        raise HTTPException(status_code=422, detail=str(e))

    # Fold the governance package into the report — the approved RoE/ConOps/Deconfliction, the
    # OPPLAN objectives with their final status, and the ATT&CK coverage view are a professional
    # deliverable. Appended AFTER composition (a pure string build over the governance records),
    # so it needs no change to report_gen and nothing here executes.
    report_md += _governance_report_md(session_id)

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
# The SAME resolver feeds the cloud orchestrator, for the same reason: the cloud proposer receives
# only an inert, read-only scope description and cannot enter or look up an engagement itself.
set_cloud_scope_resolver(_loop_scope_context)


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


# --- Task 3 / Task 4: web-exploit + privesc drafting (propose/ground only; human fires) ---
class WebExploitIn(BaseModel):
    """Draft the concrete exploit for a web finding. The finding is passed by fingerprint (pulled
    from state) or inline. NOTHING is sent — the draft goes to the human to fire."""

    fingerprint: str | None = Field(None, description="Fingerprint of a finding already in state.")
    finding: dict[str, Any] | None = Field(
        None, description="Inline finding {title, target, reference, params} when not in state yet."
    )


@app.post("/sessions/{session_id}/webexploit/draft")
def webexploit_draft(session_id: str, req: WebExploitIn = Body(...)) -> dict[str, Any]:
    """Task 3 — draft the real exploit (sqlmap / SSRF probe / IDOR / param-pollution) for a web
    finding, grounded in the bug-bounty KB, for the human to fire through the repeater/executor.

    Propose/ground/generate only: this returns a DRAFT (data). It never sends a request and never
    runs a command — the human fires the drafted step through the already-gated surface, where
    scope + approval + danger are re-checked.
    """
    finding = req.finding
    if finding is None and req.fingerprint:
        finding = next(
            (
                {**vars(f), "fingerprint": f.fingerprint()}
                for f in state_store.load(session_id).findings
                if f.fingerprint() == req.fingerprint
            ),
            None,
        )
    if not finding:
        raise HTTPException(status_code=404, detail="no such finding (pass a fingerprint in state or an inline finding)")
    state = state_store.load(session_id)
    draft = reasoning.webexploit.draft_exploit(
        finding, state, lambda q: _resilient_search(q, 3, "hybrid")
    )
    return draft.to_dict()


class PrivescIngestIn(BaseModel):
    """Paste linpeas / winpeas (or equivalent) output; get the identified vectors + drafted step."""

    output: str = Field(..., description="Raw linpeas/winpeas output pasted from the foothold.")


@app.post("/sessions/{session_id}/privesc/ingest")
def privesc_ingest(session_id: str, req: PrivescIngestIn = Body(...)) -> dict[str, Any]:
    """Task 4 — ingest linpeas/winpeas output, identify the privesc vectors, and draft the
    escalation for the strongest one, grounded in the KB + state.

    Propose/ground/draft only. The drafted step is returned as data for the human to approve and
    run on the foothold — execution stays human-approved.
    """
    state = state_store.load(session_id)
    return reasoning.privesc.ingest_and_propose(
        req.output, state, lambda q: _resilient_search(q, 3, "hybrid")
    )


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
    req: cockpit_sliver.SliverServerRequest = Body(...),
) -> cockpit_sliver.SliverServer:
    """Start the operator's OWN Sliver server in the engage sandbox. *** HUMAN-ONLY *** + GATED.

    403 naming the gate when the engagement, the approval or the red-confirm is missing —
    NOTHING spawns. 409 if the sandbox is down, the live cap is hit, the docker CLI is missing,
    or the daemon did not stay up.

    THE BODY IS NOW REQUIRED. It used to default to an empty request, which after build #7's
    gating would have meant "an omitted body is an unapproved start" — a 403 for a client that
    sent nothing, instead of a clear 422 saying which fields a start needs. A gate should refuse
    a request, not a blank.
    """
    try:
        return cockpit_sliver.start_server(req)
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
    liveness: str = Field(
        "", description="What was OBSERVED about the server process and its port after the "
        "settle window — the evidence behind `status`, not a restatement of it."
    )
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


def _obfuscation_http_error(exc: "cockpit_obfuscation.ObfuscationRefused") -> HTTPException:
    """Map a DNS-tunnel refusal to a status code.

    Same split the pivot listener uses, and for the same reason: a SAFETY refusal (engagement /
    approval / danger) is **403** naming the gate and carrying the danger reasons so the UI can
    render the red-confirm, while an AVAILABILITY problem (sandbox down, cap hit, the listener
    did not stay up) is **409**. Collapsing the two would leave the panel unable to tell "you
    must confirm this" from "the box is not there".
    """
    status = 404 if exc.gate == "unknown" else 409 if exc.gate in {"unavailable", "limit"} else 403
    return HTTPException(status_code=status, detail={
        "gate": exc.gate,
        "reason": exc.reason,
        "dangerous_flags": list(getattr(exc, "dangerous_flags", []) or []),
    })


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
    """Start a dnscat2/iodine listener in the engage sandbox. *** HUMAN-ONLY *** and GATED.

    403 naming the gate when the engagement, the approval or the red-confirm is missing —
    NOTHING spawns. 409 if the sandbox is down, the cap is hit, docker is missing or the
    listener did not stay up; 422 if the zone/secret/tunnel-net bounds reject the request.

    The response carries the CLIENT one-liner with the key masked. Carrying that line to the
    far side is the operator's own manual step — HackPit cannot reach a machine it has not
    compromised, and there is no route here that tries.
    """
    try:
        return _listener_public(cockpit_obfuscation.start_listener(req))
    except cockpit_obfuscation.ObfuscationRefused as exc:
        raise _obfuscation_http_error(exc)


@app.delete("/api/obfuscation/listeners/{lid}", response_model=ObfuscationListenerOut)
def obfuscation_stop_listener(lid: str) -> dict[str, Any]:
    """Stop a DNS-tunnel listener. *** HUMAN-ONLY. *** Idempotent; 404 on an unknown id."""
    try:
        return _listener_public(cockpit_obfuscation.stop_listener(lid))
    except cockpit_obfuscation.ObfuscationRefused as exc:
        raise _obfuscation_http_error(exc)


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


@app.post("/api/evasion/deliver", response_model=evasion_engine.DeliveryResult)
def evasion_deliver(
    req: evasion_engine.DeliveryRequest = Body(...),
) -> evasion_engine.DeliveryResult:
    """Put a built artifact on the target, and optionally RUN it (build #13 part 2).

    THIS IS THE POLICY REVERSAL. The engine used to carry no delivery or execution primitive
    at all. It does now, gated exactly like every other command here: engagement or Windows
    profile → target-lock → per-command approval → red-confirm. 403 names the gate on any
    refusal, with nothing delivered.

    The red-confirm is required UNCONDITIONALLY, not left to the heuristic to notice — build
    #5 found a red-confirm defeated by moving a cmdlet one token right.

    ``kind`` is a CLOSED SET (winrm | smb). There is no free-form delivery command, because
    one would be a general execution path with none of these gates. ``invoke`` is WinRM-only:
    running the artifact inside HackPit's own sandbox would detonate it on the operator's box,
    so it is refused rather than merely unimplemented.

    409 with ``gate='honesty'`` if the footprint cannot be produced — no footprint, no
    delivery, same contract as generate.
    """
    try:
        return evasion_engine.deliver(req)
    except evasion_engine.EvasionRefused as exc:
        raise _evasion_http_error(exc)
    except evasion_engine.EvasionError as exc:
        raise HTTPException(status_code=409, detail={"gate": "honesty", "reason": str(exc)})
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail={"gate": "artifact", "reason": str(exc)})


# --------------------------------------------------------------------------- #
# CROSS-DOMAIN KILL-CHAIN OVERLAY (see backend/killchain/) — the capstone that stitches the web
# foothold, cloud IAM and on-prem AD graphs into ONE routed kill chain.
#
# CROSS-CUTTING, so it lives HERE and not inside any graph package: it reads each graph's PUBLIC
# DICT from its store (cloud_store / ad_store) + the web lane from engagement findings, and hands
# those dicts to the killchain overlay — which imports NEITHER adgraph NOR cloudgraph (the two graph
# packages stay decoupled from each other AND from the overlay; a safety test proves it). The overlay
# PROPOSES an edge index and executes nothing: a cross-domain SEAM hop is approved and sent to
# POST /cockpit/exec (the same gated executor); a within-lane hop is approved in its own :cloud /
# :ad-graph view (single source of truth for per-lane abuse — no duplicated catalog here).
# --------------------------------------------------------------------------- #
from killchain import service as kc_service  # noqa: E402


def _killchain_kb_grounder(seeds: str) -> dict | None:
    """Ground a CROSS-DOMAIN seam in the KB. A bridge spans lanes (web → cloud → AD), so unlike the
    cloud grounder this is not category-restricted: the best entry whose commands include a real
    invocation for the seam's seed terms. The bridge catalog only ADOPTS the command when its tool
    head matches, so a mismatched entry is cited but not mis-grounded. Returns ``{id, title,
    commands}`` or None (→ catalog fallback / ai_suggested)."""
    try:
        hits = _resilient_search(seeds, 8, "hybrid")
    except Exception:
        return None
    for h in hits:
        e = STATE.by_id.get(h.get("id"))
        if not e:
            continue
        cmds = attack_path.entry_commands(e)
        if cmds:
            return {"id": e["id"], "title": e.get("title") or e["id"], "commands": cmds[:3]}
    return None


def _killchain_graph_for(session_id: str | None, demo: bool):
    """Build the merged kill-chain graph: the synthetic demo, or a session's live lanes (the cloud
    graph's public dict + the AD graph's public dict + the web lane from engagement findings). Falls
    back to the demo when there is nothing live to stitch, so the surface always renders."""
    if demo or not session_id:
        return kc_service.build_demo()
    cloud_row = cloud_store.latest_for_session(session_id)
    ad_row = ad_store.latest_for_session(session_id)
    cloud_dict = cloud_row.get("graph") if isinstance(cloud_row, dict) else None
    ad_dict = ad_row.get("graph") if isinstance(ad_row, dict) else None
    try:
        findings = state_store.load(session_id).findings
    except Exception:
        findings = []
    graph = kc_service.build_from_session(cloud_dict, ad_dict, findings)
    return graph if graph.nodes else kc_service.build_demo()


class KillchainProposeIn(BaseModel):
    session_id: str | None = Field(
        None, description="Session whose live lanes to merge (omit / demo=true for the synthetic chain)."
    )
    demo: bool = Field(False, description="Use the synthetic three-lane demo instead of live lanes.")
    owned: list[str] = Field(default_factory=list, description="Merged node ids of footholds you control.")
    traversed: list[str] = Field(default_factory=list, description="Edge keys already walked.")
    goal: str | None = Field(None, description="Objective node id; omit to auto-pick the furthest high-value node.")
    engagement_id: str | None = Field(None, description="Engagement to scope the pre-check to.")
    avoid: list[str] = Field(default_factory=list, description="Edge keys the operator skipped.")


class KillchainAdvanceIn(BaseModel):
    session_id: str | None = None
    demo: bool = False
    owned: list[str] = Field(default_factory=list)
    traversed: list[str] = Field(default_factory=list)
    source: str
    target: str
    kind: str
    run_id: str | None = Field(
        None, description="The approved, exit-0 run that carried out a cross-domain hop. Not required "
        "for a within-lane hop (approved in its own view) or an inherited-rights hop.",
    )


@app.get("/killchain/graph")
def killchain_graph(session_id: str | None = Query(None), demo: bool = Query(False),
                    start: str | None = Query(None), goal: str | None = Query(None)) -> dict[str, Any]:
    """The merged three-lane kill-chain graph + the computed route from an owned foothold to the
    objective, with each hop's technique. Read-only — nothing runs."""
    graph = _killchain_graph_for(session_id, demo)
    return kc_service.graph_payload(graph, start, goal, _killchain_kb_grounder)


@app.post("/killchain/propose")
def killchain_propose(req: KillchainProposeIn) -> dict[str, Any]:
    """Propose the NEXT edge to take across the chain. Executes NOTHING — returns a proposal the
    human reviews and explicitly approves (a seam step → POST /cockpit/exec; a within-lane step → its
    own :cloud / :ad-graph view)."""
    graph = _killchain_graph_for(req.session_id, req.demo)
    scope_ctx = _loop_scope_context(req.engagement_id) if req.engagement_id else None
    try:
        return kc_service.propose_payload(
            graph, req.owned, req.traversed, req.goal, llm.load_config(),
            _killchain_kb_grounder, scope_ctx, req.avoid, engagement=bool(req.engagement_id),
        )
    except kc_service.KillchainError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.detail)
    except llm.LLMError as exc:
        raise HTTPException(status_code=503, detail=str(exc))


@app.post("/killchain/advance")
def killchain_advance(req: KillchainAdvanceIn) -> dict[str, Any]:
    """Record that a hop SUCCEEDED and advance the chain. A cross-domain (runnable) hop advances ONLY
    on an approved, exit-0 run (evidence, not a claim); a within-lane hop advances on the operator's
    word (it was approved in its own view). Executes nothing."""
    from cockpit import runstore

    graph = _killchain_graph_for(req.session_id, req.demo)
    try:
        out = kc_service.advance_step(
            graph, owned=req.owned, traversed=req.traversed, source=req.source, target=req.target,
            kind=req.kind, run_id=req.run_id, run_lookup=runstore.get_run,
        )
    except kc_service.KillchainError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.detail)
    # The kill-chain STEP lands as a Finding in engagement state (mirrors :cloud / :ad-graph).
    if req.session_id:
        try:
            edge = out["proposal"]["edge"]
            state_store.upsert_findings([Finding(
                session_id=req.session_id,
                title=f"Kill-chain step: {edge['kind']} ({edge['domain_from']}→{edge['domain_to']})",
                severity="high",
                target=edge["target_label"],
                tool="killchain", reference=req.run_id or "within-lane",
                evidence=f"{edge['source_label']} --{edge['kind']}--> {edge['target_label']} "
                         f"(run {req.run_id or 'n/a'})",
                source_run_id=req.run_id,
            )])
        except Exception:  # noqa: BLE001 - finding is best-effort
            pass
    return out
