"""Formal engagement governance — RoE / ConOps / Deconfliction / OPPLAN, as persisted records.

WHY THIS EXISTS
HackPit's bound on a real-target run has always been *human approval of every command*. That
is the wall. What it lacked was the written frame a professional engagement approves inside:
the Rules of Engagement the operator signs off, the Concept of Operations the work follows,
the Deconfliction Plan that tells a blue team this traffic is us, and an OPPLAN — a list of
objectives with a status state machine and a MITRE ATT&CK mapping — that the objectives-driven
targeting proposes toward.

This package turns "human approves each command" into "human approves each command *inside a
written, agreed operating frame*." The RoE FORMALISES the scope handrail (scope.py); it does
NOT replace it and it is NOT a machine veto — human approval stays the actual bound, exactly
as the standing model says. Generation is propose-only (see governance_draft.py): the model
DRAFTS these four documents from the scope + target, the human edits and approves, and nothing
is "live" until then.

PORTED FROM Decepticon (tools/opplan.py — Objective / OPPLAN / ObjectivePhase / ObjectiveStatus
/ C2Tier / OpsecLevel + the objective status state machine; tools/defense/conops.py; and the
RoE structure in middleware/roe.py), Apache-2.0. See THIRD_PARTY_LICENSES and NOTICE. The data
model and the state machine are ported wholesale; the persistence is reshaped onto HackPit's
SQLite (shared ``sessions.db``, upsert-only, one engagement is one slice keyed by session_id).

NOTHING IN THIS MODULE EXECUTES ANYTHING. Like the rest of the state package it has no
subprocess, no socket, no network, no eval/exec, and it imports nothing from cockpit / the
executor / the engagement-mode entry — the RoE-vs-scope advisory check lives in the app layer
(main.py), which is where scope.py may be imported. A safety test proves this by AST. The
governance package adds NO new gate: it is authored, human-approved documentation plus a
formalised scope frame, and it can only ever DESCRIBE — never block, never run.
"""

from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

from . import killchain
from .store import DB_PATH

# --------------------------------------------------------------------------- #
# the ported enums (kept as string constants + tuples, HackPit's house style)
# --------------------------------------------------------------------------- #

# ObjectiveStatus — the state machine's states.
STATUS_PENDING = "pending"
STATUS_IN_PROGRESS = "in-progress"
STATUS_COMPLETED = "completed"
STATUS_BLOCKED = "blocked"
STATUS_CANCELLED = "cancelled"
OBJECTIVE_STATUSES = (
    STATUS_PENDING, STATUS_IN_PROGRESS, STATUS_COMPLETED, STATUS_BLOCKED, STATUS_CANCELLED,
)

# The ported status state machine. completed and cancelled are TERMINAL — no transition out.
# A blocked objective can be unblocked (back to in-progress) or cancelled. This is opplan.py's
# ``_VALID_TRANSITIONS`` verbatim in intent: pending -> in-progress -> completed/blocked/cancelled.
_VALID_TRANSITIONS: dict[str, frozenset[str]] = {
    STATUS_PENDING: frozenset({STATUS_IN_PROGRESS, STATUS_CANCELLED, STATUS_BLOCKED}),
    STATUS_IN_PROGRESS: frozenset({STATUS_COMPLETED, STATUS_BLOCKED, STATUS_CANCELLED}),
    STATUS_BLOCKED: frozenset({STATUS_IN_PROGRESS, STATUS_CANCELLED}),
    STATUS_COMPLETED: frozenset(),   # terminal
    STATUS_CANCELLED: frozenset(),   # terminal
}

# ObjectivePhase — HackPit's four ConOps phases (see killchain.PHASES).
OBJECTIVE_PHASES = killchain.PHASES  # recon / exploitation / post-exploitation / actions-on-objectives

# OpsecLevel — how loud an objective is allowed to be, quietest last.
OPSEC_RECKLESS = "reckless"
OPSEC_STANDARD = "standard"
OPSEC_CAREFUL = "careful"
OPSEC_GHOST = "ghost"
OPSEC_LEVELS = (OPSEC_RECKLESS, OPSEC_STANDARD, OPSEC_CAREFUL, OPSEC_GHOST)

# C2Tier — the C2 posture an objective assumes (none = no implant/callback involved).
C2_NONE = "none"
C2_TIER1 = "tier1-interactive"
C2_TIER2 = "tier2-short-haul"
C2_TIER3 = "tier3-long-haul"
C2_TIERS = (C2_NONE, C2_TIER1, C2_TIER2, C2_TIER3)

# The four governance document kinds.
DOC_ROE = "roe"
DOC_CONOPS = "conops"
DOC_DECONFLICTION = "deconfliction"
DOC_OPPLAN = "opplan"
DOC_TYPES = (DOC_ROE, DOC_CONOPS, DOC_DECONFLICTION, DOC_OPPLAN)

# Bounds — an OPPLAN a human reads, not a runaway. Mirrors tasks.py's philosophy.
MAX_OBJECTIVES = 200
MAX_CHILDREN = 24
MAX_DEPTH = 3
MAX_TITLE_CHARS = 200
MAX_NOTES_CHARS = 2000

_ID_RE = re.compile(r"^\d+(?:\.\d+)*$")


class TransitionError(ValueError):
    """Raised when an objective status change is not allowed by the state machine."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def can_transition(current: str, target: str) -> bool:
    """True if ``current -> target`` is a legal objective status change. A no-op
    (current == target) is always legal so re-saving an objective never fails."""
    cur = (current or "").strip().lower()
    tgt = (target or "").strip().lower()
    if tgt not in OBJECTIVE_STATUSES:
        return False
    if cur == tgt:
        return True
    return tgt in _VALID_TRANSITIONS.get(cur, frozenset())


# --------------------------------------------------------------------------- #
# the OPPLAN objective (ported data model)
# --------------------------------------------------------------------------- #
@dataclass
class Objective:
    """One OPPLAN objective. ``obj_id`` is a dotted path ("1", "1.2") so an objective can be
    EXPANDED into sub-objectives and COLLAPSED back — the opplan.py expand/collapse tools."""

    session_id: str
    obj_id: str
    title: str
    phase: str = OBJECTIVE_PHASES[0]
    status: str = STATUS_PENDING
    technique_ids: list[str] = field(default_factory=list)   # MITRE ATT&CK ids
    opsec: str = OPSEC_STANDARD
    c2_tier: str = C2_NONE
    notes: str = ""
    evidence_run_id: str | None = None      # the approved, exit-0 run that advanced it
    finding_fingerprints: list[str] = field(default_factory=list)  # findings this objective produced
    created_at: str = ""
    updated_at: str = ""

    @property
    def depth(self) -> int:
        return self.obj_id.count(".") + 1

    @property
    def parent_id(self) -> str | None:
        return self.obj_id.rsplit(".", 1)[0] if "." in self.obj_id else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "obj_id": self.obj_id,
            "title": self.title,
            "phase": self.phase,
            "status": self.status,
            "technique_ids": list(self.technique_ids),
            "techniques": [
                {"id": t, "name": killchain.technique_name(t), "known": killchain.is_known(t)}
                for t in self.technique_ids
            ],
            "opsec": self.opsec,
            "c2_tier": self.c2_tier,
            "notes": self.notes,
            "evidence_run_id": self.evidence_run_id,
            "finding_fingerprints": list(self.finding_fingerprints),
            "depth": self.depth,
            "parent_id": self.parent_id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


def _clean_techniques(raw: Any) -> list[str]:
    """Normalise a technique-id list: upper-cased, de-duplicated, order-preserved. Anything
    that is not a plausible ATT&CK id (Tnnnn or Tnnnn.nnn) is dropped, not invented."""
    out: list[str] = []
    if isinstance(raw, str):
        raw = re.split(r"[\s,]+", raw)
    for t in raw or []:
        tid = str(t or "").strip().upper()
        if re.fullmatch(r"T\d{4}(?:\.\d{3})?", tid) and tid not in out:
            out.append(tid)
    return out


def _valid_phase(phase: Any) -> str:
    p = str(phase or "").strip().lower()
    return p if p in OBJECTIVE_PHASES else OBJECTIVE_PHASES[0]


def _valid_opsec(level: Any) -> str:
    v = str(level or "").strip().lower()
    return v if v in OPSEC_LEVELS else OPSEC_STANDARD


def _valid_c2(tier: Any) -> str:
    v = str(tier or "").strip().lower()
    return v if v in C2_TIERS else C2_NONE


# --------------------------------------------------------------------------- #
# the four documents (data model)
# --------------------------------------------------------------------------- #
@dataclass
class GovernanceDoc:
    """One persisted governance document — RoE / ConOps / Deconfliction / OPPLAN-settings.

    ``payload`` is the document's structured body (each kind has its own shape; the drafter
    and the frontend agree on it). It is stored as versioned JSON: every save bumps
    ``version``. ``approved`` is the human sign-off — nothing is "live" until it is set, and
    it is the human's act, never the drafter's. The RoE's approval is what turns the scope
    handrail into a written frame the operator agreed to."""

    session_id: str
    doc_type: str
    version: int = 0
    payload: dict[str, Any] = field(default_factory=dict)
    approved: bool = False
    approved_by: str = ""
    approved_at: str = ""
    updated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "doc_type": self.doc_type,
            "version": self.version,
            "payload": self.payload,
            "approved": self.approved,
            "approved_by": self.approved_by,
            "approved_at": self.approved_at,
            "updated_at": self.updated_at,
        }


# Default (empty-but-shaped) payloads, so a never-drafted document still renders a form the
# operator can fill in by hand. These are the field lists from spec §2a.
def default_payload(doc_type: str) -> dict[str, Any]:
    if doc_type == DOC_ROE:
        return {
            "scope_spec": "",                 # references the scope model (scope.py), never replaces it
            "authorized_techniques": [],
            "forbidden_techniques": [],
            "opsec_level": OPSEC_STANDARD,
            "time_windows": [],
            "excluded_targets": [],
            "excluded_actions": [],
            "sensitive_data_handling": "",
            "stop_conditions": [],
            "emergency_contacts": [],
        }
    if doc_type == DOC_CONOPS:
        return {
            "approach": "",
            "phases": [],                     # [{name, description, success_criteria}]
            "success_criteria": [],
        }
    if doc_type == DOC_DECONFLICTION:
        return {
            "engagement_signature": "",       # the per-engagement tag/marker
            "source_markers": [],
            "notification_contacts": [],
            "traffic_identification": "",
            "blue_team_notes": "",
        }
    if doc_type == DOC_OPPLAN:
        # OPPLAN settings only — the objectives themselves live in their own table so they can
        # be CRUD'd individually and advanced by the orchestrator.
        return {"default_opsec": OPSEC_STANDARD, "default_c2_tier": C2_NONE, "notes": ""}
    return {}


# --------------------------------------------------------------------------- #
# schema
# --------------------------------------------------------------------------- #
def init_db() -> None:
    """Create the governance tables. Idempotent; safe on every startup."""
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS governance_docs (
                session_id  TEXT NOT NULL,
                doc_type    TEXT NOT NULL,
                version     INTEGER NOT NULL DEFAULT 0,
                payload     TEXT NOT NULL DEFAULT '{}',
                approved    INTEGER NOT NULL DEFAULT 0,
                approved_by TEXT NOT NULL DEFAULT '',
                approved_at TEXT NOT NULL DEFAULT '',
                updated_at  TEXT NOT NULL,
                PRIMARY KEY (session_id, doc_type)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS governance_objectives (
                session_id      TEXT NOT NULL,
                obj_id          TEXT NOT NULL,
                title           TEXT NOT NULL,
                phase           TEXT NOT NULL DEFAULT 'recon',
                status          TEXT NOT NULL DEFAULT 'pending',
                technique_ids   TEXT NOT NULL DEFAULT '[]',
                opsec           TEXT NOT NULL DEFAULT 'standard',
                c2_tier         TEXT NOT NULL DEFAULT 'none',
                notes           TEXT NOT NULL DEFAULT '',
                evidence_run_id TEXT,
                finding_fps     TEXT NOT NULL DEFAULT '[]',
                created_at      TEXT NOT NULL,
                updated_at      TEXT NOT NULL,
                PRIMARY KEY (session_id, obj_id)
            )
            """
        )
        # A monotonically-increasing OPPLAN version per session: every objective mutation bumps
        # it, so the OPPLAN's "versioned JSON" has a real version and two reads can be ordered.
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS governance_opplan_meta (
                session_id TEXT NOT NULL,
                version    INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (session_id)
            )
            """
        )


# --------------------------------------------------------------------------- #
# documents — read / write / approve (versioned JSON)
# --------------------------------------------------------------------------- #
def get_doc(session_id: str, doc_type: str) -> GovernanceDoc:
    """The stored document, or an empty-but-shaped one (version 0, not approved) when none
    has been drafted yet — so the UI always has a form to render."""
    dt = (doc_type or "").strip().lower()
    if dt not in DOC_TYPES:
        raise ValueError(f"unknown governance document '{doc_type}'")
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM governance_docs WHERE session_id=? AND doc_type=?",
            (session_id, dt),
        ).fetchone()
    if row is None:
        return GovernanceDoc(
            session_id=session_id, doc_type=dt, version=0,
            payload=default_payload(dt), approved=False, updated_at="",
        )
    return GovernanceDoc(
        session_id=row["session_id"], doc_type=row["doc_type"], version=row["version"],
        payload=json.loads(row["payload"] or "{}"),
        approved=bool(row["approved"]), approved_by=row["approved_by"],
        approved_at=row["approved_at"], updated_at=row["updated_at"],
    )


def save_doc(session_id: str, doc_type: str, payload: dict[str, Any]) -> GovernanceDoc:
    """Persist an edited document body. Bumps ``version`` and RESETS approval — an edited RoE
    must be re-approved, because the frame the human signed off has changed. Executes nothing."""
    dt = (doc_type or "").strip().lower()
    if dt not in DOC_TYPES:
        raise ValueError(f"unknown governance document '{doc_type}'")
    if not session_id:
        raise ValueError("session_id is required")
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    current = get_doc(session_id, dt)
    new_version = current.version + 1
    now = _now()
    body = json.dumps(payload)[:200_000]
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO governance_docs
                (session_id, doc_type, version, payload, approved, approved_by, approved_at, updated_at)
            VALUES (?,?,?,?,0,'','',?)
            ON CONFLICT(session_id, doc_type) DO UPDATE SET
                version = excluded.version,
                payload = excluded.payload,
                approved = 0, approved_by = '', approved_at = '',
                updated_at = excluded.updated_at
            """,
            (session_id, dt, new_version, body, now),
        )
    return get_doc(session_id, dt)


def approve_doc(session_id: str, doc_type: str, approved_by: str) -> GovernanceDoc:
    """The human sign-off. Marks the current version approved. This is documentation of a
    human decision — it grants no capability, gates nothing, and runs nothing; it records that
    the operator agreed to this frame before going live."""
    dt = (doc_type or "").strip().lower()
    if dt not in DOC_TYPES:
        raise ValueError(f"unknown governance document '{doc_type}'")
    current = get_doc(session_id, dt)
    if current.version == 0:
        raise ValueError("cannot approve an empty document — draft or edit it first")
    now = _now()
    with _connect() as conn:
        conn.execute(
            "UPDATE governance_docs SET approved=1, approved_by=?, approved_at=? "
            "WHERE session_id=? AND doc_type=?",
            ((approved_by or "operator").strip()[:120], now, session_id, dt),
        )
    return get_doc(session_id, dt)


# --------------------------------------------------------------------------- #
# objectives — CRUD + the state machine (mirrors opplan.py's tool set)
# --------------------------------------------------------------------------- #
def _bump_version(conn: sqlite3.Connection, session_id: str) -> None:
    conn.execute(
        """
        INSERT INTO governance_opplan_meta (session_id, version, updated_at)
        VALUES (?, 1, ?)
        ON CONFLICT(session_id) DO UPDATE SET
            version = governance_opplan_meta.version + 1, updated_at = excluded.updated_at
        """,
        (session_id, _now()),
    )


def opplan_version(session_id: str) -> int:
    with _connect() as conn:
        row = conn.execute(
            "SELECT version FROM governance_opplan_meta WHERE session_id=?", (session_id,)
        ).fetchone()
    return int(row["version"]) if row else 0


def _row_to_objective(r: sqlite3.Row) -> Objective:
    return Objective(
        session_id=r["session_id"], obj_id=r["obj_id"], title=r["title"],
        phase=r["phase"], status=r["status"],
        technique_ids=json.loads(r["technique_ids"] or "[]"),
        opsec=r["opsec"], c2_tier=r["c2_tier"], notes=r["notes"],
        evidence_run_id=r["evidence_run_id"],
        finding_fingerprints=json.loads(r["finding_fps"] or "[]"),
        created_at=r["created_at"], updated_at=r["updated_at"],
    )


def _sort_key(obj_id: str) -> tuple[int, ...]:
    try:
        return tuple(int(p) for p in obj_id.split("."))
    except ValueError:
        return (10**9,)


def load_objectives(session_id: str) -> list[Objective]:
    if not session_id:
        return []
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM governance_objectives WHERE session_id=?", (session_id,)
        ).fetchall()
    objs = [_row_to_objective(r) for r in rows]
    objs.sort(key=lambda o: _sort_key(o.obj_id))
    return objs


def get_objective(session_id: str, obj_id: str) -> Objective | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM governance_objectives WHERE session_id=? AND obj_id=?",
            (session_id, obj_id),
        ).fetchone()
    return _row_to_objective(row) if row else None


def _write_objective(conn: sqlite3.Connection, obj: Objective) -> None:
    conn.execute(
        """
        INSERT INTO governance_objectives
            (session_id, obj_id, title, phase, status, technique_ids, opsec, c2_tier, notes,
             evidence_run_id, finding_fps, created_at, updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(session_id, obj_id) DO UPDATE SET
            title = excluded.title, phase = excluded.phase, status = excluded.status,
            technique_ids = excluded.technique_ids, opsec = excluded.opsec,
            c2_tier = excluded.c2_tier, notes = excluded.notes,
            evidence_run_id = COALESCE(excluded.evidence_run_id, governance_objectives.evidence_run_id),
            finding_fps = excluded.finding_fps,
            updated_at = excluded.updated_at
        """,
        (
            obj.session_id, obj.obj_id, obj.title[:MAX_TITLE_CHARS], obj.phase, obj.status,
            json.dumps(_clean_techniques(obj.technique_ids)), obj.opsec, obj.c2_tier,
            obj.notes[:MAX_NOTES_CHARS], obj.evidence_run_id,
            json.dumps(list(obj.finding_fingerprints or [])),
            obj.created_at or _now(), _now(),
        ),
    )


def _next_child_id(existing: dict[str, Objective], parent_id: str | None) -> str | None:
    prefix = f"{parent_id}." if parent_id else ""
    depth = (parent_id.count(".") + 2) if parent_id else 1
    siblings = [o.obj_id for o in existing.values()
                if o.parent_id == parent_id and o.depth == depth]
    if len(siblings) >= MAX_CHILDREN:
        return None
    used = set()
    for sid in siblings:
        try:
            used.add(int(sid.rsplit(".", 1)[-1]))
        except ValueError:
            continue
    n = 1
    while n in used:
        n += 1
    return f"{prefix}{n}"


def add_objective(
    session_id: str,
    title: str,
    *,
    parent_id: str | None = None,
    phase: str = OBJECTIVE_PHASES[0],
    technique_ids: Iterable[str] | None = None,
    opsec: str = OPSEC_STANDARD,
    c2_tier: str = C2_NONE,
    notes: str = "",
) -> Objective:
    """Add a root objective, or a sub-objective under ``parent_id`` (expand). New objectives
    always start ``pending`` — the state machine's initial state."""
    if not session_id:
        raise ValueError("session_id is required")
    t = (title or "").strip()
    if not t:
        raise ValueError("an objective needs a title")
    existing = {o.obj_id: o for o in load_objectives(session_id)}
    if len(existing) >= MAX_OBJECTIVES:
        raise ValueError(f"OPPLAN is full ({MAX_OBJECTIVES} objectives)")
    if parent_id is not None:
        parent_id = str(parent_id).strip()
        if not _ID_RE.match(parent_id):
            raise ValueError(f"malformed parent id {parent_id!r}")
        if parent_id not in existing:
            raise ValueError(f"unknown parent objective {parent_id}")
        if existing[parent_id].depth >= MAX_DEPTH:
            raise ValueError(f"max objective depth {MAX_DEPTH} reached at {parent_id}")
    new_id = _next_child_id(existing, parent_id)
    if new_id is None:
        raise ValueError(f"{parent_id or 'the OPPLAN'} already has {MAX_CHILDREN} children")
    obj = Objective(
        session_id=session_id, obj_id=new_id, title=t, phase=_valid_phase(phase),
        status=STATUS_PENDING, technique_ids=_clean_techniques(technique_ids),
        opsec=_valid_opsec(opsec), c2_tier=_valid_c2(c2_tier), notes=(notes or "").strip(),
        created_at=_now(), updated_at=_now(),
    )
    with _connect() as conn:
        _write_objective(conn, obj)
        _bump_version(conn, session_id)
    return obj


def update_objective(
    session_id: str,
    obj_id: str,
    *,
    status: str | None = None,
    title: str | None = None,
    phase: str | None = None,
    technique_ids: Iterable[str] | None = None,
    opsec: str | None = None,
    c2_tier: str | None = None,
    notes: str | None = None,
    evidence_run_id: str | None = None,
    finding_fingerprints: Iterable[str] | None = None,
) -> Objective:
    """Update an objective's fields. A ``status`` change is validated against the state
    machine — an illegal transition raises ``TransitionError`` and NOTHING is written. This is
    the only place a status changes, so ``completed``/``cancelled`` are genuinely terminal.

    ``evidence_run_id`` is how objectives integrate with the orchestrator/graph ``advance``
    model: an approved, exit-0 run that advanced this objective is recorded here as the proof,
    exactly as a graph edge advance records the run that walked it."""
    obj = get_objective(session_id, obj_id)
    if obj is None:
        raise ValueError(f"unknown objective {obj_id}")
    if status is not None:
        target = str(status).strip().lower()
        if target not in OBJECTIVE_STATUSES:
            raise TransitionError(f"unknown status {status!r}")
        if not can_transition(obj.status, target):
            raise TransitionError(
                f"illegal transition {obj.status} -> {target}"
                + (" (terminal state)" if obj.status in (STATUS_COMPLETED, STATUS_CANCELLED) else "")
            )
        obj.status = target
    if title is not None:
        t = str(title).strip()
        if not t:
            raise ValueError("title cannot be blank")
        obj.title = t
    if phase is not None:
        obj.phase = _valid_phase(phase)
    if technique_ids is not None:
        obj.technique_ids = _clean_techniques(technique_ids)
    if opsec is not None:
        obj.opsec = _valid_opsec(opsec)
    if c2_tier is not None:
        obj.c2_tier = _valid_c2(c2_tier)
    if notes is not None:
        obj.notes = str(notes)[:MAX_NOTES_CHARS]
    if evidence_run_id is not None:
        obj.evidence_run_id = str(evidence_run_id).strip()[:64] or None
    if finding_fingerprints is not None:
        obj.finding_fingerprints = [str(f).strip() for f in finding_fingerprints if str(f).strip()]
    with _connect() as conn:
        _write_objective(conn, obj)
        _bump_version(conn, session_id)
    return obj


def expand_objective(session_id: str, parent_id: str, child_titles: Iterable[str]) -> list[Objective]:
    """Expand an objective into sub-objectives (opplan.py ``expand``). Each child is a normal
    objective under ``parent_id``; the parent stays as-is. Returns the children created."""
    made: list[Objective] = []
    for title in child_titles:
        t = (title or "").strip()
        if not t:
            continue
        try:
            made.append(add_objective(session_id, t, parent_id=parent_id))
        except ValueError:
            break  # full / too deep — stop, keep what was added
    return made


def collapse_objective(session_id: str, obj_id: str) -> int:
    """Collapse an objective (opplan.py ``collapse``): delete its descendants, keep the
    objective itself. Returns how many sub-objectives were removed."""
    prefix = f"{obj_id}."
    removed = 0
    with _connect() as conn:
        cur = conn.execute(
            "DELETE FROM governance_objectives WHERE session_id=? AND obj_id LIKE ?",
            (session_id, prefix + "%"),
        )
        removed = cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
        if removed:
            _bump_version(conn, session_id)
    return removed


def delete_objective(session_id: str, obj_id: str) -> int:
    """Delete an objective AND its descendants. Returns how many rows were removed."""
    prefix = f"{obj_id}."
    with _connect() as conn:
        cur = conn.execute(
            "DELETE FROM governance_objectives WHERE session_id=? AND (obj_id=? OR obj_id LIKE ?)",
            (session_id, obj_id, prefix + "%"),
        )
        removed = cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
        if removed:
            _bump_version(conn, session_id)
    return removed


def active_objectives(session_id: str) -> list[Objective]:
    """Objectives the orchestrator may propose TOWARD — pending or in-progress, leaf-first
    ordering so a sub-objective is targeted before its parent's summary."""
    return [o for o in load_objectives(session_id) if o.status in (STATUS_PENDING, STATUS_IN_PROGRESS)]


# --------------------------------------------------------------------------- #
# OPPLAN payload (versioned JSON + summary) and ATT&CK coverage
# --------------------------------------------------------------------------- #
def opplan_summary(session_id: str) -> dict[str, int]:
    objs = load_objectives(session_id)
    return {
        "total": len(objs),
        "pending": sum(1 for o in objs if o.status == STATUS_PENDING),
        "in_progress": sum(1 for o in objs if o.status == STATUS_IN_PROGRESS),
        "completed": sum(1 for o in objs if o.status == STATUS_COMPLETED),
        "blocked": sum(1 for o in objs if o.status == STATUS_BLOCKED),
        "cancelled": sum(1 for o in objs if o.status == STATUS_CANCELLED),
    }


def attack_coverage(session_id: str) -> dict[str, Any]:
    """The MITRE ATT&CK coverage view for this engagement — which tactics/techniques the
    objectives (and any findings mapped in) exercise. A professional deliverable and a report
    input. Delegates the grid to killchain.coverage; pure, deterministic."""
    ids: list[str] = []
    for o in load_objectives(session_id):
        ids.extend(o.technique_ids)
    return killchain.coverage(ids)


def opplan_payload(session_id: str, settings: dict[str, Any] | None = None) -> dict[str, Any]:
    """The full OPPLAN as versioned JSON: version, objectives, summary counts, ATT&CK
    coverage, and the OPPLAN settings doc. This is opplan.py's payload builder, reshaped."""
    doc = settings if settings is not None else get_doc(session_id, DOC_OPPLAN).payload
    return {
        "version": opplan_version(session_id),
        "settings": doc or default_payload(DOC_OPPLAN),
        "objectives": [o.to_dict() for o in load_objectives(session_id)],
        "summary": opplan_summary(session_id),
        "attack_coverage": attack_coverage(session_id),
    }


def package(session_id: str) -> dict[str, Any]:
    """The whole governance package for one engagement — the four documents + the OPPLAN.
    What the frontend renders as tabs and what the report ingests."""
    return {
        "session_id": session_id,
        "roe": get_doc(session_id, DOC_ROE).to_dict(),
        "conops": get_doc(session_id, DOC_CONOPS).to_dict(),
        "deconfliction": get_doc(session_id, DOC_DECONFLICTION).to_dict(),
        "opplan": {
            **get_doc(session_id, DOC_OPPLAN).to_dict(),
            **opplan_payload(session_id),
        },
    }


def clear(session_id: str) -> None:
    """Drop one engagement's governance. Used by tests and an explicit operator reset."""
    with _connect() as conn:
        for table in ("governance_docs", "governance_objectives", "governance_opplan_meta"):
            conn.execute(f"DELETE FROM {table} WHERE session_id=?", (session_id,))
