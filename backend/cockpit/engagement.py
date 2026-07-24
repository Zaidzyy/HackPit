"""Engagement-mode registry — the DELIBERATE, explicit switch into real-target mode.

Real-target ("engagement") mode removes the isolation floor: the cockpit execs against a
human-named REAL target through the fully-open sandbox. Because that is the highest-risk path,
entering it must be a conscious act, not something a bare exec can trip into. This module is
that gate's state:

* :func:`enter` records an engagement — the named ``target`` + the operator's ``authorization``
  acknowledgement — and returns an ``engagement_id``. Only an exec that references an ACTIVE
  engagement id runs in engagement mode; everything else is lab mode, unchanged.
* :func:`get_active` is what the executor consults on every exec — it returns the record ONLY
  while active, so an exited/unknown engagement fails closed (the executor refuses).
* :func:`exit_engagement` ends an engagement (no more engagement-mode runs against it).

Records persist in the shared ``sessions.db`` (gitignored) so they survive a reload AND leave
an audit trail (who entered mode against what, and when). This module holds NO execution — it
only answers "is this engagement explicitly, currently entered?".
"""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone

from .models import EngagementRecord
from .runstore import DB_PATH  # same single-file SQLite store as the run records

_write_lock = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def init_db() -> None:
    """Create the engagement_mode table if absent. Safe to call repeatedly."""
    with _write_lock, _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS engagement_mode (
                engagement_id  TEXT PRIMARY KEY,
                target         TEXT NOT NULL,
                authorization  TEXT NOT NULL,
                active         INTEGER NOT NULL,
                entered_at     TEXT NOT NULL,
                exited_at      TEXT,
                session_id     TEXT,
                resolved_scope TEXT NOT NULL DEFAULT '[]',
                scope_kind     TEXT
            )
            """
        )
        # migrate DBs created before the scope-lock columns existed.
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(engagement_mode)")}
        if "resolved_scope" not in cols:
            conn.execute(
                "ALTER TABLE engagement_mode ADD COLUMN resolved_scope TEXT NOT NULL DEFAULT '[]'"
            )
        if "scope_kind" not in cols:
            conn.execute("ALTER TABLE engagement_mode ADD COLUMN scope_kind TEXT")


def _valid_target(target: str) -> str:
    """Normalise + sanity-check the named target. Not a security control (the target-lock +
    Wall A are), just a guard against an empty/obviously-broken target so mode entry is honest.
    """
    t = (target or "").strip()
    if not t or any(ch.isspace() for ch in t):
        raise ValueError("target must be a single non-empty host or URL (no spaces)")
    return t


def enter(
    target: str,
    authorization: str,
    session_id: str | None = None,
    resolved_scope: list[str] | None = None,
    scope_kind: str | None = None,
) -> EngagementRecord:
    """Record an entered engagement against ``target`` (with its already-resolved+applied
    scope) and return the active record.

    Pure registry write — the caller (router) resolves the scope and applies the scope-lock
    FIRST, then records it here with ``resolved_scope`` (the firewall allow-list) so the
    executor's scope-lock gate can verify it. Requires a non-empty ``authorization``
    acknowledgement — the deliberate, warned action of leaving the isolated lab.
    """
    t = _valid_target(target)
    auth = (authorization or "").strip()
    if not auth:
        raise ValueError(
            "authorization acknowledgement is required to enter engagement mode — you are "
            "responsible for authorization and staying in scope"
        )
    scope = list(resolved_scope or [])
    engagement_id = "eng-" + uuid.uuid4().hex[:12]
    entered_at = _now()
    with _write_lock, _connect() as conn:
        conn.execute(
            "INSERT INTO engagement_mode "
            "(engagement_id, target, authorization, active, entered_at, exited_at, session_id, "
            " resolved_scope, scope_kind) "
            "VALUES (?, ?, ?, 1, ?, NULL, ?, ?, ?)",
            (engagement_id, t, auth, entered_at, session_id, json.dumps(scope), scope_kind),
        )
    return EngagementRecord(
        engagement_id=engagement_id,
        target=t,
        authorization=auth,
        active=True,
        entered_at=entered_at,
        exited_at=None,
        session_id=session_id,
        resolved_scope=scope,
        scope_kind=scope_kind,
    )


def get_active(engagement_id: str) -> EngagementRecord | None:
    """The engagement record ONLY while it is active (else None — fail closed)."""
    if not engagement_id:
        return None
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM engagement_mode WHERE engagement_id = ? AND active = 1",
            (engagement_id,),
        ).fetchone()
    return _row(row) if row else None


def exit_engagement(engagement_id: str) -> bool:
    """End an engagement — no further engagement-mode runs against it. True if one was active."""
    with _write_lock, _connect() as conn:
        cur = conn.execute(
            "UPDATE engagement_mode SET active = 0, exited_at = ? "
            "WHERE engagement_id = ? AND active = 1",
            (_now(), engagement_id),
        )
        return cur.rowcount > 0


def list_active() -> list[EngagementRecord]:
    """All currently-active engagements (for the status endpoint / UI mode indicator)."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM engagement_mode WHERE active = 1 ORDER BY entered_at DESC"
        ).fetchall()
    return [_row(r) for r in rows]


def _row(row: sqlite3.Row) -> EngagementRecord:
    keys = row.keys()
    try:
        scope = json.loads(row["resolved_scope"]) if "resolved_scope" in keys else []
    except (TypeError, ValueError):
        scope = []
    return EngagementRecord(
        engagement_id=row["engagement_id"],
        target=row["target"],
        authorization=row["authorization"],
        active=bool(row["active"]),
        entered_at=row["entered_at"],
        exited_at=row["exited_at"],
        session_id=row["session_id"],
        resolved_scope=scope if isinstance(scope, list) else [],
        scope_kind=row["scope_kind"] if "scope_kind" in keys else None,
    )
