"""The durable DECISION QUEUE — the exploitation actions the auto-runner held for a human.

In ASSISTED mode the runner fires the passive tier itself and QUEUES every exploitation-class
action for the operator; in FULL mode an RoE/budget-blocked fire is queued too. The append-only
audit RECORDS that a queue happened (surface name + param KEYS, secrets stripped) but cannot
re-fire it. THIS store keeps the FULL proposal so the operator can review it and APPROVE (fire) or
SKIP it — the human decision that assisted mode exists to collect.

Approving fires through the SAME gated path the operator's own approve uses (autorun.fire): a
queued item a human approves IS the human-in-the-loop gate — human approval is HackPit's ultimate
authority, so an approved item fires even where the RoE would have blocked an AUTONOMOUS fire.

Dedup: the daemon re-proposes a held action every tick (nothing changed until the human acts), so
enqueue is idempotent on a stable key (surface + sorted params, or command + args) while an item is
still pending — one held action is one queue row, not one per tick.

Persisted in the shared sessions.db (gitignored). Locked by test_decisionqueue_safety.py.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from typing import Any

from .runstore import DB_PATH

_write_lock = threading.Lock()

PENDING = "pending"
APPROVED = "approved"
SKIPPED = "skipped"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def init_db() -> None:
    """Create the queue table. Idempotent."""
    with _write_lock, _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS decision_queue (
                id            TEXT PRIMARY KEY,
                engagement_id TEXT NOT NULL,
                session_id    TEXT,
                dedup_key     TEXT NOT NULL,
                tier          TEXT NOT NULL,
                proposal      TEXT NOT NULL,
                status        TEXT NOT NULL DEFAULT 'pending',
                at            TEXT NOT NULL,
                decided_at    TEXT
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS ix_decision_queue_eng "
            "ON decision_queue(engagement_id, status)"
        )


def dedup_key(proposal: dict[str, Any]) -> str:
    """A stable identity for a proposal, so the same held action queued each tick is one row."""
    kind = str(proposal.get("kind", "command")).lower()
    if kind == "surface":
        params = proposal.get("surface_params") or {}
        basis = json.dumps([str(proposal.get("surface", "")), _canon(params)], sort_keys=True)
    else:
        basis = json.dumps([str(proposal.get("command", "")),
                            [str(a) for a in proposal.get("args", []) or []]], sort_keys=True)
    return hashlib.sha256(basis.encode()).hexdigest()[:16]


def _canon(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _canon(obj[k]) for k in sorted(obj)}
    if isinstance(obj, list):
        return [_canon(x) for x in obj]
    return obj


def enqueue(engagement_id: str, session_id: str | None, proposal: dict[str, Any], tier: str) -> str:
    """Add a held action to the queue, or return the existing PENDING row's id (idempotent per
    dedup_key). Returns the queue id."""
    key = dedup_key(proposal)
    with _write_lock, _connect() as conn:
        row = conn.execute(
            "SELECT id FROM decision_queue WHERE engagement_id=? AND dedup_key=? AND status=?",
            (engagement_id, key, PENDING),
        ).fetchone()
        if row is not None:
            return row["id"]
        qid = "dq-" + uuid.uuid4().hex[:12]
        conn.execute(
            "INSERT INTO decision_queue (id, engagement_id, session_id, dedup_key, tier, proposal, "
            "status, at) VALUES (?,?,?,?,?,?,?,?)",
            (qid, engagement_id, session_id, key, tier, json.dumps(proposal), PENDING, _now()),
        )
    return qid


def pending(engagement_id: str, limit: int = 50) -> list[dict[str, Any]]:
    """Pending held actions for an engagement, newest first. Each item carries the FULL proposal."""
    try:
        with _connect() as conn:
            rows = conn.execute(
                "SELECT id, tier, proposal, at FROM decision_queue WHERE engagement_id=? AND "
                "status=? ORDER BY at DESC LIMIT ?",
                (engagement_id, PENDING, int(limit)),
            ).fetchall()
    except sqlite3.OperationalError:
        return []
    out: list[dict[str, Any]] = []
    for r in rows:
        try:
            out.append({"id": r["id"], "tier": r["tier"], "at": r["at"],
                        "proposal": json.loads(r["proposal"])})
        except ValueError:
            continue
    return out


def pending_action_classes(engagement_id: str) -> list[str]:
    """The surface names / commands already queued — passed to the proposer as `avoid` so the
    runner keeps doing NEW work instead of re-proposing an action already waiting for the human."""
    seen: list[str] = []
    for item in pending(engagement_id, limit=100):
        p = item["proposal"]
        name = (str(p.get("surface", "")) if str(p.get("kind", "")).lower() == "surface"
                else str(p.get("command", ""))).strip()
        if name and name not in seen:
            seen.append(name)
    return seen


def get(qid: str) -> dict[str, Any] | None:
    """One queue row (any status), with its full proposal, or None."""
    with _connect() as conn:
        r = conn.execute("SELECT * FROM decision_queue WHERE id=?", (qid,)).fetchone()
    if r is None:
        return None
    try:
        proposal = json.loads(r["proposal"])
    except ValueError:
        proposal = {}
    return {"id": r["id"], "engagement_id": r["engagement_id"], "session_id": r["session_id"],
            "tier": r["tier"], "status": r["status"], "at": r["at"], "proposal": proposal}


def mark(qid: str, status: str) -> dict[str, Any] | None:
    """Set a queue item's status (approved/skipped). Returns the updated row, or None if unknown."""
    with _write_lock, _connect() as conn:
        conn.execute(
            "UPDATE decision_queue SET status=?, decided_at=? WHERE id=?",
            (status, _now(), qid),
        )
    return get(qid)
