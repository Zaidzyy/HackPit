"""Continuous hunting — snapshot the engagement's discovered assets, diff against the previous
snapshot, and raise an ALERT when something NEW appears (a subdomain, a live host, an endpoint, a
finding).

This is where a standing engagement earns its keep. On a mature program everyone has already
scanned the known surface; the bounties live in what appeared *since* — a new subdomain, a fresh
staging host, a JS bundle that leaked a new endpoint. Being first to see it is the edge, and a human
cannot watch at 3am. The scheduler calls :func:`check` after each autonomous step; the auto-runner's
next propose then naturally targets whatever is new.

READ-ONLY. It reads ``state.store.load`` (what the recon/scan surfaces already ingested) and writes
only its own snapshot + alert rows. It fires nothing and executes nothing — detecting a new asset is
reading a list, not attacking. Locked by test_watch_diff.py.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any

from .runstore import DB_PATH

_write_lock = threading.Lock()

#: The asset categories a diff reports, in priority order for an alert.
CATEGORIES = ("hosts", "services", "endpoints", "findings")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def init_db() -> None:
    """Create the snapshot + alert tables. Idempotent."""
    with _write_lock, _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS watch_snapshot (
                engagement_id TEXT PRIMARY KEY,
                snapshot      TEXT NOT NULL,
                updated_at    TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS watch_alert (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id TEXT NOT NULL,
                at            TEXT NOT NULL,
                new_assets    TEXT NOT NULL
            )
            """
        )


def snapshot(session_id: str) -> dict[str, list[str]]:
    """The set of discovered ASSET KEYS for a session, by category. Read-only over state.store."""
    from state import store

    s = store.load(session_id)
    return {
        "hosts": sorted({h.address for h in s.hosts if getattr(h, "address", "")}),
        "services": sorted({f"{sv.address}:{sv.port}" for sv in s.services if getattr(sv, "address", "")}),
        "endpoints": sorted({e.url for e in s.endpoints if getattr(e, "url", "")}),
        "findings": sorted(
            {f"{f.title}|{getattr(f, 'target', '')}" for f in s.findings if getattr(f, "title", "")}
        ),
    }


def _diff(prev: dict[str, list[str]], curr: dict[str, list[str]]) -> dict[str, list[str]]:
    """The items in ``curr`` not present in ``prev``, per category. Empty categories omitted."""
    out: dict[str, list[str]] = {}
    for cat in CATEGORIES:
        seen = set(prev.get(cat, []))
        fresh = [item for item in curr.get(cat, []) if item not in seen]
        if fresh:
            out[cat] = fresh
    return out


def _load_snapshot(engagement_id: str) -> dict[str, list[str]] | None:
    try:
        with _connect() as conn:
            row = conn.execute(
                "SELECT snapshot FROM watch_snapshot WHERE engagement_id=?", (engagement_id,)
            ).fetchone()
    except sqlite3.OperationalError:
        return None
    if row is None:
        return None
    try:
        return json.loads(row["snapshot"])
    except ValueError:
        return None


def _save_snapshot(engagement_id: str, snap: dict[str, list[str]]) -> None:
    init_db()
    with _write_lock, _connect() as conn:
        conn.execute(
            "INSERT INTO watch_snapshot (engagement_id, snapshot, updated_at) VALUES (?,?,?) "
            "ON CONFLICT(engagement_id) DO UPDATE SET snapshot=excluded.snapshot, "
            "updated_at=excluded.updated_at",
            (engagement_id, json.dumps(snap), _now()),
        )


def _record_alert(engagement_id: str, delta: dict[str, list[str]]) -> None:
    with _write_lock, _connect() as conn:
        conn.execute(
            "INSERT INTO watch_alert (engagement_id, at, new_assets) VALUES (?,?,?)",
            (engagement_id, _now(), json.dumps(delta)),
        )


def check(engagement_id: str, session_id: str) -> dict[str, Any]:
    """Snapshot now, diff against the stored previous snapshot, persist the new one, and record an
    alert for anything new. The FIRST check for an engagement is a silent baseline (everything is
    'new' the first time, and alerting on that would just be noise). Returns ``{first, new}``."""
    curr = snapshot(session_id)
    prev = _load_snapshot(engagement_id)
    _save_snapshot(engagement_id, curr)
    if prev is None:
        return {"first": True, "new": {}}
    delta = _diff(prev, curr)
    if delta:
        _record_alert(engagement_id, delta)
    return {"first": False, "new": delta}


def alerts(engagement_id: str, limit: int = 50) -> list[dict[str, Any]]:
    """The most recent new-asset alerts for an engagement, newest first. Empty if none/unknown."""
    try:
        with _connect() as conn:
            rows = conn.execute(
                "SELECT at, new_assets FROM watch_alert WHERE engagement_id=? ORDER BY id DESC LIMIT ?",
                (engagement_id, int(limit)),
            ).fetchall()
    except sqlite3.OperationalError:
        return []
    out: list[dict[str, Any]] = []
    for r in rows:
        try:
            out.append({"at": r["at"], "new_assets": json.loads(r["new_assets"])})
        except ValueError:
            continue
    return out
