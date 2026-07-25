"""Persistence for parsed AD graphs — an ``ad_graphs`` table in the shared sessions.db.

One row per ingested collection, attached to a session (and its engagement, when the collector
ran in engagement mode). The parsed graph is stored as JSON (the stable schema from
``schema.py``), so the UI + path engine read it back without re-parsing the raw BloodHound
files. Stdlib only; reuses the same single-file store the runs + engagements use.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DB_PATH = Path(__file__).parent.parent / "sessions.db"

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
    """Create the ad_graphs table if absent. Idempotent."""
    with _write_lock, _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ad_graphs (
                graph_id      TEXT PRIMARY KEY,
                session_id    TEXT,
                engagement_id TEXT,
                domain        TEXT,
                source        TEXT,            -- 'collector' | 'sample' | 'upload'
                graph_json    TEXT NOT NULL,   -- the serialized Graph.to_dict()
                node_count    INTEGER NOT NULL DEFAULT 0,
                edge_count    INTEGER NOT NULL DEFAULT 0,
                created_at    TEXT NOT NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS ix_ad_graphs_session ON ad_graphs(session_id, created_at)"
        )


def save_graph(
    graph_dict: dict[str, Any],
    session_id: str | None,
    engagement_id: str | None = None,
    source: str = "collector",
) -> str:
    """Persist a parsed graph; returns its new ``graph_id``."""
    graph_id = "adg-" + uuid.uuid4().hex[:12]
    stats = graph_dict.get("stats") or {}
    with _write_lock, _connect() as conn:
        conn.execute(
            "INSERT INTO ad_graphs (graph_id, session_id, engagement_id, domain, source, "
            "graph_json, node_count, edge_count, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                graph_id, session_id, engagement_id, graph_dict.get("domain"), source,
                json.dumps(graph_dict), int(stats.get("nodes", 0)), int(stats.get("edges", 0)),
                _now(),
            ),
        )
    return graph_id


def get_graph(graph_id: str) -> dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM ad_graphs WHERE graph_id = ?", (graph_id,)
        ).fetchone()
    return _row(row) if row else None


def latest_for_session(session_id: str) -> dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM ad_graphs WHERE session_id = ? ORDER BY created_at DESC LIMIT 1",
            (session_id,),
        ).fetchone()
    return _row(row) if row else None


def list_for_session(session_id: str) -> list[dict[str, Any]]:
    """Metadata for every graph on a session (no graph_json payload — light listing)."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT graph_id, session_id, engagement_id, domain, source, node_count, "
            "edge_count, created_at FROM ad_graphs WHERE session_id = ? ORDER BY created_at DESC",
            (session_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def _row(row: sqlite3.Row) -> dict[str, Any]:
    d = dict(row)
    try:
        d["graph"] = json.loads(d.pop("graph_json"))
    except (ValueError, TypeError):
        d["graph"] = None
    return d
