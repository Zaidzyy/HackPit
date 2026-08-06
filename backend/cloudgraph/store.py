"""Persistence for parsed cloud IAM graphs — a ``cloud_graphs`` table in the shared sessions.db.

The cloud parallel to ``adgraph/store.py``. One row per enumeration, attached to a session (and its
engagement, when the enumeration ran in engagement mode). The parsed graph is stored as JSON (the
stable schema from ``schema.py``) so the UI + path engine read it back without re-parsing the raw
tool output. Stdlib only; reuses the same single-file store the runs + engagements use.
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
    """Create the cloud_graphs table if absent. Idempotent."""
    with _write_lock, _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS cloud_graphs (
                graph_id      TEXT PRIMARY KEY,
                session_id    TEXT,
                engagement_id TEXT,
                provider      TEXT,
                account       TEXT,
                source        TEXT,            -- 'enumerate' | 'sample' | 'upload'
                graph_json    TEXT NOT NULL,   -- the serialized Graph.to_dict()
                node_count    INTEGER NOT NULL DEFAULT 0,
                edge_count    INTEGER NOT NULL DEFAULT 0,
                created_at    TEXT NOT NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS ix_cloud_graphs_session "
            "ON cloud_graphs(session_id, created_at)"
        )


def save_graph(
    graph_dict: dict[str, Any],
    session_id: str | None,
    engagement_id: str | None = None,
    source: str = "enumerate",
) -> str:
    """Persist a parsed graph; returns its new ``graph_id``."""
    graph_id = "clg-" + uuid.uuid4().hex[:12]
    stats = graph_dict.get("stats") or {}
    with _write_lock, _connect() as conn:
        conn.execute(
            "INSERT INTO cloud_graphs (graph_id, session_id, engagement_id, provider, account, "
            "source, graph_json, node_count, edge_count, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                graph_id, session_id, engagement_id, graph_dict.get("provider"),
                graph_dict.get("account"), source, json.dumps(graph_dict),
                int(stats.get("nodes", 0)), int(stats.get("edges", 0)), _now(),
            ),
        )
    return graph_id


def get_graph(graph_id: str) -> dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM cloud_graphs WHERE graph_id = ?", (graph_id,)
        ).fetchone()
    return _row(row) if row else None


def latest_for_session(session_id: str) -> dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM cloud_graphs WHERE session_id = ? ORDER BY created_at DESC LIMIT 1",
            (session_id,),
        ).fetchone()
    return _row(row) if row else None


def list_for_session(session_id: str) -> list[dict[str, Any]]:
    """Metadata for every graph on a session (no graph_json payload — light listing)."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT graph_id, session_id, engagement_id, provider, account, source, node_count, "
            "edge_count, created_at FROM cloud_graphs WHERE session_id = ? "
            "ORDER BY created_at DESC",
            (session_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def mark_owned(session_id: str, principals: list[str]) -> list[str]:
    """Mark the graph nodes for ``principals`` as OWNED in the session's latest graph.

    A captured credential / assumed role makes the matching principal owned, which opens new
    frontier edges the next time :cloud asks for the route. Pure persistence — no execution, no
    network. Matches a principal (an ARN, a bare name, or a role/user name) to a node by id, label,
    or its label's last segment, case-insensitively. Returns the labels it newly marked."""
    if not session_id or not principals:
        return []
    latest = latest_for_session(session_id)
    if not latest:
        return []
    graph = latest.get("graph")
    graph_id = latest.get("graph_id")
    if not isinstance(graph, dict) or not graph_id:
        return []
    wanted = {p.strip().lower() for p in principals if p.strip()}
    marked: list[str] = []
    for node in graph.get("nodes", []):
        if not isinstance(node, dict) or node.get("owned"):
            continue
        nid = str(node.get("id") or "").strip().lower()
        label = str(node.get("label") or "")
        tail = label.rsplit(":", 1)[-1].rsplit("/", 1)[-1].strip().lower()
        if nid in wanted or label.strip().lower() in wanted or (tail and tail in wanted):
            node["owned"] = True
            marked.append(label or node.get("id", ""))
    if not marked:
        return []
    with _write_lock, _connect() as conn:
        conn.execute(
            "UPDATE cloud_graphs SET graph_json = ? WHERE graph_id = ?",
            (json.dumps(graph), graph_id),
        )
    return marked


def _row(row: sqlite3.Row) -> dict[str, Any]:
    d = dict(row)
    try:
        d["graph"] = json.loads(d.pop("graph_json"))
    except (ValueError, TypeError):
        d["graph"] = None
    return d
