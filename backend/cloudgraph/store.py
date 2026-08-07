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


def seed_owned_node(
    session_id: str,
    node_dict: dict[str, Any],
    aliases: list[str],
    provider: str | None = None,
    account: str | None = None,
    engagement_id: str | None = None,
) -> dict[str, Any] | None:
    """Seed an OWNED principal (an SSRF/IMDS-captured identity) into a session's graph.

    The web↔cloud seam's persistence half. If the session already has a graph, the seed MERGES:
    when the captured identity matches an already-enumerated node (by id, label, or a role/email
    ``alias`` — the same matching ``mark_owned`` uses), that node is marked ``owned`` so the privesc
    walk can start from it; otherwise the owned node is added standalone. If the session has no graph
    yet, a fresh one is created holding the account root + the owned identity.

    Pure persistence — no execution, no network. Returns ``{graph_id, node_id, created,
    matched_existing, stats}`` or ``None`` when there is nothing to seed (no session / no node).
    """
    if not session_id or not isinstance(node_dict, dict) or not node_dict.get("id"):
        return None

    # local import keeps store.py free of a schema import at module load (it stores plain dicts)
    from .schema import Edge, Graph, Node

    want = {a.strip().lower() for a in ([*aliases, node_dict.get("id", ""),
                                         node_dict.get("label", "")]) if a and a.strip()}

    latest = latest_for_session(session_id)
    if latest and isinstance(latest.get("graph"), dict) and latest.get("graph_id"):
        graph_dict = latest["graph"]
        graph_id = latest["graph_id"]
        g = Graph(provider=graph_dict.get("provider"), account=graph_dict.get("account"))
        for n in graph_dict.get("nodes", []):
            g.add_node(Node(id=n["id"], type=n.get("type", "resource"), label=n.get("label", ""),
                            provider=n.get("provider") or "", props=n.get("props") or {},
                            high_value=bool(n.get("high_value")), owned=bool(n.get("owned"))))
        for e in graph_dict.get("edges", []):
            g.add_edge(Edge(source=e["source"], target=e["target"], kind=e["kind"],
                            props=e.get("props") or {}))

        matched = _match_existing(g, want)
        if matched is not None:
            matched.owned = True
            matched.props.update({k: v for k, v in (node_dict.get("props") or {}).items()
                                  if v not in (None, "")})
            node_id = matched.id
            matched_existing = True
        else:
            seed = Node(id=node_dict["id"], type=node_dict.get("type", "role"),
                        label=node_dict.get("label") or node_dict["id"],
                        provider=node_dict.get("provider") or (provider or ""), owned=True,
                        props=node_dict.get("props") or {})
            g.add_node(seed)
            node_id = seed.id
            matched_existing = False

        new_dict = g.to_dict()
        with _write_lock, _connect() as conn:
            conn.execute(
                "UPDATE cloud_graphs SET graph_json = ?, node_count = ?, edge_count = ? "
                "WHERE graph_id = ?",
                (json.dumps(new_dict), len(g.nodes), len(g.edges), graph_id),
            )
        return {"graph_id": graph_id, "node_id": node_id, "created": False,
                "matched_existing": matched_existing, "stats": new_dict.get("stats", {})}

    # no graph yet — create a minimal one: the account root (context) + the owned identity.
    prov = node_dict.get("provider") or (provider or "")
    g = Graph(provider=prov or None, account=account or None)
    seed = Node(id=node_dict["id"], type=node_dict.get("type", "role"),
                label=node_dict.get("label") or node_dict["id"], provider=prov, owned=True,
                props=node_dict.get("props") or {})
    g.add_node(seed)
    if account:
        acct_id = f"arn:aws:iam::{account}:account" if prov == "aws" else f"account:{account}"
        g.add_node(Node(id=acct_id, type="account", label=account, provider=prov))
        g.add_edge(Edge(source=acct_id, target=seed.id, kind="Contains"))
    graph_dict = g.to_dict()
    graph_id = save_graph(graph_dict, session_id, engagement_id, source="seed-imds")
    return {"graph_id": graph_id, "node_id": seed.id, "created": True,
            "matched_existing": False, "stats": graph_dict.get("stats", {})}


def _match_existing(graph, want: set[str]):
    """The first graph node whose id, label, or label tail matches any wanted alias, or None.
    Mirrors ``mark_owned``'s case-insensitive id/label/tail matching."""
    for node in graph.nodes.values():
        nid = (node.id or "").strip().lower()
        label = (node.label or "")
        tail = label.rsplit(":", 1)[-1].rsplit("/", 1)[-1].strip().lower()
        if nid in want or label.strip().lower() in want or (tail and tail in want):
            return node
    return None


def _row(row: sqlite3.Row) -> dict[str, Any]:
    d = dict(row)
    try:
        d["graph"] = json.loads(d.pop("graph_json"))
    except (ValueError, TypeError):
        d["graph"] = None
    return d
