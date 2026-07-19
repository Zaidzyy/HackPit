"""HackPit engagement sessions — local SQLite persistence (no login).

A *session* turns a composed attack-path (see ``attack_path.py``) into a saved,
interactive engagement: the full path JSON is stored verbatim, and per-step
state (checked + pasted results) is tracked against the stable ``{phase}-{n}``
step ids the path already carries.

Storage is a single SQLite file (``backend/sessions.db``, gitignored) via the
stdlib ``sqlite3`` — no new dependency, no server. This is single-user local
data, so each call opens a short-lived connection (WAL mode + a busy timeout
keep the occasional concurrent write from erroring); a module lock serialises
writers as a belt-and-suspenders guard.

Nothing here imports FastAPI — the API layer calls these functions and maps
their return values / ``None`` to HTTP.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DB_PATH = Path(__file__).with_name("sessions.db")

_write_lock = threading.Lock()


def _now() -> str:
    """UTC ISO-8601 timestamp, second precision, with a trailing Z."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    """Create tables if they don't exist. Safe to call on every startup."""
    with _connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                id                  TEXT PRIMARY KEY,
                label               TEXT NOT NULL,
                goal                TEXT NOT NULL,
                target_type         TEXT,
                path_json           TEXT NOT NULL,
                created_at          TEXT NOT NULL,
                updated_at          TEXT NOT NULL,
                report_md           TEXT,
                report_generated_at TEXT
            );

            CREATE TABLE IF NOT EXISTS step_state (
                session_id  TEXT NOT NULL,
                step_id     TEXT NOT NULL,
                checked     INTEGER NOT NULL DEFAULT 0,
                result_text TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (session_id, step_id),
                FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
            );
            """
        )
        # migrate DBs created before the report columns existed
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(sessions)")}
        if "report_md" not in cols:
            conn.execute("ALTER TABLE sessions ADD COLUMN report_md TEXT")
        if "report_generated_at" not in cols:
            conn.execute(
                "ALTER TABLE sessions ADD COLUMN report_generated_at TEXT"
            )


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _path_step_ids(path: dict) -> list[str]:
    """All stable step ids present in a composed path, in order."""
    ids: list[str] = []
    for phase in path.get("phases", []) or []:
        for step in phase.get("steps", []) or []:
            sid = step.get("id")
            if isinstance(sid, str) and sid:
                ids.append(sid)
    return ids


def _touch(conn: sqlite3.Connection, session_id: str) -> None:
    conn.execute(
        "UPDATE sessions SET updated_at=? WHERE id=?", (_now(), session_id)
    )


# --------------------------------------------------------------------------- #
# create / read
# --------------------------------------------------------------------------- #
def create_session(
    goal: str, target_type: str | None, path: dict
) -> str:
    """Persist a composed path as a new session. Returns the new session id.

    The label defaults to the goal. Step state rows are lazily created on first
    update, so creation just stores the path + metadata.
    """
    sid = uuid.uuid4().hex[:12]
    now = _now()
    label = (goal or "").strip() or "untitled engagement"
    with _write_lock, _connect() as conn:
        conn.execute(
            "INSERT INTO sessions "
            "(id, label, goal, target_type, path_json, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                sid,
                label,
                goal,
                target_type,
                json.dumps(path, ensure_ascii=False),
                now,
                now,
            ),
        )
    return sid


def list_sessions() -> list[dict[str, Any]]:
    """All sessions (newest-updated first) with checked/total progress."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, label, goal, target_type, path_json, created_at, "
            "updated_at FROM sessions ORDER BY updated_at DESC"
        ).fetchall()
        checked_counts = dict(
            conn.execute(
                "SELECT session_id, COUNT(*) FROM step_state "
                "WHERE checked=1 GROUP BY session_id"
            ).fetchall()
        )

    out: list[dict[str, Any]] = []
    for r in rows:
        path = json.loads(r["path_json"])
        total = len(_path_step_ids(path))
        out.append(
            {
                "id": r["id"],
                "label": r["label"],
                "goal": r["goal"],
                "target_type": r["target_type"],
                "checked": int(checked_counts.get(r["id"], 0)),
                "total": total,
                "created_at": r["created_at"],
                "updated_at": r["updated_at"],
            }
        )
    return out


def get_session(session_id: str) -> dict[str, Any] | None:
    """Full session: metadata + the path with per-step checked/result merged in.

    Returns ``None`` if the session doesn't exist.
    """
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM sessions WHERE id=?", (session_id,)
        ).fetchone()
        if row is None:
            return None
        state_rows = conn.execute(
            "SELECT step_id, checked, result_text FROM step_state "
            "WHERE session_id=?",
            (session_id,),
        ).fetchall()

    state = {
        s["step_id"]: {
            "checked": bool(s["checked"]),
            "result_text": s["result_text"] or "",
        }
        for s in state_rows
    }

    path = json.loads(row["path_json"])
    checked = 0
    total = 0
    for phase in path.get("phases", []) or []:
        for step in phase.get("steps", []) or []:
            total += 1
            st = state.get(step.get("id"), {})
            step["checked"] = bool(st.get("checked", False))
            step["result_text"] = st.get("result_text", "")
            if step["checked"]:
                checked += 1

    keys = row.keys()
    return {
        "id": row["id"],
        "label": row["label"],
        "goal": row["goal"],
        "target_type": row["target_type"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "checked": checked,
        "total": total,
        "path": path,
        "report_md": row["report_md"] if "report_md" in keys else None,
        "report_generated_at": (
            row["report_generated_at"] if "report_generated_at" in keys else None
        ),
    }


# --------------------------------------------------------------------------- #
# update / delete
# --------------------------------------------------------------------------- #
def update_step(
    session_id: str,
    step_id: str,
    checked: bool | None = None,
    result: str | None = None,
) -> dict[str, Any] | None:
    """Partially update one step's state (checked and/or result_text).

    Returns the merged step state ``{checked, result_text}`` on success,
    ``None`` if the session doesn't exist or ``step_id`` isn't part of its path.
    """
    with _write_lock, _connect() as conn:
        row = conn.execute(
            "SELECT path_json FROM sessions WHERE id=?", (session_id,)
        ).fetchone()
        if row is None:
            return None
        if step_id not in _path_step_ids(json.loads(row["path_json"])):
            return None

        # ensure a state row exists, then apply only the provided fields
        conn.execute(
            "INSERT OR IGNORE INTO step_state (session_id, step_id) VALUES (?, ?)",
            (session_id, step_id),
        )
        if checked is not None:
            conn.execute(
                "UPDATE step_state SET checked=? WHERE session_id=? AND step_id=?",
                (1 if checked else 0, session_id, step_id),
            )
        if result is not None:
            conn.execute(
                "UPDATE step_state SET result_text=? "
                "WHERE session_id=? AND step_id=?",
                (result, session_id, step_id),
            )
        _touch(conn, session_id)

        cur = conn.execute(
            "SELECT checked, result_text FROM step_state "
            "WHERE session_id=? AND step_id=?",
            (session_id, step_id),
        ).fetchone()

    return {"checked": bool(cur["checked"]), "result_text": cur["result_text"] or ""}


def rename_session(session_id: str, label: str) -> bool:
    """Set a session's label. Returns False if the session doesn't exist."""
    label = (label or "").strip() or "untitled engagement"
    with _write_lock, _connect() as conn:
        cur = conn.execute(
            "UPDATE sessions SET label=?, updated_at=? WHERE id=?",
            (label, _now(), session_id),
        )
        return cur.rowcount > 0


def save_report(session_id: str, report_md: str) -> str | None:
    """Persist a generated report on the session. Returns its timestamp.

    Returns ``None`` if the session doesn't exist.
    """
    ts = _now()
    with _write_lock, _connect() as conn:
        cur = conn.execute(
            "UPDATE sessions SET report_md=?, report_generated_at=?, updated_at=? "
            "WHERE id=?",
            (report_md, ts, ts, session_id),
        )
        if cur.rowcount == 0:
            return None
    return ts


def delete_session(session_id: str) -> bool:
    """Delete a session and its step state. Returns False if it didn't exist."""
    with _write_lock, _connect() as conn:
        cur = conn.execute("DELETE FROM sessions WHERE id=?", (session_id,))
        return cur.rowcount > 0
