"""Persistence for Cockpit run-records — a `cockpit_runs` table in sessions.db.

Reuses the same single-file SQLite store the engagement layer uses (backend/
sessions.db, gitignored) so a run can attach to an engagement + step. Stdlib only.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

from .models import RunRecord

# Same DB file the Companion's engagement layer uses (backend/sessions.db).
DB_PATH = Path(__file__).parent.parent / "sessions.db"

_write_lock = threading.Lock()


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def init_db() -> None:
    """Create the cockpit_runs table if absent. Safe to call repeatedly."""
    with _write_lock, _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS cockpit_runs (
                run_id      TEXT PRIMARY KEY,
                session_id  TEXT,
                step_id     TEXT,
                command     TEXT NOT NULL,
                args        TEXT NOT NULL,      -- json array
                target      TEXT NOT NULL,
                approved    INTEGER NOT NULL,
                exit_code   INTEGER,
                stdout      TEXT NOT NULL DEFAULT '',
                stderr      TEXT NOT NULL DEFAULT '',
                started_at  TEXT NOT NULL,
                finished_at TEXT
            )
            """
        )


def save_run(record: RunRecord) -> None:
    """Insert or replace a run-record."""
    with _write_lock, _connect() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO cockpit_runs
              (run_id, session_id, step_id, command, args, target, approved,
               exit_code, stdout, stderr, started_at, finished_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record.run_id,
                record.session_id,
                record.step_id,
                record.command,
                json.dumps(record.args),
                record.target,
                int(record.approved),
                record.exit_code,
                record.stdout,
                record.stderr,
                record.started_at,
                record.finished_at,
            ),
        )


def get_run(run_id: str) -> RunRecord | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM cockpit_runs WHERE run_id = ?", (run_id,)
        ).fetchone()
    if row is None:
        return None
    return _row_to_record(row)


def _row_to_record(row: sqlite3.Row) -> RunRecord:
    d: dict[str, Any] = dict(row)
    return RunRecord(
        run_id=d["run_id"],
        session_id=d["session_id"],
        step_id=d["step_id"],
        command=d["command"],
        args=json.loads(d["args"]),
        target=d["target"],
        approved=bool(d["approved"]),
        exit_code=d["exit_code"],
        stdout=d["stdout"],
        stderr=d["stderr"],
        started_at=d["started_at"],
        finished_at=d["finished_at"],
    )
