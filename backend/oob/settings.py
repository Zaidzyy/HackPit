"""OOB auto-poll settings — one row, read by the background sweep (spec 2026-08-06 §4.4).

Auto-poll reads the operator's OWN callbacks on a timer and files them; it is read-only
automation that reaches ``poll.poll_all -> ingest -> state`` and no execution surface, so it
does not cross the propose-only invariant. This module only stores the toggle and interval —
the loop itself is ``autopoll.py``.

Default ENABLED, so a configured backend's callbacks appear without anyone clicking poll (the
operator asked for this); a visible off switch turns it back to manual. The interval is floored
so a mistyped value cannot hammer interact.sh.

This module executes nothing and opens no socket.
"""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from typing import Any

DB_PATH = Path(__file__).parent.parent / "sessions.db"

_write_lock = threading.Lock()

ROW_ID = "oob"
DEFAULT_ENABLED = True
DEFAULT_INTERVAL = 60
# The floor: a canary poll crossing the internet to a shared public service should not fire more
# often than this, whatever a caller types.
MIN_INTERVAL = 30


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def init_db() -> None:
    """Create the settings table. Idempotent; safe to call on every startup."""
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS oob_settings (
                row_id   TEXT PRIMARY KEY,
                enabled  INTEGER NOT NULL DEFAULT 1,
                interval INTEGER NOT NULL DEFAULT 60
            )
            """
        )


def get() -> dict[str, Any]:
    """The current setting, or the defaults when nothing has been written yet."""
    try:
        with _connect() as conn:
            row = conn.execute(
                "SELECT enabled, interval FROM oob_settings WHERE row_id = ?", (ROW_ID,)
            ).fetchone()
    except sqlite3.OperationalError:
        row = None
    if row is None:
        return {"enabled": DEFAULT_ENABLED, "interval": DEFAULT_INTERVAL}
    return {"enabled": bool(row["enabled"]), "interval": int(row["interval"])}


def set(enabled: bool, interval: int) -> dict[str, Any]:  # noqa: A001 - deliberate verb name
    """Write the toggle + interval. The interval is floored at :data:`MIN_INTERVAL`."""
    init_db()
    bounded = max(MIN_INTERVAL, int(interval))
    with _write_lock, _connect() as conn:
        conn.execute(
            "INSERT INTO oob_settings (row_id, enabled, interval) VALUES (?,?,?) "
            "ON CONFLICT(row_id) DO UPDATE SET enabled=excluded.enabled, interval=excluded.interval",
            (ROW_ID, 1 if enabled else 0, bounded),
        )
    return get()
