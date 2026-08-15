"""The auto-runner SCHEDULER — a background timer that takes autonomous steps for engagements the
operator has switched to assisted/full mode.

UNLIKE oob-autopoll (read-only, default ON), THIS DAEMON HAS HANDS, so it is DEFAULT OFF and is
guarded by TWO independent switches, BOTH of which must be on before anything fires:

  1. this daemon's toggle (``get_settings()["enabled"]`` — default False), and
  2. the engagement's ``autonomy_mode`` (default 'manual').

A manual engagement is never stepped even while the daemon runs; the daemon off means nothing is
stepped at all. Turning the daemon off is the KILL-SWITCH — re-read every cycle AND before each
engagement's step, so it halts mid-tick without a restart. Each cycle takes at most
``MAX_STEPS_PER_TICK`` step per engagement (the per-tick budget), so an autonomous engagement
advances in bounded, observable increments rather than running away, and a step that raises is
contained to its own engagement. Every fire it triggers is still recorded in the append-only
autorun audit (via ``autorun.step_session`` → ``autoaudit``).

This module holds the toggle+interval settings and the loop; the propose→decide→fire policy is in
``autorun``. Locked by test_autoloop_safety.py.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from typing import Any

from . import autorun, engagement as engagement_mod
from .runstore import DB_PATH

_write_lock = threading.Lock()

ROW_ID = "autorun"
#: DEFAULT OFF. This is the difference from oob-autopoll: this daemon executes, so nothing runs
#: autonomously until the operator deliberately enables it AND sets an engagement to assisted/full.
DEFAULT_ENABLED = False
DEFAULT_INTERVAL = 60
#: The floor — an autonomous loop against a real target should not step faster than this.
MIN_INTERVAL = 20
#: Per-engagement, per-tick budget. One step per cycle keeps the loop maximally observable and
#: avoids re-proposing an async job's action before its result has landed.
MAX_STEPS_PER_TICK = 1


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def init_db() -> None:
    """Create the settings table. Idempotent; safe to call on every startup."""
    with _write_lock, _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS autorun_settings (
                row_id   TEXT PRIMARY KEY,
                enabled  INTEGER NOT NULL DEFAULT 0,
                interval INTEGER NOT NULL DEFAULT 60
            )
            """
        )


def get_settings() -> dict[str, Any]:
    """The current toggle+interval, or the (OFF) defaults when nothing has been written."""
    try:
        with _connect() as conn:
            row = conn.execute(
                "SELECT enabled, interval FROM autorun_settings WHERE row_id = ?", (ROW_ID,)
            ).fetchone()
    except sqlite3.OperationalError:
        row = None
    if row is None:
        return {"enabled": DEFAULT_ENABLED, "interval": DEFAULT_INTERVAL}
    return {"enabled": bool(row["enabled"]), "interval": int(row["interval"])}


def set_settings(enabled: bool, interval: int) -> dict[str, Any]:
    """Write the toggle + interval. The interval is floored at :data:`MIN_INTERVAL`. Enabling this
    is the deliberate act that lets assisted/full engagements advance without a click."""
    init_db()
    bounded = max(MIN_INTERVAL, int(interval))
    with _write_lock, _connect() as conn:
        conn.execute(
            "INSERT INTO autorun_settings (row_id, enabled, interval) VALUES (?,?,?) "
            "ON CONFLICT(row_id) DO UPDATE SET enabled=excluded.enabled, interval=excluded.interval",
            (ROW_ID, 1 if enabled else 0, bounded),
        )
    return get_settings()


def _active_autonomous() -> list[tuple[str, str]]:
    """``(engagement_id, session_id)`` for every ACTIVE engagement in assisted/full mode that has a
    session to advance. A manual engagement is filtered out here — the FIRST of the two switches."""
    out: list[tuple[str, str]] = []
    for rec in engagement_mod.list_active():
        if rec.autonomy_mode in ("assisted", "full") and rec.session_id:
            out.append((rec.engagement_id, rec.session_id))
    return out


def tick() -> dict[str, Any]:
    """One scheduler pass: step each autonomous engagement (up to the per-tick budget). Re-checks
    the kill-switch before each engagement so disabling halts mid-tick. A step that raises is
    contained to its engagement and reported, never aborting the others."""
    stepped: dict[str, Any] = {}
    for eid, sid in _active_autonomous():
        if not get_settings()["enabled"]:  # KILL-SWITCH, mid-tick
            break
        try:
            r = autorun.step_session(sid, eid)
            stepped[eid] = {"action": r.get("action"), "tier": r.get("tier"),
                            "reason": r.get("reason")}
        except Exception as exc:  # noqa: BLE001 — one engagement's fire error never stops the rest
            stepped[eid] = {"action": "error", "reason": str(exc)}
    return {"stepped": stepped}


def start(app: Any = None) -> None:
    """Spawn the daemon thread. Called once from the app lifespan. Sleeps first (startup is never
    blocked); each tick fully guarded; honours the toggle + floor every cycle so enabling/disabling
    or changing the interval takes effect without a restart. Off by default — it does nothing at all
    until both switches are on."""

    def _run() -> None:
        while True:
            cfg = get_settings()
            time.sleep(max(MIN_INTERVAL, int(cfg["interval"])))
            if not get_settings()["enabled"]:
                continue
            try:
                tick()
            except Exception:  # pragma: no cover — a background scheduler is never load-bearing
                pass

    threading.Thread(target=_run, name="hp-autorun", daemon=True).start()
