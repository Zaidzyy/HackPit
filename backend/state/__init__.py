"""Structured engagement state — hosts, services, endpoints, credentials, findings, tasks.

The fix for the deepest gap in HackPit: before this, every result was a text blob and the
orchestrator's "adapt to prior results" meant re-reading the tail of the last dozen stdout
buffers. There was no attack-surface object to reason over.

    models.py    the five things a pentest accumulates, as dataclasses
    store.py     SQLite persistence (shares sessions.db); every write is an upsert
    parsers.py   tool output -> records; pure functions, no I/O
    ingest.py    called after each run: parses stdout + new loot files, persists
    tasks.py     the Pentest Task Tree — a plan that updates as results arrive
    render.py    state -> the prompt block that replaces stdout tails

NOTHING IN THIS PACKAGE EXECUTES ANYTHING. It has no subprocess, no network and no
container access, and it must never gain any: ingest runs automatically after every
command, which is precisely the position from which an execution path would sit outside
the approval gate. A safety test enforces this.
"""

from __future__ import annotations

from . import ingest, models, parsers, render, store, tasks

__all__ = ["ingest", "models", "parsers", "render", "store", "tasks"]


def init_db() -> None:
    """Create every state table. Idempotent; called once at startup."""
    store.init_db()
    tasks.init_db()
