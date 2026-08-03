"""Canary token minting and correlation (spec §3.2).

A token is the one thing that travels: HackPit renders it into a payload, the payload goes
into a target, and — if the vulnerability is real — a resolver or an HTTP client somewhere
inside that target's network asks for ``<token>.<zone>`` minutes later. The hit arrives with
no memory of why. This module is that memory.

WHAT THE TOKEN HAS TO SURVIVE
-----------------------------
It travels as a **DNS label** through a resolver chain HackPit does not control, so the
grammar is deliberately narrower than the RFC: lowercase, letter-first, alphanumeric, no
hyphens. Each exclusion removes a class of mangling rather than hoping for it —
letter-first because a leading digit is legal but still trips older validators, hyphen-free
because a leading or trailing hyphen is not legal at all.

Case is the subtle one. Resolvers randomise query case as an anti-spoofing measure (DNS
0x20) and echo the qname however they like, so the wire form of a token is not the form it
was minted in. :func:`correlate` folds case, which is why the store keeps tokens lowercase.

WHY IT IS UNGUESSABLE
---------------------
The canary is internet-facing and its log holds a client's internal hostnames. A token is
therefore a bearer secret in the DNS: anyone who can guess one can write into an
engagement's evidence. ``secrets``, never ``random`` — the two are indistinguishable at the
call site, so test_oob_tokens.py asserts the import structurally rather than trusting a
reading.

This module executes nothing and opens no socket. It reads and writes a SQLite table in the
same gitignored ``sessions.db`` the engagement records use. The listener is a separate
deployable (``oob/server.py``); the poll client that joins them lands in a later part.
"""

from __future__ import annotations

import re
import secrets
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# The same single-file gitignored store the state package writes to, resolved the same way
# (state/store.py:33) rather than imported from it — backend/oob owes nothing to another
# package for a path both already know.
DB_PATH = Path(__file__).parent.parent / "sessions.db"

_write_lock = threading.Lock()

# 32 symbols: the 26 letters without `l`/`o` and the digits without `0`/`1`. The exclusions
# are the pairs a human miscopies when reading a token off a terminal into a payload, which
# is how these are actually used. 32 keeps the arithmetic honest at exactly 5 bits a
# character, so TOKEN_LEN below reads as the entropy it is.
ALPHABET = "abcdefghijkmnpqrstuvwxyz23456789"
_FIRST = "abcdefghijkmnpqrstuvwxyz"  # a label may not start with a digit for every consumer

# 12 * 5 = 60 bits. The floor, not a target: a token is guessable-once-and-you-are-in, and
# the cost of a longer label is nothing.
TOKEN_LEN = 12

# What correlate() will accept off the wire. Anyone on the internet can query anything under
# the zone, so every query label reaches this pattern before it reaches the database.
_TOKEN_RE = re.compile(r"^[a-z][a-z0-9]{11,62}$")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def init_db() -> None:
    """Create the token table. Idempotent; safe to call on every startup."""
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS oob_tokens (
                token         TEXT PRIMARY KEY,
                engagement_id TEXT NOT NULL,
                step_id       TEXT,
                note          TEXT NOT NULL DEFAULT '',
                at            TEXT NOT NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS oob_tokens_engagement ON oob_tokens (engagement_id)"
        )


def is_token(value: str) -> bool:
    """True if `value` could be a token this module minted.

    A grammar check, not a lookup: it says the string is safe to carry as a DNS label and
    safe to hand to the store, nothing about whether it exists.
    """
    return bool(_TOKEN_RE.match(value))


def _new_token() -> str:
    return secrets.choice(_FIRST) + "".join(
        secrets.choice(ALPHABET) for _ in range(TOKEN_LEN - 1)
    )


def mint(engagement_id: str, step_id: str | None = None, note: str = "") -> dict[str, Any]:
    """Mint a token and record what it is for.

    ``step_id`` and ``note`` are the correlation: without them a hit is "something reached
    the internet", with them it is "the payload from step 7 came back". Both are optional
    because a canary is often minted before the step that uses it exists.
    """
    record = {
        "token": _new_token(),
        "engagement_id": engagement_id,
        "step_id": step_id,
        "note": note,
        "at": _now(),
    }
    with _write_lock, _connect() as conn:
        conn.execute(
            "INSERT INTO oob_tokens (token, engagement_id, step_id, note, at) "
            "VALUES (?, ?, ?, ?, ?)",
            (record["token"], engagement_id, step_id, note, record["at"]),
        )
    return record


def correlate(token: str) -> dict[str, Any] | None:
    """Resolve a token seen on the wire back to the test that minted it.

    Called with attacker-controlled input: every label anyone on the internet queries under
    the zone ends up here. So it folds case (a 0x20-randomising resolver does not return the
    token as minted), trims the whitespace a qname split can leave, rejects anything outside
    the label grammar, and returns None rather than raising for all of it.
    """
    if not isinstance(token, str):
        return None
    candidate = token.strip().lower()
    if not is_token(candidate):
        return None
    with _connect() as conn:
        row = conn.execute(
            "SELECT token, engagement_id, step_id, note, at FROM oob_tokens WHERE token = ?",
            (candidate,),
        ).fetchone()
    return dict(row) if row else None


def list_for(engagement_id: str) -> list[dict[str, Any]]:
    """Every token minted for one engagement, newest first."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT token, engagement_id, step_id, note, at FROM oob_tokens "
            "WHERE engagement_id = ? ORDER BY at DESC, token DESC",
            (engagement_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def clear(engagement_id: str) -> None:
    """Drop one engagement's tokens. Used when an engagement is deleted, and by the tests."""
    with _write_lock, _connect() as conn:
        conn.execute("DELETE FROM oob_tokens WHERE engagement_id = ?", (engagement_id,))
