"""Saved Windows connection profiles — the "Windows targets" store (Option A).

A profile names ONE Windows/AD box HackPit can drive over the network: a host, a
transport (WinRM today; SSH is a documented later seam), a port, a username, an auth
method (password | ntlm-hash for pass-the-hash) and an optional domain. Switching which
VM the cockpit drives is then "pick a different profile" — a different host + creds — and
nothing else changes.

WHY A PROFILE, AND WHY IT MATTERS FOR CONTAINMENT
-------------------------------------------------
A Windows-mode ExecRequest carries only a ``windows_profile_id`` — never a host or a
credential. The executor resolves that id to a host+creds HERE, so a request can name a
stored profile but can never redirect a run to an arbitrary box. This is the exact
containment shape :kali uses with its hardcoded container: the destination is derived
server-side from a trusted constant/record, not from the request body. See
docs/WINDOWS-EXECUTION.md and [[kali-shell-containment]].

SECRETS. The password / NTLM hash is stored in the gitignored ``sessions.db`` (same store
the credential vault + engagement records use) and is NEVER returned in the clear: every
public view masks it to ``has_secret: bool``. The raw secret is read only by the WinRM
transport, via :func:`get_secret`, and is never serialised into an API response, a run
record, or a command line. See [[c2-session-panel]] for the same source-scan discipline.

This module executes nothing. It reads and writes a SQLite table.
"""

from __future__ import annotations

import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from typing import Any

from .runstore import DB_PATH  # the same single-file gitignored SQLite store

_write_lock = threading.Lock()

# The transports a profile may declare. WinRM is the AD-native path and the only one wired
# today; ``ssh`` is reserved as the documented later seam (see docs/WINDOWS-EXECUTION.md) so
# the schema does not have to change when it is added.
TRANSPORTS = ("winrm", "ssh")
# How a profile authenticates. ``password`` is cleartext-over-NTLM; ``ntlm-hash`` is
# pass-the-hash (the NT hash used directly, no password). Both go over NTLM/Negotiate so a
# LOCAL Windows account works over plain HTTP:5985 without enabling Basic auth.
AUTH_KINDS = ("password", "ntlm-hash")

DEFAULT_PORT = 5985  # WinRM over HTTP


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def init_db() -> None:
    """Create the windows_profiles table if absent. Idempotent."""
    with _write_lock, _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS windows_profiles (
                profile_id  TEXT PRIMARY KEY,
                name        TEXT NOT NULL,
                host        TEXT NOT NULL,
                transport   TEXT NOT NULL DEFAULT 'winrm',
                port        INTEGER NOT NULL DEFAULT 5985,
                username    TEXT NOT NULL,
                auth_kind   TEXT NOT NULL DEFAULT 'password',
                secret      TEXT NOT NULL DEFAULT '',   -- masked in every public view
                domain      TEXT NOT NULL DEFAULT '',
                created_at  TEXT NOT NULL
            )
            """
        )


def _validate(
    name: str, host: str, transport: str, port: int, username: str, auth_kind: str
) -> None:
    if not (name or "").strip():
        raise ValueError("a profile needs a name")
    if not (host or "").strip() or any(ch.isspace() for ch in host.strip()):
        raise ValueError("host must be a single non-empty hostname or IP (no spaces)")
    if transport not in TRANSPORTS:
        raise ValueError(f"transport must be one of {TRANSPORTS}, got {transport!r}")
    if transport == "ssh":
        # The seam exists in the schema; the transport itself is not built yet. Refuse
        # rather than silently accept a profile nothing can run.
        raise ValueError("the ssh transport is not implemented yet — use 'winrm'")
    if not isinstance(port, int) or not (1 <= port <= 65535):
        raise ValueError("port must be a TCP port (1-65535)")
    if not (username or "").strip():
        raise ValueError("a profile needs a username")
    if auth_kind not in AUTH_KINDS:
        raise ValueError(f"auth_kind must be one of {AUTH_KINDS}, got {auth_kind!r}")


def create_profile(
    name: str,
    host: str,
    username: str,
    *,
    transport: str = "winrm",
    port: int = DEFAULT_PORT,
    auth_kind: str = "password",
    secret: str = "",
    domain: str = "",
) -> dict[str, Any]:
    """Create a Windows target profile. Returns the PUBLIC view (secret masked)."""
    _validate(name, host, transport, port, username, auth_kind)
    profile_id = "win-" + uuid.uuid4().hex[:12]
    created = _now()
    with _write_lock, _connect() as conn:
        conn.execute(
            "INSERT INTO windows_profiles "
            "(profile_id, name, host, transport, port, username, auth_kind, secret, domain, "
            " created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (profile_id, name.strip(), host.strip(), transport, int(port), username.strip(),
             auth_kind, secret or "", (domain or "").strip(), created),
        )
    pub = get_public(profile_id)
    assert pub is not None
    return pub


def update_profile(profile_id: str, **fields: Any) -> dict[str, Any] | None:
    """Update selected fields on a profile. Returns the PUBLIC view, or None if unknown.

    An empty/omitted ``secret`` leaves the stored secret UNCHANGED — so editing a
    profile's host does not silently wipe its credential and force a re-type. Pass a
    non-empty ``secret`` to replace it.
    """
    cur = _raw(profile_id)
    if cur is None:
        return None
    merged = {
        "name": fields.get("name", cur["name"]),
        "host": fields.get("host", cur["host"]),
        "transport": fields.get("transport", cur["transport"]),
        "port": int(fields.get("port", cur["port"])),
        "username": fields.get("username", cur["username"]),
        "auth_kind": fields.get("auth_kind", cur["auth_kind"]),
        "domain": fields.get("domain", cur["domain"]),
    }
    _validate(merged["name"], merged["host"], merged["transport"], merged["port"],
              merged["username"], merged["auth_kind"])
    new_secret = fields.get("secret")
    secret = new_secret if new_secret else cur["secret"]  # empty ⇒ keep existing
    with _write_lock, _connect() as conn:
        conn.execute(
            "UPDATE windows_profiles SET name=?, host=?, transport=?, port=?, username=?, "
            "auth_kind=?, secret=?, domain=? WHERE profile_id=?",
            (merged["name"].strip(), merged["host"].strip(), merged["transport"],
             merged["port"], merged["username"].strip(), merged["auth_kind"], secret,
             merged["domain"].strip(), profile_id),
        )
    return get_public(profile_id)


def delete_profile(profile_id: str) -> bool:
    """Delete a profile. True if one was removed."""
    with _write_lock, _connect() as conn:
        cur = conn.execute(
            "DELETE FROM windows_profiles WHERE profile_id=?", (profile_id,)
        )
        return cur.rowcount > 0


def _raw(profile_id: str) -> sqlite3.Row | None:
    if not profile_id:
        return None
    with _connect() as conn:
        try:
            return conn.execute(
                "SELECT * FROM windows_profiles WHERE profile_id=?", (profile_id,)
            ).fetchone()
        except sqlite3.OperationalError:
            # Table not created yet (init_db runs at app startup) — treat as "no such
            # profile" rather than crashing a gate check.
            return None


def get_profile(profile_id: str) -> dict[str, Any] | None:
    """The FULL profile INCLUDING the secret — for the WinRM transport ONLY.

    Never serialise the result of this into an API response. The public surfaces call
    :func:`get_public` / :func:`list_profiles`, which mask the secret.
    """
    row = _raw(profile_id)
    if row is None:
        return None
    d = dict(row)
    return {
        "profile_id": d["profile_id"],
        "name": d["name"],
        "host": d["host"],
        "transport": d["transport"],
        "port": int(d["port"]),
        "username": d["username"],
        "auth_kind": d["auth_kind"],
        "secret": d["secret"] or "",
        "domain": d["domain"] or "",
        "created_at": d["created_at"],
    }


def get_secret(profile_id: str) -> str:
    """The raw secret for a profile (transport use only). '' if the profile is unknown."""
    row = _raw(profile_id)
    return (row["secret"] if row else "") or ""


def _public(row: sqlite3.Row) -> dict[str, Any]:
    d = dict(row)
    return {
        "profile_id": d["profile_id"],
        "name": d["name"],
        "host": d["host"],
        "transport": d["transport"],
        "port": int(d["port"]),
        "username": d["username"],
        "auth_kind": d["auth_kind"],
        # The secret is NEVER returned. The UI only needs to know whether one is stored.
        "has_secret": bool(d["secret"]),
        "domain": d["domain"] or "",
        "created_at": d["created_at"],
    }


def get_public(profile_id: str) -> dict[str, Any] | None:
    """The masked public view of one profile, or None if unknown."""
    row = _raw(profile_id)
    return _public(row) if row else None


def list_profiles() -> list[dict[str, Any]]:
    """Every profile, masked, newest first — for the picker."""
    with _connect() as conn:
        try:
            rows = conn.execute(
                "SELECT * FROM windows_profiles ORDER BY created_at DESC"
            ).fetchall()
        except sqlite3.OperationalError:
            return []
    return [_public(r) for r in rows]
