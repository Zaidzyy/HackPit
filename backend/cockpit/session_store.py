"""Operator-provided authenticated SESSIONS, kept per engagement — IN MEMORY ONLY.

The operator logs in themselves (login stays human) and hands cockpit the session, parsed from a
captured request. The repeater can then ATTACH it to a send, so the operator tests AS themselves —
authenticated testing with the operator's OWN session, never a stolen one. This is the in-cockpit
form of what an operator otherwise does by hand: paste a captured request, replay it with a swapped
id.

**Never written to disk.** A live session token is more sensitive than a stored credential and
expires on its own, so it lives only as long as this process. Reads are MASKED — values are never
returned to a caller, only header names + a length. It is not a persistence feature; restart clears
it and the operator re-attaches, which is the correct security posture for a bearer credential.
"""
from __future__ import annotations

from dataclasses import dataclass
from threading import Lock
from typing import Any

from . import reqimport


@dataclass(frozen=True)
class StoredSession:
    """The session-bearing headers for one engagement, in capture order."""

    engagement_id: str
    headers: tuple[tuple[str, str], ...]   # ordered (name, value)
    label: str = ""


_LOCK = Lock()
_SESSIONS: dict[str, StoredSession] = {}


def session_from_capture(raw: str) -> list[tuple[str, str]]:
    """Pull the session/credential headers (with values) out of a captured request.

    Uses the same classifier as ``:repeater`` import: the headers it flags as session/bearer/cookie
    are the ones worth attaching. Returns [] when the capture has no such header.
    """
    req = reqimport.parse_capture(raw)
    names = {n.strip().lower() for n in req.session_headers}
    return [(h.name, h.value) for h in req.headers if h.name.strip().lower() in names]


def set_session(engagement_id: str, headers: list[tuple[str, str]], label: str = "") -> StoredSession:
    eid = (engagement_id or "").strip()
    if not eid:
        raise ValueError("an engagement id is required to attach a session")
    stored = StoredSession(engagement_id=eid, headers=tuple(headers), label=label.strip())
    with _LOCK:
        _SESSIONS[eid] = stored
    return stored


def get_session(engagement_id: str) -> StoredSession | None:
    with _LOCK:
        return _SESSIONS.get((engagement_id or "").strip())


def clear_session(engagement_id: str) -> bool:
    with _LOCK:
        return _SESSIONS.pop((engagement_id or "").strip(), None) is not None


def masked_view(engagement_id: str) -> dict[str, Any] | None:
    """A caller-safe view: header NAMES + a masked length. The token value never leaves here."""
    s = get_session(engagement_id)
    if s is None:
        return None
    return {
        "engagement_id": s.engagement_id,
        "attached": True,
        "label": s.label,
        "headers": [{"name": n, "value": f"•••• ({len(v)} chars)"} for n, v in s.headers],
    }
