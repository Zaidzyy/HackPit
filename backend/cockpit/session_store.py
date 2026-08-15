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


# --------------------------------------------------------------------------- #
# shared attach helpers — used by the repeater AND the scan surfaces so an
# authenticated run is one mechanism, not five copies.
# --------------------------------------------------------------------------- #
def header_pairs(engagement_id: str) -> list[tuple[str, str]]:
    """The engagement's stored session headers, or [] — so run paths stay branch-light."""
    s = get_session(engagement_id)
    return list(s.headers) if s else []


def additional_session_headers(
    existing_names: "list[str] | set[str]", stored: list[tuple[str, str]]
) -> list[tuple[str, str]]:
    """The stored headers NOT already present by name — typed headers always win (no override,
    no duplicate credential). The one merge rule the repeater and every scan surface share."""
    have = {n.strip().lower() for n in existing_names}
    return [(n, v) for (n, v) in stored if n.strip().lower() not in have]


#: argv flags whose VALUE is a header/cookie we must never persist in a job record.
_HEADER_FLAGS = frozenset({"-H", "--header", "--headers", "-b", "--cookie"})


def _mask_one_header(val: str) -> str:
    """'Cookie: session_key=abc' -> 'Cookie: •••• (N chars)'; a bare cookie string -> fully masked."""
    if ":" in val:
        name, _, rest = val.partition(":")
        return f"{name}: •••• ({len(rest.strip())} chars)"
    return f"•••• ({len(val)} chars)"


def mask_header_flag_values(argv: list[str]) -> list[str]:
    """A copy of ``argv`` with the value after every header/cookie flag masked — for the job's
    PERSISTED/displayed argv, so a session token never lands in a record. The real argv (with the
    live value) is built only for the exec and is never stored."""
    out = list(argv)
    for i in range(len(out) - 1):
        if out[i] in _HEADER_FLAGS:
            out[i + 1] = _mask_one_header(out[i + 1])
    return out
