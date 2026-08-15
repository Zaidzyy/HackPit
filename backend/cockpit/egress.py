"""Egress-proxy rotation — WHICH controlled source IP the next run goes out through.

Companion to two things that already exist:
  * :mod:`cockpit.engagement`'s egress config, which HOLDS the pool (the credential-bearing
    list of proxy URLs) and returns it only via ``engagement.egress_config``.
  * :func:`cockpit.executor.apply_egress`, which puts a chosen URL on a tool's own proxy flag.

This module owns only the transient CHOICE: round-robin over the engagement's pool, skipping
any URL marked banned this session, so one WAF ban on a single IP does not strand the whole
engagement. It executes nothing and holds no credential — it reads the pool from the engagement
store and returns one URL.

State is in-process and per-engagement. The pool itself is persisted (engagement DB); the
rotation cursor and ban set are ephemeral BY DESIGN — a fresh process just starts the
round-robin over and re-arms every IP, which is correct behaviour, not lost data.
"""

from __future__ import annotations

import threading

from . import engagement as engagement_mod

_lock = threading.Lock()
_cursor: dict[str, int] = {}
_banned: dict[str, set[str]] = {}


def pick(engagement_id: str) -> str | None:
    """The next egress URL for this engagement — round-robin, skipping banned. None if none usable.

    None means "went direct" to the caller, which turns it into an honest note rather than a
    silent full-speed-from-the-real-IP run. Advances the rotation cursor by one; call it ONCE
    per run (the executor does).
    """
    if not engagement_id:
        return None
    pool, _ = engagement_mod.egress_config(engagement_id)
    if not pool:
        return None
    with _lock:
        banned = _banned.get(engagement_id, set())
        usable = [u for u in pool if u not in banned]
        if not usable:
            return None
        i = _cursor.get(engagement_id, 0) % len(usable)
        _cursor[engagement_id] = i + 1
        return usable[i]


def mark_banned(engagement_id: str, url: str) -> None:
    """Take one URL out of rotation for this session (e.g. after a 403/429 wall traced to it)."""
    if not engagement_id or not url:
        return
    with _lock:
        _banned.setdefault(engagement_id, set()).add(url)


def banned(engagement_id: str) -> set[str]:
    """The URLs currently benched for this engagement (for status / tests). A copy, not the live set."""
    with _lock:
        return set(_banned.get(engagement_id, set()))


def reset(engagement_id: str) -> None:
    """Clear rotation + ban state for one engagement — re-arm every IP. Test hook / manual re-arm."""
    with _lock:
        _cursor.pop(engagement_id, None)
        _banned.pop(engagement_id, None)
