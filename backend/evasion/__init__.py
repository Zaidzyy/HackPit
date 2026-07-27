"""Bespoke evasion engine (build #4, item C) — GENERATE-ONLY artifact production.

A top-level package, peer to ``detection/`` and ``state/`` rather than part of ``cockpit/``:
the cockpit and arsenal packages may not reference each other in either direction, and the
cross-cutting HTTP route for this engine lives in ``backend/main.py``.

See :mod:`evasion.engine` for the containment contract. The short version: it builds an
artifact and stops. It never runs or deploys what it builds, the orchestrator has no path to
it, and every result carries the defender's view of the artifact alongside an honest note
naming what still records it.
"""
from .engine import (  # noqa: F401
    EvasionError,
    EvasionRefused,
    EvasionRequest,
    EvasionResult,
    TECHNIQUES,
    generate,
    render_stub,
)

__all__ = [
    "EvasionError",
    "EvasionRefused",
    "EvasionRequest",
    "EvasionResult",
    "TECHNIQUES",
    "generate",
    "render_stub",
]
