"""OOB auto-poll — a background timer that files callbacks without a click (spec 2026-08-06 §4.4).

WHY THIS DOES NOT CROSS THE PROPOSE-ONLY LINE
---------------------------------------------
Every gate in this project rests on a human approving each command *against a target*. This
loop does nothing of the kind: it reads the operator's OWN callbacks off the canary (self-hosted
and/or interact.sh) and files the correlated ones as findings. It reaches ``poll.poll_all ->
ingest -> state`` and no execution surface — no delivery, no command, no offensive action. So it
is automation of *reading a mailbox*, which is why it can run unattended where nothing else may.

It imports ``cockpit.engagement`` only to map an engagement to its state session (the same call
the /oob/poll route makes). It imports no execution surface and no delivery surface, and the
safety scan asserts as much.
"""

from __future__ import annotations

import threading
import time
from typing import Any

from cockpit import engagement as engagement_mod

from . import config, interactsh, poll as poll_mod, settings as settings_mod


def tick() -> dict[str, Any]:
    """One sweep of both backends, filing what correlates. Resolves sessions across ALL engagements.

    A callback routinely lands after its engagement has been exited, so the mapping is taken from
    every engagement, not just the active ones — the same reason the /oob/poll route does.
    """
    return poll_mod.poll_all(engagement_mod.session_ids())


def _backend_configured() -> bool:
    return config.is_configured() or interactsh.is_registered()


def start(app: Any = None) -> None:
    """Spawn the daemon sweep thread. Called once from the app lifespan.

    The loop sleeps first, so startup is never blocked and a just-configured backend is not polled
    mid-boot. Each tick is fully guarded: a slow, down, or rate-limited backend logs nothing and
    crashes nothing — it simply tries again next interval. Honours the toggle and the floor each
    cycle, so turning auto-poll off or changing the interval takes effect without a restart.
    """

    def _run() -> None:
        while True:
            cfg = settings_mod.get()
            time.sleep(max(settings_mod.MIN_INTERVAL, int(cfg["interval"])))
            if not settings_mod.get()["enabled"]:
                continue
            if not _backend_configured():
                continue
            try:
                tick()
            except Exception:  # pragma: no cover - a background sweep is never load-bearing
                pass

    threading.Thread(target=_run, name="oob-autopoll", daemon=True).start()
