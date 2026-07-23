"""Cockpit constants — the single source of truth for *what the lab is*.

Everything here is deliberately hardcoded (not user-supplied) so the target lock
cannot be widened at runtime. Changing these is a code review, on purpose.
"""

from __future__ import annotations

import os

# --- Sandbox (where allowlisted commands run) -------------------------------
# The Kali sandbox container that the backend execs into. Overridable by env for
# local dev only; defaults to the Compose service name in docker/.
SANDBOX_CONTAINER = os.environ.get("HACKPIT_SANDBOX_CONTAINER", "hackpit-kali-sandbox")

# --- Lab target (the ONLY thing the sandbox may be pointed at) ---------------
# The self-hosted vulnerable app on the isolated network. While unsupervised this
# is the ONLY allowed target — never an external, real, or user-supplied host.
LAB_TARGET_HOST = os.environ.get("HACKPIT_LAB_TARGET", "hackpit-lab-target")

# Aliases that all resolve to "the lab" for the target-lock check. Kept explicit
# so the allowlist/target validator can accept the service name or its localhost
# form but nothing else.
LAB_TARGET_ALIASES: frozenset[str] = frozenset(
    {
        LAB_TARGET_HOST,
        "lab-target",
        "hackpit-lab-target",
    }
)

# --- Docker network (isolation) ---------------------------------------------
# The internal (no-gateway) network the sandbox + lab share. Created with
# `internal: true` in docker/ so there is no route to host or internet.
ISOLATED_NETWORK = os.environ.get("HACKPIT_ISOLATED_NET", "hackpit-isolated")

# --- Execution bounds --------------------------------------------------------
# Hard ceiling on how long a single command may run before it is killed.
EXEC_TIMEOUT_SECONDS = int(os.environ.get("HACKPIT_EXEC_TIMEOUT", "180"))
