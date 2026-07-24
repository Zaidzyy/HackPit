"""Cockpit constants — the single source of truth for *what the lab is*.

Everything here is deliberately hardcoded (not user-supplied) so the target lock
cannot be widened at runtime. Changing these is a code review, on purpose.
"""

from __future__ import annotations

import os

# --- Sandbox (where allowlisted commands run) -------------------------------
# The ISOLATED Kali sandbox the cockpit executor + future autonomous agent exec into.
# Egress-less (`internal: true` network) — this is the safety net guarded by the
# executor's 4th gate, assert_isolation_proven. Overridable by env for local dev only.
SANDBOX_CONTAINER = os.environ.get("HACKPIT_SANDBOX_CONTAINER", "hackpit-kali-sandbox")

# --- :kali OPEN sandbox (human-only shell with FULL network reach) -----------
# A SEPARATE container the :kali human-only shell execs into. On a normal bridge
# (NAT egress): it reaches the internet + host + LAN. This is intentional and applies
# to :kali ONLY (POST /cockpit/kali) — the cockpit/agent path never touches it. It is
# NOT isolated, so :kali does NOT run assert_isolation_proven. Hardcoded (never a
# request field) so a request can't redirect the exec elsewhere.
KALI_OPEN_CONTAINER = os.environ.get("HACKPIT_KALI_OPEN_CONTAINER", "hackpit-kali-open")

# --- Engagement sandbox (REAL-TARGET mode — SCOPE-LOCKED egress, per-target network floor) ---
# The sandbox the cockpit execs into ONLY in explicit engagement mode (POST
# /cockpit/engagement/enter). Its egress is a DEFAULT-DENY firewall that allows ONLY the
# engagement's resolved authorized scope (a single host's IPs, or a CIDR). It shares the
# firewall sidecar's netns, so it keeps cap_drop:ALL + no-new-privileges and cannot alter the
# rules or leave scope. Because the containment is NETWORK-enforced, the guided loop may DRAFT
# commands here; NEVER-AUTO-RUN still requires human approval of EVERY command. The scope-lock
# gate (assert_scope_locked) is the engagement analog of assert_isolation_proven. Hardcoded
# (never a request field) so a request can't redirect the exec elsewhere.
ENGAGE_SANDBOX_CONTAINER = os.environ.get("HACKPIT_ENGAGE_CONTAINER", "hackpit-engage-sandbox")

# The NET_ADMIN firewall SIDECAR that OWNS the engagement sandbox's netns and enforces the
# scope-lock (default-DENY + allow-only-scope). The backend programs its rules at engagement
# ENTER (scope_lock.sh apply <resolved-scope>) and resets them at EXIT (scope_lock.sh deny),
# and re-reads them before every engagement exec (assert_scope_locked). Hardcoded.
ENGAGE_FIREWALL_CONTAINER = os.environ.get("HACKPIT_ENGAGE_FIREWALL", "hackpit-engage-firewall")

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
