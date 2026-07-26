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

# --- Engagement sandbox (REAL-TARGET mode — FULLY OPEN, NO isolation floor, WALL A DOWN) -----
# The egress-capable sandbox the cockpit execs into ONLY in explicit engagement mode
# (POST /cockpit/engagement/enter). Wall A is DOWN (Zaid's informed decision): on a normal
# NAT bridge it has FULL network reach — internet + LAN + host + cloud metadata. Nothing
# bounds WHERE it can reach; the ONLY guard on a real-target run is HUMAN APPROVAL OF EVERY
# COMMAND (explicit entry + approve-each + heuristic red-confirm; never hands-off). It also runs
# PRIVILEGED (D3): root + Docker's default capability set + NET_ADMIN + /dev/net/tun, so SYN
# scans, tcpdump, raw sockets, privileged-port binds (responder/ntlmrelayx) and VPN all work.
# cap_drop:ALL is still the floor and every granted capability is listed explicitly in
# docker-compose.yml; SYS_ADMIN/SYS_PTRACE/SYS_MODULE/SYS_TIME are withheld, and
# no-new-privileges stays on. It is NOT isolated, so it does NOT run assert_isolation_proven and
# there is NO Wall-A gate to assert. Hardcoded (never a request field) so a request can't
# redirect the exec elsewhere.
ENGAGE_SANDBOX_CONTAINER = os.environ.get("HACKPIT_ENGAGE_CONTAINER", "hackpit-engage-sandbox")

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
# DEFAULT time a single command gets before it is killed. A request may ask for more
# (ExecRequest.timeout_seconds / KaliRequest.timeout_seconds) up to MAX_TIMEOUT_SECONDS.
# 180s is a sensible default for interactive work; it is NOT a safety property — the
# safety gates are target-lock, approval, danger-confirm and (lab only) isolation, none
# of which a longer timeout weakens.
EXEC_TIMEOUT_SECONDS = int(os.environ.get("HACKPIT_EXEC_TIMEOUT", "180"))

# HARD ceiling a per-request timeout is clamped to. Real work needs it: a full TCP sweep
# is 2-10 min, `-sU --top-ports 100` 5-20 min, ffuf on raft-medium 5-30 min, a full nuclei
# run 10-60 min. The arsenal's own first template (`nmap -p- --min-rate 2000`) could not
# finish under the old flat 180s. An hour is long enough for all of them and still bounds
# a runaway process. Requests above it are clamped, not refused.
MAX_TIMEOUT_SECONDS = int(os.environ.get("HACKPIT_MAX_TIMEOUT", "3600"))

# --- Long-running jobs -------------------------------------------------------
# A backgrounded run keeps its output buffered in memory so a reconnecting client can
# replay it. Cap per stream so a runaway `yes` cannot exhaust the backend's memory; the
# persisted RunRecord is capped the same way.
JOB_OUTPUT_CAP = int(os.environ.get("HACKPIT_JOB_OUTPUT_CAP", "2000000"))  # chars/stream

# How long a FINISHED job's buffer is kept for late reconnects before the reaper drops it.
# The RunRecord is already durable in SQLite by then; this only bounds the in-memory replay.
JOB_RETENTION_SECONDS = int(os.environ.get("HACKPIT_JOB_RETENTION", "3600"))


def clamp_timeout(requested: int | float | None) -> int:
    """The effective timeout for one run: default when unset, clamped to the hard ceiling.

    Clamps rather than rejects — a caller asking for 24h gets an hour, not a 422. A
    non-positive value is treated as "unset" so `0` can never mean "no timeout".
    """
    if requested is None or requested <= 0:
        return EXEC_TIMEOUT_SECONDS
    return int(min(requested, MAX_TIMEOUT_SECONDS))
