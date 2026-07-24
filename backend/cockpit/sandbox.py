"""Sandbox lifecycle + the runtime isolation gate.

`docker exec` is the only bridge into the sandbox. Before the executor runs anything
it asserts, structurally, that the sandbox is running and attached ONLY to `internal`
Docker networks — i.e. it has no path to host or internet. This is the code-level
expression of docs/cockpit-plan.md §c Layer 1, re-checked at run time (the M1.2
functional proof is the one-time evidence; this is the always-on guard).
"""

from __future__ import annotations

import subprocess

from . import config


class SandboxError(RuntimeError):
    """Raised for sandbox lifecycle / availability / isolation problems."""


def _docker(args: list[str], timeout: float = 10.0) -> tuple[int, str, str]:
    """Run a docker CLI command, return (rc, stdout, stderr). rc=127 if missing."""
    try:
        p = subprocess.run(
            ["docker", *args],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except FileNotFoundError:
        return 127, "", "docker CLI not found on PATH"
    except subprocess.TimeoutExpired:
        return 124, "", "docker command timed out"


def is_sandbox_up() -> bool:
    """True iff the sandbox container exists and is running."""
    rc, out, _ = _docker(
        ["inspect", "-f", "{{.State.Running}}", config.SANDBOX_CONTAINER]
    )
    return rc == 0 and out == "true"


def _sandbox_networks() -> list[str]:
    """Network names the sandbox container is attached to."""
    rc, out, err = _docker(
        [
            "inspect",
            "-f",
            "{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}",
            config.SANDBOX_CONTAINER,
        ]
    )
    if rc != 0:
        raise SandboxError(f"cannot inspect sandbox networks: {err or 'rc ' + str(rc)}")
    return [n for n in out.split() if n]


def _network_is_internal(network: str) -> bool:
    rc, out, err = _docker(["network", "inspect", "-f", "{{.Internal}}", network])
    if rc != 0:
        raise SandboxError(f"cannot inspect network '{network}': {err or 'rc ' + str(rc)}")
    return out == "true"


def assert_isolation_proven() -> None:
    """Raise SandboxError unless the running sandbox is safely isolated.

    Structural, always-on guard: the sandbox must be running and EVERY network it is
    attached to must be `internal: true`. A single non-internal network would be an
    egress path, so we refuse. Cheap enough to call before every first exec.
    """
    if not is_sandbox_up():
        raise SandboxError(
            f"sandbox '{config.SANDBOX_CONTAINER}' is not running — bring the stack up "
            "(docker compose -f docker/docker-compose.yml up -d)"
        )

    networks = _sandbox_networks()
    if not networks:
        raise SandboxError("sandbox is attached to no network — cannot verify isolation")

    non_internal = [n for n in networks if not _network_is_internal(n)]
    if non_internal:
        raise SandboxError(
            "sandbox is attached to non-internal network(s) "
            f"{non_internal} — that is an egress path; refusing to execute"
        )


# --------------------------------------------------------------------------- #
# ENGAGEMENT MODE — the SCOPE-LOCK egress floor (per-target, network-enforced).
# On a real target the containment is a DEFAULT-DENY firewall (the NET_ADMIN sidecar that
# owns the sandbox's shared netns) that allows ONLY the engagement's resolved authorized
# scope. The operator's host, out-of-scope LAN, cloud metadata, IPv6 (unless scoped), and the
# rest of the internet are dropped. This REPLACES isolation on real targets. The backend
# programs the rules at ENTER (apply_scope) / resets them at EXIT (clear_scope), and re-reads
# them before every engagement exec (assert_scope_locked — see below / executor). Because the
# floor is network-enforced, the guided loop may DRAFT here; NEVER-AUTO-RUN still requires
# human approval of EVERY command.
# --------------------------------------------------------------------------- #

_SCOPE_LOCK = "/usr/local/bin/scope_lock.sh"
# A stable marker so /etc/hosts injection is idempotent across re-entries.
_HOSTS_MARKER = "# hackpit-scope"


def _running(name: str) -> bool:
    rc, out, _ = _docker(["inspect", "-f", "{{.State.Running}}", name])
    return rc == 0 and out == "true"


def is_engage_sandbox_up() -> bool:
    """True iff the engagement sandbox container is running."""
    return _running(config.ENGAGE_SANDBOX_CONTAINER)


def is_engage_firewall_up() -> bool:
    """True iff the scope-lock firewall sidecar is running (it owns the sandbox's netns)."""
    return _running(config.ENGAGE_FIREWALL_CONTAINER)


def apply_scope(allow_tokens: list[str], hosts_line: str | None = None) -> None:
    """Program the scope-lock: DEFAULT-DENY + allow ONLY ``allow_tokens`` (resolved IPs or a
    CIDR), then inject an ``/etc/hosts`` mapping into the sandbox so the scope name resolves
    locally with no DNS egress. Raises SandboxError on any failure (so entry fails closed)."""
    if not allow_tokens:
        raise SandboxError("refusing to apply an EMPTY scope — engagement needs a resolved scope")
    if not is_engage_firewall_up():
        raise SandboxError(
            f"scope-lock firewall '{config.ENGAGE_FIREWALL_CONTAINER}' is not running — bring the "
            "engagement stack up (docker compose -f docker/docker-compose.yml up -d)"
        )
    rc, out, err = _docker(
        ["exec", config.ENGAGE_FIREWALL_CONTAINER, _SCOPE_LOCK, "apply", *allow_tokens]
    )
    if rc != 0:
        raise SandboxError(f"could not apply scope-lock rules: {err or out or 'rc ' + str(rc)}")

    if hosts_line:
        # Inject into the FIREWALL container's /etc/hosts: it OWNS the shared netns, so the
        # sandbox sees this file (its own /etc/hosts is a read-only bind mount of it). Idempotent
        # across re-entries: filter out any prior injected line, add the current mapping, and
        # rewrite IN PLACE via `cat >` (NOT `sed -i`, which can't replace the /etc/hosts inode —
        # it's a bind mount).
        script = (
            f"{{ grep -v '{_HOSTS_MARKER}' /etc/hosts; "
            f"printf '%s %s\\n' '{hosts_line}' '{_HOSTS_MARKER}'; }} "
            f"> /tmp/hp_hosts && cat /tmp/hp_hosts > /etc/hosts"
        )
        _docker(["exec", config.ENGAGE_FIREWALL_CONTAINER, "sh", "-c", script])


def clear_scope() -> None:
    """Reset the scope-lock to DEFAULT-DENY (no scope) and drop the injected /etc/hosts line.
    Best-effort — used on engagement EXIT; a still-running firewall then reaches nothing."""
    if is_engage_firewall_up():
        _docker(["exec", config.ENGAGE_FIREWALL_CONTAINER, _SCOPE_LOCK, "deny"])
        # Rewrite in place (cat >, not sed -i — /etc/hosts is a bind mount).
        _docker(
            ["exec", config.ENGAGE_FIREWALL_CONTAINER, "sh", "-c",
             f"grep -v '{_HOSTS_MARKER}' /etc/hosts > /tmp/hp_hosts 2>/dev/null "
             "&& cat /tmp/hp_hosts > /etc/hosts || true"]
        )
