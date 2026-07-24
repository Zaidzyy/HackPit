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
# ENGAGEMENT MODE — Wall A (the guard that REPLACES the isolation floor).
# Engagement mode has no isolation floor (the sandbox reaches the internet — the point
# of the mode). What contains it is Wall A: it must NOT reach the operator's host, the
# LAN, or link-local/metadata. This guard verifies — structurally + against the LIVE
# firewall ruleset — that Wall A is in force before every engagement exec, the way
# assert_isolation_proven guards the lab. It is NOT a substitute for human approval of
# every command (that remains the only bound on WHAT runs); it bounds WHERE it can reach.
# --------------------------------------------------------------------------- #


def _running(name: str) -> bool:
    rc, out, _ = _docker(["inspect", "-f", "{{.State.Running}}", name])
    return rc == 0 and out == "true"


def _inspect_field(name: str, fmt: str) -> str:
    rc, out, err = _docker(["inspect", "-f", fmt, name])
    if rc != 0:
        raise SandboxError(f"cannot inspect '{name}': {err or 'rc ' + str(rc)}")
    return out


def _drops_cidr(ruleset: str, cidr: str) -> bool:
    """True if the iptables -S output has an OUTPUT rule dropping traffic to ``cidr``."""
    for line in ruleset.splitlines():
        if f"-d {cidr}" in line and "-j DROP" in line:
            return True
    return False


def is_engage_sandbox_up() -> bool:
    """True iff both the engagement sandbox and its firewall sidecar are running."""
    return _running(config.ENGAGE_SANDBOX_CONTAINER) and _running(config.ENGAGE_FIREWALL_CONTAINER)


def assert_wall_a_holds() -> None:
    """Raise SandboxError unless Wall A is provably in force for the engagement sandbox.

    Checks, fail-closed on any docker error:
      1. the firewall sidecar + the engagement sandbox are both running;
      2. the sandbox SHARES the firewall's network namespace (``network_mode: service:`` →
         ``container:<firewall-id>``) — that is what subjects its egress to Wall A;
      3. the firewall's LIVE ruleset drops EVERY WALL_A_BLOCKED range (host/LAN/metadata).
    A flushed ruleset, a detached sandbox, or a down sidecar all refuse execution.
    """
    fw = config.ENGAGE_FIREWALL_CONTAINER
    sbx = config.ENGAGE_SANDBOX_CONTAINER

    if not _running(fw):
        raise SandboxError(
            f"engagement firewall '{fw}' is not running — Wall A has no owner; refusing to "
            "execute (bring the engagement pair up: docker compose ... up -d)"
        )
    if not _running(sbx):
        raise SandboxError(
            f"engagement sandbox '{sbx}' is not running — bring the engagement pair up"
        )

    # 2. the sandbox must share the firewall's netns (else Wall A does not apply to it).
    mode = _inspect_field(sbx, "{{.HostConfig.NetworkMode}}")
    fw_id = _inspect_field(fw, "{{.Id}}")
    netns = mode.split(":", 1)[1] if mode.startswith("container:") else ""
    if not netns or not (fw_id == netns or fw_id.startswith(netns) or netns.startswith(fw_id[:12])):
        raise SandboxError(
            f"engagement sandbox is not sharing the firewall netns (NetworkMode='{mode}') — "
            "Wall A would not apply; refusing to execute"
        )

    # 3. the firewall's live ruleset must DROP every Wall-A range.
    rc, ruleset, err = _docker(["exec", fw, "iptables", "-S", "OUTPUT"])
    if rc != 0:
        raise SandboxError(
            f"cannot read the Wall-A ruleset from '{fw}': {err or 'rc ' + str(rc)}; refusing"
        )
    missing = [cidr for cidr in config.WALL_A_BLOCKED if not _drops_cidr(ruleset, cidr)]
    if missing:
        raise SandboxError(
            f"Wall A is not fully in force — the firewall is not dropping {missing}; refusing "
            "to execute (the sandbox could reach host/LAN/metadata)"
        )
