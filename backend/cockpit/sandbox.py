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
