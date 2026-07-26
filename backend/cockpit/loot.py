"""Loot directories — where a run's artefacts land on the host.

WHY THIS EXISTS
Every tool worth running writes files: `nmap -oA`, `ffuf -o`, `nuclei -o`, hashcat pots,
secretsdump output, downloaded pages. Before this module those files lived inside a
disposable container and vanished with `docker compose down`, so the only durable record
of a run was its captured stdout.

THE SHAPE
`docker/docker-compose.yml` bind-mounts the host's ``backend/data/engagements`` directory
to ``/loot`` in the sandboxes that get one. Each engagement owns a subdirectory named for
its id, and every command in that engagement runs with its working directory set there
(``docker exec -w``), so a bare ``-oA scan`` writes to the right place with no path
juggling by the operator or the planner.

WHY A PARENT MOUNT AND NOT A PER-ENGAGEMENT ONE
A bind mount is fixed when the container is CREATED. The sandboxes are long-lived and
shared across engagements, so a per-engagement mount would mean recreating a container on
every `enter` — losing the "stack is up" model and any running session with it. Mounting
the parent once and switching the working directory per exec gets the same isolation
between engagements with none of that.

WHICH SANDBOXES GET IT — and the one that deliberately does NOT
    hackpit-engage-sandbox   yes — real engagements, this is the point
    hackpit-kali-open        yes — the human `:kali` shell, same open-network posture
    hackpit-kali-sandbox     NO  — the ISOLATED lab sandbox
The lab sandbox is the container the safety layer leans on: egress-less, unprivileged, and
the host for unattended agent runs. Handing it a writable host directory would widen its
reach for no real gain — lab output is already captured in the run record, and the lab
target is a practice app whose artefacts nobody keeps. Lab runs therefore keep the image's
default working directory. If that ever changes it should be a deliberate decision, not a
side effect of adding loot support.

Nothing here executes anything. It resolves and creates directories; the caller decides
what to do with the path.
"""

from __future__ import annotations

import re
from pathlib import Path

from . import config

# Container-side mount point. Matches the `- ../data/engagements:/loot` bind in
# docker/docker-compose.yml — change both together or a run gets a working directory
# that does not exist and `docker exec -w` fails.
LOOT_MOUNT = "/loot"

# Host-side root, the other half of that same bind. backend/data/engagements/.
LOOT_ROOT = Path(__file__).parent.parent / "data" / "engagements"

# The subdirectory `:kali` uses — it has no engagement id, but it is the human shell on
# the open network and its downloads are worth keeping.
KALI_DIRNAME = "kali"

# Engagement ids are hex from uuid4, but this module must never interpolate an
# unvalidated string into a `docker exec -w` argument or a host path. Anything that is
# not a plain safe token is refused rather than sanitised, so a surprising id fails
# loudly instead of quietly writing somewhere unexpected.
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")


class LootError(ValueError):
    """A loot directory name was not a safe token — nothing was created."""


def _checked(name: str) -> str:
    name = (name or "").strip()
    if not _SAFE_NAME.match(name):
        raise LootError(f"unsafe loot directory name: {name!r}")
    return name


def host_dir(name: str) -> Path:
    """The host path for one loot directory. Does not create it."""
    return LOOT_ROOT / _checked(name)


def container_dir(name: str) -> str:
    """The container path for one loot directory, as `docker exec -w` wants it."""
    return f"{LOOT_MOUNT}/{_checked(name)}"


def ensure(name: str) -> str:
    """Create the host loot directory if needed; return its CONTAINER path.

    The host side is created because `docker exec -w` fails outright on a missing
    directory — and since /loot is a bind mount, making it on the host makes it exist in
    the container too, with no need to exec anything first.
    """
    host_dir(name).mkdir(parents=True, exist_ok=True)
    return container_dir(name)


def workdir_for(mode: str, engagement_id: str | None) -> str | None:
    """The working directory a run should use, or None to keep the image default.

    None is returned for LAB mode on purpose — see the module docstring. Callers must
    treat None as "add no -w flag", NOT as "use /loot".
    """
    if mode == "engagement" and engagement_id:
        try:
            return ensure(engagement_id)
        except (LootError, OSError):
            # A loot directory is a convenience, never a gate. If it cannot be made, the
            # run still happens in the image's default directory rather than being
            # refused — losing an -oA file is a far smaller harm than dropping a command
            # the operator already approved.
            return None
    return None


def kali_workdir() -> str | None:
    """The working directory for a `:kali` shell command, or None on failure."""
    try:
        return ensure(KALI_DIRNAME)
    except (LootError, OSError):
        return None


def exec_flags(workdir: str | None) -> list[str]:
    """`docker exec` flags for a working directory — empty when there is none.

    Keeping this in one place means the lab path stays byte-identical to what it was
    before loot existed: no workdir, no flags, same argv.
    """
    return ["-w", workdir] if workdir else []


def describe() -> dict[str, object]:
    """What the UI needs to explain where files go."""
    return {
        "mount": LOOT_MOUNT,
        "host_root": str(LOOT_ROOT),
        "sandboxes_with_loot": [
            config.ENGAGE_SANDBOX_CONTAINER,
            config.KALI_OPEN_CONTAINER,
        ],
        "lab_sandbox_has_loot": False,
    }
