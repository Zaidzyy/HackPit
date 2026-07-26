"""Startup reconciliation — does the sandbox actually have the tools the catalog claims?

WHY THIS EXISTS
For months `backend/arsenal/tools.json` catalogued 73 tools while the sandbox image shipped
seven, and `orchestrator.py` told the model verbatim that gobuster and nikto were available.
Nothing in the system compared the two, so the planner proposed commands that could only
ever fail with "executable not found", and the failure looked like a bad plan rather than a
missing tool.

This module closes that loop the only way that stays closed: it asks the sandbox. At
startup it runs `command -v` for every name and alias in the catalog and records what
actually resolved. The answer drives two things:

  * the planner's prompt block excludes tools that are not installed, so the model cannot
    propose them in the first place (D7);
  * the UI can show the gap honestly instead of implying availability (D6).

It re-checks every time the image changes, which is the property that matters — this class
of bug comes back the moment a Dockerfile edit drops a package, and a check that only ran
once would not catch it.

DESIGN NOTES
* ONE probe, not one exec per tool. 73 tools would be 73 `docker exec` round trips; instead
  a single `sh -c` loop prints the names that resolve. It runs in whichever sandbox is up —
  all three share an image, so any of them answers for all of them.
* NON-FATAL, always. Docker being down is the normal state on a fresh boot, and the app must
  start regardless. An unavailable probe reports "unknown", never "missing" — claiming a
  tool is absent because Docker was not running would be worse than saying nothing.
* WINDOWS-ONLY TOOLS ARE NOT MISSING. PowerShell/.NET tooling cannot run on a Linux
  container by construction (D9), so it is reported as `windows_only` rather than counted
  as a gap the image should close.
* READ-ONLY. `command -v` resolves a name against PATH. This module runs nothing else and
  is not an execution path.
"""

from __future__ import annotations

import subprocess
import threading
import time
from typing import Any, Iterable

from . import config

# Probing runs one tiny shell loop; if the sandbox cannot answer in this long, something is
# wrong with Docker rather than with the catalog, and "unknown" is the honest answer.
PROBE_TIMEOUT_SECONDS = 30

# Catalog entries whose `platform` says they cannot run here. Kept as a constant so the
# arsenal loader and this module agree on the spelling.
WINDOWS_PLATFORM = "windows"


class Reconciliation:
    """The result of one probe, plus enough context to explain it in the UI."""

    def __init__(self) -> None:
        self.checked_at: str | None = None
        self.container: str | None = None
        self.available: bool = False        # did the probe itself succeed?
        self.detail: str = "not yet checked"
        self.present: set[str] = set()      # catalog tool NAMES that resolved
        self.missing: list[str] = []        # catalog tool NAMES that did not
        self.windows_only: list[str] = []   # cannot run here by construction (D9)

    def is_present(self, name: str) -> bool:
        """True when the tool resolved — or when we could not check.

        Unknown is treated as present ON PURPOSE. If Docker is down, filtering the
        planner's prompt block by an empty probe would strip every tool and produce a
        far stranger failure than letting the model propose something that turns out to
        be missing. Absence must be proven, not assumed.
        """
        if not self.available:
            return True
        return name in self.present

    def to_dict(self) -> dict[str, Any]:
        return {
            "checked_at": self.checked_at,
            "container": self.container,
            "available": self.available,
            "detail": self.detail,
            "present_count": len(self.present),
            "missing": list(self.missing),
            "windows_only": list(self.windows_only),
        }


_STATE = Reconciliation()
_LOCK = threading.Lock()


def _running_sandbox() -> str | None:
    """The first sandbox container that is up. All three share an image, so any will do."""
    for name in (
        config.SANDBOX_CONTAINER,
        config.ENGAGE_SANDBOX_CONTAINER,
        config.KALI_OPEN_CONTAINER,
    ):
        try:
            proc = subprocess.run(
                ["docker", "inspect", "-f", "{{.State.Running}}", name],
                capture_output=True,
                text=True,
                timeout=10.0,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return None
        if proc.returncode == 0 and proc.stdout.strip() == "true":
            return name
    return None


def _probe(container: str, candidates: Iterable[str]) -> set[str]:
    """Return the subset of `candidates` that resolve on PATH inside the container.

    One exec, one loop. Names are passed on stdin rather than interpolated into the shell
    command so a catalog entry can never inject shell syntax into the probe.
    """
    names = [n for n in candidates if n and not any(c.isspace() for c in n)]
    if not names:
        return set()
    script = 'while IFS= read -r n; do command -v "$n" >/dev/null 2>&1 && echo "$n"; done'
    # BYTES, not text=True. On Windows, text mode translates '\n' to '\r\n' on the way
    # into stdin, so every name would arrive as "nmap\r" and `command -v` would report
    # EVERY tool missing — a silent, total false negative that reads exactly like an empty
    # sandbox. Encoding here keeps the bytes on the wire exactly as written.
    proc = subprocess.run(
        ["docker", "exec", "-i", container, "sh", "-c", script],
        input=("\n".join(names) + "\n").encode("utf-8"),
        capture_output=True,
        timeout=PROBE_TIMEOUT_SECONDS,
    )
    out = proc.stdout.decode("utf-8", "replace")
    return {line.strip() for line in out.splitlines() if line.strip()}


def check(arsenal: Any = None) -> Reconciliation:
    """Probe the sandbox for every catalogued tool and cache the result.

    ``arsenal`` is the loaded catalog (arsenal.loader.Arsenal). Imported lazily by the
    caller rather than here so this module has no import-time dependency on the arsenal
    package — the cockpit must keep working with no catalog at all.
    """
    state = Reconciliation()
    state.checked_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    if arsenal is None or not getattr(arsenal, "tools", None):
        state.detail = "no tool catalog loaded — nothing to reconcile"
        with _LOCK:
            _STATE.__dict__.update(state.__dict__)
        return state

    container = _running_sandbox()
    if container is None:
        state.detail = (
            "no sandbox container running — tool availability unknown. Bring the stack up "
            "(docker compose -f docker/docker-compose.yml up -d) and re-check."
        )
        with _LOCK:
            _STATE.__dict__.update(state.__dict__)
        return state
    state.container = container

    linux_tools = []
    for tool in arsenal.tools:
        if (getattr(tool, "platform", "") or "").lower() == WINDOWS_PLATFORM:
            state.windows_only.append(tool.name)
        else:
            linux_tools.append(tool)

    # Probe names AND aliases: a tool counts as present when any of the names it is known
    # by resolves. testssl.sh, certipy and bloodyAD all install under a different binary
    # name than the catalog uses, and treating those as missing would be plain wrong.
    candidates: set[str] = set()
    for tool in linux_tools:
        candidates.update(tool.names())

    try:
        resolved = _probe(container, sorted(candidates))
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        state.detail = f"probe failed ({exc}) — tool availability unknown"
        with _LOCK:
            _STATE.__dict__.update(state.__dict__)
        return state

    state.available = True
    for tool in linux_tools:
        if any(n in resolved for n in tool.names()):
            state.present.add(tool.name)
        else:
            state.missing.append(tool.name)

    state.detail = (
        f"{len(state.present)}/{len(linux_tools)} catalogued Linux tools present in "
        f"{container}"
        + (f"; {len(state.windows_only)} Windows-only entries not applicable" if state.windows_only else "")
    )
    with _LOCK:
        _STATE.__dict__.update(state.__dict__)
    return state


def windows_target_view(arsenal: Any, host: str) -> dict[str, Any]:
    """Tool availability reconciled for a WINDOWS target instead of the Linux sandbox.

    Windows-only tools (Rubeus/PowerView/Mimikatz/winPEAS) DO run on a selected Windows box,
    so they report runnable; the Linux tools are N/A for this target. Availability is per
    ACTIVE TARGET — never a global flip: the Linux :func:`check` view is untouched. Computed
    from the catalog's ``platform`` field (the same split :func:`check` uses), not a remote
    probe. Pure: ``arsenal`` is an opaque catalog object, so this stays reconcile's job while
    the cockpit gate modules stay catalog-blind.
    """
    windows_tools, linux_tools = [], []
    for tool in getattr(arsenal, "tools", []) or []:
        if (getattr(tool, "platform", "") or "").lower() == WINDOWS_PLATFORM:
            windows_tools.append(tool.name)
        else:
            linux_tools.append(tool.name)
    return {
        "target_kind": "windows",
        "target": host,
        "available": True,
        "detail": f"{len(windows_tools)} Windows tools runnable on {host}; "
        f"{len(linux_tools)} Linux-only tools N/A for a Windows target",
        "runnable": sorted(windows_tools),
        "not_applicable": sorted(linux_tools),
        "present_count": len(windows_tools),
    }


def current() -> Reconciliation:
    """The cached result. Safe before any check has run (reports 'not yet checked')."""
    with _LOCK:
        return _STATE


def check_in_background(arsenal: Any = None) -> None:
    """Run the probe off the startup path.

    App start must never block on Docker: the probe shells out several times and Docker
    Desktop can take tens of seconds to become responsive after a boot. Failures are
    swallowed — an unreconciled catalog degrades to "unknown", which every consumer of
    this module already handles.
    """

    def _run() -> None:
        try:
            check(arsenal)
        except Exception:  # pragma: no cover - never load-bearing
            pass

    threading.Thread(target=_run, name="tool-reconcile", daemon=True).start()
