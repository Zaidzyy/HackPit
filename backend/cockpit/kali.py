""":kali — the human-only interactive shell with FULL NETWORK REACH.

This is the ONE feature that runs arbitrary commands. It runs ``sh -c "<command>"`` inside
a SEPARATE, intentionally NON-isolated sandbox (``hackpit-kali-open``) that has NAT egress
— it reaches the internet, the host, and the LAN. That is Zaid's informed decision. It is
NOT made safe by input filtering (there is none, on purpose — do not add fake sanitisation
that pretends arbitrary shell is "safe").

WHY THIS DOESN'T TOUCH THE COCKPIT'S SAFETY NET:
The cockpit executor + the future autonomous agent exec into a DIFFERENT container,
``config.SANDBOX_CONTAINER`` (``hackpit-kali-sandbox``), which stays egress-less
(``internal: true``) and behind all four gates — including ``assert_isolation_proven``.
:kali uses its own ``config.KALI_OPEN_CONTAINER`` and does NOT run the isolation gate
(it is intentionally not isolated). The two never mix.

WHAT STILL HOLDS FOR :kali (the containment that remains):

1. HARDCODED TARGET CONTAINER. Every exec is
       docker exec <KALI_OPEN_CONTAINER> sh -c "<command>"
   with the container name taken from ``config.KALI_OPEN_CONTAINER`` — a code constant,
   NEVER a field in the request. No input can redirect the exec to another container.
   (Regression-locked in test_kali.py.)

2. HUMAN-ONLY — the rule that matters MOST now. :kali is a full-reach shell, so an
   autonomous agent wired to it = autonomous attacks on the host, the LAN and the
   internet. The orchestrator / agent / executor MUST have ZERO code path to
   ``run_kali``; nothing in that path imports this module. (Regression-locked by
   test_kali_is_human_only, which scans the source tree.)

3. DISPOSABLE + HARDENED. The open sandbox still runs cap_drop ALL + no-new-privileges
   and resets via ``docker compose down -v``.

4. AUDIT + LIMITS. Every command + output is recorded to the engagement session (reuses
   the M1 run store), with a per-command timeout and an output-size cap.

5. LOCAL-ONLY, AUTH REQUIRED BEFORE EXPOSURE — now far more load-bearing. An exposed
   :kali endpoint reaches your HOST and LAN, not just a disposable lab. It has NO auth;
   if this app is ever exposed or deployed, this endpoint MUST be put behind
   authentication first. See the matching note on the route in router.py.
"""

from __future__ import annotations

import subprocess
import uuid
from datetime import datetime, timezone

from pydantic import BaseModel, Field

from . import config, runstore
from .models import RunRecord

# Per-command hard ceilings. A free shell must neither hang nor flood the audit log.
KALI_TIMEOUT_SECONDS = 60
# Cap EACH stream; a runaway `yes` or huge dump gets truncated (marked in the record).
KALI_OUTPUT_CAP = 200_000  # chars per stream


class KaliRequest(BaseModel):
    """A request to run ONE arbitrary shell command inside the open sandbox.

    NOTE — deliberately there is NO container / target / host field. The container is a
    code constant (config.KALI_OPEN_CONTAINER); nothing in this request can redirect the
    exec anywhere else. Adding such a field would break containment rule #1.
    """

    command: str = Field(..., min_length=1, description="Shell command to run via `sh -c`.")
    session_id: str | None = Field(
        None, description="Optional engagement to record this run against."
    )


class KaliResult(BaseModel):
    """The captured result of one shell run (also persisted to the run store)."""

    run_id: str
    command: str
    container: str
    exit_code: int | None
    stdout: str
    stderr: str
    started_at: str
    finished_at: str
    timed_out: bool = False
    truncated: bool = False
    session_id: str | None = None


class KaliRefused(RuntimeError):
    """Raised when the open sandbox isn't available (nothing was executed).

    NOTE: this is an AVAILABILITY check (is the container running?), NOT an isolation
    gate — :kali is intentionally not isolated. The cockpit executor keeps the real
    isolation gate; :kali does not.
    """


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _container_running(name: str) -> bool:
    """True iff the named container exists and is running (availability only)."""
    try:
        p = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", name],
            capture_output=True,
            text=True,
            timeout=10.0,
        )
        return p.returncode == 0 and p.stdout.strip() == "true"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _cap(text: str) -> tuple[str, bool]:
    """Truncate a stream to the output cap; return (text, truncated?)."""
    if len(text) > KALI_OUTPUT_CAP:
        return text[:KALI_OUTPUT_CAP] + "\n…[output truncated]…", True
    return text, False


def run_kali(request: KaliRequest) -> KaliResult:
    """Run one arbitrary shell command inside the OPEN sandbox and capture its result.

    :kali is intentionally NOT isolated, so there is NO ``assert_isolation_proven`` gate
    here (that gate lives on the cockpit executor's isolated sandbox and would correctly
    refuse every full-reach command). The only pre-check is availability: if the open
    container isn't running, this raises ``KaliRefused`` and nothing runs. Otherwise the
    command runs as ``docker exec <KALI_OPEN_CONTAINER> sh -c "<command>"`` (container
    hardcoded) with a hard timeout and an output cap, and the run is recorded.
    """
    # Availability (NOT isolation): refuse cleanly if the open sandbox isn't up.
    if not _container_running(config.KALI_OPEN_CONTAINER):
        raise KaliRefused(
            f"open sandbox '{config.KALI_OPEN_CONTAINER}' is not running — bring the "
            "stack up (docker compose -f docker/docker-compose.yml up -d)"
        )

    run_id = uuid.uuid4().hex[:12]
    started_at = _now()

    # The container is a CONSTANT, never from the request. `sh -c` is intentional: the
    # human operator gets a full shell — here, one with full network reach.
    argv = ["docker", "exec", config.KALI_OPEN_CONTAINER, "sh", "-c", request.command]

    timed_out = False
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=KALI_TIMEOUT_SECONDS,
        )
        stdout, stderr, exit_code = proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        stdout = exc.stdout or ""
        stderr = (exc.stderr or "") + f"\n[killed: exceeded {KALI_TIMEOUT_SECONDS}s timeout]"
        exit_code = None
    except FileNotFoundError:
        stdout, stderr, exit_code = "", "docker CLI not found on PATH", 127

    stdout, t1 = _cap(stdout)
    stderr, t2 = _cap(stderr)
    finished_at = _now()

    # Audit: record every run to the engagement session (reusing the M1 run store). The
    # command line is stored as the args of a `sh -c` invocation so the log is honest
    # about what actually ran. target = the open sandbox (the box the shell reached).
    record = RunRecord(
        run_id=run_id,
        command="sh -c",
        args=[request.command],
        target=config.KALI_OPEN_CONTAINER,
        approved=True,  # a human typing the command IS the approval
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        started_at=started_at,
        finished_at=finished_at,
        session_id=request.session_id,
        step_id=None,
    )
    try:
        runstore.save_run(record)
    except Exception:  # persistence must never crash the response
        pass

    return KaliResult(
        run_id=run_id,
        command=request.command,
        container=config.KALI_OPEN_CONTAINER,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        started_at=started_at,
        finished_at=finished_at,
        timed_out=timed_out,
        truncated=t1 or t2,
        session_id=request.session_id,
    )


def kali_status() -> dict:
    """Availability of the :kali OPEN sandbox — drives the UI banner.

    Reports whether the open container is up. It makes NO isolation claim (there is none):
    the banner must say 'full network reach · NOT isolated', never 'isolated'.
    """
    up = _container_running(config.KALI_OPEN_CONTAINER)
    return {
        "container": config.KALI_OPEN_CONTAINER,
        "isolated": False,  # intentionally — :kali has full network reach
        "up": up,
        "ready": up,
        "detail": "" if up else "open sandbox container is not running",
    }
