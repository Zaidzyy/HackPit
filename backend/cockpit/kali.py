""":kali — the human-only interactive shell INTO the isolated sandbox.

This is the ONE feature that runs arbitrary commands. Unlike the allowlisted cockpit
executor (argv, no shell, recon-only), :kali intentionally runs ``sh -c "<command>"``
so a human operator gets pipes, redirects and their full toolkit — "command injection"
is the point, because the human typing *is* the operator. That is safe ONLY because of
the containment model below; it is NOT made safe by input filtering (there is none, on
purpose — do not add fake sanitisation that pretends arbitrary shell is "safe").

THE CONTAINMENT MODEL (all of these must hold — this is the whole safety story):

1. HARDCODED TARGET CONTAINER. Every exec is
       docker exec <SANDBOX_CONTAINER> sh -c "<command>"
   with the container name taken from ``config.SANDBOX_CONTAINER`` — a code constant,
   NEVER a field in the request. There is no input that can redirect the exec to the
   host, to another container, or to any other target. This is rule #1: the shell can
   only ever reach into that one isolated box. (Regression-locked in test_kali.py.)

2. EGRESS-LESS + HARDENED + DISPOSABLE SANDBOX (M1). The sandbox sits on an
   ``internal: true`` Docker network (no route to host/internet), with cap_drop ALL and
   no-new-privileges, and resets via ``docker compose down -v``. So arbitrary commands
   are contained: ``curl evil.com`` simply fails.

3. ISOLATION RE-CHECKED BEFORE EVERY EXEC. We call the M1 gate
   ``assert_isolation_proven`` on every run; if the sandbox is ever attached to a
   non-internal (egress) network, the shell REFUSES to run. :kali drops M1's other
   gates (allowlist / target-lock / per-command approval — a human typing is the
   approval) but isolation is NEVER dropped.

4. HUMAN-ONLY. This module is driven by a person at a terminal. The orchestrator /
   autonomous agent MUST NEVER be wired to it — there is deliberately no code path from
   the agent/executor to ``run_kali`` (an autonomous agent + an arbitrary shell = the
   RCE nightmare). Keep them physically separate: nothing in the agent/exec path imports
   this module.

5. AUDIT + LIMITS. Every command + its output is recorded to the engagement session
   (reusing the M1 run store), with a per-command timeout and an output-size cap so a
   command can neither hang nor flood.

6. LOCAL-ONLY. This is a localhost dev tool with NO auth. If the app is ever exposed or
   deployed, this endpoint MUST get authentication first — otherwise it is an open
   shell-into-the-sandbox for anyone who can reach it (still contained to the disposable
   lab, but not something to expose). See the matching note on the route in router.py.
"""

from __future__ import annotations

import subprocess
import uuid
from datetime import datetime, timezone

from pydantic import BaseModel, Field

from . import config, runstore
from .models import RunRecord
from .sandbox import assert_isolation_proven  # re-exported for tests to monkeypatch

# Per-command hard ceilings. A free shell must neither hang nor flood the audit log.
KALI_TIMEOUT_SECONDS = 60
# Cap EACH stream; a runaway `yes` or huge dump gets truncated (marked in the record).
KALI_OUTPUT_CAP = 200_000  # chars per stream


class KaliRequest(BaseModel):
    """A request to run ONE arbitrary shell command inside the sandbox.

    NOTE — deliberately there is NO container / target / host field. The container is a
    code constant (config.SANDBOX_CONTAINER); nothing in this request can redirect the
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
    """Raised when the isolation gate refuses the run (nothing was executed)."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _cap(text: str) -> tuple[str, bool]:
    """Truncate a stream to the output cap; return (text, truncated?)."""
    if len(text) > KALI_OUTPUT_CAP:
        return text[:KALI_OUTPUT_CAP] + "\n…[output truncated]…", True
    return text, False


def run_kali(request: KaliRequest) -> KaliResult:
    """Run one arbitrary shell command inside the sandbox and capture its result.

    Isolation is re-checked FIRST — if the sandbox is not provably isolated, this raises
    ``KaliRefused`` and NOTHING runs. Otherwise the command runs as
    ``docker exec <SANDBOX_CONTAINER> sh -c "<command>"`` (container hardcoded) with a
    hard timeout and an output cap, and the run is recorded to the engagement session.
    """
    # Gate: the sandbox must be provably isolated (internal-only networks). This is the
    # one M1 gate :kali keeps. It is re-checked on EVERY exec, before anything runs.
    try:
        assert_isolation_proven()
    except Exception as exc:  # SandboxError (or any inspect failure) => refuse to run
        raise KaliRefused(str(exc)) from exc

    run_id = uuid.uuid4().hex[:12]
    started_at = _now()

    # The container is a CONSTANT, never from the request. `sh -c` is intentional: the
    # human operator gets a full shell inside the contained box.
    argv = ["docker", "exec", config.SANDBOX_CONTAINER, "sh", "-c", request.command]

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
    # about what actually ran. target = the sandbox itself (the box the shell reached).
    record = RunRecord(
        run_id=run_id,
        command="sh -c",
        args=[request.command],
        target=config.SANDBOX_CONTAINER,
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
        container=config.SANDBOX_CONTAINER,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        started_at=started_at,
        finished_at=finished_at,
        timed_out=timed_out,
        truncated=t1 or t2,
        session_id=request.session_id,
    )
