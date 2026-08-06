"""Credential-attack JOBS — the execution half of the spray/crack surface.

*** WHERE THE EXECUTION LIVES, AND WHY IT IS NOT IN credattack.py. ***
`credattack.py` is the PURE planner: it builds argv and parses text and is regression-locked
to execute nothing (it runs after a job, without an approval of its own — the same position
`state/` sits in). THIS module is the worker: it validates through the executor's gate, writes
the secret-bearing lists to the sandbox's loot directory, spawns ONE `docker exec` per job, and
turns the output back into state. It is the intruder pattern applied to a long-running process
rather than a request loop:

  * ONE APPROVAL BUYS THE WHOLE JOB. A spray of 300 accounts is one human approval, gated by
    the SAME executor gates every command clears — no batch approval, no per-attempt gate, no
    new gate. `validate_request` runs BEFORE anything spawns.
  * THE STOP IS UNGATED. `stop()` sets an event and kills the process — the panic switch, like
    `stop_scan` and the intruder's stop. A gate that could refuse to stop a live spray would
    make the system less safe.
  * ENGAGEMENT-BOUND. A spray/crack needs the OPEN, loot-mounted engagement sandbox — the
    secret lists are written to `/loot/<engagement>` and cracking reads the image's wordlists
    there. No active engagement → refused (an availability precondition, never a bypass): the
    isolated lab sandbox has no loot mount and no reach to a real target.
  * SECRETS TO FILES, NEVER ARGV. Users, passwords and hashes are written to loot files; the
    argv references only their paths. The persisted `RunRecord` (which `report.py` renders
    verbatim) therefore carries no secret.
"""

from __future__ import annotations

import subprocess
import threading
import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from state import store as state_store

from . import config, credattack, engagement, loot, repeater as repeater_mod, runstore, secretargs
from .models import RunRecord

# Output markers that mean an account was locked out — the operator's `stop_on_lockouts` knob
# watches for these and stops the job before it locks more.
_LOCKOUT_MARKERS = ("STATUS_ACCOUNT_LOCKED", "account has been locked", "ACCOUNT_LOCKED_OUT")
#: Per-job output kept, in chars — a spray/crack transcript, not a data feed.
_OUTPUT_CAP = 400_000


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------- #
# models
# --------------------------------------------------------------------------- #
class CredHit(BaseModel):
    """One recovered credential surfaced to the UI. NO SECRET — the vault masks; a job feed
    that streamed plaintext would put it on screen and in a screenshot."""

    principal: str
    domain: str = ""
    target: str = ""
    admin: bool = False
    note: str = ""


class CredJob(BaseModel):
    """One spray/crack job. Counts are what HAPPENED, never what was planned."""

    id: str
    kind: str = Field(description="spray | crack")
    state: str = Field("running", description="running | finished | stopped | refused")
    argv: list[str] = Field(default_factory=list, description="The approved command line (no secret).")
    target: str = ""
    container: str = ""
    engagement_id: str | None = None
    session_id: str | None = None
    started_at: str = ""
    finished_at: str = ""
    attempts: int = Field(0, description="Login attempts observed (spray) / hashes fed (crack).")
    lockouts: int = Field(0, description="Account-lockout signals seen. Drives stop_on_lockouts.")
    hits: list[CredHit] = Field(default_factory=list, description="Recovered credentials.")
    new_credentials: int = 0
    new_findings: int = 0
    owned: list[str] = Field(default_factory=list, description="AD nodes marked owned by this job.")
    output_tail: str = Field("", description="The last lines of transcript, for the live view.")
    warnings: list[str] = Field(default_factory=list)
    refused: str = Field("", description="Set when a gate refused the job — the reason.")
    refused_gate: str = ""


class CredRefused(RuntimeError):
    """Refused BEFORE anything ran. Carries the gate that refused it."""

    def __init__(self, gate: str, reason: str, dangerous_flags: list[str] | None = None) -> None:
        super().__init__(reason)
        self.gate = gate
        self.reason = reason
        self.dangerous_flags = dangerous_flags or []


# --------------------------------------------------------------------------- #
# registry — stop is a flag, and setting it is ungated
# --------------------------------------------------------------------------- #
_jobs: dict[str, CredJob] = {}
_stops: dict[str, threading.Event] = {}
_procs: dict[str, subprocess.Popen] = {}
_lock = threading.Lock()


def get(job_id: str) -> CredJob | None:
    with _lock:
        return _jobs.get(job_id)


def list_jobs(session_id: str | None = None) -> list[CredJob]:
    with _lock:
        jobs = list(_jobs.values())
    if session_id:
        jobs = [j for j in jobs if j.session_id == session_id]
    return sorted(jobs, key=lambda j: j.started_at, reverse=True)


def stop(job_id: str) -> CredJob | None:
    """Stop an in-flight job. NOT GATED — the panic button, like `stop_scan` and the intruder's
    stop. Sets the event and kills the process; whichever the worker notices first ends it."""
    with _lock:
        ev = _stops.get(job_id)
        proc = _procs.get(job_id)
        job = _jobs.get(job_id)
    if ev is not None:
        ev.set()
    if proc is not None and proc.poll() is None:
        try:
            proc.kill()
        except Exception:  # noqa: BLE001 - a dead process is already stopped
            pass
    return job


def status() -> dict[str, Any]:
    """Availability of the engagement sandbox + how many jobs are live — drives the UI banner."""
    up = repeater_mod._container_running(config.ENGAGE_SANDBOX_CONTAINER)
    with _lock:
        running = sum(1 for j in _jobs.values() if j.state == "running")
    return {
        "container": config.ENGAGE_SANDBOX_CONTAINER,
        "up": up, "ready": up, "running": running,
        "detail": "" if up else "engagement sandbox is not running",
    }


# --------------------------------------------------------------------------- #
# shared preconditions
# --------------------------------------------------------------------------- #
def _require_engagement(engagement_id: str | None) -> str:
    """The active engagement's loot dir (container path), or refuse. Credattack jobs are
    engagement-bound: the open, loot-mounted sandbox is where the secret lists live and where a
    real target is reachable."""
    if not engagement_id or engagement.get_active(engagement_id) is None:
        raise CredRefused(
            "engagement",
            "credential attacks run in an active engagement — enter engagement mode first "
            "(POST /cockpit/engagement/enter). The isolated lab sandbox has no loot mount.",
        )
    if not repeater_mod._container_running(config.ENGAGE_SANDBOX_CONTAINER):
        raise CredRefused(
            "unavailable",
            f"engagement sandbox '{config.ENGAGE_SANDBOX_CONTAINER}' is not running — nothing ran",
        )
    try:
        return loot.ensure(engagement_id)
    except loot.LootError as exc:
        raise CredRefused("loot", f"could not prepare a loot directory: {exc}")


def _write_loot(engagement_id: str, name: str, lines: list[str]) -> tuple[str, str]:
    """Write a secret-bearing list to the engagement loot dir. Returns (container_path, host_path).
    Files land beside the run's other artefacts and are referenced by path, never inlined."""
    host_dir = loot.host_dir(engagement_id)
    host_dir.mkdir(parents=True, exist_ok=True)
    host_path = host_dir / name
    host_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return f"{loot.container_dir(engagement_id)}/{name}", str(host_path)


# --------------------------------------------------------------------------- #
# spray
# --------------------------------------------------------------------------- #
def start_spray(req: credattack.SprayRequest) -> CredJob:
    """Validate, write the lists, and run ONE spray in the background. GATE BEFORE ANYTHING RUNS."""
    workdir = _require_engagement(req.engagement_id)
    users = [u.strip() for u in req.usernames if u.strip()]
    passwords = [p for p in req.passwords if p]
    if not users or not passwords:
        raise CredRefused("input", "a spray needs at least one username and one password")

    job_id = uuid.uuid4().hex[:12]
    users_c, _ = _write_loot(req.engagement_id or "", f"credattack-{job_id}-users.txt", users)
    pass_c, _ = _write_loot(req.engagement_id or "", f"credattack-{job_id}-pass.txt", passwords)
    argv, warnings = credattack.spray_argv(req, users_path=users_c, pass_path=pass_c)
    if not argv:
        raise CredRefused("input", "; ".join(warnings) or "no spray command could be built")

    exec_req = credattack.spray_exec_request(req, users_path=users_c, pass_path=pass_c)
    rejected = _gate(exec_req)
    if rejected is not None:
        raise CredRefused(rejected.gate, rejected.reason, list(rejected.dangerous_flags or []))

    job = CredJob(
        id=job_id, kind="spray", argv=argv, target=req.target,
        container=config.ENGAGE_SANDBOX_CONTAINER, engagement_id=req.engagement_id,
        session_id=req.session_id or req.engagement_id, started_at=_now(),
        attempts=len(users) * len(passwords), warnings=warnings,
    )
    _register(job)
    threading.Thread(target=_run, args=(job_id, argv, workdir, req, "spray"),
                     daemon=True, name=f"cred-spray-{job_id}").start()
    return job


# --------------------------------------------------------------------------- #
# crack
# --------------------------------------------------------------------------- #
def start_crack(req: credattack.CrackRequest) -> CredJob:
    """Validate, write the hashes, and run hashcat (one invocation per mode). GATE FIRST."""
    workdir = _require_engagement(req.engagement_id)
    session_id = req.session_id or req.engagement_id or ""
    creds = state_store.load(session_id).credentials
    plan = credattack.plan_crack(req, creds)
    if not plan.crack:
        raise CredRefused("input", "; ".join(plan.warnings) or "no crackable hashes in state")

    exec_req = credattack.crack_exec_request(
        req, hash_path=f"{workdir}/preview.txt", mode=plan.crack[0].mode
    )
    rejected = _gate(exec_req)
    if rejected is not None:
        raise CredRefused(rejected.gate, rejected.reason, list(rejected.dangerous_flags or []))

    job_id = uuid.uuid4().hex[:12]
    by_principal = {c.principal.strip().lower(): c for c in creds}
    argvs: list[list[str]] = []
    total_hashes = 0
    for grp in plan.crack:
        lines: list[str] = []
        for principal in grp.principals:
            c = by_principal.get(principal.strip().lower())
            if c and (c.secret or "").strip():
                lines.append(c.secret.strip())
        if not lines:
            continue
        hash_c, _ = _write_loot(
            req.engagement_id or "", f"credattack-{job_id}-m{grp.mode}.txt", lines
        )
        argvs.append(credattack.crack_argv(req, hash_path=hash_c, mode=grp.mode))
        total_hashes += len(lines)

    job = CredJob(
        id=job_id, kind="crack", argv=argvs[0] if argvs else [], target=req.wordlist,
        container=config.ENGAGE_SANDBOX_CONTAINER, engagement_id=req.engagement_id,
        session_id=session_id, started_at=_now(), attempts=total_hashes, warnings=plan.warnings,
    )
    _register(job)
    threading.Thread(target=_run_crack, args=(job_id, argvs, workdir, req, session_id, list(creds)),
                     daemon=True, name=f"cred-crack-{job_id}").start()
    return job


# --------------------------------------------------------------------------- #
# the gate + registry helpers
# --------------------------------------------------------------------------- #
def _gate(exec_req):
    """The executor's gate verdict — the SAME gates every command clears, nothing added."""
    from . import executor

    return executor.validate_request(exec_req)


def _register(job: CredJob) -> None:
    with _lock:
        _jobs[job.id] = job
        _stops[job.id] = threading.Event()


def _docker_argv(container: str, workdir: str, argv: list[str]) -> list[str]:
    return ["docker", "exec", *loot.exec_flags(workdir), container, *argv]


def _drain(job_id: str, proc: subprocess.Popen, req_stop_on: int) -> str:
    """Stream one process's merged output into the job; honour stop + stop_on_lockouts. Returns
    the full captured text. Never raises."""
    chunks: list[str] = []
    total = 0
    lockouts = 0
    stop_ev = _stops.get(job_id) or threading.Event()
    assert proc.stdout is not None
    for raw in iter(proc.stdout.readline, ""):
        if stop_ev.is_set():
            break
        line = raw.rstrip("\n")
        if total < _OUTPUT_CAP:
            chunks.append(raw)
            total += len(raw)
        lock = any(m in line for m in _LOCKOUT_MARKERS)
        with _lock:
            j = _jobs.get(job_id)
            if j is not None:
                if lock:
                    j.lockouts += 1
                j.output_tail = "".join(chunks[-40:])[-4000:]
                lockouts = j.lockouts
        if req_stop_on and lock and lockouts >= req_stop_on:
            with _lock:
                j = _jobs.get(job_id)
                if j is not None:
                    j.warnings.append(
                        f"stopped after {lockouts} lockout(s) — the stop_on_lockouts threshold"
                    )
            stop_ev.set()
            try:
                proc.kill()
            except Exception:  # noqa: BLE001
                pass
            break
    try:
        proc.stdout.close()
    except Exception:  # noqa: BLE001
        pass
    return "".join(chunks)


def _spawn(job_id: str, argv: list[str], workdir: str, timeout: int, stop_on: int) -> str:
    """Run one `docker exec` to completion (or until stop/timeout), capturing output. Never
    raises — a transport failure becomes a note in the transcript."""
    container = config.ENGAGE_SANDBOX_CONTAINER
    full = _docker_argv(container, workdir, argv)
    try:
        proc = subprocess.Popen(
            full, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
        )
    except FileNotFoundError:
        return "[credattack] docker CLI not found on PATH\n"
    except Exception as exc:  # noqa: BLE001
        return f"[credattack] could not start: {exc}\n"
    with _lock:
        _procs[job_id] = proc

    timed = {"v": False}

    def _watchdog() -> None:
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed["v"] = True
            try:
                proc.kill()
            except Exception:  # noqa: BLE001
                pass

    wd = threading.Thread(target=_watchdog, daemon=True)
    wd.start()
    text = _drain(job_id, proc, stop_on)
    proc.wait()
    if timed["v"]:
        text += f"\n[credattack] timed out after {timeout}s\n"
    return text


def _run(job_id: str, argv: list[str], workdir: str, req: credattack.SprayRequest, kind: str) -> None:
    """Spray worker: run the process, then correlate its output back into state. Never raises."""
    timeout = config.clamp_timeout(None) * 3  # a spray of many accounts outlasts a single command
    text = _spawn(job_id, argv, workdir, timeout, req.stop_on_lockouts)
    session_id = req.session_id or req.engagement_id or ""
    run_id = job_id
    try:
        creds, findings = credattack.correlate_spray(req, text, session_id, run_id)
    except Exception:  # noqa: BLE001 - correlation must never lose the run
        creds, findings = [], []
    _finish(job_id, kind, text, session_id, run_id, creds, findings,
            command="netexec", args=argv[1:] if argv else [])


def _run_crack(job_id: str, argvs: list[list[str]], workdir: str, req: credattack.CrackRequest,
               session_id: str, before: list) -> None:
    """Crack worker: run hashcat once per mode, then correlate the cracked lines to accounts."""
    timeout = config.clamp_timeout(None) * 6  # cracking a wordlist can run long
    texts: list[str] = []
    for argv in argvs:
        stop_ev = _stops.get(job_id)
        if stop_ev is not None and stop_ev.is_set():
            break
        texts.append(_spawn(job_id, argv, workdir, timeout, 0))
    text = "\n".join(texts)
    run_id = job_id
    try:
        creds, findings = credattack.correlate_crack(text, before, session_id, run_id)
    except Exception:  # noqa: BLE001
        creds, findings = [], []
    _finish(job_id, "crack", text, session_id, run_id, creds, findings,
            command="hashcat", args=argvs[0][1:] if argvs else [])


def _finish(job_id: str, kind: str, text: str, session_id: str, run_id: str,
            creds: list, findings: list, *, command: str, args: list[str]) -> None:
    """Persist the recovered state, light the AD graph, and close the job out. Never raises."""
    new_creds = new_finds = 0
    owned: list[str] = []
    if session_id:
        try:
            new_creds = state_store.upsert_credentials(creds)
            new_finds = state_store.upsert_findings(findings)
        except Exception:  # noqa: BLE001
            pass
        # LIGHT THE GRAPH: a fresh working credential marks its principal owned, opening new
        # frontier edges in :ad-graph. Best-effort — no graph, or no match, marks nothing.
        try:
            from adgraph import store as ad_store

            owned = ad_store.mark_owned(session_id, credattack.owned_from(creds))
        except Exception:  # noqa: BLE001
            owned = []

    hits = [
        CredHit(principal=c.principal, domain=c.domain, target=getattr(c, "target", "") or "",
                admin="Pwn3d" in (c.note or ""), note=c.note)
        for c in creds
    ]

    with _lock:
        job = _jobs.get(job_id)
        stopped = _stops.get(job_id)
        if job is not None:
            job.state = "stopped" if (stopped is not None and stopped.is_set()) else "finished"
            job.finished_at = _now()
            job.hits = hits
            job.new_credentials = new_creds
            job.new_findings = new_finds
            job.owned = owned
            job.output_tail = text[-4000:]
        _procs.pop(job_id, None)

    # ONE audit record for the whole job — it was one approval. Args reference files, never a
    # secret, and are redacted for uniformity with every other persisted run.
    try:
        runstore.save_run(RunRecord(
            run_id=run_id, command=command,
            args=secretargs.redact_argv(command, args),
            target=(job.target if job else ""), approved=True, mode="engagement",
            exit_code=0, stdout=text[-8000:], stderr="",
            started_at=(job.started_at if job else _now()), finished_at=_now(),
            session_id=session_id or None, step_id=None,
        ))
    except Exception:  # noqa: BLE001 - an audit failure must not lose the results
        pass


def reset() -> None:
    """Drop all job state. Tests only — never called by the app."""
    with _lock:
        _jobs.clear()
        _stops.clear()
        _procs.clear()
