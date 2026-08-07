"""JWT weak-secret CRACK — the one gated job of the token workbench.

*** WHY THIS IS ONE GATED JOB AND NOT PART OF THE PURE MODULE. ***
``cockpit/tokens.py`` is the PURE analysis/tamper core — it decodes, analyses and mutates tokens
and executes nothing, so the hermetic suite covers it against fixtures. Recovering a weak HMAC
secret is the one thing that must actually RUN a tool (``hashcat -m 16500`` over a wordlist), so
it lives here, in exactly the shape ``credjobs.py`` gives the spray/crack surface:

  * ONE APPROVAL BUYS THE WHOLE JOB. A dictionary run of millions of candidates is one human
    approval, gated by the SAME executor gates every command clears — no new gate. ``validate_
    request`` runs BEFORE anything spawns.
  * THE STOP IS UNGATED. ``stop()`` sets an event and kills the process — the panic switch, like
    every other stop in this codebase.
  * ENGAGEMENT-BOUND. A crack needs the OPEN, loot-mounted engagement sandbox: the token is
    written to ``/loot/<engagement>`` and the recovered secret is written back there. A crack
    names no host, so in the isolated lab it is refused (there is no loot mount and no engagement).
  * THE SECRET GOES TO LOOT, NEVER AN ARGV OR A FINDING. The token is written to a loot file; the
    argv references only its path. The recovered secret is written to a loot file too, and the
    Finding says a weak key was recovered without carrying the key — the persisted ``RunRecord``
    (which ``report.py`` renders verbatim) therefore holds no secret.
"""

from __future__ import annotations

import subprocess
import threading
import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from state.models import Finding

from . import config, engagement, loot, repeater as repeater_mod, runstore, tokens
from .models import RunRecord

#: Per-job output kept, in chars — a crack transcript, not a data feed.
_OUTPUT_CAP = 200_000


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------- #
# models
# --------------------------------------------------------------------------- #
class TokenCrackRequest(BaseModel):
    """One JWT weak-secret crack: a token, a wordlist, and the approval fields the gate reads."""

    token: str = Field(..., min_length=1, description="The JWT to crack (HS* alg). Written to a "
                       "loot file, never the argv.")
    wordlist: str = Field(
        "/usr/share/wordlists/rockyou.txt", min_length=1,
        description="Wordlist path inside the sandbox (operator input).")
    rule: str = Field("", description="Optional hashcat rule file path.")
    engagement_id: str | None = None
    session_id: str | None = None
    approved: bool = Field(False, description="Explicit human approval. Never defaulted true.")
    dangerous_ack: bool = Field(
        False, description="The red-confirm, WHEN THE GATE ASKS FOR IT — not demanded here.")


class TokenCrackJob(BaseModel):
    """One crack job. Counts are what HAPPENED, never what was planned. NO secret is carried."""

    id: str
    state: str = Field("running", description="running | finished | stopped | refused")
    argv: list[str] = Field(default_factory=list, description="The approved command line (no secret).")
    alg: str = ""
    container: str = ""
    engagement_id: str | None = None
    session_id: str | None = None
    started_at: str = ""
    finished_at: str = ""
    cracked: bool = Field(False, description="Was a secret recovered? The secret itself is in loot.")
    secret_len: int = Field(0, description="Length of the recovered secret — never the secret.")
    new_findings: int = 0
    loot_path: str = Field("", description="Where the recovered secret was written (host path).")
    output_tail: str = Field("", description="The last lines of transcript, for the live view.")
    warnings: list[str] = Field(default_factory=list)
    refused: str = Field("", description="Set when a gate refused the job — the reason.")
    refused_gate: str = ""


class TokenCrackRefused(RuntimeError):
    """Refused BEFORE anything ran. Carries the gate that refused it."""

    def __init__(self, gate: str, reason: str, dangerous_flags: list[str] | None = None) -> None:
        super().__init__(reason)
        self.gate = gate
        self.reason = reason
        self.dangerous_flags = dangerous_flags or []


# --------------------------------------------------------------------------- #
# argv + gate — PURE builders (the worker writes the files)
# --------------------------------------------------------------------------- #
def crack_argv(req: TokenCrackRequest, *, token_path: str) -> list[str]:
    """``hashcat -a 0 -m 16500`` (JWT) with the token in a FILE. Only its path is on the argv.

    ``--quiet`` so the cracked ``token:secret`` line is not buried under the status screen, and
    ``--potfile-disable`` so a stale pot from a previous job does not make a fresh crack look
    instant-and-empty."""
    argv = ["hashcat", "-a", "0", "-m", "16500", "--quiet", "--potfile-disable",
            token_path, req.wordlist]
    if (req.rule or "").strip():
        argv += ["-r", req.rule.strip()]
    return argv


def crack_exec_request(req: TokenCrackRequest, *, token_path: str):
    """The ``ExecRequest`` a crack is EQUIVALENT TO, for the gate. Lazy-imports the executor so
    this stays a pure builder even though the worker below runs things."""
    from .models import ExecRequest

    argv = crack_argv(req, token_path=token_path)
    return ExecRequest(
        command=argv[0], args=argv[1:], approved=req.approved, dangerous_ack=req.dangerous_ack,
        engagement_id=req.engagement_id, session_id=req.session_id,
    )


def validate(req: TokenCrackRequest):
    """The gate verdict for a crack, running nothing. A crack names no host, so it is an
    engagement-mode target-less command (allowed) — and refused in lab mode, which is why the
    UI asks for an engagement. Returns None when it passes."""
    from . import executor

    sid = (req.session_id or req.engagement_id or "session").strip() or "session"
    return executor.validate_request(
        crack_exec_request(req, token_path=f"/loot/{sid}/token-preview.txt"))


# --------------------------------------------------------------------------- #
# registry — stop is a flag, and setting it is ungated
# --------------------------------------------------------------------------- #
_jobs: dict[str, TokenCrackJob] = {}
_stops: dict[str, threading.Event] = {}
_procs: dict[str, subprocess.Popen] = {}
_lock = threading.Lock()


def get(job_id: str) -> TokenCrackJob | None:
    with _lock:
        return _jobs.get(job_id)


def list_jobs(session_id: str | None = None) -> list[TokenCrackJob]:
    with _lock:
        jobs = list(_jobs.values())
    if session_id:
        jobs = [j for j in jobs if j.session_id == session_id]
    return sorted(jobs, key=lambda j: j.started_at, reverse=True)


def stop(job_id: str) -> TokenCrackJob | None:
    """Stop an in-flight crack. NOT GATED — the panic button, like ``stop_scan``. Sets the event
    and kills the process; whichever the worker notices first ends it."""
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
    """Engagement-sandbox availability + running-job count — drives the UI banner."""
    up = repeater_mod._container_running(config.ENGAGE_SANDBOX_CONTAINER)
    with _lock:
        running = sum(1 for j in _jobs.values() if j.state == "running")
    return {
        "container": config.ENGAGE_SANDBOX_CONTAINER,
        "up": up, "ready": up, "running": running,
        "detail": "" if up else "engagement sandbox is not running",
    }


def reset() -> None:
    """Drop all job state. Tests only — never called by the app."""
    with _lock:
        _jobs.clear()
        _stops.clear()
        _procs.clear()


# --------------------------------------------------------------------------- #
# start — GATE BEFORE ANYTHING SPAWNS
# --------------------------------------------------------------------------- #
def _require_engagement(engagement_id: str | None) -> str:
    if not engagement_id or engagement.get_active(engagement_id) is None:
        raise TokenCrackRefused(
            "engagement",
            "a JWT crack runs in an active engagement — enter engagement mode first "
            "(POST /cockpit/engagement/enter). The isolated lab sandbox has no loot mount.")
    if not repeater_mod._container_running(config.ENGAGE_SANDBOX_CONTAINER):
        raise TokenCrackRefused(
            "unavailable",
            f"engagement sandbox '{config.ENGAGE_SANDBOX_CONTAINER}' is not running — nothing ran")
    try:
        return loot.ensure(engagement_id)
    except loot.LootError as exc:
        raise TokenCrackRefused("loot", f"could not prepare a loot directory: {exc}")


def _write_loot(engagement_id: str, name: str, lines: list[str]) -> tuple[str, str]:
    host_dir = loot.host_dir(engagement_id)
    host_dir.mkdir(parents=True, exist_ok=True)
    host_path = host_dir / name
    host_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return f"{loot.container_dir(engagement_id)}/{name}", str(host_path)


def start_crack(req: TokenCrackRequest) -> TokenCrackJob:
    """Validate, write the token, and run hashcat in the background. GATE BEFORE ANYTHING RUNS."""
    workdir = _require_engagement(req.engagement_id)
    decoded = tokens.decode_jwt(req.token)
    if not decoded.header:
        raise TokenCrackRefused("input", decoded.note or "not a JWT — nothing to crack")
    if not decoded.alg.lower().startswith("hs"):
        raise TokenCrackRefused(
            "input",
            f"alg is {decoded.alg or 'unset'!r}; only HS256/384/512 have a symmetric secret a "
            "wordlist can recover. RS/ES tokens are not crackable this way — try alg confusion.")

    job_id = uuid.uuid4().hex[:12]
    token_c, _ = _write_loot(req.engagement_id or "", f"jwtcrack-{job_id}.jwt", [req.token.strip()])
    argv = crack_argv(req, token_path=token_c)

    rejected = _gate(crack_exec_request(req, token_path=token_c))
    if rejected is not None:
        raise TokenCrackRefused(rejected.gate, rejected.reason, list(rejected.dangerous_flags or []))

    job = TokenCrackJob(
        id=job_id, argv=argv, alg=decoded.alg, container=config.ENGAGE_SANDBOX_CONTAINER,
        engagement_id=req.engagement_id, session_id=req.session_id or req.engagement_id,
        started_at=_now(),
    )
    _register(job)
    threading.Thread(target=_run_crack, args=(job_id, argv, workdir, req, decoded.signing_input),
                     daemon=True, name=f"jwt-crack-{job_id}").start()
    return job


# --------------------------------------------------------------------------- #
# the gate + registry helpers
# --------------------------------------------------------------------------- #
def _gate(exec_req):
    """The executor's gate verdict — the SAME gates every command clears, nothing added."""
    from . import executor

    return executor.validate_request(exec_req)


def _register(job: TokenCrackJob) -> None:
    with _lock:
        _jobs[job.id] = job
        _stops[job.id] = threading.Event()


def _docker_argv(container: str, workdir: str, argv: list[str]) -> list[str]:
    return ["docker", "exec", *loot.exec_flags(workdir), container, *argv]


def _spawn(job_id: str, argv: list[str], workdir: str, timeout: int) -> str:
    """Run one ``docker exec`` to completion (or until stop/timeout), capturing output. Never
    raises — a transport failure becomes a note in the transcript."""
    full = _docker_argv(config.ENGAGE_SANDBOX_CONTAINER, workdir, argv)
    try:
        proc = subprocess.Popen(
            full, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    except FileNotFoundError:
        return "[jwtcrack] docker CLI not found on PATH\n"
    except Exception as exc:  # noqa: BLE001
        return f"[jwtcrack] could not start: {exc}\n"
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

    threading.Thread(target=_watchdog, daemon=True).start()
    text = _drain(job_id, proc)
    proc.wait()
    if timed["v"]:
        text += f"\n[jwtcrack] timed out after {timeout}s\n"
    return text


def _drain(job_id: str, proc: subprocess.Popen) -> str:
    """Stream the process's merged output into the job; honour stop. Returns the captured text."""
    chunks: list[str] = []
    total = 0
    stop_ev = _stops.get(job_id) or threading.Event()
    assert proc.stdout is not None
    for raw in iter(proc.stdout.readline, ""):
        if stop_ev.is_set():
            break
        if total < _OUTPUT_CAP:
            chunks.append(raw)
            total += len(raw)
        with _lock:
            j = _jobs.get(job_id)
            if j is not None:
                j.output_tail = "".join(chunks[-40:])[-4000:]
    try:
        proc.stdout.close()
    except Exception:  # noqa: BLE001
        pass
    return "".join(chunks)


def parse_cracked_secret(text: str, token: str) -> str:
    """A hashcat -m 16500 ``<token>:<secret>`` line -> the recovered secret. PURE.

    The token carries no ``:`` (base64url + dots), so the FIRST colon after the submitted token
    prefix splits token from secret unambiguously — and matching on the submitted token, rather
    than a generic ``split(':')``, is what makes a secret that itself contains a colon survive.
    """
    tok = (token or "").strip()
    for line in str(text or "").splitlines():
        line = line.rstrip("\r")
        if tok and line.startswith(tok + ":"):
            return line[len(tok) + 1:]
    return ""


def _run_crack(job_id: str, argv: list[str], workdir: str, req: TokenCrackRequest,
               signing_input: str) -> None:
    """Crack worker: run hashcat, then turn a recovered secret into loot + a finding. Never raises."""
    timeout = config.clamp_timeout(None) * 6  # cracking a wordlist can run long
    text = _spawn(job_id, argv, workdir, timeout)
    session_id = req.session_id or req.engagement_id or ""
    run_id = job_id
    secret = parse_cracked_secret(text, req.token)

    findings: list[Finding] = []
    loot_host = ""
    if secret and session_id:
        try:
            _, loot_host = _write_loot(
                req.engagement_id or "", f"jwtcrack-{job_id}-secret.txt", [secret])
        except Exception:  # noqa: BLE001
            loot_host = ""
        findings.append(Finding(
            session_id=session_id,
            title="weak JWT signing secret recovered",
            severity="high", target=(req.engagement_id or "jwt"), tool="hashcat",
            evidence=(f"a {len(secret)}-char HMAC secret was recovered offline from the wordlist — "
                      "the token can now be re-signed with any claims. Secret in loot, not here."),
            reference="jwt-weak-secret", source_run_id=run_id))

    _finish(job_id, text, session_id, run_id, secret, loot_host, findings, argv)


def _finish(job_id: str, text: str, session_id: str, run_id: str, secret: str, loot_host: str,
            findings: list, argv: list[str]) -> None:
    """Persist the finding, close the job out, and audit the run. Never raises."""
    new_finds = 0
    if session_id and findings:
        try:
            from state import store as state_store

            new_finds = state_store.upsert_findings(findings)
        except Exception:  # noqa: BLE001
            new_finds = 0

    with _lock:
        job = _jobs.get(job_id)
        stopped = _stops.get(job_id)
        if job is not None:
            job.state = "stopped" if (stopped is not None and stopped.is_set()) else "finished"
            job.finished_at = _now()
            job.cracked = bool(secret)
            job.secret_len = len(secret)
            job.new_findings = new_finds
            job.loot_path = loot_host
            job.output_tail = text[-4000:]
        _procs.pop(job_id, None)

    try:
        runstore.save_run(RunRecord(
            run_id=run_id, command="hashcat", args=argv[1:] if argv else [],
            target=(session_id or "jwt"), approved=True, mode="engagement",
            exit_code=0, stdout=text[-8000:], stderr="",
            started_at=(job.started_at if job else _now()), finished_at=_now(),
            session_id=session_id or None, step_id=None,
        ))
    except Exception:  # noqa: BLE001 - an audit failure must not lose the results
        pass
