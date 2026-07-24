"""The exec layer — validated, approved, target-locked `docker exec` into the sandbox.

Wired in M1.3, permitted only because the M1.2 isolation proof passed. Every run must
clear four independent gates, in order:
    1. allowlist   — command is on the safe set, args are metachar-free + rule-valid
    2. target lock — the lab is explicitly targeted and NO non-lab host appears
    3. approval    — request.approved is True (per-command human approval)
    4. isolation   — the running sandbox is attached only to internal networks
Only then is the command run, argv-style (never through a shell), with a hard timeout.
"""

from __future__ import annotations

import queue
import re
import subprocess
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Iterator

from . import allowlist, config, runstore
from .models import ExecRejected, ExecRequest, RunRecord
from .sandbox import SandboxError, assert_isolation_proven

_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _looks_like_host(token: str) -> bool:
    """True if a token is addressing *something* (URL, dotted host, IP, host:port).

    Bare words with none of these (e.g. curl's ``GET``) are NOT hosts — they cannot
    address a non-lab machine on the isolated network and are ignored by the lock.
    """
    if "://" in token:
        return True
    host = _host_of(token) or ""
    if not host:
        return False
    if _IPV4.match(host):
        return True
    if "." in host:
        return True
    return False


def _host_of(token: str) -> str | None:
    """Extract a bare host from a token that may be a URL or host[:port]."""
    t = token.strip()
    if not t or t.startswith("-"):
        return None
    if "://" in t:
        t = t.split("://", 1)[1]
    for sep in ("/", "?", "#"):
        if sep in t:
            t = t.split(sep, 1)[0]
    if "@" in t:
        t = t.split("@", 1)[1]
    if ":" in t:
        t = t.split(":", 1)[0]
    return t or None


def _recon_target_lock(args: list[str]) -> tuple[bool, str]:
    """RECON target-lock: every hostish operand must be the lab; at least one required.

    A token is either the lab alias, another host (→ reject), or a non-host operand
    (→ ignore). Unchanged from the recon milestone.
    """
    found_lab = False
    for token in allowlist.extract_hostish(args):
        if token in config.LAB_TARGET_ALIASES:
            found_lab = True
            continue
        if _looks_like_host(token):
            host = _host_of(token)
            if host in config.LAB_TARGET_ALIASES:
                found_lab = True
            else:
                return False, f"target '{host}' is not the lab — only the lab is allowed"
        # else: bare non-host operand → ignore
    if not found_lab:
        return False, "no lab target specified — the command must target the lab"
    return True, ""


def _active_target_lock(command: str, args: list[str]) -> tuple[bool, str]:
    """ACTIVE target-lock: bind the tool's TARGET (its ``target_flags`` value) to the lab.

    Only the designated target flag(s) are lab-checked (sqlmap ``-u``, ffuf ``-u``,
    nuclei ``-u``/``-target``) — so a wordlist/data operand with a dot is not mistaken for
    a target host. At least one lab target is required (fail closed); isolation is the
    backstop for any non-target egress (``--proxy``, ``-interactsh-server``…).
    """
    targets = allowlist.extract_active_targets(command, args)
    if not targets:
        return False, (
            f"no lab target — {command} must point at the lab via its target flag "
            "(e.g. -u http://<lab>/…)"
        )
    for token in targets:
        host = _host_of(token)
        if host not in config.LAB_TARGET_ALIASES:
            return False, f"target '{host}' is not the lab — only the lab is allowed"
    return True, ""


def check_target_lock(args: list[str], command: str | None = None) -> tuple[bool, str]:
    """Pure target-lock. Dispatches by tool MODE: active tools bind their per-tool target
    flag to the lab; recon tools (or an unknown command) use the hostish-operand rule.

    ``command`` is optional for backward compatibility — omitted → recon behavior.
    """
    spec = allowlist.ALLOWLIST.get(command) if command else None
    if spec is not None and spec.active:
        return _active_target_lock(command, args)  # type: ignore[arg-type]
    return _recon_target_lock(args)


def _resolved_target(command: str, args: list[str]) -> str:
    """The lab host this command targets (for the record/UI)."""
    spec = allowlist.ALLOWLIST.get(command)
    tokens = (
        allowlist.extract_active_targets(command, args)
        if spec is not None and spec.active
        else allowlist.extract_hostish(args)
    )
    for token in tokens:
        host = _host_of(token)
        if token in config.LAB_TARGET_ALIASES or host in config.LAB_TARGET_ALIASES:
            return host or config.LAB_TARGET_HOST
    return config.LAB_TARGET_HOST


def validate_request(request: ExecRequest) -> ExecRejected | None:
    """Run all four gates. Return an ExecRejected on the first failure, else None."""
    ok, reason = allowlist.validate(request.command, request.args)
    if not ok:
        return ExecRejected(reason=reason, gate="allowlist")

    ok, reason = check_target_lock(request.args, request.command)
    if not ok:
        return ExecRejected(reason=reason, gate="target")

    if not request.approved:
        return ExecRejected(
            reason="command not approved — set approved=true to run", gate="approval"
        )

    try:
        assert_isolation_proven()
    except SandboxError as exc:
        return ExecRejected(reason=str(exc), gate="sandbox")

    return None


def iter_run(request: ExecRequest, prevalidated: bool = False) -> Iterator[dict[str, Any]]:
    """Validate then stream a run as events.

    Yields dict events: {type: start|stdout|stderr|exit|rejected|error, ...}. The full
    output is accumulated and persisted as a RunRecord when the process finishes. The
    caller (router) formats events for transport (SSE). Validation happens first, so a
    rejected request yields exactly one {type: rejected} event and nothing runs.

    ``prevalidated=True`` skips the gate re-check when the caller (router) already ran
    validate_request to decide the HTTP status.
    """
    if not prevalidated:
        rejected = validate_request(request)
        if rejected is not None:
            yield {"type": "rejected", "gate": rejected.gate, "reason": rejected.reason}
            return

    run_id = uuid.uuid4().hex[:12]
    target = _resolved_target(request.command, request.args)
    started_at = _now()
    argv = ["docker", "exec", config.SANDBOX_CONTAINER, request.command, *request.args]

    yield {
        "type": "start",
        "run_id": run_id,
        "command": request.command,
        "args": request.args,
        "target": target,
        "started_at": started_at,
    }

    out_buf: list[str] = []
    err_buf: list[str] = []
    exit_code: int | None = None
    events: "queue.Queue[dict[str, Any]]" = queue.Queue()

    try:
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
    except FileNotFoundError:
        yield {"type": "error", "reason": "docker CLI not found on PATH"}
        return

    def _pump(stream, kind: str, buf: list[str]) -> None:
        for line in iter(stream.readline, ""):
            buf.append(line)
            events.put({"type": kind, "line": line.rstrip("\n")})
        stream.close()

    threads = [
        threading.Thread(target=_pump, args=(proc.stdout, "stdout", out_buf), daemon=True),
        threading.Thread(target=_pump, args=(proc.stderr, "stderr", err_buf), daemon=True),
    ]
    for t in threads:
        t.start()

    # Hard timeout: kill the docker exec client if it overruns.
    timed_out = {"v": False}

    def _watchdog() -> None:
        try:
            proc.wait(timeout=config.EXEC_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            timed_out["v"] = True
            proc.kill()

    wd = threading.Thread(target=_watchdog, daemon=True)
    wd.start()

    # Drain events until the process exits and both pumps finish.
    while True:
        try:
            ev = events.get(timeout=0.2)
            yield ev
        except queue.Empty:
            if proc.poll() is not None and not any(t.is_alive() for t in threads):
                break

    # flush any last events
    while not events.empty():
        yield events.get_nowait()

    exit_code = proc.poll()
    finished_at = _now()
    if timed_out["v"]:
        yield {"type": "error", "reason": f"timed out after {config.EXEC_TIMEOUT_SECONDS}s"}

    record = RunRecord(
        run_id=run_id,
        command=request.command,
        args=request.args,
        target=target,
        approved=request.approved,
        exit_code=exit_code,
        stdout="".join(out_buf),
        stderr="".join(err_buf),
        started_at=started_at,
        finished_at=finished_at,
        session_id=request.session_id,
        step_id=request.step_id,
    )
    try:
        runstore.save_run(record)
    except Exception as exc:  # persistence must never crash the stream
        yield {"type": "error", "reason": f"run recorded in-memory only: {exc}"}

    yield {"type": "exit", "run_id": run_id, "code": exit_code, "finished_at": finished_at}


def run_command(request: ExecRequest) -> RunRecord:
    """Non-streaming convenience: run to completion and return the RunRecord.

    Raises SandboxError/ValueError semantics via the ExecRejected path — used by tests
    and the dry-run. Prefer iter_run() for the live UI.
    """
    rejected = validate_request(request)
    if rejected is not None:
        raise PermissionError(f"[{rejected.gate}] {rejected.reason}")

    last_exit: int | None = None
    run_id = None
    for ev in iter_run(request):
        if ev["type"] == "start":
            run_id = ev["run_id"]
        elif ev["type"] == "exit":
            last_exit = ev["code"]
    assert run_id is not None
    record = runstore.get_run(run_id)
    if record is None:  # pragma: no cover - defensive
        raise RuntimeError("run completed but record not found")
    return record
