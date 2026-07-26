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
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, NamedTuple

from state import ingest as state_ingest

from . import allowlist, config, engagement, loot, runstore
from .models import EngagementRecord, ExecRejected, ExecRequest, RunRecord
from .sandbox import SandboxError, assert_isolation_proven

_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

# A plausible TLD: letters only, 2-24 chars. This is the POSITIVE test for "the last label
# of a dotted token looks like a real domain suffix" (com, org, io, local, internal). It is
# what separates a host from the two things that used to false-trip the target-lock:
#   * versions / list names — `directory-list-2.3-medium`, `scan.1.2`, `raft-2.3` — whose
#     last label has a digit or hyphen, so it is NOT an alphabetic TLD, so NOT a host;
#   * filenames — `words.txt`, `config.yaml` — whose last label IS alphabetic, handled by
#     the file-extension exclusion below.
_TLD_RE = re.compile(r"^[a-z]{2,24}$")

# File extensions that are alphabetic (so they pass _TLD_RE) but name a FILE operand, not a
# host — a wordlist, output file, config. Only the ALPHABETIC entries are load-bearing now
# (a `.7z` or `.mp3` already fails _TLD_RE), but the fuller list is kept for clarity.
# Non-load-bearing overall (isolation / human-approval is the real bound), so imperfect is fine.
_FILE_EXTS = frozenset({
    "txt", "json", "xml", "csv", "html", "htm", "js", "py", "conf", "cfg", "ini", "list",
    "lst", "dic", "gz", "zip", "tar", "log", "md", "yaml", "yml", "php", "asp", "aspx",
    "bak", "pem", "key", "crt", "db", "sqlite", "pdf", "png", "jpg", "gif", "svg", "css",
})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _looks_like_host(token: str) -> bool:
    """True if a token is addressing *something* (URL, dotted host, IP, host:port).

    Recognises a host POSITIVELY rather than assuming every dotted token is one. A dotted
    token is a host only if its last label is a plausible alphabetic TLD (``evil.com``,
    ``dc01.corp.local``) and is not a file extension (``words.txt``). This stops the whole
    class of false rejections the old assume-host-unless-known-extension logic produced —
    ``directory-list-2.3-medium``, ``--user-agent Mozilla/5.0``, ``-oA scan.1.2``, version
    strings — which read as out-of-scope hosts and blocked legitimate, human-approved
    commands. Best-effort DiD, not the real bound (isolation / human-approval is); a scheme'd
    URL always wins, and under-detecting an exotic host (punycode) fails toward allowing a
    command the human already approved, which is the safe direction here.
    """
    if "://" in token:
        return True
    host = _host_of(token) or ""
    if not host:
        return False
    if _IPV4.match(host):
        return True
    if "." not in host:
        return False
    last = host.rsplit(".", 1)[-1].lower()
    if not _TLD_RE.match(last):
        return False                    # 2.3, 3-medium, scan.1.2 — a version/list, not a host
    return last not in _FILE_EXTS       # words.txt / config.yaml — a file operand, not a host


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


def _engagement_aliases(target: str) -> frozenset[str]:
    """The accepted target-lock aliases for an engagement's named target: the raw string
    (a host or URL) plus its bare host form, so both ``scanme.nmap.org`` and
    ``http://scanme.nmap.org/`` resolve to the same locked target."""
    aliases = {target}
    host = _host_of(target)
    if host:
        aliases.add(host)
    return frozenset(aliases)


def _engagement_lock(eng: EngagementRecord) -> tuple[frozenset[str], Any, str]:
    """(allowed aliases, in_scope matcher, label) for an engagement's SCOPE-AWARE target-lock.

    The allowed set is the named target's aliases plus the LIVE allowed set (the scope's exact
    hosts + every in-scope host recon has revealed). The matcher additionally accepts anything
    the PROGRAM SCOPE covers — a subdomain under a ``*.wildcard``, an IP inside a CIDR — so the
    loop can pivot within the authorized scope without re-entering mode. Exclusions always win
    (they are part of the matcher). Falls back to the single named target if the scope can't be
    resolved — fail-closed, never wider.
    """
    aliases = set(_engagement_aliases(eng.target))
    aliases.update(h for h in eng.allowed_hosts if h)
    try:
        matcher = engagement.resolved_scope(eng)
        return frozenset(aliases), matcher.in_scope, (eng.scope or eng.target)
    except Exception:  # pragma: no cover - defensive: a broken scope narrows, never widens
        return frozenset(aliases), None, eng.target


def check_target_lock(
    args: list[str],
    command: str | None = None,
    allowed: frozenset[str] | None = None,
    label: str | None = None,
    in_scope: Any = None,
) -> tuple[bool, str]:
    """BEST-EFFORT target-lock: every host-shaped token in args must be an allowed target.

    ``allowed`` defaults to the lab aliases (LAB mode — messages + behaviour unchanged); in
    ENGAGEMENT mode it is the engagement's live allowed set, ``in_scope`` is the PROGRAM SCOPE
    matcher (so any in-scope host passes, not just one exact host) and ``label`` names the scope
    in the reason. This is cheap defense-in-depth (it catches e.g. ``nmap evil.com``), NOT a
    load-bearing control: args can be an arbitrary command whose real target is invisible to any
    argv inspection (``python -c "...connect to X..."``, ``curl @file``, a host inside a base64
    blob). In LAB mode ISOLATION is the actual bound; in ENGAGEMENT mode there is no isolation
    floor and Wall A is down, so HUMAN APPROVAL of every command is the actual bound and this
    lock is an aid to the human, not a guarantee. ``command`` is for signature compatibility.

    A token is an allowed/in-scope target, another host (→ reject), or a non-host operand
    (→ ignore).

    TARGET-LESS COMMANDS split by mode. In LAB a command must still reference the lab —
    isolation is the real bound there and the rule is part of the locked lab invariant. In
    ENGAGEMENT a command that names no host at all is ALLOWED: the hosts of ``nmap -iL
    targets.txt`` live in the file, so refusing it protected nothing (this lock cannot see
    into files either way) while blocking a legitimate, human-approved command. Refusing
    where the check has no information is friction without safety.
    """
    is_lab = allowed is None and in_scope is None
    allow = allowed if allowed is not None else config.LAB_TARGET_ALIASES
    found = False
    for token in allowlist.extract_hostish(args):
        if token in allow:
            found = True
            continue
        if _looks_like_host(token):
            host = _host_of(token)
            if host in allow or (in_scope is not None and in_scope(token)):
                found = True
            elif is_lab:
                return False, f"target '{host}' is not the lab — only the lab is allowed"
            else:
                return False, f"target '{host}' is not in the engagement scope '{label}'"
        # else: bare non-host operand → ignore
    if not found and is_lab:
        return False, "no lab target specified — the command must reference the lab"
    return True, ""


def _resolved_target(
    command: str,
    args: list[str],
    allowed: frozenset[str] | None = None,
    default: str | None = None,
    in_scope: Any = None,
) -> str:
    """The host this command targets (for the record/UI), among the allowed/in-scope hosts."""
    allow = allowed if allowed is not None else config.LAB_TARGET_ALIASES
    for token in allowlist.extract_hostish(args):
        host = _host_of(token)
        if token in allow or host in allow:
            return host or (default or config.LAB_TARGET_HOST)
        if in_scope is not None and _looks_like_host(token) and in_scope(token):
            return host or (default or config.LAB_TARGET_HOST)
    return default or config.LAB_TARGET_HOST


def _engagement_for(request: ExecRequest) -> EngagementRecord | None:
    """The ACTIVE engagement this request runs under, or None (→ lab mode). An engagement_id
    that is set but not active resolves to None; the caller treats that as a hard refusal."""
    if not request.engagement_id:
        return None
    return engagement.get_active(request.engagement_id)


def validate_request(request: ExecRequest) -> ExecRejected | None:
    """Run the mode's gates in order, returning an ExecRejected on the first failure.

    MODE SPLIT (the whole risk model): if ``engagement_id`` names an ACTIVE, explicitly-entered
    engagement, the request runs against a REAL target with NO isolation floor and is gated by
    :func:`_validate_engagement`. Otherwise it is LAB mode, gated by :func:`_validate_lab` —
    entirely unchanged. An ``engagement_id`` that doesn't resolve is refused (never silently
    downgraded to lab), so engagement mode can only be reached by explicitly entering it.
    """
    if request.engagement_id:
        eng = _engagement_for(request)
        if eng is None:
            return ExecRejected(
                reason="engagement mode is not active for this id — enter engagement mode first "
                "(POST /cockpit/engagement/enter); an unknown or exited engagement cannot run",
                gate="engagement",
            )
        return _validate_engagement(request, eng)
    return _validate_lab(request)


def _validate_lab(request: ExecRequest) -> ExecRejected | None:
    """LAB mode gates (UNCHANGED): best-effort target-lock (lab) → human approval → heuristic
    danger red-confirm → ISOLATION (the real lab containment: an egress-less sandbox)."""
    ok, reason = check_target_lock(request.args, request.command)
    if not ok:
        return ExecRejected(reason=reason, gate="target")

    if not request.approved:
        return ExecRejected(
            reason="command not approved — set approved=true to run", gate="approval"
        )

    # Danger gate: a command the HEURISTIC flags as dangerous (interpreter, reverse shell,
    # framework…) needs an EXPLICIT second confirm (dangerous_ack) on top of approval — so
    # arbitrary code / a shell can't be approved by accident, incl. an agent-proposed one.
    # NEVER blocks outright; requires the confirm. Over-inclusive assist — human is the gate.
    dangerous = allowlist.dangerous_command_heuristic(request.command, request.args)
    if dangerous and not request.dangerous_ack:
        return ExecRejected(
            reason="this command is flagged dangerous — confirm to run: " + "; ".join(dangerous),
            gate="danger",
            dangerous_flags=dangerous,
        )

    try:
        assert_isolation_proven()
    except SandboxError as exc:
        return ExecRejected(reason=str(exc), gate="sandbox")

    return None


def _validate_engagement(request: ExecRequest, eng: EngagementRecord) -> ExecRejected | None:
    """ENGAGEMENT mode gates (REAL target, NO isolation floor, WALL A DOWN). Order:
        target-lock (the engagement's PROGRAM SCOPE) → NEVER-AUTO-RUN human approval →
        heuristic danger red-confirm.

    There is NO isolation gate and NO Wall-A gate here — the sandbox is FULLY OPEN (internet +
    LAN + host + metadata) on purpose. Nothing bounds WHERE it can reach. The ONLY bound is the
    per-command human approval below (there is no batch/approve-all path) plus the heuristic
    red-confirm — a conscious human on every single command. That guard now protects real
    targets AND the operator's own machine; it must hold every command, every time.
    """
    allowed, in_scope, label = _engagement_lock(eng)
    ok, reason = check_target_lock(
        request.args, request.command, allowed=allowed, label=label, in_scope=in_scope
    )
    if not ok:
        return ExecRejected(reason=reason, gate="target")

    # NEVER-AUTO-RUN: on a real target every single command needs an INDIVIDUAL human approval.
    # No batch, no approve-all, no autonomy. This is the ONLY bound on what runs (Wall A is
    # down) — so it is more load-bearing than ever. Enforce hard.
    if not request.approved:
        return ExecRejected(
            reason="engagement mode: every command needs an individual human approval "
            "(approved=true) — never hands-off / no batch approval on a real target",
            gate="approval",
        )

    dangerous = allowlist.dangerous_command_heuristic(request.command, request.args)
    if dangerous and not request.dangerous_ack:
        return ExecRejected(
            reason="this command is flagged dangerous — confirm to run: " + "; ".join(dangerous),
            gate="danger",
            dangerous_flags=dangerous,
        )

    return None


class EngagementInactive(RuntimeError):
    """The request names an engagement that is no longer active — nothing may run.

    Raised by :func:`resolve_mode` so a run can NEVER silently fall back to LAB mode
    against an id that was meant for a real target.
    """


class ResolvedMode(NamedTuple):
    """Which sandbox a request execs into, and what it is pointed at."""

    mode: str  # "lab" | "engagement"
    container: str  # the sandbox container for that mode
    target: str  # the resolved target, for the record/UI
    engagement: EngagementRecord | None


def resolve_mode(request: ExecRequest) -> ResolvedMode:
    """The SINGLE SOURCE OF TRUTH for which container a mode execs into.

    Shared by :func:`iter_run` (one-shot commands) and the live-session manager
    (cockpit/session.py), so a long-lived session can never bind to a different sandbox
    than a one-shot command would in the same mode. LAB → the isolated, egress-less
    sandbox; ENGAGEMENT → the fully-open engagement sandbox.

    Raises :class:`EngagementInactive` when ``engagement_id`` is set but no longer
    active. Pure: it only reads the engagement record and resolves names — it never
    executes anything, so calling it before a gate re-check is safe.
    """
    eng = _engagement_for(request)
    if request.engagement_id and eng is None:
        raise EngagementInactive("engagement is no longer active — refusing to run")
    if eng is not None:
        allowed, in_scope, _label = _engagement_lock(eng)
        return ResolvedMode(
            mode="engagement",
            container=config.ENGAGE_SANDBOX_CONTAINER,
            target=_resolved_target(
                request.command,
                request.args,
                allowed=allowed,
                default=eng.target,
                in_scope=in_scope,
            ),
            engagement=eng,
        )
    return ResolvedMode(
        mode="lab",
        container=config.SANDBOX_CONTAINER,
        target=_resolved_target(request.command, request.args),
        engagement=None,
    )


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

    # Route by mode. An engagement_id that is set but no longer active is refused here too
    # (even when prevalidated), so a run can NEVER fall back to lab against a real-target id.
    try:
        mode, container, target, eng = resolve_mode(request)
    except EngagementInactive as exc:
        yield {"type": "rejected", "gate": "engagement", "reason": str(exc)}
        return
    if eng is not None:
        # Belt-and-suspenders (ENGAGEMENT ONLY): with Wall A down, per-command human
        # approval is the SOLE floor on a real target, so its enforcement must not depend
        # solely on every future caller remembering to run validate_request first. Re-check
        # approval here even in the prevalidated path. This is a pure no-op for valid flows —
        # the router runs validate_request (which rejects an unapproved engagement at the
        # approval gate) before it ever sets prevalidated=True. The LAB path is deliberately
        # left behaviourally unchanged.
        if not request.approved:
            yield {
                "type": "rejected",
                "gate": "approval",
                "reason": "engagement mode: every command needs an individual human approval "
                "(approved=true) — never hands-off / no batch approval on a real target",
            }
            return

    run_id = uuid.uuid4().hex[:12]
    started_at = _now()
    # Wall-clock start, kept so the state ingest can tell which loot files THIS run wrote.
    # Loot directories persist across runs; without this, an old scan's XML would be
    # re-attributed to whatever ran last and the source_run_id would be a lie.
    started_epoch = time.time()
    # Working directory: engagement runs land in their own loot directory so `-oA scan`
    # writes somewhere durable. LAB runs get None -> no -w flag -> argv byte-identical to
    # what it was before loot existed. See cockpit/loot.py for why the lab is excluded.
    workdir = loot.workdir_for(mode, eng.engagement_id if eng is not None else None)
    timeout_seconds = config.clamp_timeout(request.timeout_seconds)
    argv = ["docker", "exec", *loot.exec_flags(workdir), container, request.command, *request.args]

    yield {
        "type": "start",
        "run_id": run_id,
        "command": request.command,
        "args": request.args,
        "target": target,
        "mode": mode,
        "started_at": started_at,
        "timeout_seconds": timeout_seconds,
        "workdir": workdir,
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
            proc.wait(timeout=timeout_seconds)
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
        yield {"type": "error", "reason": f"timed out after {timeout_seconds}s"}

    record = RunRecord(
        run_id=run_id,
        command=request.command,
        args=request.args,
        target=target,
        approved=request.approved,
        mode=mode,
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

    # STATE INGEST: turn this finished run into structured state — hosts, services,
    # endpoints, credentials, findings — from its stdout AND from any file it just wrote
    # into its loot directory (that is how `nmap -oA` gets picked up). Additive enrichment,
    # never a gate: the command has already run and a failure here must not surface as a
    # run failure. The ingest layer executes nothing.
    if request.session_id:
        try:
            counts = state_ingest.ingest_run(
                session_id=request.session_id,
                run_id=run_id,
                command=request.command,
                stdout=record.stdout,
                # target + full command line let the proof/local.txt flag capture attribute a
                # flag to the right host (the flag file sits in the args, e.g. `cat proof.txt`).
                target=record.target or "",
                command_line=" ".join([request.command, *request.args]),
                loot_dir=Path(loot.host_dir(eng.engagement_id)) if eng is not None else None,
                started_at_epoch=started_epoch,
            )
            if any(counts.values()):
                yield {"type": "state", "run_id": run_id, "added": counts}
        except Exception as exc:  # pragma: no cover - never load-bearing
            yield {"type": "error", "reason": f"state ingest skipped: {exc}"}

    # RECON-DRIVEN EXPANSION (engagement only): mine this run's output for hosts and sort them
    # by the engagement's PROGRAM SCOPE. In-scope hosts join the live allowed set (so the loop
    # can pivot to them); out-of-scope hosts are surfaced read-only and never added. This
    # approves NOTHING — every command against a discovered host still needs its own individual
    # human approval. Best-effort: a failure here can never affect the run that already ran.
    if eng is not None:
        try:
            found = engagement.record_discoveries(
                eng, record.stdout + record.stderr, run_id=run_id
            )
            if found["added"] or found["out_of_scope"]:
                yield {
                    "type": "discovered",
                    "run_id": run_id,
                    "in_scope": found["added"],
                    "out_of_scope": found["out_of_scope"],
                    "truncated": found["truncated"],
                }
        except Exception as exc:  # pragma: no cover - never load-bearing
            yield {"type": "error", "reason": f"scope expansion skipped: {exc}"}

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
