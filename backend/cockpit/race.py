"""The single-packet race tester — one request, fired N times so they land in the same instant.

*** WHY THIS FITS THE APPROVAL MODEL — THE INTRUDER'S ARGUMENT, WORD FOR WORD. ***
HackPit refuses **batching across approvals** — an agent queueing five commands and a human
clicking once. It has never refused ONE approval that produces many requests, and could not:
`ffuf`, `nuclei`, the ZAP active scanner and the intruder are each a single approval buying many
requests. A race tester is that same shape, with a synchronized transport instead of a serial
one: ONE gated job, gated by the SAME four gates, with NO new ones.

THE WHOLE REQUEST TEMPLATE AND THE CONCURRENCY COUNT ARE PART OF THE APPROVED SURFACE. That is the
intruder's Critical-2 lesson carried across: :func:`race_argv_for` puts the method, the URL, the
body and every header into the gate surface — not a count, not a sample — so a body carrying a
shell pattern is visible to the danger gate rather than hidden while a human approves a summary.
Measured on the intruder: the danger gate DOES fire on request CONTENT, so the surface being
complete is what makes that check real rather than decorative.

CONTAINMENT, inherited wholesale from the intruder and stated rather than assumed:

* **HARDCODED CONTAINER.** Every request runs inside ``config.KALI_OPEN_CONTAINER`` — the same
  box the repeater and intruder use. NO new egress path is created, and the container is a code
  constant that no request field can redirect.
* **ARGV-ONLY engine, the request on stdin.** The synchronized client runs as
  ``docker exec … race-singlepacket --job-stdin`` and the whole request (URL, headers, body,
  mode, N) is delivered as JSON on STDIN — no shell parses any request byte, exactly as the
  intruder feeds a curl body on ``@-``.
* **SCOPE-CHECKED ON THE WIRE.** The URL host is checked against the engagement scope on the
  bytes that will actually go out, before anything is dispatched — build #18's rule. An
  out-of-scope host is refused and nothing is sent.
* **STOP IS UNGATED**, like every other stop in this codebase. N synchronized requests are in
  flight; a gate that could refuse to stop them would make the system less safe.

WHAT THIS IS FOR: limit-overrun / TOCTOU / coupon-reuse / one-time-token races — the class the
intruder's serial loop cannot hit, because the target's check-then-act window closes between
requests. Two transports, operator-selected:

* **h2-single-packet** — one HTTP/2 connection, N requests queued with their final frame
  withheld, then all final frames released together so all N complete in a single packet
  (PortSwigger's technique). The reliable modern mode; shipped first.
* **h1-last-byte** — N connections, every byte but the last sent, then the last byte released on
  all connections together. The fallback for HTTP/1.1-only targets.

The verdict is the race-window signal, not a raw dump: the N responses are clustered, and when the
*rare* outcome a serial baseline would return once (the single "coupon applied" / "withdrawal ok")
appears **more than once**, that is a race — reported as "K of N requests won the race".
"""

from __future__ import annotations

import json
import subprocess
import threading
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from . import config, loot, repeater as repeater_mod, runstore, scope as scope_mod
from .models import RunRecord

#: The two transports. h2-single-packet is the default and the reliable one; h1-last-byte is the
#: HTTP/1.1 fallback. An unknown mode falls back to the default and SAYS SO — it does not refuse.
MODES = ("h2-single-packet", "h1-last-byte")
DEFAULT_MODE = "h2-single-packet"

#: A race needs at least two requests to be a race. One is just a send.
RACE_MIN_REQUESTS = 2
#: Ceiling on concurrency one approved job may fire. NOT a refusal — the job runs, fires this
#: many, and REPORTS that it clamped (`capped`). A single-packet window that needs thousands of
#: parallel streams is unusual; 500 covers the real coupon/limit cases and still bounds a runaway.
RACE_MAX_REQUESTS = 500
#: Per-response body kept, in chars. A race result is read as a table of status/size/time; a race
#: of 500 rows each holding megabytes is how a panel becomes unusable.
RACE_BODY_CAP = 2_000


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------- #
# models
# --------------------------------------------------------------------------- #
class RaceRequest(BaseModel):
    """One race job: a request, a transport, a concurrency count, and the gate fields.

    NO container/target field — the box is a code constant (rule #1), exactly like the intruder.
    Same-request-×N is the whole model: unlike the intruder there are no marked positions, because
    a race fires the *identical* request many times and looks at how many won.
    """

    url: str = Field(..., min_length=1, description="Absolute http(s) URL the request goes to.")
    method: str = "POST"
    headers: list[repeater_mod.RepeaterHeader] = Field(default_factory=list)
    body: str = Field("", description="Request body — the coupon/redeem/transfer payload.")
    mode: str = Field(
        DEFAULT_MODE,
        description="h2-single-packet (default, reliable) or h1-last-byte. An unknown mode falls "
        "back to the default and SAYS SO; it does not refuse.",
    )
    count: int = Field(
        20, ge=1,
        description="N — how many synchronized copies to fire. Clamped to the ceiling and reported "
        "if over, never silently dropped.",
    )
    follow_redirects: bool = False
    insecure: bool = False
    timeout_seconds: int | None = None
    engagement_id: str | None = None
    session_id: str | None = None
    use_cookie_jar: bool = Field(
        True, description="Attach the repeater's session jar — most race targets are authenticated."
    )
    # THE GATE FIELDS — the scanner's / intruder's, unchanged. Both default False so an omitted
    # field is REFUSED rather than granted.
    approved: bool = Field(False, description="Explicit human approval. Never defaulted true.")
    dangerous_ack: bool = Field(
        False,
        description="The red-confirm, WHEN THE GATE ASKS FOR IT. Not demanded by this model: the "
        "four gates decide, and they fire on request CONTENT (a body carrying '| sh' trips "
        "'reverse-shell / code-exec pattern'). Requiring it unconditionally here would be this "
        "build adding a confirm, which it may not.",
    )


class RaceResult(BaseModel):
    """One request in the batch. No response headers — a table of N needs a table's shape."""

    index: int
    status: int | None = None
    size_bytes: int = 0
    time_ms: int = 0
    body_excerpt: str = ""
    error: str = ""
    #: Which response cluster this row fell into (assigned by the verdict). The winning cluster is
    #: the rare outcome a serial baseline returns once; a row in it is a request that WON the race.
    won: bool = False


class RaceVerdict(BaseModel):
    """The race-window signal. ``race_detected`` when the rare outcome appeared more than once."""

    race_detected: bool = False
    won: int = Field(0, description="How many requests landed the winning (rare) outcome.")
    of: int = Field(0, description="How many requests got a real (error-free) response.")
    winning_status: int | None = None
    clusters: list[dict[str, int]] = Field(
        default_factory=list,
        description="(status, size, count) buckets the N responses fell into, rarest first.",
    )
    note: str = ""


class RaceJob(BaseModel):
    """The job. Counts are what HAPPENED, never what was planned."""

    id: str
    state: str = Field("running", description="running | finished | stopped | refused")
    request: RaceRequest
    container: str = ""
    started_at: str = ""
    finished_at: str = ""
    mode: str = ""
    planned: int = Field(0, description="Requests this job intends to fire (after clamping).")
    sent: int = Field(0, description="Requests the engine actually fired.")
    baseline: RaceResult | None = Field(
        None, description="A single SERIAL request, sent first. Without it 'this cluster is the "
        "rare one' has no serial reference to be rare against."
    )
    results: list[RaceResult] = Field(default_factory=list)
    verdict: RaceVerdict | None = None
    capped: bool = Field(
        False, description="True when N was over the ceiling and the job clamped. Reported."
    )
    warnings: list[str] = Field(default_factory=list)
    scope_refusals: int = Field(
        0, description="Requests NOT sent because the URL host left the engagement scope. When "
        "this fires the whole batch is refused (all N share one URL) and nothing is sent."
    )
    finding_written: bool = Field(
        False, description="True when a confirmed race was written to engagement state as a Finding."
    )


class RaceRefused(RuntimeError):
    """Refused BEFORE anything ran. Carries the gate that refused it."""

    def __init__(self, gate: str, reason: str, dangerous_flags: list[str] | None = None) -> None:
        super().__init__(reason)
        self.gate = gate
        self.reason = reason
        self.dangerous_flags = dangerous_flags or []


# --------------------------------------------------------------------------- #
# the gate — THE SCANNER'S FOUR, UNCHANGED
# --------------------------------------------------------------------------- #
def race_argv_for(req: RaceRequest) -> list[str]:
    """The command this job is EQUIVALENT TO, which is what the human approves.

    ``race-singlepacket`` because that IS what runs — the in-repo synchronized client baked into
    the sandbox. NOT because it is "allowed": there is no tool allowlist in this product (the
    module that sounds like one says so itself). The gates are approval, target, danger and
    isolation, and none consults a list of binaries — so the only thing the declared command has
    to be is HONEST, because that string is what a human approves and what the danger heuristic
    reads.

    The URL rides as ``-u`` (where the target gate reads the host), and the method, body and every
    header travel verbatim so the surface is COMPLETE — the intruder's Critical-2 rule: nothing is
    summarised, so a body carrying a shell pattern reaches the danger gate rather than hiding
    behind a count.
    """
    argv = ["race-singlepacket", "-u", req.url]
    method = (req.method or "GET").strip().upper()
    if method != "GET":
        argv += ["-X", method]
    argv += ["--mode", _mode_of(req)[0], "-n", str(_clamp_count(req.count)[0])]
    for h in req.headers:
        name = (h.name or "").strip()
        if name:
            argv += ["-H", f"{name}: {h.value}"]
    if req.body:
        argv += ["-d", req.body]
    return argv


def _gate_request(req: RaceRequest):
    from .models import ExecRequest

    argv = race_argv_for(req)
    return ExecRequest(
        command=argv[0], args=argv[1:],
        approved=req.approved, dangerous_ack=req.dangerous_ack,
        engagement_id=req.engagement_id,
    )


def validate(req: RaceRequest):
    """The gate verdict, attacking nothing. PURE. Returns None when it passes.

    All four gates, in the executor's order, unchanged and with nothing added — so a UI can ask
    "would this be refused" without launching anything, the same split the intruder makes.
    """
    from . import executor

    return executor.validate_request(_gate_request(req))


# --------------------------------------------------------------------------- #
# planning — PURE, so what will be fired is inspectable before anything is
# --------------------------------------------------------------------------- #
def _mode_of(req: RaceRequest) -> tuple[str, str | None]:
    """``(mode, warning)``. An unknown mode falls back to the default and reports it."""
    mode = (req.mode or "").strip().lower()
    if mode not in MODES:
        return DEFAULT_MODE, (
            f"unknown mode {req.mode!r} — running as {DEFAULT_MODE!r}. Known: {', '.join(MODES)}"
        )
    return mode, None


def _clamp_count(count: int) -> tuple[int, str | None]:
    """``(n, warning)``. Below the floor is raised to it; above the ceiling is clamped."""
    if count > RACE_MAX_REQUESTS:
        return RACE_MAX_REQUESTS, (
            f"{count} requests asked for, over the {RACE_MAX_REQUESTS} ceiling — the job will fire "
            f"the first {RACE_MAX_REQUESTS} and report `capped`. It is NOT refused, and nothing is "
            "silently dropped."
        )
    if count < RACE_MIN_REQUESTS:
        return RACE_MIN_REQUESTS, (
            f"a race needs at least {RACE_MIN_REQUESTS} requests — {count} was raised to "
            f"{RACE_MIN_REQUESTS}"
        )
    return count, None


def plan(req: RaceRequest) -> tuple[int, list[str], bool]:
    """``(planned_count, warnings, capped)``. Fires nothing. WARN AND CONTINUE throughout."""
    warnings: list[str] = []
    mode, mode_warn = _mode_of(req)
    if mode_warn:
        warnings.append(mode_warn)
    n, count_warn = _clamp_count(req.count)
    if count_warn:
        warnings.append(count_warn)
    capped = req.count > RACE_MAX_REQUESTS
    return n, warnings, capped


# --------------------------------------------------------------------------- #
# the verdict — PURE, testable on a fixture result set
# --------------------------------------------------------------------------- #
def race_verdict(results: list[RaceResult]) -> RaceVerdict:
    """Cluster the responses and decide whether the rare outcome won more than once. PURE.

    A serial baseline returns the "single-success" outcome exactly ONCE — one coupon applied, one
    withdrawal ok — and every other attempt gets the "already used" outcome. A race is when that
    single-success cluster has TWO OR MORE members: more than one request slipped through the
    check-then-act window. So the WINNING cluster is the *rarest* one (tie broken toward a 2xx),
    and ``race_detected`` is simply ``won >= 2``.

    All-identical responses are NOT a race: they mean either everything succeeded or everything
    failed, and neither distinguishes a first-time success from a repeat — the exact thing a race
    needs to be visible.
    """
    ok = [r for r in results if r.status is not None and not r.error]
    buckets: dict[tuple[int, int], int] = {}
    for r in ok:
        key = (int(r.status), (int(r.size_bytes) // 16) * 16)
        buckets[key] = buckets.get(key, 0) + 1
    clusters = [
        {"status": k[0], "size": k[1], "count": v} for k, v in buckets.items()
    ]
    # Rarest first; among equal counts a 2xx (the usual "success" shape) sorts ahead.
    clusters.sort(key=lambda c: (c["count"], 0 if 200 <= c["status"] < 300 else 1, c["status"]))

    if len(clusters) < 2:
        return RaceVerdict(
            race_detected=False, won=0, of=len(ok), clusters=clusters,
            note="every response fell in one cluster — a race needs a distinguishable "
            "single-success outcome to appear more than once, so there is no signal here.",
        )
    winner = clusters[0]
    won = winner["count"]
    detected = won >= 2
    return RaceVerdict(
        race_detected=detected, won=won, of=len(ok), winning_status=winner["status"],
        clusters=clusters,
        note=(
            f"{won} of {len(ok)} requests landed the rare '{winner['status']}' outcome that a "
            "serial baseline returns only once — the race window let more than one through."
            if detected else
            f"the rare '{winner['status']}' outcome occurred once, as a serial baseline would — "
            "no race window observed."
        ),
    )


# --------------------------------------------------------------------------- #
# the job registry — stop is a flag, and setting it is ungated
# --------------------------------------------------------------------------- #
_jobs: dict[str, RaceJob] = {}
_stops: dict[str, threading.Event] = {}
_lock = threading.Lock()


def get(job_id: str) -> RaceJob | None:
    with _lock:
        return _jobs.get(job_id)


def list_jobs(session_id: str | None = None) -> list[RaceJob]:
    with _lock:
        jobs = list(_jobs.values())
    if session_id:
        jobs = [j for j in jobs if j.request.session_id == session_id]
    return sorted(jobs, key=lambda j: j.started_at, reverse=True)


def stop(job_id: str) -> RaceJob | None:
    """Stop an in-flight job. NOT GATED — the panic button, exactly like `stop_scan`.

    N synchronized requests may be in flight. A gate that could refuse to stop them would make the
    system less safe, which is the position every other stop in this codebase already takes.
    """
    with _lock:
        ev = _stops.get(job_id)
        job = _jobs.get(job_id)
    if ev is not None:
        ev.set()
    return job


# --------------------------------------------------------------------------- #
# scope
# --------------------------------------------------------------------------- #
def _scope_ok(req: RaceRequest, url: str) -> tuple[bool, str]:
    """Per-request scope check on the URL that goes on the WIRE. Same matcher as everywhere else."""
    if not req.engagement_id:
        return True, ""
    from . import engagement

    eng = engagement.get_active(req.engagement_id)
    if eng is None:
        return False, f"engagement {req.engagement_id!r} is not active"
    host = scope_mod.bare_host(url)
    if not host:
        return False, f"no host in {url!r}"
    if not engagement.resolved_scope(eng).in_scope(host):
        return False, f"{host} is out of scope for {req.engagement_id}"
    return True, ""


# --------------------------------------------------------------------------- #
# execution
# --------------------------------------------------------------------------- #
def _cookie_header(req: RaceRequest, url: str) -> str:
    if not req.use_cookie_jar:
        return ""
    try:
        from . import cookiejar

        jar = cookiejar.jar_for(req.session_id)
        return jar.select(url, repeater_mod.typed_cookie_names(req)).header
    except Exception:  # noqa: BLE001 - the jar must never take the race down
        return ""


def _job_spec(req: RaceRequest, n: int, mode: str, cookie_header: str) -> dict[str, Any]:
    """The JSON the engine reads on STDIN. The request bytes travel here, never on the argv."""
    headers = [[h.name, h.value] for h in req.headers if (h.name or "").strip()]
    if cookie_header:
        # One Cookie header, operator's first — RFC 6265 §5.4, the repeater's rule.
        typed = [h.value.strip().rstrip(";") for h in req.headers
                 if h.name.strip().lower() == "cookie" and h.value.strip()]
        merged = "; ".join(typed + [cookie_header])
        headers = [h for h in headers if h[0].strip().lower() != "cookie"]
        headers.append(["Cookie", merged])
    return {
        "url": req.url,
        "method": (req.method or "GET").strip().upper(),
        "headers": headers,
        "body": req.body or "",
        "mode": mode,
        "count": n,
        "insecure": bool(req.insecure),
        "follow_redirects": bool(req.follow_redirects),
        "timeout": config.clamp_timeout(req.timeout_seconds),
        "body_cap": RACE_BODY_CAP,
    }


def _engine_argv() -> list[str]:
    """``docker exec -i <open sandbox> race-singlepacket --job-stdin`` — argv-only, request on stdin."""
    return ["docker", "exec", "-i", *loot.exec_flags(loot.kali_workdir()),
            config.KALI_OPEN_CONTAINER, "race-singlepacket", "--job-stdin"]


def _parse_engine_output(stdout: str) -> tuple[RaceResult | None, list[RaceResult], str]:
    """``(baseline, results, error)`` from the engine's JSON. Never raises."""
    try:
        data = json.loads(stdout.strip().splitlines()[-1]) if stdout.strip() else {}
    except (ValueError, IndexError):
        return None, [], "engine produced no parseable JSON"
    if not isinstance(data, dict):
        return None, [], "engine JSON was not an object"

    def _one(d: dict[str, Any], idx: int) -> RaceResult:
        return RaceResult(
            index=idx,
            status=d.get("status"),
            size_bytes=int(d.get("size_bytes") or 0),
            time_ms=int(d.get("time_ms") or 0),
            body_excerpt=str(d.get("body") or "")[:RACE_BODY_CAP],
            error=str(d.get("error") or ""),
        )

    base = data.get("baseline")
    baseline = _one(base, -1) if isinstance(base, dict) else None
    results = [_one(r, i) for i, r in enumerate(data.get("results", []))
               if isinstance(r, dict)]
    return baseline, results, str(data.get("error") or "")


def _write_finding(req: RaceRequest, verdict: RaceVerdict) -> bool:
    """A confirmed race -> a Finding in engagement state. Best-effort; never takes the job down."""
    if not (verdict.race_detected and req.session_id):
        return False
    try:
        from state import store as state_store
        from state.models import Finding

        host = scope_mod.bare_host(req.url) or req.url
        state_store.upsert_findings([Finding(
            session_id=req.session_id,
            title="race condition — single-packet limit-overrun / TOCTOU",
            severity="high",
            target=host,
            evidence=(f"{verdict.won} of {verdict.of} synchronized requests landed the rare "
                      f"'{verdict.winning_status}' outcome a serial baseline returns once "
                      f"({req.method} {req.url}, mode {_mode_of(req)[0]})."),
            tool="race-singlepacket",
            vuln_class="race-condition",
            attacker_path=("Fire N identical requests in one packet (HTTP/2 single-packet or "
                           "HTTP/1.1 last-byte sync) so they arrive inside the target's "
                           "check-then-act window, redeeming a one-time action more than once."),
        )])
        return True
    except Exception:  # noqa: BLE001
        return False


def _run(job_id: str, req: RaceRequest, n: int, mode: str) -> None:
    """The worker. Scope-checks the wire URL, fires the batch through the engine, verdicts it."""
    stop_ev = _stops[job_id]

    # SCOPE ON THE WIRE, before anything is dispatched. All N share one URL, so one check refuses
    # the whole batch — nothing is sent when the host is out of scope.
    ok, why = _scope_ok(req, req.url)
    if not ok:
        with _lock:
            j = _jobs[job_id]
            j.scope_refusals = n
            j.warnings.append(f"URL host is off-scope: {why} — nothing was sent")
            j.state = "finished"
            j.finished_at = _now()
        return

    cookie_header = _cookie_header(req, req.url)
    spec = _job_spec(req, n, mode, cookie_header)
    timeout = config.clamp_timeout(req.timeout_seconds) + 30

    baseline: RaceResult | None = None
    results: list[RaceResult] = []
    engine_error = ""
    if not stop_ev.is_set():
        try:
            proc = subprocess.run(
                _engine_argv(), capture_output=True, text=True, timeout=timeout,
                input=json.dumps(spec),
            )
            baseline, results, engine_error = _parse_engine_output(proc.stdout)
            if not results and proc.returncode != 0 and not engine_error:
                engine_error = (proc.stderr or f"engine exited {proc.returncode}").strip()[:500]
        except subprocess.TimeoutExpired:
            engine_error = f"engine exceeded {timeout}s and was killed"
        except FileNotFoundError:
            engine_error = "docker CLI not found on PATH"

    verdict = race_verdict(results)
    # Mark the winning-cluster rows, so the table can point at the requests that won.
    if verdict.race_detected and verdict.winning_status is not None:
        for r in results:
            if r.status == verdict.winning_status and not r.error:
                r.won = True
    wrote = _write_finding(req, verdict)

    with _lock:
        j = _jobs[job_id]
        j.baseline = baseline
        j.results = results
        j.sent = len([r for r in results if r.status is not None or r.error])
        j.verdict = verdict
        j.finding_written = wrote
        if engine_error:
            j.warnings.append(engine_error)
        j.state = "stopped" if stop_ev.is_set() else "finished"
        j.finished_at = _now()
        snapshot = j.model_copy(deep=True)

    # Audit — one run record for the WHOLE job, because it was one approval. `args` carries the
    # method, the URL, the mode and the counts, and deliberately NOT the body or headers: report.py
    # renders a run record's command line verbatim into a report, and a race body is occasionally a
    # coupon code or a session-bound token.
    try:
        runstore.save_run(RunRecord(
            run_id=job_id, command="race-singlepacket",
            args=[req.method.upper(), req.url, f"mode={mode}", f"n={n}",
                  f"won={snapshot.verdict.won if snapshot.verdict else 0}"],
            target=scope_mod.bare_host(req.url) or req.url,
            approved=True,
            exit_code=0,
            stdout=_summarise(snapshot), stderr="",
            started_at=snapshot.started_at, finished_at=snapshot.finished_at,
            session_id=req.session_id, step_id=None,
        ))
    except Exception:  # noqa: BLE001 - an audit failure must not lose the results
        pass


def _summarise(job: RaceJob) -> str:
    """A table an operator (and a report) can read, instead of N raw bodies."""
    v = job.verdict
    lines = [
        f"race {job.id}: {job.sent} request(s) fired, mode={job.mode}",
    ]
    if job.baseline is not None:
        lines.append(f"serial baseline: status={job.baseline.status} size={job.baseline.size_bytes}")
    if v is not None:
        lines.append(v.note)
        if v.race_detected:
            lines.append(f"RACE: {v.won} of {v.of} requests won (status {v.winning_status}).")
        for c in v.clusters:
            lines.append(f"  cluster status={c['status']} size~{c['size']}B  x{c['count']}")
    if job.capped:
        lines.append("CAPPED: N was over the ceiling; not every request ran.")
    if job.scope_refusals:
        lines.append(f"{job.scope_refusals} request(s) not sent — URL host left scope.")
    return "\n".join(lines)


def start(req: RaceRequest) -> RaceJob:
    """Validate, then fire the whole batch in the background. THE GATE RUNS BEFORE ANYTHING FIRES.

    Refuses (nothing fired) on any of the four gates, on a non-http(s) URL, or if the open sandbox
    is down. Otherwise the job is registered `running` and a worker fires the synchronized batch,
    which is what makes `stop` meaningful: there is something to stop.
    """
    parsed = urlparse(req.url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise RaceRefused("input", f"URL must be an absolute http(s) URL — got {req.url!r}")

    verdict = validate(req)
    if verdict is not None and getattr(verdict, "rejected", False):
        raise RaceRefused(verdict.gate, verdict.reason, list(verdict.dangerous_flags or []))
    if not repeater_mod._container_running(config.KALI_OPEN_CONTAINER):
        raise RaceRefused(
            "unavailable",
            f"open sandbox '{config.KALI_OPEN_CONTAINER}' is not running — nothing was fired",
        )

    n, warnings, capped = plan(req)
    mode, _ = _mode_of(req)
    job_id = uuid.uuid4().hex[:12]
    job = RaceJob(
        id=job_id, request=req, container=config.KALI_OPEN_CONTAINER,
        started_at=_now(), mode=mode, planned=n, warnings=warnings, capped=capped,
    )
    with _lock:
        _jobs[job_id] = job
        _stops[job_id] = threading.Event()
    threading.Thread(target=_run, args=(job_id, req, n, mode), daemon=True,
                     name=f"race-{job_id}").start()
    return job


def status() -> dict[str, Any]:
    """Availability of the race tester's sandbox — drives the UI banner. Same box as the intruder."""
    up = repeater_mod._container_running(config.KALI_OPEN_CONTAINER)
    with _lock:
        running = sum(1 for j in _jobs.values() if j.state == "running")
    return {
        "container": config.KALI_OPEN_CONTAINER,
        "up": up, "ready": up, "running": running,
        "detail": "" if up else "open sandbox container is not running",
    }
