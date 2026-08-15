"""The intruder — one captured request, marked positions, a payload set, ONE approval.

*** WHY THIS FITS THE APPROVAL MODEL, WRITTEN DOWN SO NOBODY RE-LITIGATES IT. ***
HackPit refuses **batching across approvals** — an agent queueing five commands and a human
clicking once. It has never refused ONE approval that produces many requests, and could not:
`ffuf`, `nuclei` and the ZAP active scanner are each a single approval buying thousands of
requests, and the scanner's own measurement was 376 requests from one press. An intruder is that
same shape. It is ONE gated job, gated by the SAME four gates, with NO new ones.

THE PAYLOAD SET AND THE POSITIONS ARE PART OF THE APPROVED SURFACE. Crawl depth and duration are
in the spider's surface for the same reason: a fuzzer that decides its own bounds is a command
that has stopped describing what it will do. So :func:`intruder_argv_for` puts **every payload**
into the gate surface — not a count, not a sample.

*** AND THAT IS WHY THE SET IS NOT TRUNCATED THERE. ***
Rendering "…and 4,993 more" would let a payload carrying `| sh` sit at position 5,000 where the
danger heuristic cannot see it, while the human approves a summary. That is Critical 2 — the
gated argv is not the spawned argv — expressed in a payload list. Measured: the danger gate DOES
fire on payload content (`'| sh'` -> "reverse-shell / code-exec pattern"), so the surface being
complete is what makes that check real rather than decorative.

CONTAINMENT, inherited wholesale from the repeater and stated rather than assumed:

* **HARDCODED CONTAINER.** Every request runs inside ``config.KALI_OPEN_CONTAINER`` — the same
  box the repeater uses. NO new egress path is created, and the container is a code constant that
  no request field can redirect.
* **ARGV-ONLY curl**, body on stdin. No shell parses a payload. This matters more here than in
  the repeater, because a payload set is precisely where shell metacharacters live.
* **SCOPE-CHECKED PER REQUEST, ON THE SUBSTITUTED URL.** Not once at the start — a payload can
  contain a `.` and a `/`, and a marked span inside the host would otherwise send the substituted
  request somewhere the gate never saw. Build #18's rule: check the bytes that go on the wire.
* **STOP IS UNGATED**, like every other stop in this codebase. Thousands of requests are in
  flight; a gate that could refuse to stop them would make the system less safe.

WHAT IS DELIBERATELY NOT BUILT: `pitchfork` and `cluster bomb`, which need two or more
independent payload sets. They are a real thing an intruder does and they are left out, because
the combinatorics change what "the approved surface" means — a cluster bomb of two 1,000-entry
lists is a million requests from one press, and that deserves its own argument rather than being
inherited from this one. `sniper` and `battering-ram` cover the single-set cases.
"""

from __future__ import annotations

import subprocess
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Sequence

from pydantic import BaseModel, Field

from . import (
    config, loot, repeater as repeater_mod, runstore, scope as scope_mod, session_store, shaping,
)
from .models import RunRecord

#: Payload positions reuse the SHAPING marker, and that is one vocabulary rather than two.
#: `[[...]]` already means "the interesting span of this request" everywhere in the product; here
#: its contents are the BASELINE value and each payload replaces it. Inventing a second marker
#: would mean an operator's marked request meant a different thing in two panels.
POSITION_OPEN = shaping.SHAPE_OPEN
POSITION_CLOSE = shaping.SHAPE_CLOSE

#: Ceiling on requests one approved job may send. NOT a refusal to run — the job runs, sends this
#: many, and REPORTS that it stopped early (`capped`). A silent truncation would tell the operator
#: the payload set had been exhausted when it had not.
INTRUDER_MAX_REQUESTS = 10_000
#: Per-response body kept, in chars. An intruder result is read as a table of status and length;
#: keeping megabytes per row for thousands of rows is how a panel becomes unusable.
INTRUDER_BODY_CAP = 4_000

MODES = ("sniper", "battering-ram")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------- #
# positions
# --------------------------------------------------------------------------- #
def find_positions(text: str) -> list[tuple[int, int, str]]:
    """``[(start, end, baseline)]`` for every ``[[…]]`` span. PURE.

    An UNCLOSED marker is not a position — the same rule `shaping.apply_shapes` follows, and for
    the same reason: treating it as one would swallow the rest of the request into a payload slot.
    """
    out: list[tuple[int, int, str]] = []
    rest = text or ""
    offset = 0
    while True:
        start = rest.find(POSITION_OPEN, offset)
        if start == -1:
            return out
        end = rest.find(POSITION_CLOSE, start + len(POSITION_OPEN))
        if end == -1:
            return out
        out.append((start, end + len(POSITION_CLOSE),
                    rest[start + len(POSITION_OPEN):end]))
        offset = end + len(POSITION_CLOSE)


def substitute(text: str, payload: str, only_index: int | None = None) -> str:
    """Replace marked spans with ``payload``.

    ``only_index`` is SNIPER: that one position takes the payload and every other position takes
    its BASELINE value — not an empty string. A sniper run that blanked the other parameters would
    change two things at once and make every result uninterpretable.

    ``None`` is BATTERING-RAM: every position takes the payload.
    """
    positions = find_positions(text)
    if not positions:
        return text or ""
    out: list[str] = []
    cursor = 0
    for i, (start, end, baseline) in enumerate(positions):
        out.append((text or "")[cursor:start])
        out.append(payload if (only_index is None or i == only_index) else baseline)
        cursor = end
    out.append((text or "")[cursor:])
    return "".join(out)


def shape_payload(payload: str, shapes: list[str]) -> tuple[str, list[str]]:
    """One payload through build #18's value transforms, in order. ``(shaped, unknown_names)``.

    *** IT CALLS `shaping.VALUE_TRANSFORMS` DIRECTLY RATHER THAN `apply_shapes`. ***
    `apply_shapes` transforms the contents of `[[…]]` spans, and by the time a payload reaches
    here the span is what is being REPLACED — the marker is a position, not an annotation on this
    string. Routing through it would have required wrapping each payload in markers to unwrap
    them again, which is a second encoder wearing the first one's name. The transforms themselves
    are shared, which is what "do not grow a second encoder" was asking for.
    """
    unknown = [s for s in shapes if s not in shaping.VALUE_TRANSFORMS]
    out = payload
    for name in shapes:
        fn = shaping.VALUE_TRANSFORMS.get(name)
        if fn is not None:
            out = fn[0](out)
    return out, unknown


# --------------------------------------------------------------------------- #
# models
# --------------------------------------------------------------------------- #
class IntruderRequest(BaseModel):
    """One intruder job: a marked request, a payload set, and the gate fields."""

    url: str = Field(..., min_length=1, description="Absolute URL, `[[…]]` marking positions.")
    method: str = "GET"
    headers: list[repeater_mod.RepeaterHeader] = Field(default_factory=list)
    body: str = Field("", description="Request body; `[[…]]` marks positions here too.")
    payloads: list[str] = Field(
        default_factory=list,
        description="THE PAYLOAD SET, verbatim. Every entry goes into the approved surface — see "
        "the module docstring for why it is never summarised there.",
    )
    mode: str = Field(
        "sniper",
        description="sniper = one position at a time, others keep their baseline value. "
        "battering-ram = every position gets the same payload. An unknown mode falls back to "
        "sniper and SAYS SO; it does not refuse.",
    )
    shapes: list[str] = Field(
        default_factory=list,
        description="Build #18 value transforms applied to each payload before substitution.",
    )
    follow_redirects: bool = False
    insecure: bool = False
    impersonate: bool = Field(
        False,
        description="Send each payload as a real browser via curl-impersonate (curl_chrome116) to "
        "get past a WAF that fingerprints the TLS handshake and 403s a plain client. The ffuf "
        "'shape' shown for approval is a representation — the real sends are per-payload curl, "
        "which this impersonates; ffuf bulk fuzzing itself cannot JA3-impersonate.",
    )
    timeout_seconds: int | None = None
    delay_ms: int = Field(
        0, ge=0, le=60_000,
        description="Pause between requests. Pacing, not a control — 0 is allowed and is the "
        "default, because an edge that needs pacing is a property of the target, not a rule.",
    )
    engagement_id: str | None = None
    session_id: str | None = None
    use_cookie_jar: bool = Field(
        True, description="Attach the repeater's session jar. Most fuzzing is authenticated."
    )
    attach_session: bool = Field(
        False,
        description="Also merge the engagement's stored operator session (session_store) into every "
        "send — the same authenticated mechanism the scan surfaces use. Typed headers win; the "
        "session is added at SEND time only, so the token never enters the job record. Login stays human.",
    )
    # THE GATE FIELDS — the scanner's, unchanged. Both default False so an omitted field is
    # REFUSED rather than granted.
    approved: bool = Field(False, description="Explicit human approval. Never defaulted true.")
    dangerous_ack: bool = Field(
        False,
        description="The red-confirm, WHEN THE GATE ASKS FOR IT. It is not demanded by this "
        "model: the four gates decide, and they were measured firing on payload CONTENT (a "
        "payload carrying '| sh' trips 'reverse-shell / code-exec pattern'). Requiring it "
        "unconditionally here would be this build adding a confirm, which it may not.",
    )


class IntruderResult(BaseModel):
    """One request in the job. No response headers — a table of thousands needs a table's shape."""

    index: int
    payload: str = Field(description="The payload AS SENT, i.e. after shaping.")
    position: int = Field(0, description="Which marked position it went into (sniper).")
    url: str = ""
    status: int | None = None
    size_bytes: int = 0
    time_ms: int = 0
    body_excerpt: str = ""
    error: str = ""
    #: *** THE INTERESTING COLUMN. *** A fuzzer's signal is a row that DIFFERS from the others,
    #: so the baseline is recorded once and every row is compared against it rather than the
    #: operator eyeballing 5,000 sizes.
    differs_from_baseline: bool = False


class IntruderJob(BaseModel):
    """The job. Counts are what HAPPENED, never what was planned."""

    id: str
    state: str = Field("running", description="running | finished | stopped | refused")
    request: IntruderRequest
    container: str = ""
    started_at: str = ""
    finished_at: str = ""
    positions: int = 0
    planned: int = Field(0, description="Requests this job intends to send.")
    sent: int = Field(0, description="Requests actually sent. Below `planned` means stopped.")
    results: list[IntruderResult] = Field(default_factory=list)
    baseline: IntruderResult | None = Field(
        None, description="The request with every position at its BASELINE value, sent FIRST. "
        "Without it 'this row is interesting' has nothing to be interesting against."
    )
    capped: bool = Field(
        False, description="True when the payload set was longer than INTRUDER_MAX_REQUESTS and "
        "the job stopped at the ceiling. Reported, never silent."
    )
    warnings: list[str] = Field(default_factory=list)
    scope_refusals: int = Field(
        0, description="Requests NOT sent because the substituted URL left the engagement scope. "
        "The job continues; each one is counted and the reason is in `warnings`."
    )


class IntruderRefused(RuntimeError):
    """Refused BEFORE anything ran. Carries the gate that refused it."""

    def __init__(self, gate: str, reason: str, dangerous_flags: list[str] | None = None) -> None:
        super().__init__(reason)
        self.gate = gate
        self.reason = reason
        self.dangerous_flags = dangerous_flags or []


# --------------------------------------------------------------------------- #
# the gate — THE SCANNER'S FOUR, UNCHANGED
# --------------------------------------------------------------------------- #
def intruder_argv_for(req: IntruderRequest) -> list[str]:
    """The command this job is EQUIVALENT TO, which is what the human approves.

    ``ffuf`` because that IS the shape — a marked request and a wordlist. NOT because it is
    "allowed": there is no tool allowlist in this product, and the module whose name suggests one
    says so itself ("Informational only ... NOT an allowlist; anything may run"). The gates are
    approval, target, danger and isolation, and none of them consults a list of binaries — so the
    only thing the declared command has to be is HONEST, because that string is what a human
    approves and what the danger heuristic reads.

    The positions travel as the marked URL and body, so the surface shows WHERE the payloads
    land, and every payload travels verbatim so the heuristic reads the same bytes that get sent.
    """
    argv = ["ffuf", "-u", req.url]
    if req.method.strip().upper() != "GET":
        argv += ["-X", req.method.strip().upper()]
    if req.body:
        argv += ["-d", req.body]
    argv += ["-mode", req.mode]
    for p in req.payloads:
        argv += ["-w", p]
    return argv


def _gate_request(req: IntruderRequest):
    from .models import ExecRequest

    argv = intruder_argv_for(req)
    return ExecRequest(
        command=argv[0], args=argv[1:],
        approved=req.approved, dangerous_ack=req.dangerous_ack,
        engagement_id=req.engagement_id,
    )


def validate(req: IntruderRequest):
    """The gate verdict, attacking nothing. PURE. Returns None when it passes.

    All four gates, in the executor's order, unchanged and with nothing added. This function
    exists so a UI can ask "would this be refused" without launching anything — the same split
    `validate_scan` makes.
    """
    from . import executor

    return executor.validate_request(_gate_request(req))


# --------------------------------------------------------------------------- #
# planning — PURE, so what will be sent is inspectable before anything is
# --------------------------------------------------------------------------- #
def plan(req: IntruderRequest) -> tuple[list[tuple[int, str]], list[str], bool]:
    """``([(position_index, shaped_payload)], warnings, capped)``. Sends nothing.

    WARN AND CONTINUE throughout. No positions marked, an unknown mode, an unknown shape name —
    each is reported and the job still runs with the honest interpretation. A job refused for a
    typo would be a prohibition invented by the tooling.
    """
    warnings: list[str] = []
    positions = max(len(find_positions(req.url)) + len(find_positions(req.body)), 0)
    mode = (req.mode or "").strip().lower()
    if mode not in MODES:
        warnings.append(
            f"unknown mode {req.mode!r} — running as 'sniper'. Known: {', '.join(MODES)}"
        )
        mode = "sniper"
    if positions == 0:
        warnings.append(
            f"no {POSITION_OPEN}…{POSITION_CLOSE} position marked in the URL or body — every "
            "request would be identical, so the payload set was NOT expanded. Mark a position "
            "and run again."
        )
        return [], warnings, False
    if not req.payloads:
        warnings.append("the payload set is empty — nothing to send beyond the baseline")
        return [], warnings, False

    unknown_seen: set[str] = set()
    shaped: list[str] = []
    for p in req.payloads:
        out, unknown = shape_payload(p, req.shapes)
        unknown_seen.update(unknown)
        shaped.append(out)
    for name in sorted(unknown_seen):
        warnings.append(
            f"unknown shape {name!r} — skipped. Known: "
            f"{', '.join(sorted(shaping.VALUE_TRANSFORMS))}"
        )

    jobs: list[tuple[int, str]] = []
    if mode == "battering-ram":
        jobs = [(-1, p) for p in shaped]
    else:
        for pos in range(positions):
            jobs.extend((pos, p) for p in shaped)

    capped = len(jobs) > INTRUDER_MAX_REQUESTS
    if capped:
        warnings.append(
            f"{len(jobs)} requests planned, which is over the {INTRUDER_MAX_REQUESTS} ceiling — "
            f"the job will send the first {INTRUDER_MAX_REQUESTS} and report `capped`. It is NOT "
            "refused, and nothing is silently dropped."
        )
        jobs = jobs[:INTRUDER_MAX_REQUESTS]
    return jobs, warnings, capped


# --------------------------------------------------------------------------- #
# the job registry — stop is a flag, and setting it is ungated
# --------------------------------------------------------------------------- #
_jobs: dict[str, IntruderJob] = {}
_stops: dict[str, threading.Event] = {}
_lock = threading.Lock()


def get(job_id: str) -> IntruderJob | None:
    with _lock:
        return _jobs.get(job_id)


def list_jobs(session_id: str | None = None) -> list[IntruderJob]:
    with _lock:
        jobs = list(_jobs.values())
    if session_id:
        jobs = [j for j in jobs if j.request.session_id == session_id]
    return sorted(jobs, key=lambda j: j.started_at, reverse=True)


def stop(job_id: str) -> IntruderJob | None:
    """Stop an in-flight job. NOT GATED — this is the panic button, like `stop_scan`.

    Thousands of requests may be queued behind this call. A gate that could refuse to stop them
    would make the system less safe, which is the position every other stop in this codebase
    already takes.
    """
    with _lock:
        ev = _stops.get(job_id)
        job = _jobs.get(job_id)
    if ev is not None:
        ev.set()
    return job


# --------------------------------------------------------------------------- #
# execution
# --------------------------------------------------------------------------- #
def _send_one(
    req: IntruderRequest, url: str, body: str, cookie_header: str,
    extra_headers: "Sequence[tuple[str, str]]" = (),
) -> dict[str, Any]:
    """One curl, argv-only, inside the open sandbox. Returns a small dict, never raises.

    ``extra_headers`` (the operator's attached session, resolved once in :func:`_run`) is merged in
    HERE, at send time — typed headers win — so the token authenticates the send without ever being
    stored in the job's ``request``."""
    headers = list(req.headers)
    if extra_headers:
        headers += [
            repeater_mod.RepeaterHeader(name=n, value=v)
            for (n, v) in session_store.additional_session_headers([h.name for h in req.headers], extra_headers)
        ]
    sentinel = repeater_mod._SENTINEL_TMPL.format(uuid.uuid4().hex)
    probe = repeater_mod.RepeaterRequest(
        method=req.method, url=url, headers=headers, body=body,
        follow_redirects=req.follow_redirects, insecure=req.insecure,
        timeout_seconds=req.timeout_seconds,
    )
    argv = ["docker", "exec", "-i", *loot.exec_flags(loot.kali_workdir()),
            config.KALI_OPEN_CONTAINER,
            *repeater_mod._build_curl(probe, sentinel, url=url, has_body=bool(body),
                                      cookie_header=cookie_header, impersonate=req.impersonate)]
    timeout = config.clamp_timeout(req.timeout_seconds) + 15
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                              input=body if body else None)
    except subprocess.TimeoutExpired:
        return {"error": f"exceeded {timeout}s"}
    except FileNotFoundError:
        return {"error": "docker CLI not found on PATH"}
    resp = repeater_mod._parse_response(proc.stdout, sentinel)
    err = ""
    if proc.returncode != 0 and resp.status is None:
        err = (proc.stderr or f"curl exited {proc.returncode}").strip()[:500]
    return {
        "status": resp.status, "size_bytes": resp.size_bytes, "time_ms": resp.time_ms,
        "body": resp.body[:INTRUDER_BODY_CAP], "error": err,
    }


def _scope_ok(req: IntruderRequest, url: str) -> tuple[bool, str]:
    """Per-request scope check on the SUBSTITUTED url. Same matcher as everywhere else."""
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


def _run(job_id: str, req: IntruderRequest, work: list[tuple[int, str]]) -> None:
    """The worker. Sends the baseline first, then every planned request. Never raises."""
    from . import cookiejar

    stop_ev = _stops[job_id]
    jar = cookiejar.jar_for(req.session_id) if req.use_cookie_jar else None
    # Authenticated fuzzing via the attached operator session — resolved once, merged per send.
    extra = session_store.header_pairs(req.engagement_id) if req.attach_session else []

    def cookie_for(url: str) -> str:
        if jar is None:
            return ""
        return jar.select(url, repeater_mod.typed_cookie_names(req)).header

    def record(index: int, position: int, payload: str, url: str, body: str) -> IntruderResult:
        ok, why = _scope_ok(req, url)
        if not ok:
            with _lock:
                j = _jobs[job_id]
                j.scope_refusals += 1
                if len(j.warnings) < 20:
                    j.warnings.append(f"payload {payload!r} moved the request off-scope: {why}")
            return IntruderResult(index=index, payload=payload, position=position, url=url,
                                  error=f"NOT SENT — {why}")
        out = _send_one(req, url, body, cookie_for(url), extra)
        return IntruderResult(
            index=index, payload=payload, position=position, url=url,
            status=out.get("status"), size_bytes=int(out.get("size_bytes") or 0),
            time_ms=int(out.get("time_ms") or 0), body_excerpt=str(out.get("body") or ""),
            error=str(out.get("error") or ""),
        )

    # THE BASELINE FIRST. Every position at the value it already had, markers stripped — which is
    # exactly `shaping.strip_markers`, the same control half build #18 established for shaped
    # sends. Without it "this response is different" has nothing to be different from.
    base_url = shaping.strip_markers(req.url)
    base_body = shaping.strip_markers(req.body)
    baseline = record(-1, -1, "(baseline)", base_url, base_body)
    with _lock:
        _jobs[job_id].baseline = baseline

    for i, (position, payload) in enumerate(work):
        if stop_ev.is_set():
            break
        only = None if position < 0 else position
        url_positions = len(find_positions(req.url))
        if only is None:
            url = substitute(req.url, payload)
            body = substitute(req.body, payload)
        elif only < url_positions:
            url = substitute(req.url, payload, only)
            body = shaping.strip_markers(req.body)
        else:
            url = shaping.strip_markers(req.url)
            body = substitute(req.body, payload, only - url_positions)
        res = record(i, position, payload, url, body)
        res.differs_from_baseline = (
            res.status != baseline.status
            or abs(res.size_bytes - baseline.size_bytes) > 16
        )
        with _lock:
            j = _jobs[job_id]
            j.results.append(res)
            j.sent += 1
        if req.delay_ms:
            time.sleep(req.delay_ms / 1000.0)

    with _lock:
        j = _jobs[job_id]
        j.state = "stopped" if stop_ev.is_set() else "finished"
        j.finished_at = _now()
        snapshot = j.model_copy(deep=True)

    # Audit — one run record for the WHOLE job, because it was one approval. `args` carries the
    # method, the marked URL and the counts, and deliberately NOT the payloads: report.py renders
    # a run record's command line verbatim into a report, and a payload set is both enormous and
    # occasionally a credential list.
    try:
        runstore.save_run(RunRecord(
            run_id=job_id, command="intruder",
            args=[req.method.upper(), shaping.strip_markers(req.url),
                  f"mode={req.mode}", f"sent={snapshot.sent}"],
            target=scope_mod.bare_host(base_url) or base_url,
            approved=True,
            exit_code=0,
            stdout=_summarise(snapshot), stderr="",
            started_at=snapshot.started_at, finished_at=snapshot.finished_at,
            session_id=req.session_id, step_id=None,
        ))
    except Exception:  # noqa: BLE001 - an audit failure must not lose the results
        pass


def _summarise(job: IntruderJob) -> str:
    """A table an operator (and a report) can read, instead of thousands of raw bodies."""
    lines = [
        f"intruder {job.id}: {job.sent} request(s), mode={job.request.mode}, "
        f"{job.positions} position(s)",
    ]
    if job.baseline is not None:
        lines.append(f"baseline: status={job.baseline.status} size={job.baseline.size_bytes}")
    interesting = [r for r in job.results if r.differs_from_baseline]
    lines.append(f"differing from baseline: {len(interesting)} of {len(job.results)}")
    for r in interesting[:100]:
        lines.append(f"  [{r.index}] {r.payload!r} -> {r.status} {r.size_bytes}B {r.time_ms}ms")
    if len(interesting) > 100:
        lines.append(f"  …and {len(interesting) - 100} more differing rows")
    if job.capped:
        lines.append("CAPPED: the payload set was longer than the ceiling; not every one ran.")
    if job.scope_refusals:
        lines.append(f"{job.scope_refusals} request(s) not sent — substituted URL left scope.")
    return "\n".join(lines)


def start(req: IntruderRequest) -> IntruderJob:
    """Validate, then run the whole set in the background. THE GATE RUNS BEFORE ANYTHING SENDS.

    Refuses (nothing sent) on any of the four gates, or if the open sandbox is down. Otherwise
    the job is registered `running` and a worker thread sends the baseline and then every planned
    request, which is what makes `stop` meaningful: there is something to stop.
    """
    verdict = validate(req)
    if verdict is not None and getattr(verdict, "rejected", False):
        raise IntruderRefused(verdict.gate, verdict.reason, list(verdict.dangerous_flags or []))
    if not repeater_mod._container_running(config.KALI_OPEN_CONTAINER):
        raise IntruderRefused(
            "unavailable",
            f"open sandbox '{config.KALI_OPEN_CONTAINER}' is not running — nothing was sent",
        )

    work, warnings, capped = plan(req)
    job_id = uuid.uuid4().hex[:12]
    job = IntruderJob(
        id=job_id, request=req, container=config.KALI_OPEN_CONTAINER,
        started_at=_now(),
        positions=len(find_positions(req.url)) + len(find_positions(req.body)),
        planned=len(work), warnings=warnings, capped=capped,
    )
    with _lock:
        _jobs[job_id] = job
        _stops[job_id] = threading.Event()
    threading.Thread(target=_run, args=(job_id, req, work), daemon=True,
                     name=f"intruder-{job_id}").start()
    return job


def status() -> dict[str, Any]:
    """Availability of the intruder's sandbox — drives the UI banner. Same box as the repeater."""
    up = repeater_mod._container_running(config.KALI_OPEN_CONTAINER)
    with _lock:
        running = sum(1 for j in _jobs.values() if j.state == "running")
    return {
        "container": config.KALI_OPEN_CONTAINER,
        "up": up, "ready": up, "running": running,
        "detail": "" if up else "open sandbox container is not running",
    }
