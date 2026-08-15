"""JavaScript recon -> mined endpoints/params + secrets (:jsrecon — a :recon sibling).

*** WHY THIS IS ONE GATED JOB WITH NO NEW GATE, WRITTEN DOWN SO NOBODY RE-LITIGATES IT. ***
Pulling a target's JavaScript (bundles + source maps) and mining ENDPOINTS, PARAMETERS and
SECRETS / API keys out of it is the manual step every hunt does by hand today (the S3→bundle→secret
chain was conceptual; nothing mined a live target's JS as a surface). It is the SAME shape :recon
already runs: ONE human approval buys a fetch+mine job that sends many requests — exactly like ffuf,
nuclei, the intruder, :recon's own sweep and :discover, each a single approval buying many. So this
module adds NO new gate: one job, gated by the SAME ``executor.validate_request`` every command
clears, run BEFORE anything spawns, with an UNGATED stop.

*** ENGINE-ON-STDIN, mirroring :cache/:race/:smuggle. ***
The mining runs inside the engagement sandbox as ``docker exec -i <sandbox> js-mine --job-stdin``,
the in-repo engine (docker/js_mine.py) with a stable JSON contract. getjs/subjs/LinkFinder/
SecretFinder/trufflehog/sourcemapper are the standard external tools, installed alongside for MANUAL
use and named in tools.json; the engine gives the GATED job a headless miner the backend can parse —
and trufflehog is folded into the engine BEST-EFFORT to mark VERIFIED keys.

*** SCOPE-SAFETY BY CONSTRUCTION, mirroring :recon/:discover — two filters, neither an extra gate. ***
  * OPERATOR INPUTS ARE SCOPE-LOCKED BEFORE THE JOB RUNS. The collection target and any explicitly
    named JS URL are checked against the engagement scope in :func:`start`; a job can never be
    pointed off-scope. (URLs :recon/:discover already put in state are in-scope already.)
  * EVERY CANDIDATE JS URL AND EVERY MINED URL/HOST IS SCOPE-FILTERED BEFORE IT LANDS. JS URLs
    collected from a page (a ``<script src>`` to a third-party CDN) and URLs mined from inside a
    bundle routinely point at other hosts; :func:`filter_urls_in_scope` /
    :func:`filter_endpoints_in_scope` drop any whose host the scope does not cover, so ONLY in-scope
    JS is ever fetched and ONLY in-scope mined endpoints reach the surface, the loot or state.

*** SECRETS -> LOOT, NEVER FINDING TEXT (mirror :credentials). ***
A found secret's VALUE is written to a loot file; the Finding names the TYPE, the source URL, a
MASKED preview and the loot path — never the value (report.py renders findings verbatim). A
trufflehog-VERIFIED key is High; an unverified regex match is Low (confirm before reporting).

THE SPLIT, mirroring recon/discover/cache:

  * PURE, INSPECTABLE HALF — the ``*_argv`` builders, :func:`filter_urls_in_scope`,
    :func:`filter_endpoints_in_scope`, :func:`parse_mine_output`, :func:`_secret_finding`,
    :func:`_mask`, :func:`_to_mined_*`. They build argv, sort by scope and label rows; they execute
    NOTHING. Regression-locked in test_jsrecon_safety.py by an AST walk.
  * THE WORKER — :func:`start` validates through the gate BEFORE anything spawns and scope-locks the
    target, then a background thread runs the collect + mine ``docker exec``s in the engagement
    sandbox, scope-filters what comes back, upserts only in-scope endpoints (which raise the host's
    rank in the :recon surface) and writes secrets to loot + Findings.
"""

from __future__ import annotations

import json
import re
import subprocess
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable, Sequence

from pydantic import BaseModel, Field

from state import store as state_store
from state.models import Endpoint, Finding
from state.parsers import parse_jsmine

from . import (
    config, engagement, loot, repeater as repeater_mod, runstore, scope as scope_mod, session_store,
)
from .models import RunRecord

#: The engine command the job runs, and the honest name the gate surface carries.
ENGINE = "js-mine"
#: Per-job transcript kept, in chars — a mining transcript, not a data feed.
_OUTPUT_CAP = 400_000
#: How many JS URLs one approved job will fetch+mine. A broad crawl can list hundreds of bundles;
#: bounded so one approval does not turn into an unbounded fetch storm. Truncation is REPORTED.
JS_URL_CAP = 60
#: How many collection seeds one job accepts (target + operator seeds). Bounded, same reasoning.
SEED_CAP = 20


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _dedupe(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for it in items:
        it = (it or "").strip()
        if it and it.lower() not in seen:
            seen.add(it.lower())
            out.append(it)
    return out


# --------------------------------------------------------------------------- #
# models
# --------------------------------------------------------------------------- #
class JsReconRequest(BaseModel):
    """One JS-recon job: what to collect JS from / mine, and the gate fields."""

    target: str = Field(
        "", description="An in-scope page or host to COLLECT JS from (its <script src> set). Its "
        "host is scope-locked before anything runs. EMPTY = collect nothing, mine only `js_urls`.")
    js_urls: list[str] = Field(
        default_factory=list,
        description="Explicit in-scope JS URLs to fetch+mine directly. Each host is scope-locked "
        "before the job runs. Handy for a bundle you already found in :recon / the proxy history.")
    include_state: bool = Field(
        True, description="Also mine the `.js` endpoints already in this session's state (from a "
        ":recon sweep / the proxy). They are in-scope already; still scope-filtered.")
    maps: bool = Field(
        True, description="Fetch + unpack source maps (recover original source paths/comments and "
        "mine the recovered source too). The bonus half — safe to leave on.")
    verify: bool = Field(
        True, description="Fold trufflehog in (best-effort) to mark VERIFIED keys High. Off = "
        "regex-only mining, everything unverified.")
    insecure: bool = Field(False, description="Skip TLS verification when fetching JS (staging certs).")
    rate_limit: int | None = Field(
        None, ge=1, le=100000, description="Advisory only for JS recon (pacing lives in the engine).")
    timeout_seconds: int | None = None
    engagement_id: str | None = None
    session_id: str | None = None
    attach_session: bool = Field(
        False,
        description="Fetch JS AS the logged-in operator — the engagement's stored session "
        "(session_store) is added to the engine's fetch, so login-gated bundles are collected + "
        "mined. The operator's OWN session; it rides in the STDIN job spec, never the argv/record.",
    )
    # THE GATE FIELDS — the executor's, unchanged. Both default False so an omitted field is
    # REFUSED rather than granted.
    approved: bool = Field(False, description="Explicit human approval. Never defaulted true.")
    dangerous_ack: bool = Field(
        False, description="The red-confirm, WHEN THE GATE ASKS FOR IT — decided by the four gates.")


class JsReconStage(BaseModel):
    """One engine call inside a job — what it was and what happened."""

    tool: str
    argv: list[str] = Field(default_factory=list)
    state: str = Field("ran", description="ran | stopped | skipped")
    note: str = ""


class MinedEndpoint(BaseModel):
    """One endpoint mined from JS + the pre-filled hand-offs. Tagged source `js`."""

    url: str
    params: list[str] = Field(default_factory=list)
    source_url: str = Field("", description="The JS file it was mined from.")
    tag: str = "js"
    #: HAND-OFFS — pre-filled, never fired.
    nuclei_target: str = ""
    repeater_url: str = ""


class MinedSecret(BaseModel):
    """One secret/API key found in JS — its TYPE + location, NEVER its value.

    The value lives ONLY in the loot file (mirror :credentials). ``masked`` is a value-free preview
    (first/last few chars) so the operator can recognise it; a test pins that no field carries the
    real secret."""

    type: str
    source_url: str = ""
    verified: bool = False
    masked: str = ""
    loot_file: str = ""


class RecoveredSource(BaseModel):
    """A JS file's recovered source map — original paths + top-of-file comments."""

    js_url: str
    map_url: str = ""
    recovered_sources: list[str] = Field(default_factory=list)
    comments: list[str] = Field(default_factory=list)


class JsReconJob(BaseModel):
    """One JS-recon job. Counts are what HAPPENED, never what was planned."""

    id: str
    state: str = Field("running", description="running | finished | stopped | refused")
    argv: list[str] = Field(default_factory=list, description="The approved entry command line.")
    target: str = ""
    container: str = ""
    engagement_id: str | None = None
    session_id: str | None = None
    started_at: str = ""
    finished_at: str = ""
    stages: list[JsReconStage] = Field(default_factory=list)
    js_urls_mined: list[str] = Field(default_factory=list, description="The in-scope JS actually mined.")
    endpoints: list[MinedEndpoint] = Field(default_factory=list)
    secrets: list[MinedSecret] = Field(default_factory=list)
    recovered_sources: list[RecoveredSource] = Field(default_factory=list)
    discovered_out_of_scope: list[str] = Field(
        default_factory=list, description="JS URLs / mined hosts surfaced READ-ONLY — never fetched, "
        "never handed off, never upserted.")
    new_endpoints: int = 0
    new_findings: int = 0
    secrets_found: int = 0
    verified_secrets: int = 0
    loot_file: str = Field("", description="Loot path the secret VALUES were written to (container path).")
    output_tail: str = ""
    warnings: list[str] = Field(default_factory=list)
    refused: str = Field("", description="Set when a gate refused the job — the reason.")
    refused_gate: str = ""


class JsReconRefused(RuntimeError):
    """Refused BEFORE anything ran. Carries the gate that refused it."""

    def __init__(self, gate: str, reason: str, dangerous_flags: list[str] | None = None) -> None:
        super().__init__(reason)
        self.gate = gate
        self.reason = reason
        self.dangerous_flags = dangerous_flags or []


# --------------------------------------------------------------------------- #
# PURE: argv builders + the engine job specs. Never a shell.
# --------------------------------------------------------------------------- #
def gate_argv(req: "JsReconRequest") -> list[str]:
    """The command a job is APPROVED as: ``js-mine --mine -u <each in-scope target/js url>``.

    ``js-mine`` because that IS what runs. Every operator-named host (the collection target + each
    explicit JS URL) rides as ``-u`` so the target handrail and the danger heuristic read the same
    hosts that go out — the honest surface (recon's subfinder / cache's -u rule). The engine reads
    the URL set on STDIN, never the argv, so no URL byte reaches a shell.
    """
    argv = [ENGINE, "--mine"]
    hosts = _dedupe(([req.target] if (req.target or "").strip() else [])
                    + [u for u in req.js_urls if (u or "").strip()])
    for u in hosts[:JS_URL_CAP]:
        argv += ["-u", u.strip()]
    if req.maps:
        argv += ["--maps"]
    if req.verify:
        argv += ["--verify"]
    return argv


def collect_job_spec(
    seeds: list[str], req: "JsReconRequest", extra_headers: "Sequence[tuple[str, str]]" = ()
) -> dict[str, Any]:
    """The JSON the engine's COLLECT action reads on stdin. ``extra_headers`` (the operator's attached
    session, resolved by the caller — this stays PURE) authenticate the fetch; they ride on STDIN, so
    the token never reaches the argv/job record."""
    spec: dict[str, Any] = {"action": "collect", "seed_urls": seeds,
                            "timeout": config.clamp_timeout(req.timeout_seconds),
                            "insecure": bool(req.insecure)}
    if extra_headers:
        spec["headers"] = [[n, v] for n, v in extra_headers]
    return spec


def mine_job_spec(
    js_urls: list[str], req: "JsReconRequest", extra_headers: "Sequence[tuple[str, str]]" = ()
) -> dict[str, Any]:
    """The JSON the engine's MINE action reads on stdin. ``extra_headers`` authenticate the fetch on
    STDIN (never the argv)."""
    spec: dict[str, Any] = {"action": "mine", "js_urls": js_urls, "maps": bool(req.maps),
                            "verify": bool(req.verify),
                            "timeout": config.clamp_timeout(req.timeout_seconds),
                            "insecure": bool(req.insecure)}
    if extra_headers:
        spec["headers"] = [[n, v] for n, v in extra_headers]
    return spec


# --------------------------------------------------------------------------- #
# PURE: scope discipline — the correctness property, testable with no Docker
# --------------------------------------------------------------------------- #
def _endpoint_host(url: str) -> str:
    return scope_mod.bare_host(url).lower()


def filter_urls_in_scope(
    urls: list[str], matcher: scope_mod.ResolvedScope
) -> tuple[list[str], list[str]]:
    """Split candidate JS URLs by the scope. IN-scope URLs are kept (they may be fetched); OUT-of-
    scope hosts are collected read-only and their URLs dropped. This is what keeps an out-of-scope
    ``<script src>`` from ever being fetched. PURE."""
    kept: list[str] = []
    out_hosts: list[str] = []
    for u in _dedupe(urls):
        host = _endpoint_host(u)
        if host and matcher.in_scope(host):
            kept.append(u)
        elif host and host not in out_hosts:
            out_hosts.append(host)
    return kept, out_hosts


def filter_endpoints_in_scope(
    endpoints: list[Endpoint], matcher: scope_mod.ResolvedScope
) -> tuple[list[Endpoint], list[str]]:
    """Split mined endpoints by the scope. IN-scope endpoints are kept (they may enter state and be
    handed off); OUT-of-scope hosts are collected read-only and their endpoints dropped. This is what
    keeps a URL mined from inside a bundle but pointing at another host out of the surface. PURE."""
    kept: list[Endpoint] = []
    out_hosts: list[str] = []
    for e in endpoints:
        host = _endpoint_host(e.url)
        if host and matcher.in_scope(host):
            kept.append(e)
        elif host and host not in out_hosts:
            out_hosts.append(host)
    return kept, out_hosts


def _mask(value: str) -> str:
    """A value-free preview of a secret — first/last chars only, length hinted. NEVER the value. PURE."""
    v = (value or "").strip()
    if not v:
        return ""
    if len(v) <= 8:
        return f"{v[0]}…({len(v)} chars)"
    return f"{v[:4]}…{v[-2:]} ({len(v)} chars)"


def parse_mine_output(stdout: str) -> tuple[list[Endpoint], list[dict[str, Any]], list[dict[str, Any]], str]:
    """The engine's mine JSON -> (endpoints, secret dicts, source-map dicts, error). Never raises.

    Endpoints are parsed by :func:`state.parsers.parse_jsmine` (hand-parsed, urllib-ban-safe) so the
    one place a JS endpoint becomes a surface record is shared with a plain-terminal ``js-mine`` run.
    Secrets keep their VALUE here (the worker writes it to loot then drops it); each is tagged with
    its source JS URL. Source-map dicts carry the recovered original paths + comments.
    """
    text = (stdout or "").strip()
    if not text:
        return [], [], [], "engine produced no output"
    try:
        data = json.loads(text.splitlines()[-1])
    except (ValueError, IndexError):
        return [], [], [], "engine produced no parseable JSON"
    if not isinstance(data, dict):
        return [], [], [], "engine JSON was not an object"
    err = str(data.get("error") or "")
    results = data.get("results")
    if not isinstance(results, list):
        return [], [], [], err or "engine JSON carried no results array"

    endpoints = parse_jsmine(text, "", None).endpoints  # session_id filled by the caller on upsert
    secrets: list[dict[str, Any]] = []
    maps: list[dict[str, Any]] = []
    for r in results:
        if not isinstance(r, dict):
            continue
        src = str(r.get("url") or "")
        for s in (r.get("secrets") or []):
            if isinstance(s, dict) and str(s.get("value") or ""):
                secrets.append({
                    "type": str(s.get("type") or "secret"),
                    "value": str(s.get("value")),
                    "verified": bool(s.get("verified")),
                    "context": str(s.get("context") or ""),
                    "source_url": src,
                })
        sm = r.get("source_map")
        if isinstance(sm, dict) and (sm.get("recovered_sources") or sm.get("comments")):
            maps.append({
                "js_url": src,
                "map_url": str(sm.get("map_url") or ""),
                "recovered_sources": [str(x) for x in (sm.get("recovered_sources") or [])][:500],
                "comments": [str(x) for x in (sm.get("comments") or [])][:40],
            })
    return endpoints, secrets, maps, err


def _secret_finding(secret: dict[str, Any], loot_file: str, session_id: str,
                    run_id: str | None) -> Finding:
    """A found secret -> a Finding whose text carries the TYPE + source + MASKED preview + loot path,
    NEVER the value (mirror :credentials; report.py renders findings verbatim). PURE.

    A trufflehog-VERIFIED key is High; an unverified regex match is Low (confirm before reporting)."""
    stype = str(secret.get("type") or "secret")
    src = str(secret.get("source_url") or "")
    verified = bool(secret.get("verified"))
    host = _endpoint_host(src) or src
    sev = "high" if verified else "low"
    vlabel = "VERIFIED (trufflehog confirmed it authenticates)" if verified else \
        "unverified regex match — confirm before reporting"
    return Finding(
        session_id=session_id,
        title=f"Secret in client JavaScript: {stype} ({'verified' if verified else 'unverified'})",
        severity=sev,
        target=host,
        evidence=(f"A {stype} was found in {src or 'a mined JS bundle'} — {vlabel}. The value is in "
                  f"the loot file {loot_file} ({_mask(secret.get('value', ''))}); it is deliberately "
                  "NOT reproduced here."),
        tool="js-mine",
        vuln_class="exposed-secret",
        reference="CWE-615",
        attacker_path=(
            "Pull the target's JavaScript bundles (and their source maps), grep the shipped code for "
            "hardcoded API keys / tokens / credentials, then use the key directly against the service "
            "it authenticates to — a secret in client JS is readable by anyone who loads the page."),
        source_refs=[src] if src else [],
    )


def _to_mined_secret(secret: dict[str, Any], loot_file: str) -> MinedSecret:
    return MinedSecret(
        type=str(secret.get("type") or "secret"),
        source_url=str(secret.get("source_url") or ""),
        verified=bool(secret.get("verified")),
        masked=_mask(str(secret.get("value") or "")),
        loot_file=loot_file,
    )


def _to_mined_endpoint(e: Endpoint) -> MinedEndpoint:
    return MinedEndpoint(url=e.url, params=list(e.params), source_url=(e.source_run_id or ""),
                         nuclei_target=e.url, repeater_url=e.url)


# --------------------------------------------------------------------------- #
# the gate — THE EXECUTOR'S, UNCHANGED
# --------------------------------------------------------------------------- #
def _exec_request(argv: list[str], req: "JsReconRequest"):
    """The ExecRequest a job is gated as — its entry command with the built argv."""
    from .models import ExecRequest

    return ExecRequest(
        command=argv[0], args=argv[1:],
        approved=req.approved, dangerous_ack=req.dangerous_ack,
        engagement_id=req.engagement_id, session_id=req.session_id,
        timeout_seconds=req.timeout_seconds,
    )


def _gate(exec_req):
    """The executor's gate verdict — the SAME gates every command clears, nothing added."""
    from . import executor

    return executor.validate_request(exec_req)


def validate(req: "JsReconRequest") -> Any:
    """The gate verdict for a job, mining nothing. PURE. Returns None when it passes."""
    return _gate(_exec_request(gate_argv(req), req))


# --------------------------------------------------------------------------- #
# job registry — stop is a flag, and setting it is ungated
# --------------------------------------------------------------------------- #
_jobs: dict[str, JsReconJob] = {}
_stops: dict[str, threading.Event] = {}
_procs: dict[str, subprocess.Popen] = {}
_lock = threading.Lock()


def get(job_id: str) -> JsReconJob | None:
    with _lock:
        return _jobs.get(job_id)


def list_jobs(session_id: str | None = None) -> list[JsReconJob]:
    with _lock:
        jobs = list(_jobs.values())
    if session_id:
        jobs = [j for j in jobs if j.session_id == session_id]
    return sorted(jobs, key=lambda j: j.started_at, reverse=True)


def stop(job_id: str) -> JsReconJob | None:
    """Stop an in-flight job. NOT GATED — the panic button, like `stop_scan` and the intruder's stop.
    Sets the event and kills the current engine process; the worker ends the job."""
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
    """Engagement-sandbox availability + running-job count — drives the UI banner. Read-only."""
    up = repeater_mod._container_running(config.ENGAGE_SANDBOX_CONTAINER)
    with _lock:
        running = sum(1 for j in _jobs.values() if j.state == "running")
    return {
        "container": config.ENGAGE_SANDBOX_CONTAINER,
        "up": up, "ready": up, "running": running,
        "detail": "" if up else "engagement sandbox is not running",
    }


# --------------------------------------------------------------------------- #
# shared preconditions — the recon/discover model, one place
# --------------------------------------------------------------------------- #
def _require_engagement(engagement_id: str | None):
    """The active engagement record + its loot workdir, or refuse. JS recon is engagement-bound: the
    open, loot-mounted sandbox is where a real target's JS is reachable and where the scope lives."""
    record = engagement.get_active(engagement_id) if engagement_id else None
    if record is None:
        raise JsReconRefused(
            "engagement",
            "JS recon runs in an active engagement — enter engagement mode first "
            "(POST /cockpit/engagement/enter). The isolated lab sandbox has no egress or loot.",
        )
    if not repeater_mod._container_running(config.ENGAGE_SANDBOX_CONTAINER):
        raise JsReconRefused(
            "unavailable",
            f"engagement sandbox '{config.ENGAGE_SANDBOX_CONTAINER}' is not running — nothing ran",
        )
    try:
        workdir = loot.ensure(engagement_id or "")
    except loot.LootError as exc:
        raise JsReconRefused("loot", f"could not prepare a loot directory: {exc}")
    return record, workdir


def _target_in_scope(record, host: str) -> bool:
    if not host:
        return False
    return engagement.resolved_scope(record).in_scope(host)


def _register(job: JsReconJob) -> None:
    with _lock:
        _jobs[job.id] = job
        _stops[job.id] = threading.Event()


# --------------------------------------------------------------------------- #
# start — GATE BEFORE ANYTHING SPAWNS; OPERATOR INPUTS SCOPE-LOCKED BY CONSTRUCTION
# --------------------------------------------------------------------------- #
def start(req: JsReconRequest) -> JsReconJob:
    """Validate, scope-lock the operator inputs, then run ONE JS-recon job in the background.

    THE GATE RUNS BEFORE ANY SPAWN. Refuses (nothing runs) on any of the four gates, if the target or
    any explicitly-named JS URL is out of scope, if there is nothing to mine, or if the engagement
    sandbox is down.
    """
    record, workdir = _require_engagement(req.engagement_id)
    warnings: list[str] = []

    target = (req.target or "").strip()
    if target:
        thost = scope_mod.bare_host(target).lower()
        if not thost:
            raise JsReconRefused("input", f"collection target {target!r} has no host")
        if not _target_in_scope(record, thost):
            raise JsReconRefused("scope", f"{thost} is out of scope for {req.engagement_id}")

    # Explicitly-named JS URLs are OPERATOR INPUTS — off-scope refuses (a job pointed off-scope),
    # unlike URLs discovered from a page/bundle, which are scope-FILTERED in the worker.
    explicit = [u.strip() for u in req.js_urls if (u or "").strip()]
    for u in explicit:
        h = scope_mod.bare_host(u).lower()
        if not h:
            raise JsReconRefused("input", f"JS URL {u!r} has no host")
        if not _target_in_scope(record, h):
            raise JsReconRefused("scope", f"{h} is out of scope for {req.engagement_id}")

    if not target and not explicit and not req.include_state:
        raise JsReconRefused(
            "input", "nothing to mine — give a collection `target`, some `js_urls`, or leave "
            "`include_state` on to mine the .js endpoints already in this session's state")

    argv = gate_argv(req)
    rejected = _gate(_exec_request(argv, req))
    if rejected is not None:
        raise JsReconRefused(rejected.gate, rejected.reason, list(rejected.dangerous_flags or []))

    job = JsReconJob(
        id=uuid.uuid4().hex[:12], argv=argv, target=target,
        container=config.ENGAGE_SANDBOX_CONTAINER, engagement_id=req.engagement_id,
        session_id=req.session_id or req.engagement_id, started_at=_now(), warnings=warnings,
    )
    _register(job)
    threading.Thread(
        target=_run, args=(job.id, req, record, workdir, target, explicit),
        daemon=True, name=f"jsrecon-{job.id}",
    ).start()
    return job


# --------------------------------------------------------------------------- #
# worker — one job = one approval; scope-filter twice; secrets -> loot + Findings
# --------------------------------------------------------------------------- #
def _run(job_id: str, req: JsReconRequest, record, workdir: str, target: str,
         explicit: list[str]) -> None:
    """The worker. Collects → scope-filters JS → mines → scope-filters mined endpoints → upserts
    in-scope endpoints and writes secrets to loot + Findings. Never raises."""
    session_id = req.session_id or req.engagement_id or ""
    eng_id = req.engagement_id or ""
    matcher = engagement.resolved_scope(record)

    # --- candidate JS URL set: explicit + state .js + collected-from-target ---
    candidates: list[str] = list(explicit)
    if req.include_state and session_id:
        try:
            for e in state_store.load(session_id).endpoints:
                if (e.url or "").split("?", 1)[0].lower().endswith(".js"):
                    candidates.append(e.url)
        except Exception:  # noqa: BLE001 - a state read must not take the job down
            pass

    # Authenticated JS recon: resolve the operator's attached session once; it rides in the STDIN
    # job spec (never the argv), so login-gated bundles are fetched without a token touching a record.
    extra = session_store.header_pairs(req.engagement_id) if req.attach_session else []

    # STAGE 1 — collect (only when a target is given). Its output is DISCOVERED, so it is
    # scope-FILTERED, not refused.
    if target and not _stopped(job_id):
        spec = collect_job_spec([target], req, extra_headers=extra)
        text = _spawn_json(job_id, spec, workdir, _timeout(req))
        collected, cerr = _parse_collect(text)
        candidates += collected
        _add_stage(job_id, ENGINE, [ENGINE, "--collect", "-u", target],
                   "stopped" if _stopped(job_id) else "ran",
                   f"collected {len(collected)} JS URL(s) from {target}" + (f"; {cerr}" if cerr else ""))

    # SCOPE-FILTER the candidate JS URLs — ONLY in-scope JS is ever fetched (construction).
    in_scope_js, out_hosts = filter_urls_in_scope(candidates, matcher)
    if len(in_scope_js) > JS_URL_CAP:
        _warn(job_id, f"JS fetch capped at {JS_URL_CAP} of {len(in_scope_js)} in-scope bundle(s)")
        in_scope_js = in_scope_js[:JS_URL_CAP]

    endpoints: list[Endpoint] = []
    secrets: list[dict[str, Any]] = []
    maps: list[dict[str, Any]] = []
    last_text = ""

    # STAGE 2 — mine the in-scope JS set.
    if in_scope_js and not _stopped(job_id):
        spec = mine_job_spec(in_scope_js, req, extra_headers=extra)
        last_text = _spawn_json(job_id, spec, workdir, _timeout(req) * 2)
        endpoints, secrets, maps, merr = parse_mine_output(last_text)
        for e in endpoints:
            e.session_id = session_id
        _add_stage(job_id, ENGINE, [ENGINE, "--mine", f"({len(in_scope_js)} in-scope JS)"],
                   "stopped" if _stopped(job_id) else "ran",
                   f"mined {len(endpoints)} endpoint(s), {len(secrets)} secret(s)"
                   + (f"; {merr}" if merr else ""))
    elif not in_scope_js:
        _add_stage(job_id, ENGINE, [ENGINE, "--mine"], "skipped",
                   "no in-scope JS to mine" + (f" ({len(out_hosts)} out-of-scope dropped)" if out_hosts else ""))

    # SCOPE-FILTER the mined endpoints — ONLY in-scope mined hosts reach the surface (construction).
    kept_eps, ep_out = filter_endpoints_in_scope(endpoints, matcher)
    out_hosts = _dedupe(out_hosts + ep_out)

    # Secrets: keep only those whose source JS host is in scope (it was fetched in-scope, but a
    # source-map recovery can name another origin — belt and braces).
    in_scope_secrets = [s for s in secrets if matcher.in_scope(_endpoint_host(str(s.get("source_url") or "")))
                        or not _endpoint_host(str(s.get("source_url") or ""))]

    # SECRETS -> LOOT (values), then Findings that carry NO value.
    loot_file = ""
    findings: list[Finding] = []
    if in_scope_secrets:
        loot_file = _write_secret_loot(eng_id, job_id, in_scope_secrets)
        findings = [_secret_finding(s, loot_file, session_id, job_id) for s in in_scope_secrets]

    new_ep = new_find = 0
    if session_id:
        try:
            new_ep = state_store.upsert_endpoints(kept_eps)
            new_find = state_store.upsert_findings(findings)
        except Exception:  # noqa: BLE001 - a persistence hiccup must not lose the job
            pass

    _finish(job_id, session_id, target or (explicit[0] if explicit else ""), in_scope_js, kept_eps,
            in_scope_secrets, maps, out_hosts, loot_file, new_ep, new_find, last_text)


# --------------------------------------------------------------------------- #
# worker helpers
# --------------------------------------------------------------------------- #
def _timeout(req: JsReconRequest) -> int:
    return config.clamp_timeout(req.timeout_seconds) * 3


def _stopped(job_id: str) -> bool:
    ev = _stops.get(job_id)
    return ev is not None and ev.is_set()


def _parse_collect(text: str) -> tuple[list[str], str]:
    """The engine's collect JSON -> (js_urls, error). Never raises."""
    blob = (text or "").strip()
    if not blob:
        return [], "engine produced no output"
    try:
        data = json.loads(blob.splitlines()[-1])
    except (ValueError, IndexError):
        return [], "collect produced no parseable JSON"
    if not isinstance(data, dict):
        return [], "collect JSON was not an object"
    urls = [str(u) for u in (data.get("js_urls") or []) if str(u).strip()]
    errs = data.get("errors") or []
    return urls, (f"{len(errs)} fetch error(s)" if errs else "")


def _write_secret_loot(engagement_id: str, job_id: str, secrets: list[dict[str, Any]]) -> str:
    """Write the secret VALUES to the engagement loot dir; returns its CONTAINER path.

    This is the ONLY place a value is written, and it never reaches a Finding or an argv (mirror
    :credentials). Tab-separated: type, verified, source_url, value.
    """
    name = f"jsrecon-{job_id}-secrets.txt"
    try:
        host_dir = loot.host_dir(engagement_id)
        host_dir.mkdir(parents=True, exist_ok=True)
        lines = ["# type\tverified\tsource_url\tvalue"]
        for s in secrets:
            val = str(s.get("value") or "").replace("\t", " ").replace("\n", "\\n")
            lines.append(f"{s.get('type')}\t{bool(s.get('verified'))}\t{s.get('source_url')}\t{val}")
        (host_dir / name).write_text("\n".join(lines) + "\n", encoding="utf-8")
    except (loot.LootError, OSError):
        return ""
    return f"{loot.container_dir(engagement_id)}/{name}"


def _add_stage(job_id: str, tool: str, argv: list[str], state: str, note: str) -> None:
    with _lock:
        job = _jobs.get(job_id)
        if job is not None:
            job.stages.append(JsReconStage(tool=tool, argv=argv, state=state, note=note))


def _warn(job_id: str, msg: str) -> None:
    with _lock:
        job = _jobs.get(job_id)
        if job is not None:
            job.warnings.append(msg)


def _finish(job_id: str, session_id: str, target: str, js_urls: list[str], kept_eps: list[Endpoint],
            secrets: list[dict[str, Any]], maps: list[dict[str, Any]], out_hosts: list[str],
            loot_file: str, new_ep: int, new_find: int, text: str) -> None:
    """Close the job out, build the hand-off rows, persist one audit record. Never raises."""
    with _lock:
        job = _jobs.get(job_id)
        stopped = _stops.get(job_id)
        if job is not None:
            job.state = "stopped" if (stopped is not None and stopped.is_set()) else "finished"
            job.finished_at = _now()
            job.js_urls_mined = list(js_urls)
            job.endpoints = [_to_mined_endpoint(e) for e in kept_eps]
            job.secrets = [_to_mined_secret(s, loot_file) for s in secrets]
            job.recovered_sources = [
                RecoveredSource(js_url=str(m.get("js_url") or ""), map_url=str(m.get("map_url") or ""),
                                recovered_sources=list(m.get("recovered_sources") or []),
                                comments=list(m.get("comments") or []))
                for m in maps
            ]
            job.discovered_out_of_scope = _dedupe(out_hosts)
            job.new_endpoints = new_ep
            job.new_findings = new_find
            job.secrets_found = len(secrets)
            job.verified_secrets = sum(1 for s in secrets if s.get("verified"))
            job.loot_file = loot_file
            job.output_tail = text[-4000:]
        argv = job.argv if job else [ENGINE]
        _procs.pop(job_id, None)
    try:
        runstore.save_run(RunRecord(
            run_id=job_id, command=ENGINE,
            args=[a for a in (argv[1:] if argv else []) if not a.startswith("http")]
                 + [f"js={len(js_urls)}", f"endpoints={new_ep}", f"secrets={len(secrets)}"],
            target=scope_mod.bare_host(target) or target, approved=True, mode="engagement",
            exit_code=0, stdout=text[-8000:], stderr="",
            started_at=(job.started_at if job else _now()), finished_at=_now(),
            session_id=session_id or None, step_id=None,
        ))
    except Exception:  # noqa: BLE001 - an audit failure must not lose the results
        pass


def _spawn_json(job_id: str, spec: dict[str, Any], workdir: str, timeout: int) -> str:
    """Run ONE `docker exec -i js-mine --job-stdin` with the spec on STDIN, to completion (or until
    stop/timeout). argv-only, the URL set on stdin — no URL byte reaches a shell. Never raises."""
    full = ["docker", "exec", "-i", *loot.exec_flags(workdir), config.ENGAGE_SANDBOX_CONTAINER,
            ENGINE, "--job-stdin"]
    try:
        proc = subprocess.Popen(
            full, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
    except FileNotFoundError:
        return json.dumps({"error": "docker CLI not found on PATH"})
    except Exception as exc:  # noqa: BLE001
        return json.dumps({"error": f"could not start: {exc}"})
    with _lock:
        _procs[job_id] = proc
    try:
        out, _ = proc.communicate(input=json.dumps(spec), timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
        except Exception:  # noqa: BLE001
            pass
        out = json.dumps({"error": f"{ENGINE} exceeded {timeout}s and was killed"})
    except Exception as exc:  # noqa: BLE001
        out = json.dumps({"error": f"engine transport error: {exc}"})
    text = (out or "")[:_OUTPUT_CAP]
    with _lock:
        job = _jobs.get(job_id)
        if job is not None:
            job.output_tail = text[-4000:]
    return text


def reset() -> None:
    """Drop all job state. Tests only — never called by the app."""
    with _lock:
        _jobs.clear()
        _stops.clear()
        _procs.clear()
