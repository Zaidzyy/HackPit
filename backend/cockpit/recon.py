"""Guided recon -> ranked attack surface (:recon).

*** THE FRONT DOOR A BOUNTY/PENTEST STARTS FROM, AND WHY IT ADDS NO NEW GATE. ***
Give it a scoped domain and it runs recon as APPROVED JOBS, seeds the engagement's structured
state (hosts/services/endpoints), and ranks what to hit first. It is the guided, first-class
front end of the recon-driven expansion that already lives in `engagement.record_discoveries`.

This module is the SAME shape as `nuclei` and `credjobs`, so nobody re-litigates it:

  * ENGAGEMENT-BOUND, like credattack. A sweep needs the OPEN, loot-mounted engagement sandbox:
    passive recon reaches the internet (crt.sh / wayback / DNS), and the SCOPE that decides what
    may be scanned lives on the engagement record. No active engagement -> refused (an
    availability precondition, never a bypass). The isolated lab sandbox has no egress and no loot.
  * ONE APPROVAL BUYS THE WHOLE SWEEP. A passive sweep chains subfinder -> dnsx -> httpx ->
    gau/waybackurls/katana; the active sweep chains naabu -> nmap. Each sweep is ONE human
    approval, gated by the SAME `executor.validate_request` every command clears, run BEFORE
    anything spawns, with an UNGATED stop — exactly the crack-worker model. NO new gate, NO batch
    auto-runner: the operator approves the sweep and can stop it.
  * SCOPE DISCIPLINE IS A CORRECTNESS PROPERTY, ENFORCED BY CONSTRUCTION — not an extra gate.
    Recon can only widen the allowed set WITHIN the declared scope. Discovered hosts are sorted
    by the scope (`engagement.record_discoveries` + :func:`filter_in_scope`): in-scope names join
    the live allowed set and become the ONLY hosts the probing tools are ever pointed at; every
    parsed record is scope-checked before it can enter scannable state; out-of-scope names are
    surfaced READ-ONLY and never scanned, never upserted. `:func:`rank_surface`` executes nothing.

THE SPLIT, mirroring nuclei/credattack:

  * PURE, INSPECTABLE HALF — the ``*_argv`` builders, :func:`filter_in_scope`, :func:`rank_surface`.
    They build argv, sort by scope, and score state; they execute NOTHING. Regression-locked in
    test_recon_safety.py by an AST walk.
  * THE WORKER — :func:`start_passive` / :func:`start_active` validate through the gate BEFORE
    anything spawns, then a background thread runs the sweep's `docker exec`s in the engagement
    sandbox, sorting discoveries by scope between stages and upserting only in-scope records.
"""

from __future__ import annotations

import re
import subprocess
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable

from pydantic import BaseModel, Field

from state import store as state_store
from state.models import Endpoint, Finding, Host, Service, severity_rank
from state.parsers import (
    Parsed,
    parse_dnsx,
    parse_httpx,
    parse_naabu,
    parse_nmap_xml,
    parse_subfinder,
    parse_urls,
)

from . import config, engagement, loot, repeater as repeater_mod, runstore, scope as scope_mod
from .models import RunRecord

#: Per-job transcript kept, in chars — a recon transcript, not a data feed.
_OUTPUT_CAP = 400_000
#: In-scope hosts the URL-listers (gau/waybackurls/katana) fan out over. Bounded so a broad
#: subdomain haul does not turn one approval into thousands of archive queries. Truncation is
#: REPORTED (a warning), never silent.
_URL_FANOUT_CAP = 20
#: Hosts naabu/nmap fan out over in an active sweep. Same reasoning, same reporting.
_ACTIVE_FANOUT_CAP = 40

#: How a ranked-surface score is spent — the WHY the operator reads, made explicit.
_SEV_WEIGHT = {"critical": 120, "high": 60, "medium": 25, "low": 8, "info": 2}
#: An endpoint whose URL or title smells like an auth / privileged surface (ATO/IDOR magnet).
_AUTH_RE = re.compile(
    r"(login|signin|sign-in|logout|auth|oauth|sso|saml|token|session|admin|account|register|"
    r"password|passwd|reset|api[-_/]?key|graphql|/api/|/v\d+/|/internal|/manage|/dashboard)",
    re.I,
)


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
class ReconRequest(BaseModel):
    """One recon sweep: the domain to start from + the gate fields."""

    domain: str = Field(
        "", description="The in-scope domain (or apex) to start from. EMPTY = the engagement's "
        "declared target. A passive sweep enumerates its subdomains; an active sweep scans the "
        "in-scope hosts already in state."
    )
    rate_limit: int | None = Field(
        None, ge=1, le=100000, description="Requests/sec cap passed to httpx/naabu. Pacing, not a gate."
    )
    timeout_seconds: int | None = None
    engagement_id: str | None = None
    session_id: str | None = None
    # THE GATE FIELDS — the executor's, unchanged. Both default False so an omitted field is
    # REFUSED rather than granted.
    approved: bool = Field(False, description="Explicit human approval. Never defaulted true.")
    dangerous_ack: bool = Field(
        False, description="The red-confirm, WHEN THE GATE ASKS FOR IT — decided by the four gates."
    )


class ReconStageResult(BaseModel):
    """One tool invocation inside a sweep — what it was and what happened."""

    tool: str
    argv: list[str] = Field(default_factory=list)
    state: str = Field("ran", description="ran | stopped | skipped")
    note: str = ""


class ReconJob(BaseModel):
    """One recon sweep job. Counts are what HAPPENED, never what was planned."""

    id: str
    kind: str = Field(description="passive | active")
    state: str = Field("running", description="running | finished | stopped | refused")
    argv: list[str] = Field(default_factory=list, description="The approved entry command line.")
    domain: str = ""
    container: str = ""
    mode: str = "engagement"
    engagement_id: str | None = None
    session_id: str | None = None
    started_at: str = ""
    finished_at: str = ""
    stages: list[ReconStageResult] = Field(default_factory=list)
    discovered_in_scope: list[str] = Field(default_factory=list)
    discovered_out_of_scope: list[str] = Field(
        default_factory=list, description="Surfaced READ-ONLY — never scanned, never upserted."
    )
    new_hosts: int = 0
    new_services: int = 0
    new_endpoints: int = 0
    new_findings: int = 0
    output_tail: str = ""
    warnings: list[str] = Field(default_factory=list)
    refused: str = Field("", description="Set when a gate refused the job — the reason.")
    refused_gate: str = ""


class RankedEndpoint(BaseModel):
    url: str
    params: list[str] = Field(default_factory=list)
    tech: str = ""
    status: int | None = None


class RankedTarget(BaseModel):
    """One host in the ranked surface, with the WHY that earned its place."""

    address: str
    hostname: str = ""
    score: int = 0
    reasons: list[str] = Field(default_factory=list)
    open_services: int = 0
    services: list[str] = Field(default_factory=list)
    cve_stacks: list[str] = Field(default_factory=list)
    param_endpoints: list[RankedEndpoint] = Field(default_factory=list)
    auth_endpoints: list[str] = Field(default_factory=list)
    findings: int = 0
    #: Handoff — the endpoints worth pointing :nuclei at first.
    nuclei_targets: list[str] = Field(default_factory=list)


class ReconSurface(BaseModel):
    session_id: str
    generated_at: str = ""
    counts: dict[str, int] = Field(default_factory=dict)
    targets: list[RankedTarget] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class ReconRefused(RuntimeError):
    """Refused BEFORE anything ran. Carries the gate that refused it."""

    def __init__(self, gate: str, reason: str, dangerous_flags: list[str] | None = None) -> None:
        super().__init__(reason)
        self.gate = gate
        self.reason = reason
        self.dangerous_flags = dangerous_flags or []


# --------------------------------------------------------------------------- #
# PURE: argv builders — the commands a sweep is EQUIVALENT TO. Never a shell.
# --------------------------------------------------------------------------- #
def subfinder_argv(domain: str) -> list[str]:
    """Passive subdomain enumeration from CT logs / passive sources. `-silent` = names only."""
    return ["subfinder", "-silent", "-d", domain]


def dnsx_argv(list_path: str) -> list[str]:
    """Resolve a host list; `-json` carries the A records. Reads a file the worker wrote."""
    return ["dnsx", "-silent", "-json", "-l", list_path]


def httpx_argv(list_path: str, rate_limit: int | None = None) -> list[str]:
    """Probe a host list for live HTTP + tech/title/status; `-json` per line for parse_httpx."""
    argv = ["httpx", "-silent", "-json", "-title", "-tech-detect", "-status-code", "-l", list_path]
    if rate_limit:
        argv += ["-rate-limit", str(int(rate_limit))]
    return argv


def url_argv(tool: str, host: str) -> list[str]:
    """gau / waybackurls take a bare host; katana crawls one URL. All emit URLs (parse_urls)."""
    if tool == "katana":
        return ["katana", "-silent", "-u", host]
    return [tool, host]


def naabu_argv(list_path: str, rate_limit: int | None = None) -> list[str]:
    """Fast port discovery over a host list; `-json` per open port for parse_naabu."""
    argv = ["naabu", "-silent", "-json", "-l", list_path]
    if rate_limit:
        argv += ["-rate", str(int(rate_limit))]
    return argv


def nmap_argv(host: str, out_path: str) -> list[str]:
    """Service/version detection on one host, XML to loot so the loot-ingest parses it."""
    return ["nmap", "-sV", "-Pn", "-oX", out_path, host]


# --------------------------------------------------------------------------- #
# PURE: scope discipline — the correctness property, testable with no Docker
# --------------------------------------------------------------------------- #
def _endpoint_host(url: str) -> str:
    """The bare host of a URL (scheme/path/port stripped) — `scope.bare_host` already does this."""
    return scope_mod.bare_host(url).lower()


def filter_in_scope(
    parsed: Parsed, matcher: scope_mod.ResolvedScope
) -> tuple[Parsed, list[str]]:
    """Split parsed records by the scope. IN-scope records are kept (they may enter scannable
    state); OUT-of-scope hosts are collected read-only and their records dropped.

    This is the enforced correctness property: nothing recon discovers can enter state — and so
    become a target a later scan seeds from — unless the declared scope already covered it. PURE.
    """
    kept = Parsed()
    out_hosts: list[str] = []

    def _out(host: str) -> None:
        host = (host or "").strip().lower()
        if host and host not in out_hosts:
            out_hosts.append(host)

    for h in parsed.hosts:
        (kept.hosts.append(h) if matcher.in_scope(h.address) else _out(h.address))
    for s in parsed.services:
        (kept.services.append(s) if matcher.in_scope(s.address) else _out(s.address))
    for e in parsed.endpoints:
        host = _endpoint_host(e.url)
        (kept.endpoints.append(e) if (host and matcher.in_scope(host)) else _out(host))
    for f in parsed.findings:
        host = _endpoint_host(f.target) or scope_mod.bare_host(f.target).lower()
        # A finding with no host-shaped target (a technique note) is kept; a host-shaped one
        # must be in scope like everything else.
        if not host or matcher.in_scope(host):
            kept.findings.append(f)
        else:
            _out(host)
    return kept, out_hosts


# --------------------------------------------------------------------------- #
# PURE: ranking — score the surface already in state. Advisory, executes nothing.
# --------------------------------------------------------------------------- #
def _looks_auth(endpoint: Endpoint) -> bool:
    hay = f"{endpoint.url} {endpoint.title}"
    return bool(_AUTH_RE.search(hay))


class _Bucket:
    def __init__(self) -> None:
        self.host: Host | None = None
        self.services: list[Service] = []
        self.endpoints: list[Endpoint] = []
        self.findings: list[Finding] = []


def rank_surface(session_id: str, index: Any = None) -> ReconSurface:
    """Score every host in a session's state by likely-exploitable, most-promising first. PURE.

    Signals, all already in state — open service count, CVE-worthy stacks (via the :exploits
    index), parameter-rich endpoints (IDOR/injection surface), auth surfaces, and any findings.
    Deterministic: same state -> same order (ties broken by address). ADVISORY — it proposes an
    order and runs nothing; the operator still approves every scan it hands off to.
    """
    summary = state_store.load(session_id)
    if index is None:
        try:
            from exploits.index import get_index

            index = get_index()
        except Exception:  # noqa: BLE001 - ranking must work with no exploit index
            index = None

    buckets: dict[str, _Bucket] = {}

    def _bucket(key: str) -> _Bucket:
        key = (key or "").strip().lower()
        return buckets.setdefault(key, _Bucket())

    for h in summary.hosts:
        b = _bucket(h.address)
        b.host = h
        if h.hostname and h.hostname.lower() != h.address.lower():
            buckets.setdefault(h.hostname.strip().lower(), b)
    for s in summary.services:
        _bucket(s.address).services.append(s)
    for e in summary.endpoints:
        host = _endpoint_host(e.url)
        if host:
            _bucket(host).endpoints.append(e)
    for f in summary.findings:
        host = _endpoint_host(f.target) or scope_mod.bare_host(f.target).lower()
        if host:
            _bucket(host).findings.append(f)

    # Collapse alias buckets (a name and its address may point at the same _Bucket object).
    seen_ids: set[int] = set()
    targets: list[RankedTarget] = []
    for key, b in buckets.items():
        if id(b) in seen_ids:
            continue
        seen_ids.add(id(b))
        address = b.host.address if b.host else key
        hostname = b.host.hostname if b.host else ""

        reasons: list[str] = []
        score = 0

        open_services = len(b.services)
        if open_services:
            score += min(open_services, 10) * 6
            reasons.append(f"{open_services} open service(s)")

        cve_stacks: list[str] = []
        if index is not None and getattr(index, "ready", False):
            for s in b.services:
                if not (s.product or "").strip():
                    continue
                try:
                    cves = index.cves_for(s.product, (s.version or None))
                except Exception:  # noqa: BLE001
                    cves = []
                if cves:
                    n = len(cves)
                    score += min(n, 5) * 15
                    ver = f" {s.version}" if s.version else ""
                    cve_stacks.append(f"{s.product}{ver} — {n} known CVE(s)")
        if cve_stacks:
            reasons.append("CVE-worthy stack: " + "; ".join(cve_stacks[:3]))

        param_eps = [e for e in b.endpoints if e.params]
        if param_eps:
            score += min(len(param_eps), 12) * 5
            total_params = sum(len(e.params) for e in param_eps)
            reasons.append(f"{len(param_eps)} parameter-rich endpoint(s) ({total_params} params — IDOR/injection surface)")

        auth_eps = [e for e in b.endpoints if _looks_auth(e)]
        if auth_eps:
            score += min(len(auth_eps), 6) * 10
            reasons.append(f"{len(auth_eps)} auth/privileged surface(s)")

        if b.findings:
            fscore = sum(_SEV_WEIGHT.get((f.severity or "info").lower(), 2) for f in b.findings)
            score += fscore
            worst = min(b.findings, key=lambda f: severity_rank(f.severity))
            reasons.append(f"{len(b.findings)} finding(s), worst {worst.severity}")

        if score == 0 and not b.host and not b.endpoints:
            continue  # a bare alias key with nothing behind it

        nuclei_targets = _dedupe(
            [e.url for e in param_eps] + [e.url for e in auth_eps]
        )[:15]
        targets.append(
            RankedTarget(
                address=address,
                hostname=hostname,
                score=score,
                reasons=reasons or ["seen in recon, no strong signal yet"],
                open_services=open_services,
                services=[s.label() for s in sorted(b.services, key=lambda s: s.port)],
                cve_stacks=cve_stacks,
                param_endpoints=[
                    RankedEndpoint(url=e.url, params=e.params, tech=e.tech, status=e.status)
                    for e in param_eps[:12]
                ],
                auth_endpoints=[e.url for e in auth_eps[:12]],
                findings=len(b.findings),
                nuclei_targets=nuclei_targets,
            )
        )

    targets.sort(key=lambda t: (-t.score, t.address))
    notes: list[str] = []
    if not targets:
        notes.append(
            "no surface in state yet — run a passive sweep (subfinder -> dnsx -> httpx) first"
        )
    if index is None or not getattr(index, "ready", False):
        notes.append("exploit index not loaded — CVE-stack ranking is off this run")
    return ReconSurface(
        session_id=session_id,
        generated_at=_now(),
        counts=summary.counts(),
        targets=targets,
        notes=notes,
    )


# --------------------------------------------------------------------------- #
# the gate — THE EXECUTOR'S, UNCHANGED
# --------------------------------------------------------------------------- #
def _exec_request(command: str, args: list[str], req: ReconRequest):
    """The ExecRequest a sweep is gated as — its entry command with the built argv."""
    from .models import ExecRequest

    return ExecRequest(
        command=command,
        args=args,
        approved=req.approved,
        dangerous_ack=req.dangerous_ack,
        engagement_id=req.engagement_id,
        session_id=req.session_id,
        timeout_seconds=req.timeout_seconds,
    )


def _gate(exec_req):
    """The executor's gate verdict — the SAME gates every command clears, nothing added."""
    from . import executor

    return executor.validate_request(exec_req)


def _resolve_domain(req: ReconRequest, record) -> str:
    """The domain a sweep starts from: the request's, else the engagement's declared target."""
    domain = (req.domain or "").strip()
    if not domain and record is not None:
        domain = (record.target or "").strip()
    return scope_mod.bare_host(domain).lower() if domain else ""


def validate(req: ReconRequest, kind: str = "passive") -> Any:
    """The gate verdict for a sweep, attacking nothing. PURE. Returns None when it passes.

    Gated against the sweep's entry command (`subfinder -d <domain>` for passive, `naabu` for
    active) — the same `executor.validate_request` a one-shot exec asks. A UI calls this to show
    'would this be refused' before launching anything.
    """
    record = engagement.get_active(req.engagement_id) if req.engagement_id else None
    domain = _resolve_domain(req, record)
    if kind == "active":
        exec_req = _exec_request("naabu", ["-silent"], req)
    else:
        exec_req = _exec_request("subfinder", subfinder_argv(domain or "example.com")[1:], req)
    return _gate(exec_req)


# --------------------------------------------------------------------------- #
# job registry — stop is a flag, and setting it is ungated
# --------------------------------------------------------------------------- #
_jobs: dict[str, ReconJob] = {}
_stops: dict[str, threading.Event] = {}
_procs: dict[str, subprocess.Popen] = {}
_lock = threading.Lock()


def get(job_id: str) -> ReconJob | None:
    with _lock:
        return _jobs.get(job_id)


def list_jobs(session_id: str | None = None) -> list[ReconJob]:
    with _lock:
        jobs = list(_jobs.values())
    if session_id:
        jobs = [j for j in jobs if j.session_id == session_id]
    return sorted(jobs, key=lambda j: j.started_at, reverse=True)


def stop(job_id: str) -> ReconJob | None:
    """Stop an in-flight sweep. NOT GATED — the panic button, like `stop_scan` and the intruder's
    stop. Sets the event and kills the current process; the worker ends the sweep."""
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
# shared preconditions — the credattack model, one place
# --------------------------------------------------------------------------- #
def _require_engagement(engagement_id: str | None):
    """The active engagement record + its loot workdir, or refuse. Recon is engagement-bound: the
    open, loot-mounted sandbox is where a real target is reachable and where the scope lives."""
    record = engagement.get_active(engagement_id) if engagement_id else None
    if record is None:
        raise ReconRefused(
            "engagement",
            "recon runs in an active engagement — enter engagement mode first "
            "(POST /cockpit/engagement/enter). The isolated lab sandbox has no egress or loot.",
        )
    if not repeater_mod._container_running(config.ENGAGE_SANDBOX_CONTAINER):
        raise ReconRefused(
            "unavailable",
            f"engagement sandbox '{config.ENGAGE_SANDBOX_CONTAINER}' is not running — nothing ran",
        )
    try:
        workdir = loot.ensure(engagement_id or "")
    except loot.LootError as exc:
        raise ReconRefused("loot", f"could not prepare a loot directory: {exc}")
    return record, workdir


def _write_loot(engagement_id: str, name: str, lines: list[str]) -> str:
    """Write a host list to the engagement loot dir; returns its CONTAINER path. Only ever called
    with an IN-SCOPE list — this is the file the probing tools read."""
    host_dir = loot.host_dir(engagement_id)
    host_dir.mkdir(parents=True, exist_ok=True)
    (host_dir / name).write_text("\n".join(lines) + "\n", encoding="utf-8")
    return f"{loot.container_dir(engagement_id)}/{name}"


def _register(job: ReconJob) -> None:
    with _lock:
        _jobs[job.id] = job
        _stops[job.id] = threading.Event()


# --------------------------------------------------------------------------- #
# start — GATE BEFORE ANYTHING SPAWNS
# --------------------------------------------------------------------------- #
def start_passive(req: ReconRequest) -> ReconJob:
    """Validate, then run ONE passive sweep in the background. THE GATE RUNS BEFORE ANY SPAWN."""
    record, workdir = _require_engagement(req.engagement_id)
    domain = _resolve_domain(req, record)
    if not domain or not re.search(r"[a-z]", domain):
        raise ReconRefused(
            "input",
            "a passive sweep needs an in-scope domain (subfinder enumerates its subdomains) — "
            "pass one, or run an active sweep on hosts already in state",
        )

    argv = subfinder_argv(domain)
    exec_req = _exec_request(argv[0], argv[1:], req)
    rejected = _gate(exec_req)
    if rejected is not None:
        raise ReconRefused(rejected.gate, rejected.reason, list(rejected.dangerous_flags or []))

    job = ReconJob(
        id=uuid.uuid4().hex[:12], kind="passive", argv=argv, domain=domain,
        container=config.ENGAGE_SANDBOX_CONTAINER, engagement_id=req.engagement_id,
        session_id=req.session_id or req.engagement_id, started_at=_now(),
    )
    _register(job)
    threading.Thread(
        target=_run_passive, args=(job.id, req, record, workdir, domain),
        daemon=True, name=f"recon-passive-{job.id}",
    ).start()
    return job


def start_active(req: ReconRequest) -> ReconJob:
    """Validate, then run ONE active service-scan sweep over the in-scope live hosts. GATE FIRST."""
    record, workdir = _require_engagement(req.engagement_id)
    session_id = req.session_id or req.engagement_id or ""
    matcher = engagement.resolved_scope(record)
    hosts = _active_host_set(record, session_id, matcher)
    if not hosts:
        raise ReconRefused(
            "input",
            "no in-scope live hosts in state to scan — run a passive sweep first",
        )

    argv = naabu_argv(f"{workdir}/recon-active-hosts.txt", req.rate_limit)
    exec_req = _exec_request(argv[0], ["-silent"], req)
    rejected = _gate(exec_req)
    if rejected is not None:
        raise ReconRefused(rejected.gate, rejected.reason, list(rejected.dangerous_flags or []))

    job = ReconJob(
        id=uuid.uuid4().hex[:12], kind="active", argv=argv, domain=(record.target or ""),
        container=config.ENGAGE_SANDBOX_CONTAINER, engagement_id=req.engagement_id,
        session_id=session_id, started_at=_now(),
    )
    _register(job)
    threading.Thread(
        target=_run_active, args=(job.id, req, record, workdir, hosts),
        daemon=True, name=f"recon-active-{job.id}",
    ).start()
    return job


def _active_host_set(record, session_id: str, matcher) -> list[str]:
    """The in-scope hosts an active sweep scans: the declared target + in-scope discovered +
    in-scope hosts already in state. Every one is scope-checked here — the file the scanner reads
    can hold NOTHING the scope does not cover."""
    candidates = [record.target or ""]
    candidates += list(getattr(record, "discovered_in_scope", []) or [])
    if session_id:
        try:
            candidates += [h.address for h in state_store.load(session_id).hosts]
        except Exception:  # noqa: BLE001
            pass
    scoped = [h for h in _dedupe(candidates) if h and matcher.in_scope(h)]
    return scoped[:_ACTIVE_FANOUT_CAP]


# --------------------------------------------------------------------------- #
# workers — one sweep = one approval; between stages, sort by scope + stop-check
# --------------------------------------------------------------------------- #
def _run_passive(job_id: str, req: ReconRequest, record, workdir: str, domain: str) -> None:
    """Passive sweep worker: subfinder -> dnsx -> httpx -> gau/waybackurls/katana. Never raises."""
    session_id = req.session_id or req.engagement_id or ""
    matcher = engagement.resolved_scope(record)
    counts = {"hosts": 0, "services": 0, "endpoints": 0, "findings": 0}
    last_text = ""

    # STAGE 1 — subfinder. Its output drives recon-driven expansion (in-scope -> allowed set,
    # out-of-scope -> read-only) AND seeds in-scope Host rows.
    text = _spawn(job_id, subfinder_argv(domain), workdir, _timeout(req))
    last_text = text
    disc = _safe_discoveries(record, text, job_id)
    self_note = f"{len(disc['added'])} in-scope, {len(disc['out_of_scope'])} out-of-scope"
    _ingest(session_id, job_id, parse_subfinder(text, session_id, job_id), matcher, counts)
    _add_stage(job_id, "subfinder", subfinder_argv(domain), "ran", self_note)
    _set_discovered(job_id, record, req.engagement_id)

    if _stopped(job_id):
        return _finish(job_id, session_id, domain, counts, last_text, "netexec")

    # The IN-SCOPE host set every probing tool below is pointed at — nothing else.
    live = engagement.get_active(req.engagement_id)
    in_scope_hosts = _dedupe(
        [domain] + list(getattr(live, "discovered_in_scope", []) or [])
    )
    hosts_path = _write_loot(req.engagement_id or "", f"recon-{job_id}-hosts.txt", in_scope_hosts)

    # STAGE 2 — dnsx (resolve), STAGE 3 — httpx (live + tech).
    for tool, argv, parser in (
        ("dnsx", dnsx_argv(hosts_path), parse_dnsx),
        ("httpx", httpx_argv(hosts_path, req.rate_limit), parse_httpx),
    ):
        if _stopped(job_id):
            _add_stage(job_id, tool, argv, "skipped", "stopped before this stage")
            return _finish(job_id, session_id, domain, counts, last_text, "netexec")
        text = _spawn(job_id, argv, workdir, _timeout(req))
        last_text = text
        _ingest(session_id, job_id, parser(text, session_id, job_id), matcher, counts)
        _add_stage(job_id, tool, argv, "ran", f"{len(in_scope_hosts)} in-scope host(s)")

    # STAGE 4 — URL listers, fanned out over the in-scope hosts (bounded, truncation reported).
    fan = in_scope_hosts[:_URL_FANOUT_CAP]
    if len(in_scope_hosts) > _URL_FANOUT_CAP:
        _warn(job_id, f"URL discovery capped at {_URL_FANOUT_CAP} of {len(in_scope_hosts)} hosts")
    for tool in ("gau", "waybackurls", "katana"):
        if _stopped(job_id):
            _add_stage(job_id, tool, [tool], "skipped", "stopped before this stage")
            break
        for host in fan:
            if _stopped(job_id):
                break
            argv = url_argv(tool, host)
            text = _spawn(job_id, argv, workdir, _timeout(req))
            last_text = text
            _ingest(session_id, job_id, parse_urls(text, session_id, job_id), matcher, counts)
        _add_stage(job_id, tool, url_argv(tool, "<in-scope host>"), "ran", f"{len(fan)} host(s)")

    _finish(job_id, session_id, domain, counts, last_text, "netexec")


def _run_active(job_id: str, req: ReconRequest, record, workdir: str, hosts: list[str]) -> None:
    """Active sweep worker: naabu (ports) -> nmap -sV (versions), in-scope hosts only. Never raises."""
    session_id = req.session_id or req.engagement_id or ""
    matcher = engagement.resolved_scope(record)
    counts = {"hosts": 0, "services": 0, "endpoints": 0, "findings": 0}
    hosts_path = _write_loot(req.engagement_id or "", "recon-active-hosts.txt", hosts)
    last_text = ""

    # STAGE 1 — naabu port discovery over the in-scope host file.
    argv = naabu_argv(hosts_path, req.rate_limit)
    text = _spawn(job_id, argv, workdir, _timeout(req) * 2)
    last_text = text
    _ingest(session_id, job_id, parse_naabu(text, session_id, job_id), matcher, counts)
    _add_stage(job_id, "naabu", argv, "ran", f"{len(hosts)} in-scope host(s)")

    # STAGE 2 — nmap -sV per host, XML to loot (parsed by the loot-ingest for product/version).
    for host in hosts:
        if _stopped(job_id):
            _add_stage(job_id, "nmap", ["nmap"], "skipped", "stopped before completing")
            break
        out_path = f"{loot.container_dir(req.engagement_id or '')}/recon-{job_id}-{scope_mod.bare_host(host)}.xml"
        argv = nmap_argv(host, out_path)
        text = _spawn(job_id, argv, workdir, _timeout(req) * 3)
        last_text = text
        # nmap's real output is the XML in loot; parse the host_dir file we just asked for.
        _ingest_nmap(session_id, job_id, req.engagement_id or "", host, matcher, counts)
    else:
        _add_stage(job_id, "nmap", nmap_argv("<in-scope host>", "<loot>.xml"), "ran",
                   f"{len(hosts)} host(s)")

    _finish(job_id, session_id, (record.target or ""), counts, last_text, "nmap")


# --------------------------------------------------------------------------- #
# worker helpers
# --------------------------------------------------------------------------- #
def _timeout(req: ReconRequest) -> int:
    return config.clamp_timeout(req.timeout_seconds) * 3


def _stopped(job_id: str) -> bool:
    ev = _stops.get(job_id)
    return ev is not None and ev.is_set()


def _safe_discoveries(record, text: str, run_id: str) -> dict:
    try:
        return engagement.record_discoveries(record, text, run_id)
    except Exception:  # noqa: BLE001 - expansion is best-effort, never load-bearing
        return {"added": [], "out_of_scope": [], "truncated": False}


def _ingest(session_id: str, run_id: str, parsed: Parsed, matcher, counts: dict) -> None:
    """Scope-filter then persist parsed records; accumulate the per-kind new counts. The scope
    filter is what keeps an out-of-scope discovery out of scannable state."""
    if not session_id or parsed.is_empty():
        return
    kept, out_hosts = filter_in_scope(parsed, matcher)
    try:
        counts["hosts"] += state_store.upsert_hosts(kept.hosts)
        counts["services"] += state_store.upsert_services(kept.services)
        counts["endpoints"] += state_store.upsert_endpoints(kept.endpoints)
        counts["findings"] += state_store.upsert_findings(kept.findings)
    except Exception:  # noqa: BLE001 - a persistence hiccup must not lose the sweep
        pass


def _ingest_nmap(session_id: str, run_id: str, engagement_id: str, host: str, matcher, counts: dict) -> None:
    """Read the nmap XML we wrote to loot for one host and ingest it (scope-filtered)."""
    if not session_id:
        return
    try:
        path = loot.host_dir(engagement_id) / f"recon-{run_id}-{scope_mod.bare_host(host)}.xml"
        if not path.is_file():
            return
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    _ingest(session_id, run_id, parse_nmap_xml(text, session_id, run_id), matcher, counts)


def _add_stage(job_id: str, tool: str, argv: list[str], state: str, note: str) -> None:
    with _lock:
        job = _jobs.get(job_id)
        if job is not None:
            job.stages.append(ReconStageResult(tool=tool, argv=argv, state=state, note=note))


def _warn(job_id: str, msg: str) -> None:
    with _lock:
        job = _jobs.get(job_id)
        if job is not None:
            job.warnings.append(msg)


def _set_discovered(job_id: str, record, engagement_id: str | None) -> None:
    live = engagement.get_active(engagement_id) if engagement_id else None
    with _lock:
        job = _jobs.get(job_id)
        if job is not None and live is not None:
            job.discovered_in_scope = list(getattr(live, "discovered_in_scope", []) or [])
            job.discovered_out_of_scope = list(getattr(live, "discovered_out_of_scope", []) or [])


def _finish(job_id: str, session_id: str, target: str, counts: dict, text: str, command: str) -> None:
    """Close the job out, persist one audit record for the whole sweep. Never raises."""
    with _lock:
        job = _jobs.get(job_id)
        stopped = _stops.get(job_id)
        if job is not None:
            job.state = "stopped" if (stopped is not None and stopped.is_set()) else "finished"
            job.finished_at = _now()
            job.new_hosts = counts["hosts"]
            job.new_services = counts["services"]
            job.new_endpoints = counts["endpoints"]
            job.new_findings = counts["findings"]
            job.output_tail = text[-4000:]
        argv = job.argv if job else [command]
        _procs.pop(job_id, None)
    try:
        runstore.save_run(RunRecord(
            run_id=job_id, command=command, args=argv[1:] if argv else [],
            target=target, approved=True, mode="engagement", exit_code=0,
            stdout=text[-8000:], stderr="",
            started_at=(job.started_at if job else _now()), finished_at=_now(),
            session_id=session_id or None, step_id=None,
        ))
    except Exception:  # noqa: BLE001 - an audit failure must not lose the results
        pass


def _spawn(job_id: str, argv: list[str], workdir: str, timeout: int) -> str:
    """Run ONE `docker exec <tool>` to completion (or until stop/timeout), capturing merged
    output. Never raises — a transport failure becomes a note in the transcript."""
    full = ["docker", "exec", *loot.exec_flags(workdir), config.ENGAGE_SANDBOX_CONTAINER, *argv]
    try:
        proc = subprocess.Popen(
            full, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
        )
    except FileNotFoundError:
        return "[recon] docker CLI not found on PATH\n"
    except Exception as exc:  # noqa: BLE001
        return f"[recon] could not start: {exc}\n"
    with _lock:
        _procs[job_id] = proc

    stop_ev = _stops.get(job_id) or threading.Event()
    chunks: list[str] = []
    total = 0
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

    assert proc.stdout is not None
    for raw in iter(proc.stdout.readline, ""):
        if stop_ev.is_set():
            break
        if total < _OUTPUT_CAP:
            chunks.append(raw)
            total += len(raw)
        with _lock:
            job = _jobs.get(job_id)
            if job is not None:
                job.output_tail = "".join(chunks[-40:])[-4000:]
    try:
        proc.stdout.close()
    except Exception:  # noqa: BLE001
        pass
    proc.wait()
    text = "".join(chunks)
    if timed["v"]:
        text += f"\n[recon] {argv[0]} timed out after {timeout}s\n"
    return text


def reset() -> None:
    """Drop all job state. Tests only — never called by the app."""
    with _lock:
        _jobs.clear()
        _stops.clear()
        _procs.clear()
