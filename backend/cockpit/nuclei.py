"""The nuclei surface — scoped target(s) → templates → results as engagement `Finding`s.

*** WHY THIS IS ONE GATED JOB WITH NO NEW GATE, WRITTEN DOWN SO NOBODY RE-LITIGATES IT. ***
A nuclei run is the bug-bounty staple, and it is the SAME shape HackPit already runs for `ffuf`,
the intruder and the ZAP active scanner: ONE human approval buys a scan that fires thousands of
template checks. It has never refused one approval that produces many requests, and could not.
So this module adds NO new gate — it is one job, gated by the SAME executor gates every command
clears (`executor.validate_request`), with an UNGATED stop, exactly like `stop_scan` and the
intruder's stop.

THE SPLIT, mirroring credattack/credjobs and intruder:

  * PURE, INSPECTABLE HALF — :func:`resolve_targets`, :func:`nuclei_argv`, :func:`parse_findings`.
    They build the argv and turn nuclei's JSONL into `Finding`s and they execute NOTHING, so what
    will run and what a result means are both inspectable before anything spawns. Regression-locked
    in test_nuclei_safety.py by an AST walk.
  * THE WORKER — :func:`start` validates through the gate BEFORE anything spawns, resolves the
    per-mode sandbox exactly as a one-shot `/cockpit/exec` would (`executor.resolve_mode`), runs
    ONE `docker exec nuclei -jsonl …`, streams the JSONL, and upserts the findings into the same
    engagement `Finding` store the report already renders.

CONTAINMENT, inherited wholesale and stated rather than assumed:

  * THE SANDBOX IS RESOLVED BY MODE, not hardcoded — LAB runs go to the isolated, egress-less lab
    sandbox (which reaches the lab target on its internal network); ENGAGEMENT runs go to the
    fully-open engagement sandbox. This is `executor.resolve_mode`, the single source of truth the
    one-shot exec path uses, so a nuclei job can never bind to a different box than a bare command
    would in the same mode.
  * THE TARGET HANDRAIL IS THE INHERITED ONE. `-u <target>` puts every target on the argv where
    `check_target_lock` reads it, so in engagement mode an out-of-scope target is refused at the
    target gate — the same best-effort handrail every command gets, NOT a stronger gate this build
    invented. Human approval of every command remains the actual bound.
  * NO SECRET, BY CONSTRUCTION. nuclei authenticates against nothing here; there is no secret to
    keep off the argv. The JSONL is captured from stdout, so nothing sensitive is written anywhere.
"""

from __future__ import annotations

import json
import subprocess
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable, Sequence

from pydantic import BaseModel, Field

from state import store as state_store
from state.models import Finding, severity_rank

from . import config, loot, repeater as repeater_mod, runstore, session_store
from .models import RunRecord

#: nuclei's five severities, in the order a results table ranks them.
SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low", "info")

#: The baked template repo inside the sandbox image (docker/Dockerfile.sandbox clones it here and
#: symlinks it into every user's $HOME/.local). MEASURED via a live lab scan: with only `-tags`
#: and no `-t`, `docker exec … nuclei` resolves NO default template directory and dies with
#: "no templates provided for scan" — the same class of defect the zap_install proof exists for.
#: So when the operator names no explicit templates we point `-t` at this baked path, which both
#: sandboxes share, rather than trusting nuclei to find its default under an exec's $HOME.
DEFAULT_TEMPLATE_DIR = "/usr/share/nuclei-templates"

#: A curated set of tag filters that are KNOWN-VALID `-tags` values, so an operator picking one
#: cannot accidentally build a scan that matches no template because the tag was a guess. This is
#: deliberately NOT derived from the installed template paths: a path category (`http/cves/…`) is
#: not a template `tag`, and offering path-derived tags would hand the operator filters nuclei
#: silently drops. The live catalogue COUNT is surfaced separately (`template_catalogue`).
CURATED_TAGS: tuple[str, ...] = (
    "cve", "misconfiguration", "exposure", "exposed-panel", "default-login", "tech",
    "takeover", "xss", "sqli", "rce", "lfi", "ssrf", "redirect", "token", "secret",
    "config", "auth-bypass", "injection", "disclosure",
)

#: Per-job transcript kept, in chars — a scan transcript, not a data feed.
_OUTPUT_CAP = 400_000


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------- #
# models
# --------------------------------------------------------------------------- #
class NucleiRequest(BaseModel):
    """One nuclei scan: what to point it at, how to filter, and the gate fields."""

    targets: list[str] = Field(
        default_factory=list,
        description="Explicit targets (URLs or hosts). EMPTY = seed from the engagement's "
        "in-scope endpoints/hosts already in state (session_id).",
    )
    severities: list[str] = Field(
        default_factory=list,
        description="Severity filter (info/low/medium/high/critical). Empty = every severity.",
    )
    tags: list[str] = Field(
        default_factory=list, description="Template tag filter (see CURATED_TAGS). Empty = all."
    )
    templates: list[str] = Field(
        default_factory=list,
        description="Template dirs/ids for -t. Empty = nuclei's full baked template set.",
    )
    rate_limit: int | None = Field(
        None, ge=1, le=10000, description="Requests/sec cap (nuclei -rate-limit). Pacing, not a gate."
    )
    timeout_seconds: int | None = None
    engagement_id: str | None = None
    session_id: str | None = None
    attach_session: bool = Field(
        False,
        description="Run this scan AS the logged-in operator: merge the engagement's stored session "
        "(session_store) headers as -H flags, so authenticated endpoints are actually scanned. The "
        "operator's OWN session; the token is MASKED in the job record. Login stays human.",
    )
    # THE GATE FIELDS — the scanner's, unchanged. Both default False so an omitted field is
    # REFUSED rather than granted.
    approved: bool = Field(False, description="Explicit human approval. Never defaulted true.")
    dangerous_ack: bool = Field(
        False, description="The red-confirm, WHEN THE GATE ASKS FOR IT — decided by the four gates."
    )


class NucleiFinding(BaseModel):
    """One nuclei match, surfaced to the UI. Same fields the `Finding` store keeps."""

    title: str
    severity: str = "info"
    target: str = ""
    template_id: str = ""
    tags: list[str] = Field(default_factory=list)
    evidence: str = ""


class NucleiJob(BaseModel):
    """One scan job. Counts are what HAPPENED, never what was planned."""

    id: str
    state: str = Field("running", description="running | finished | stopped | refused")
    argv: list[str] = Field(default_factory=list, description="The approved command line.")
    targets: list[str] = Field(default_factory=list)
    container: str = ""
    mode: str = ""
    engagement_id: str | None = None
    session_id: str | None = None
    started_at: str = ""
    finished_at: str = ""
    findings: list[NucleiFinding] = Field(default_factory=list)
    total: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    new_findings: int = Field(0, description="Findings upserted into engagement state.")
    output_tail: str = Field("", description="The last lines of transcript, for the live view.")
    warnings: list[str] = Field(default_factory=list)
    refused: str = Field("", description="Set when a gate refused the job — the reason.")
    refused_gate: str = ""


class NucleiRefused(RuntimeError):
    """Refused BEFORE anything ran. Carries the gate that refused it."""

    def __init__(self, gate: str, reason: str, dangerous_flags: list[str] | None = None) -> None:
        super().__init__(reason)
        self.gate = gate
        self.reason = reason
        self.dangerous_flags = dangerous_flags or []


# --------------------------------------------------------------------------- #
# PURE: targets, argv, parsing — inspectable before anything runs
# --------------------------------------------------------------------------- #
def resolve_targets(req: NucleiRequest) -> tuple[list[str], list[str]]:
    """``(targets, warnings)``. An explicit list wins; otherwise seed from state. PURE.

    The default target set is the engagement's in-scope endpoints (URLs carry the path a template
    wants) falling back to bare hosts. De-duplicated, order preserved. Reads state, executes nothing.
    """
    warnings: list[str] = []
    explicit = [t.strip() for t in req.targets if t.strip()]
    if explicit:
        return _dedupe(explicit), warnings

    session_id = (req.session_id or req.engagement_id or "").strip()
    if not session_id:
        warnings.append(
            "no targets and no session to seed from — paste a target, or pass a session_id whose "
            "state holds endpoints/hosts"
        )
        return [], warnings

    summary = state_store.load(session_id)
    urls = [e.url.strip() for e in summary.endpoints if e.url.strip()]
    if urls:
        return _dedupe(urls), warnings
    hosts = [h.address.strip() for h in summary.hosts if h.address.strip()]
    if hosts:
        return _dedupe(hosts), warnings
    warnings.append(
        f"session {session_id!r} has no endpoints or hosts in state yet — run recon first, or "
        "paste an explicit target"
    )
    return [], warnings


def _dedupe(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for it in items:
        if it not in seen:
            seen.add(it)
            out.append(it)
    return out


def nuclei_argv(
    targets: list[str], req: NucleiRequest, extra_headers: "Sequence[tuple[str, str]]" = ()
) -> list[str]:
    """The command this job is EQUIVALENT TO, which is what the human approves. PURE, never a shell.

    ``-jsonl`` streams one JSON object per finding to stdout (which is what :func:`parse_findings`
    reads); ``-duc`` disables the startup update check (the sandbox has no egress to fetch one);
    ``-silent`` keeps stdout to results only. Every target rides as ``-u <target>`` so it lands
    where ``check_target_lock`` reads it — the target handrail sees the exact hosts that get hit.

    ``extra_headers`` (the operator's attached session, resolved by the caller — this stays PURE and
    never reads session_store) rides as ``-H "name: value"``, so the scan is authenticated.
    """
    argv = ["nuclei", "-jsonl", "-silent", "-duc"]
    for t in targets:
        argv += ["-u", t]
    for hn, hv in extra_headers:
        argv += ["-H", f"{hn}: {hv}"]
    sev = [s for s in (x.strip().lower() for x in req.severities) if s in SEVERITIES]
    if sev:
        argv += ["-severity", ",".join(sev)]
    tags = [t.strip() for t in req.tags if t.strip()]
    if tags:
        argv += ["-tags", ",".join(tags)]
    templates = [t.strip() for t in req.templates if t.strip()] or [DEFAULT_TEMPLATE_DIR]
    for tmpl in templates:
        argv += ["-t", tmpl]
    if req.rate_limit:
        argv += ["-rate-limit", str(int(req.rate_limit))]
    return argv


def _json_lines(text: str) -> Iterable[dict[str, Any]]:
    """Yield JSON objects from nuclei's JSONL (one object per line). Malformed lines are skipped —
    a scan's progress/banner noise on stdout must never abort the parse."""
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line[0] != "{":
            continue
        try:
            obj = json.loads(line)
        except (ValueError, TypeError):
            continue
        if isinstance(obj, dict):
            yield obj


def _matched_at(obj: dict[str, Any]) -> str:
    return str(obj.get("matched-at") or obj.get("matched_at") or obj.get("host") or "").strip()


def _template_id(obj: dict[str, Any]) -> str:
    return str(obj.get("template-id") or obj.get("templateID") or obj.get("template_id") or "").strip()


def _evidence(obj: dict[str, Any]) -> str:
    """The curl/matcher output a report needs to reproduce a hit — the richest of what nuclei gives."""
    extracted = obj.get("extracted-results") or obj.get("extracted_results")
    if isinstance(extracted, list) and extracted:
        return ", ".join(str(x) for x in extracted)[:2000]
    for key in ("curl-command", "curl_command", "matcher-name", "matcher_name", "matched-line"):
        val = obj.get(key)
        if val:
            return str(val)[:2000]
    return _matched_at(obj)[:2000]


def parse_records(text: str) -> list[dict[str, Any]]:
    """Deduped nuclei objects, keyed by ``(template-id, matched-at)`` — the identity the spec pins.

    A single scan re-reports the same match on retries and across chunked reads; deduping here
    keeps one row per (template, location) BEFORE it becomes a `Finding`, so the results table and
    the state upsert agree on the count. Order is preserved (first occurrence wins). PURE.
    """
    seen: set[tuple[str, str]] = set()
    out: list[dict[str, Any]] = []
    for obj in _json_lines(text):
        key = (_template_id(obj), _matched_at(obj))
        if key in seen:
            continue
        seen.add(key)
        out.append(obj)
    return out


def parse_findings(text: str, session_id: str, run_id: str | None = None) -> list[Finding]:
    """nuclei JSONL → engagement `Finding`s, deduped by (template-id, matched-at). PURE.

    ``info.name`` → title, ``info.severity`` → severity, ``matched-at`` → target, ``template-id``
    → reference, curl/matcher output → evidence, ``tool="nuclei"``. Ranked most-severe first.
    """
    findings: list[Finding] = []
    for obj in parse_records(text):
        info = obj.get("info") if isinstance(obj.get("info"), dict) else {}
        name = str(info.get("name") or _template_id(obj) or "nuclei match").strip()
        severity = str(info.get("severity") or "info").strip().lower()
        if severity not in SEVERITIES:
            severity = "info"
        findings.append(
            Finding(
                session_id=session_id,
                title=name,
                severity=severity,
                target=_matched_at(obj),
                evidence=_evidence(obj),
                tool="nuclei",
                reference=_template_id(obj),
                source_run_id=run_id,
            )
        )
    findings.sort(key=lambda f: severity_rank(f.severity))
    return findings


def parse_ui_findings(text: str) -> list[NucleiFinding]:
    """Same records, shaped for the results table (ranked most-severe first). PURE."""
    ui: list[NucleiFinding] = []
    for obj in parse_records(text):
        info = obj.get("info") if isinstance(obj.get("info"), dict) else {}
        severity = str(info.get("severity") or "info").strip().lower()
        if severity not in SEVERITIES:
            severity = "info"
        tags = info.get("tags")
        ui.append(
            NucleiFinding(
                title=str(info.get("name") or _template_id(obj) or "nuclei match").strip(),
                severity=severity,
                target=_matched_at(obj),
                template_id=_template_id(obj),
                tags=[str(t) for t in tags] if isinstance(tags, list) else [],
                evidence=_evidence(obj),
            )
        )
    ui.sort(key=lambda f: severity_rank(f.severity))
    return ui


def _severity_counts(findings: list[NucleiFinding]) -> dict[str, int]:
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return {s: n for s, n in counts.items() if n}


def parse_template_list(text: str) -> int:
    """Count installed templates from `nuclei -tl` output (one `.yaml`/`.yml` path per line). PURE."""
    return sum(1 for ln in (text or "").splitlines() if ln.strip().lower().endswith((".yaml", ".yml")))


# --------------------------------------------------------------------------- #
# the gate — THE SCANNER'S FOUR, UNCHANGED
# --------------------------------------------------------------------------- #
def _exec_request(req: NucleiRequest, targets: list[str]):
    """The ExecRequest a nuclei job is gated as — command ``nuclei`` with the built argv."""
    from .models import ExecRequest

    argv = nuclei_argv(targets, req)
    return ExecRequest(
        command=argv[0],
        args=argv[1:],
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


def validate(req: NucleiRequest) -> Any:
    """The gate verdict, attacking nothing. PURE. Returns None when it passes.

    Resolves the targets first (so the target handrail sees the real hosts), then asks the SAME
    `executor.validate_request` a one-shot exec would. This is what a UI can call to show "would
    this be refused" before launching anything — the same split intruder/credattack make.
    """
    targets, _ = resolve_targets(req)
    return _gate(_exec_request(req, targets))


# --------------------------------------------------------------------------- #
# the job registry — stop is a flag, and setting it is ungated
# --------------------------------------------------------------------------- #
_jobs: dict[str, NucleiJob] = {}
_stops: dict[str, threading.Event] = {}
_procs: dict[str, subprocess.Popen] = {}
_lock = threading.Lock()


def get(job_id: str) -> NucleiJob | None:
    with _lock:
        return _jobs.get(job_id)


def list_jobs(session_id: str | None = None) -> list[NucleiJob]:
    with _lock:
        jobs = list(_jobs.values())
    if session_id:
        jobs = [j for j in jobs if j.session_id == session_id]
    return sorted(jobs, key=lambda j: j.started_at, reverse=True)


def stop(job_id: str) -> NucleiJob | None:
    """Stop an in-flight scan. NOT GATED — the panic button, like `stop_scan` and the intruder's
    stop. Thousands of template checks may still be queued; a gate that could refuse to stop them
    would make the system less safe. Sets the event and kills the process."""
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
    """Sandbox availability + running-job count — drives the UI banner. Read-only.

    The lab sandbox is the default box a scan runs in (engagement mode swaps in the open one at
    run time); reporting the lab box up/down is the honest banner for the common case.
    """
    container = config.SANDBOX_CONTAINER
    up = repeater_mod._container_running(container)
    with _lock:
        running = sum(1 for j in _jobs.values() if j.state == "running")
    return {
        "container": container,
        "up": up,
        "ready": up,
        "running": running,
        "detail": "" if up else "lab sandbox is not running",
    }


def template_catalogue() -> dict[str, Any]:
    """The pickable severities + curated tags, plus a best-effort LIVE template count. Read-only.

    The count runs `nuclei -tl` inside the lab sandbox when it is up — it lists installed template
    paths and sends NO attack traffic. Best-effort: if the sandbox is down or the call fails, the
    count is null and the severities/tags still stand, so the picker always renders.
    """
    container = config.SANDBOX_CONTAINER
    up = repeater_mod._container_running(container)
    count: int | None = None
    if up:
        try:
            proc = subprocess.run(
                ["docker", "exec", container, "nuclei", "-tl", "-duc", "-silent"],
                capture_output=True, text=True, timeout=60,
            )
            parsed = parse_template_list(proc.stdout)
            count = parsed or None
        except Exception:  # noqa: BLE001 - a listing failure must not break the picker
            count = None
    return {
        "severities": list(SEVERITIES),
        "tags": list(CURATED_TAGS),
        "count": count,
        "container": container,
        "up": up,
    }


# --------------------------------------------------------------------------- #
# execution
# --------------------------------------------------------------------------- #
def start(req: NucleiRequest) -> NucleiJob:
    """Validate, then run ONE nuclei scan in the background. THE GATE RUNS BEFORE ANYTHING SPAWNS.

    Refuses (nothing runs) on any of the four gates, or if the resolved sandbox is down, or if no
    target could be resolved. Otherwise the job is registered `running` and a worker execs one
    `nuclei -jsonl …`, which is what makes `stop` meaningful: there is something to stop.
    """
    targets, warnings = resolve_targets(req)
    if not targets:
        raise NucleiRefused("input", "; ".join(warnings) or "no target to scan")

    exec_req = _exec_request(req, targets)
    rejected = _gate(exec_req)
    if rejected is not None:
        raise NucleiRefused(rejected.gate, rejected.reason, list(rejected.dangerous_flags or []))

    # The per-mode sandbox, resolved exactly as a one-shot exec would resolve it.
    from . import executor

    resolved = executor.resolve_mode(exec_req)
    if not repeater_mod._container_running(resolved.container):
        raise NucleiRefused(
            "unavailable",
            f"sandbox '{resolved.container}' is not running — nothing was scanned",
        )

    # Authenticated scan: the operator's attached session rides as -H. Build the REAL argv (with the
    # live token) for the exec, but store a MASKED copy in the job record so the token never persists.
    extra_headers = (
        session_store.header_pairs(req.engagement_id) if req.attach_session else []
    )
    real_argv = nuclei_argv(targets, req, extra_headers=extra_headers)
    job_argv = session_store.mask_header_flag_values(real_argv)
    job_id = uuid.uuid4().hex[:12]
    job = NucleiJob(
        id=job_id, argv=job_argv, targets=targets, container=resolved.container,
        mode=resolved.mode, engagement_id=req.engagement_id,
        session_id=req.session_id or req.engagement_id, started_at=_now(), warnings=warnings,
    )
    with _lock:
        _jobs[job_id] = job
        _stops[job_id] = threading.Event()
    threading.Thread(
        target=_run, args=(job_id, real_argv, req, resolved), daemon=True, name=f"nuclei-{job_id}"
    ).start()
    return job


def _run(job_id: str, argv: list[str], req: NucleiRequest, resolved) -> None:
    """The worker: exec one nuclei scan, stream its JSONL, then upsert the findings. Never raises."""
    workdir = loot.workdir_for(
        resolved.mode, resolved.engagement.engagement_id if resolved.engagement else None
    )
    full = ["docker", "exec", *loot.exec_flags(workdir), resolved.container, *argv]
    timeout = config.clamp_timeout(req.timeout_seconds) * 6  # a full template run outlasts one command
    text = _spawn(job_id, full, timeout)

    session_id = req.session_id or req.engagement_id or ""
    run_id = job_id
    ui_findings = parse_ui_findings(text)
    new_finds = 0
    if session_id:
        try:
            new_finds = state_store.upsert_findings(parse_findings(text, session_id, run_id))
        except Exception:  # noqa: BLE001 - correlation must never lose the run
            new_finds = 0

    with _lock:
        job = _jobs.get(job_id)
        stopped = _stops.get(job_id)
        if job is not None:
            job.state = "stopped" if (stopped is not None and stopped.is_set()) else "finished"
            job.finished_at = _now()
            job.findings = ui_findings
            job.total = len(ui_findings)
            job.by_severity = _severity_counts(ui_findings)
            job.new_findings = new_finds
            job.output_tail = text[-4000:]
        _procs.pop(job_id, None)

    # ONE audit record for the whole scan — it was one approval. nuclei carries no secret, so the
    # argv is stored as-is; report.py renders it verbatim.
    try:
        runstore.save_run(RunRecord(
            run_id=run_id, command="nuclei", args=argv[1:],
            target=(job.targets[0] if job and job.targets else ""),
            approved=True, mode=resolved.mode, exit_code=0,
            stdout=text[-8000:], stderr="",
            started_at=(job.started_at if job else _now()), finished_at=_now(),
            session_id=session_id or None, step_id=None,
        ))
    except Exception:  # noqa: BLE001 - an audit failure must not lose the results
        pass


def _spawn(job_id: str, full: list[str], timeout: int) -> str:
    """Run one `docker exec nuclei …` to completion (or until stop/timeout), capturing stdout and
    updating the live finding count as JSONL arrives. Never raises."""
    try:
        proc = subprocess.Popen(
            full, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
        )
    except FileNotFoundError:
        return "[nuclei] docker CLI not found on PATH\n"
    except Exception as exc:  # noqa: BLE001
        return f"[nuclei] could not start: {exc}\n"
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

    wd = threading.Thread(target=_watchdog, daemon=True)
    wd.start()

    assert proc.stdout is not None
    for raw in iter(proc.stdout.readline, ""):
        if stop_ev.is_set():
            break
        if total < _OUTPUT_CAP:
            chunks.append(raw)
            total += len(raw)
        # Live count: re-parse the accumulated transcript so the UI can watch findings land.
        ui = parse_ui_findings("".join(chunks))
        with _lock:
            j = _jobs.get(job_id)
            if j is not None:
                j.findings = ui
                j.total = len(ui)
                j.by_severity = _severity_counts(ui)
                j.output_tail = "".join(chunks[-40:])[-4000:]
    try:
        proc.stdout.close()
    except Exception:  # noqa: BLE001
        pass
    proc.wait()
    text = "".join(chunks)
    if timed["v"]:
        text += f"\n[nuclei] timed out after {timeout}s\n"
    return text


def reset() -> None:
    """Drop all job state. Tests only — never called by the app."""
    with _lock:
        _jobs.clear()
        _stops.clear()
        _procs.clear()
