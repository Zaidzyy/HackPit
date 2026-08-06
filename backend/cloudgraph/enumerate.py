"""Cloud enumeration -> IAM graph, run as a GATED JOB (the recon/nuclei/credattack shape).

*** THE ONLY EXECUTING MODULE IN THIS PACKAGE, AND WHY IT ADDS NO NEW GATE. ***
Give it cloud credentials (present in the engagement sandbox's environment / ``~/.aws``, or an
operator-named profile — operator input, never auto-harvested from the host without a click) and it
runs ScoutSuite + Prowler (+ cloudfox / pacu) as ONE approved job, parses their JSON into a typed
IAM privilege-escalation graph, and files the misconfigurations as engagement-state ``Finding``s.

This module is deliberately SEPARATE from ``orchestrator.py``: the orchestrator proposes an edge
index and executes nothing (regression-locked by an AST scan), while enumeration is a real docker
exec — so it lives here, gated exactly like every other sweep:

  * ENGAGEMENT-BOUND, like recon/credattack. Enumeration reaches a real cloud API, so it needs the
    OPEN, loot-mounted engagement sandbox where the credentials live and where egress exists. No
    active engagement -> refused (an availability precondition, never a bypass).
  * ONE APPROVAL BUYS THE WHOLE SWEEP. scoutsuite -> prowler (-> cloudfox) is ONE human approval,
    gated by the SAME ``executor.validate_request`` every command clears, run BEFORE anything
    spawns, with an UNGATED stop — exactly the crack-worker model. NO new gate, NO batch auto-runner.

THE SPLIT, mirroring recon/nuclei:
  * PURE, INSPECTABLE HALF — the ``*_argv`` builders. They build argv and execute NOTHING.
    Regression-locked in test_cloudgraph_safety.py by an AST walk.
  * THE WORKER — :func:`start` validates through the gate BEFORE anything spawns, then a background
    thread runs the sweep's ``docker exec``s in the engagement sandbox, parses the captured JSON and
    upserts findings.
"""

from __future__ import annotations

import subprocess
import threading
import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from cockpit import config, engagement, loot, runstore
from cockpit.models import RunRecord
from state import store as state_store
from state.models import Finding

from . import store
from .parser import ParseError, parse_collection, parse_prowler_findings
from .paths import default_high_value_target, shortest_path
from .schema import PRINCIPAL_TYPES

_OUTPUT_CAP = 400_000
# The tools each provider's sweep runs, in order. scoutsuite feeds the graph; prowler feeds the
# findings; cloudfox augments (best-effort). pacu is available but off by default (interactive).
_SWEEP: dict[str, list[str]] = {
    "aws": ["scoutsuite", "prowler", "cloudfox"],
    "azure": ["scoutsuite", "prowler"],
    "gcp": ["scoutsuite", "prowler"],
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _container_running(name: str) -> bool:
    """Whether the named container is up. A local copy (like kali.py / obfuscation.py / proxy.py
    each keep) — deliberately NOT imported from cockpit.repeater, whose send path is human-only and
    must have no importer outside cockpit (test_repeater.py). Read-only ``docker inspect``."""
    try:
        out = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", name],
            capture_output=True, text=True, timeout=5,
        )
        return out.returncode == 0 and out.stdout.strip() == "true"
    except Exception:  # noqa: BLE001 - a missing docker / container reads as "not up"
        return False


# --------------------------------------------------------------------------- #
# models
# --------------------------------------------------------------------------- #
class CloudEnumRequest(BaseModel):
    """One cloud enumeration sweep + the gate fields."""

    provider: str = Field("aws", description="aws | azure | gcp")
    profile: str = Field(
        "", description="Optional named credential profile (a bare token, e.g. an AWS profile). "
        "The SECRET itself is never on the argv — it lives in the sandbox env / ~/.aws / ~/.azure "
        "/ gcloud config, which the operator sets (operator input, not auto-harvested)."
    )
    region: str = Field("", description="Optional region/location to scope the sweep to.")
    tools: list[str] = Field(default_factory=list, description="Override the default tool set.")
    timeout_seconds: int | None = None
    engagement_id: str | None = None
    session_id: str | None = None
    # THE GATE FIELDS — the executor's, unchanged. Both default False so an omitted field is
    # REFUSED rather than granted.
    approved: bool = Field(False, description="Explicit human approval. Never defaulted true.")
    dangerous_ack: bool = Field(
        False, description="The red-confirm, WHEN THE GATE ASKS FOR IT — decided by the four gates."
    )


class CloudEnumStage(BaseModel):
    tool: str
    argv: list[str] = Field(default_factory=list)
    state: str = Field("ran", description="ran | stopped | skipped")
    note: str = ""


class CloudEnumJob(BaseModel):
    id: str
    provider: str = "aws"
    state: str = Field("running", description="running | finished | stopped | refused")
    argv: list[str] = Field(default_factory=list)
    container: str = ""
    mode: str = "engagement"
    engagement_id: str | None = None
    session_id: str | None = None
    started_at: str = ""
    finished_at: str = ""
    graph_id: str = ""
    stages: list[CloudEnumStage] = Field(default_factory=list)
    nodes: int = 0
    edges: int = 0
    new_findings: int = 0
    output_tail: str = ""
    warnings: list[str] = Field(default_factory=list)
    refused: str = ""
    refused_gate: str = ""


class CloudEnumRefused(RuntimeError):
    """Refused BEFORE anything ran. Carries the gate that refused it."""

    def __init__(self, gate: str, reason: str, dangerous_flags: list[str] | None = None) -> None:
        super().__init__(reason)
        self.gate = gate
        self.reason = reason
        self.dangerous_flags = dangerous_flags or []


# --------------------------------------------------------------------------- #
# PURE: argv builders — the commands a sweep is EQUIVALENT TO. Never a shell.
# --------------------------------------------------------------------------- #
def scoutsuite_argv(provider: str, report_dir: str, profile: str = "", region: str = "") -> list[str]:
    """ScoutSuite collection for one provider; the report (incl. scoutsuite_results_*.js) is
    written under ``report_dir`` in the loot mount so the worker can parse it."""
    argv = ["scout", provider, "--report-dir", report_dir, "--no-browser"]
    if provider == "aws" and profile:
        argv += ["--profile", profile]
    if provider == "azure":
        argv += ["--cli"]
    if region and provider == "aws":
        argv += ["--regions", region]
    return argv


def prowler_argv(provider: str, out_dir: str, profile: str = "", region: str = "") -> list[str]:
    """Prowler posture assessment; JSON written under ``out_dir`` for the findings parser."""
    argv = ["prowler", provider or "aws", "-M", "json", "--output-directory", out_dir]
    if provider == "aws" and profile:
        argv += ["-p", profile]
    if region:
        argv += ["-f", region] if provider == "aws" else ["--region", region]
    return argv


def cloudfox_argv(provider: str, profile: str = "") -> list[str]:
    """cloudfox permission/attack-surface mapping (best-effort augmentation)."""
    argv = ["cloudfox", provider, "all-checks"]
    if provider == "aws" and profile:
        argv += ["--profile", profile]
    return argv


def pacu_argv(module: str = "iam__enum_permissions") -> list[str]:
    """pacu, driven non-interactively to run a read-only IAM enumeration module."""
    return ["pacu", "--session", "hackpit", "--module-name", module, "--exec"]


def _argv_for(tool: str, provider: str, report_dir: str, profile: str, region: str) -> list[str]:
    if tool == "scoutsuite":
        return scoutsuite_argv(provider, report_dir, profile, region)
    if tool == "prowler":
        return prowler_argv(provider, report_dir, profile, region)
    if tool == "cloudfox":
        return cloudfox_argv(provider, profile)
    if tool == "pacu":
        return pacu_argv()
    return [tool]


# --------------------------------------------------------------------------- #
# the gate — THE EXECUTOR'S, UNCHANGED
# --------------------------------------------------------------------------- #
def _exec_request(command: str, args: list[str], req: CloudEnumRequest):
    from cockpit.models import ExecRequest

    return ExecRequest(
        command=command, args=args, approved=req.approved, dangerous_ack=req.dangerous_ack,
        engagement_id=req.engagement_id, session_id=req.session_id,
        timeout_seconds=req.timeout_seconds,
    )


def _gate(exec_req):
    from cockpit import executor

    return executor.validate_request(exec_req)


def validate(req: CloudEnumRequest) -> Any:
    """The gate verdict for a sweep, attacking nothing. PURE. Returns None when it passes. Gated
    against the entry command (``scout <provider>``) — the SAME ``executor.validate_request`` a
    one-shot exec asks. A UI calls this to show 'would this be refused' before launching."""
    argv = scoutsuite_argv(req.provider or "aws", "/loot", req.profile, req.region)
    return _gate(_exec_request(argv[0], argv[1:], req))


# --------------------------------------------------------------------------- #
# job registry — stop is a flag, and setting it is ungated
# --------------------------------------------------------------------------- #
_jobs: dict[str, CloudEnumJob] = {}
_stops: dict[str, threading.Event] = {}
_procs: dict[str, subprocess.Popen] = {}
_lock = threading.Lock()


def get(job_id: str) -> CloudEnumJob | None:
    with _lock:
        return _jobs.get(job_id)


def list_jobs(session_id: str | None = None) -> list[CloudEnumJob]:
    with _lock:
        jobs = list(_jobs.values())
    if session_id:
        jobs = [j for j in jobs if j.session_id == session_id]
    return sorted(jobs, key=lambda j: j.started_at, reverse=True)


def stop(job_id: str) -> CloudEnumJob | None:
    """Stop an in-flight sweep. NOT GATED — the panic button, like recon's stop. Sets the event and
    kills the current process; the worker ends the sweep."""
    with _lock:
        ev = _stops.get(job_id)
        proc = _procs.get(job_id)
        job = _jobs.get(job_id)
    if ev is not None:
        ev.set()
    if proc is not None and proc.poll() is None:
        try:
            proc.kill()
        except Exception:  # noqa: BLE001
            pass
    return job


def status() -> dict[str, Any]:
    """Engagement-sandbox availability + running-job count — drives the UI banner. Read-only."""
    up = _container_running(config.ENGAGE_SANDBOX_CONTAINER)
    with _lock:
        running = sum(1 for j in _jobs.values() if j.state == "running")
    return {
        "container": config.ENGAGE_SANDBOX_CONTAINER,
        "up": up, "ready": up, "running": running,
        "detail": "" if up else "engagement sandbox is not running",
    }


# --------------------------------------------------------------------------- #
# preconditions — the credattack model, one place
# --------------------------------------------------------------------------- #
def _require_engagement(engagement_id: str | None):
    record = engagement.get_active(engagement_id) if engagement_id else None
    if record is None:
        raise CloudEnumRefused(
            "engagement",
            "cloud enumeration runs in an active engagement — enter engagement mode first "
            "(POST /cockpit/engagement/enter). The isolated lab sandbox has no cloud egress or loot.",
        )
    if not _container_running(config.ENGAGE_SANDBOX_CONTAINER):
        raise CloudEnumRefused(
            "unavailable",
            f"engagement sandbox '{config.ENGAGE_SANDBOX_CONTAINER}' is not running — nothing ran",
        )
    try:
        workdir = loot.ensure(engagement_id or "")
    except loot.LootError as exc:
        raise CloudEnumRefused("loot", f"could not prepare a loot directory: {exc}")
    return record, workdir


def _register(job: CloudEnumJob) -> None:
    with _lock:
        _jobs[job.id] = job
        _stops[job.id] = threading.Event()


# --------------------------------------------------------------------------- #
# start — GATE BEFORE ANYTHING SPAWNS
# --------------------------------------------------------------------------- #
def start(req: CloudEnumRequest) -> CloudEnumJob:
    """Validate, then run ONE cloud enumeration sweep in the background. THE GATE RUNS BEFORE ANY
    SPAWN — the same ``executor.validate_request`` every command clears."""
    provider = (req.provider or "aws").lower()
    if provider not in _SWEEP:
        raise CloudEnumRefused("input", f"unknown provider {provider!r} — aws | azure | gcp")
    record, workdir = _require_engagement(req.engagement_id)

    argv = scoutsuite_argv(provider, loot.container_dir(req.engagement_id or ""),
                           req.profile, req.region)
    rejected = _gate(_exec_request(argv[0], argv[1:], req))
    if rejected is not None:
        raise CloudEnumRefused(rejected.gate, rejected.reason, list(rejected.dangerous_flags or []))

    job = CloudEnumJob(
        id=uuid.uuid4().hex[:12], provider=provider, argv=argv,
        container=config.ENGAGE_SANDBOX_CONTAINER, engagement_id=req.engagement_id,
        session_id=req.session_id or req.engagement_id, started_at=_now(),
    )
    _register(job)
    threading.Thread(
        target=_run, args=(job.id, req, record, workdir, provider),
        daemon=True, name=f"cloud-enum-{job.id}",
    ).start()
    return job


# --------------------------------------------------------------------------- #
# worker — one sweep = one approval; between stages, stop-check
# --------------------------------------------------------------------------- #
def _run(job_id: str, req: CloudEnumRequest, record, workdir: str, provider: str) -> None:
    """Enumeration worker: scoutsuite (graph) -> prowler (findings) -> cloudfox. Never raises."""
    session_id = req.session_id or req.engagement_id or ""
    engagement_id = req.engagement_id or ""
    report_dir = loot.container_dir(engagement_id)
    tools = req.tools or _SWEEP[provider]
    last_text = ""

    for tool in tools:
        if _stopped(job_id):
            _add_stage(job_id, tool, [tool], "skipped", "stopped before this stage")
            break
        argv = _argv_for(tool, provider, report_dir, req.profile, req.region)
        text = _spawn(job_id, argv, workdir, _timeout(req))
        last_text = text or last_text
        note = _ingest_tool(job_id, tool, provider, session_id, engagement_id, text)
        _add_stage(job_id, tool, argv, "ran", note)

    _finish(job_id, session_id, provider, last_text)


def _ingest_tool(job_id: str, tool: str, provider: str, session_id: str, engagement_id: str,
                 text: str) -> str:
    """Parse one tool's captured output. scoutsuite -> graph; prowler -> findings; else a note."""
    try:
        if tool == "scoutsuite":
            return _ingest_scoutsuite(job_id, provider, session_id, engagement_id)
        if tool == "prowler":
            return _ingest_prowler(job_id, session_id, engagement_id, text)
    except Exception as exc:  # noqa: BLE001 - a parse hiccup must not lose the sweep
        return f"parse error: {exc}"
    return "captured (augmentation)"


def _ingest_scoutsuite(job_id: str, provider: str, session_id: str, engagement_id: str) -> str:
    """Read the scoutsuite_results_*.js the run wrote into loot, parse it into a graph, persist."""
    host = loot.host_dir(engagement_id)
    results = sorted(host.glob("**/scoutsuite_results_*.js")) if host.exists() else []
    if not results:
        return "no scoutsuite results file found in loot"
    text = results[-1].read_text(encoding="utf-8", errors="replace")
    try:
        graph = parse_collection(text)
    except ParseError as exc:
        return f"{provider} scoutsuite parsed no IAM graph ({exc})"
    graph_dict = graph.to_dict()
    graph_id = store.save_graph(graph_dict, session_id, engagement_id, source="enumerate")
    _file_privesc_findings(graph, session_id, job_id)
    with _lock:
        job = _jobs.get(job_id)
        if job is not None:
            job.graph_id = graph_id
            job.nodes = graph.stats().get("nodes", 0)
            job.edges = graph.stats().get("edges", 0)
            job.warnings.extend(graph.warnings)
    return f"{graph.stats().get('nodes', 0)} nodes, {graph.stats().get('abusable_edges', 0)} abusable edges"


def _ingest_prowler(job_id: str, session_id: str, engagement_id: str, text: str) -> str:
    """Read prowler's JSON from loot (or its stdout), turn FAIL checks into engagement Findings."""
    host = loot.host_dir(engagement_id)
    payload = text
    files = sorted(host.glob("**/prowler-*.json")) + sorted(host.glob("**/*.ocsf.json")) if host.exists() else []
    if files:
        payload = files[-1].read_text(encoding="utf-8", errors="replace")
    rows = parse_prowler_findings(payload)
    findings = [
        Finding(session_id=session_id, title=r["title"], severity=r["severity"],
                target=r["target"], evidence=r["evidence"], tool="prowler",
                reference=r["reference"], source_run_id=job_id)
        for r in rows if session_id
    ]
    n = state_store.upsert_findings(findings) if findings else 0
    with _lock:
        job = _jobs.get(job_id)
        if job is not None:
            job.new_findings += n
    return f"{n} misconfiguration finding(s)"


def _file_privesc_findings(graph, session_id: str, job_id: str) -> None:
    """Every principal that can REACH an admin/owner principal is itself a privesc finding — the
    graph's whole point, filed so it shows up in the engagement's findings and the report."""
    if not session_id:
        return
    goal = default_high_value_target(graph)
    if not goal:
        return
    goal_label = graph.node(goal).label if graph.node(goal) else goal
    findings: list[Finding] = []
    for n in list(graph.nodes.values()):
        if n.id == goal or n.type not in PRINCIPAL_TYPES:
            continue
        p = shortest_path(graph, n.id, goal)
        if p is None or not p.edges:
            continue
        chain = " -> ".join([p.edges[0].source_label] + [f"[{h.kind}] {h.target_label}" for h in p.edges])
        findings.append(Finding(
            session_id=session_id, title=f"IAM privilege escalation to {goal_label}",
            severity="high", target=n.label, tool="cloudgraph",
            evidence=f"{n.label} can reach {goal_label} in {p.length} hop(s): {chain}",
            reference="iam-privesc", source_run_id=job_id,
        ))
    if findings:
        n = state_store.upsert_findings(findings)
        with _lock:
            job = _jobs.get(job_id)
            if job is not None:
                job.new_findings += n


# --------------------------------------------------------------------------- #
# worker helpers
# --------------------------------------------------------------------------- #
def _timeout(req: CloudEnumRequest) -> int:
    return config.clamp_timeout(req.timeout_seconds) * 4


def _stopped(job_id: str) -> bool:
    ev = _stops.get(job_id)
    return ev is not None and ev.is_set()


def _add_stage(job_id: str, tool: str, argv: list[str], state: str, note: str) -> None:
    with _lock:
        job = _jobs.get(job_id)
        if job is not None:
            job.stages.append(CloudEnumStage(tool=tool, argv=argv, state=state, note=note))


def _finish(job_id: str, session_id: str, provider: str, text: str) -> None:
    with _lock:
        job = _jobs.get(job_id)
        stopped = _stops.get(job_id)
        if job is not None:
            job.state = "stopped" if (stopped is not None and stopped.is_set()) else "finished"
            job.finished_at = _now()
            job.output_tail = text[-4000:]
        argv = job.argv if job else ["scout", provider]
        _procs.pop(job_id, None)
    try:
        runstore.save_run(RunRecord(
            run_id=job_id, command=argv[0] if argv else "scout", args=argv[1:] if argv else [],
            target=f"{provider} account", approved=True, mode="engagement", exit_code=0,
            stdout=text[-8000:], stderr="", started_at=(job.started_at if job else _now()),
            finished_at=_now(), session_id=session_id or None, step_id=None,
        ))
    except Exception:  # noqa: BLE001
        pass


def _spawn(job_id: str, argv: list[str], workdir: str, timeout: int) -> str:
    """Run ONE ``docker exec <tool>`` to completion (or until stop/timeout), capturing merged
    output. Never raises — a transport failure becomes a note in the transcript."""
    full = ["docker", "exec", *loot.exec_flags(workdir), config.ENGAGE_SANDBOX_CONTAINER, *argv]
    try:
        proc = subprocess.Popen(
            full, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
        )
    except FileNotFoundError:
        return "[cloud] docker CLI not found on PATH\n"
    except Exception as exc:  # noqa: BLE001
        return f"[cloud] could not start: {exc}\n"
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
        text += f"\n[cloud] {argv[0]} timed out after {timeout}s\n"
    return text


def reset() -> None:
    """Drop all job state. Tests only — never called by the app."""
    with _lock:
        _jobs.clear()
        _stops.clear()
        _procs.clear()
