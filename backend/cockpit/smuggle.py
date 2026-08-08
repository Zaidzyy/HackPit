"""The request-smuggling / desync detector — one gated job per stage, mirroring nuclei.py + race.py.

*** WHY THIS FITS THE APPROVAL MODEL — THE INTRUDER'S / RACE'S ARGUMENT, WORD FOR WORD. ***
HackPit refuses **batching across approvals** — an agent queueing five commands and a human
clicking once. It has never refused ONE approval that produces many requests, and could not:
`ffuf`, `nuclei`, the ZAP active scanner, the intruder and the race tester are each a single
approval buying many requests. A smuggling sweep is that same shape — one probe per chosen
mutation from one press: ONE gated job, gated by the SAME four gates, with NO new ones.

TWO STAGES, and the split is the whole safety story of this build:

  * **DETECTION IS SAFE-BY-DEFAULT (TIMING-DIFFERENTIAL).** For each mutation the engine sends a
    request whose ambiguous framing makes a *back-end* wait for bytes that never come; if a
    front-end/back-end pair disagree the probe hangs (a large ``delta_ms``), if a single
    RFC-consistent server handles it it answers fast. **No other user's request is touched** — the
    probe is entirely self-contained. This is the default path.
  * **CONFIRMATION IS A SEPARATE APPROVE-EACH WITH A CO-TENANT WARNING.** Socket-poisoning
    confirmation smuggles a partial request then sends a normal one on the same connection to see
    the poisoned response — *** this is the one that can affect co-tenant traffic ***, so it is its
    own explicit approval carrying :data:`CO_TENANT_WARNING` in plain language. Still just
    approve-each; **no new gate class** — the standing rule is human-approval-only.

THE SPLIT, mirroring race/intruder/nuclei:

  * PURE, INSPECTABLE HALF — :func:`smuggle_argv_for`, :func:`plan`, :func:`_job_spec`,
    :func:`verdict_for`, :func:`detection_verdicts`, :func:`parse_engine_output`,
    :func:`parse_smuggler_output`. They build the argv/spec and turn the engine's JSON (or an
    external `smuggler.py` transcript) into per-mutation verdicts, and they execute NOTHING — so
    what will run and what a result means are both inspectable before anything spawns.
  * THE WORKER — :func:`start` validates through the gate BEFORE anything spawns, scope-checks the
    URL on the WIRE, runs ONE `docker exec … smuggle-probe --job-stdin` with the whole request +
    mutation set as JSON on stdin, parses the result and upserts a `Finding` on a hit.

CONTAINMENT, inherited wholesale from the race tester and stated rather than assumed:

  * **HARDCODED CONTAINER** — every probe runs inside ``config.KALI_OPEN_CONTAINER``, a code
    constant no request field can redirect.
  * **ARGV-ONLY engine, the request on stdin** — `docker exec -i … smuggle-probe --job-stdin`; the
    whole request (URL, headers, body, mutations, stage) is JSON on STDIN, no shell parses a byte.
  * **SCOPE-CHECKED ON THE WIRE** — the URL host is checked against the engagement scope on the
    bytes that go out, before anything is dispatched. Out-of-scope refuses the whole sweep.
  * **STOP IS UNGATED**, like every other stop in this codebase.
"""

from __future__ import annotations

import json
import re
import subprocess
import threading
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from . import config, loot, repeater as repeater_mod, runstore, scope as scope_mod
from .models import RunRecord

#: Every mutation the detector offers. CL/TE + CL.0 are the h1 must-haves; H2.* are the modern
#: downgrade variants (best-effort in the engine, honest inconclusive when the target is not h2).
MUTATIONS: tuple[str, ...] = (
    "CL.TE", "TE.CL", "CL.CL", "TE.TE", "CL.0", "H2.CL", "H2.TE", "H2.0",
)
#: The safe default sweep — the h1 CL/TE family + CL.0, which need no h2 negotiation.
DEFAULT_MUTATIONS: tuple[str, ...] = ("CL.TE", "TE.CL", "CL.0")

#: The two stages. detect is safe-by-default; confirm is the separately-approved socket-poisoning
#: step. An unknown stage falls back to detect and SAYS SO — it never escalates to confirm.
STAGES = ("detect", "confirm")
DEFAULT_STAGE = "detect"

#: *** THE ONE THRESHOLD, kept in the backend so there is a single place to tune and to pin. ***
#: The engine only TIMES; a probe is susceptible when its round trip runs at least this many ms
#: longer than a normal baseline — the peer blocked waiting for body bytes the ambiguous framing
#: promised and never delivered. The engine's per-probe read ceiling is ~6s, so a real hang shows
#: as a ~4-6s delta over a fast baseline; 4000ms sits clear of jitter without missing a true hang.
SUSCEPTIBLE_DELTA_MS = 4000

#: The plain-language co-tenant warning surfaced on the CONFIRMATION stage's approval. It is a
#: constant so the UI, the preview and the job all show the SAME words, and a safety test pins that
#: the confirm path carries it (the drift trap the cookie-jar docstring names).
CO_TENANT_WARNING = (
    "CONFIRMATION MAY AFFECT CO-TENANT REQUESTS. Socket-poisoning confirmation smuggles a partial "
    "request onto a shared connection, so the NEXT request on that connection — possibly another "
    "user's — can receive the poisoned response. Only run it on a target you are authorised to "
    "desync, and expect to affect other traffic. Detection (timing) does not do this; this stage "
    "does. It is still approve-each — no new gate — you are the bound."
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------- #
# models
# --------------------------------------------------------------------------- #
class SmuggleRequest(BaseModel):
    """One smuggling job: a request template, a mutation checklist, a stage, and the gate fields.

    NO container/target field — the box is a code constant (rule #1), exactly like the intruder and
    the race tester. The same request template is probed against each chosen mutation.
    """

    url: str = Field(..., min_length=1, description="Absolute http(s) URL the probes go to.")
    method: str = "POST"
    headers: list[repeater_mod.RepeaterHeader] = Field(default_factory=list)
    body: str = Field("", description="Request body used for the baseline / CL.0 template.")
    mutations: list[str] = Field(
        default_factory=list,
        description="Which desync variants to probe (see MUTATIONS). Empty = the safe default set.",
    )
    stage: str = Field(
        DEFAULT_STAGE,
        description="detect (safe timing-differential, the default) or confirm (socket-poisoning, "
        "a SEPARATE approve-each with a co-tenant warning). Unknown falls back to detect.",
    )
    timeout_seconds: int | None = None
    insecure: bool = False
    follow_redirects: bool = False
    engagement_id: str | None = None
    session_id: str | None = None
    use_cookie_jar: bool = Field(
        True, description="Attach the repeater's session jar — most desync targets are authed."
    )
    # THE GATE FIELDS — the scanner's / race's, unchanged. Both default False so an omitted field is
    # REFUSED rather than granted.
    approved: bool = Field(False, description="Explicit human approval. Never defaulted true.")
    dangerous_ack: bool = Field(
        False,
        description="The red-confirm, WHEN THE GATE ASKS FOR IT. Not demanded unconditionally by "
        "this model: the four gates decide and they fire on request CONTENT. The confirmation "
        "stage's co-tenant risk is surfaced as a warning on its own approval, not as a new gate.",
    )


class MutationVerdict(BaseModel):
    """One mutation's DETECTION verdict — the timing signal turned into susceptible/not."""

    mutation: str
    susceptible: bool = False
    baseline_ms: int = 0
    probe_ms: int = 0
    delta_ms: int = 0
    error: str = ""
    note: str = ""


class ConfirmVerdict(BaseModel):
    """One mutation's CONFIRMATION verdict — did socket poisoning actually desync a follow-up."""

    mutation: str
    confirmed: bool = False
    status: int | None = None
    evidence: str = ""
    error: str = ""
    note: str = ""


class SmuggleJob(BaseModel):
    """The job. Counts are what HAPPENED, never what was planned."""

    id: str
    state: str = Field("running", description="running | finished | stopped | refused")
    stage: str = DEFAULT_STAGE
    request: SmuggleRequest
    container: str = ""
    started_at: str = ""
    finished_at: str = ""
    mutations: list[str] = Field(default_factory=list, description="The mutations actually probed.")
    verdicts: list[MutationVerdict] = Field(default_factory=list, description="Detection results.")
    confirms: list[ConfirmVerdict] = Field(default_factory=list, description="Confirmation results.")
    susceptible: list[str] = Field(
        default_factory=list, description="Mutations the timing signal flagged susceptible."
    )
    confirmed: list[str] = Field(
        default_factory=list, description="Mutations socket-poisoning confirmed."
    )
    co_tenant_warning: str = Field(
        "", description="Set on the confirm stage — the plain-language co-tenant risk. Empty on "
        "detect, which is self-contained."
    )
    warnings: list[str] = Field(default_factory=list)
    scope_refusals: int = Field(
        0, description="Probes NOT sent because the URL host left the engagement scope. When this "
        "fires the whole sweep is refused (all mutations share one URL) and nothing is sent."
    )
    finding_written: bool = Field(
        False, description="True when a susceptible/confirmed result was written as a Finding."
    )


class SmuggleRefused(RuntimeError):
    """Refused BEFORE anything ran. Carries the gate that refused it."""

    def __init__(self, gate: str, reason: str, dangerous_flags: list[str] | None = None) -> None:
        super().__init__(reason)
        self.gate = gate
        self.reason = reason
        self.dangerous_flags = dangerous_flags or []


# --------------------------------------------------------------------------- #
# the gate — THE SCANNER'S FOUR, UNCHANGED
# --------------------------------------------------------------------------- #
def smuggle_argv_for(req: SmuggleRequest) -> list[str]:
    """The command this job is EQUIVALENT TO, which is what the human approves.

    ``smuggle-probe`` because that IS what runs — the in-repo desync client baked into the sandbox.
    NOT because it is "allowed": there is no tool allowlist in this product. The gates are approval,
    target, danger and isolation, and none consults a list of binaries — so the declared command
    only has to be HONEST, because that string is what a human approves and what the danger
    heuristic reads.

    The URL rides as ``-u`` (where the target handrail reads the host); the stage, the mutation set,
    the method, the body and every header travel verbatim so the surface is COMPLETE — the
    intruder's Critical-2 rule: nothing is summarised, so a body carrying a shell pattern reaches
    the danger gate rather than hiding behind a count.
    """
    argv = ["smuggle-probe", "-u", req.url, "--stage", _stage_of(req)[0]]
    # Mutations ride the surface dot-free (CL.TE -> cl-te). The dotted canonical name is host-shaped
    # (label.label), and the best-effort target-lock scans EVERY argv token for a host — a dotted
    # `CL.TE` would be read as an out-of-scope host and refuse the whole job at the target gate. The
    # dot-free spelling is exactly as honest (the operator still approves the precise mutation set)
    # and the engine gets the canonical `CL.TE` names from the JSON spec on stdin, not from here.
    argv += ["--mutations", ",".join(m.lower().replace(".", "-") for m in _mutations_of(req)[0])]
    method = (req.method or "POST").strip().upper()
    if method != "GET":
        argv += ["-X", method]
    for h in req.headers:
        name = (h.name or "").strip()
        if name:
            argv += ["-H", f"{name}: {h.value}"]
    if req.body:
        argv += ["-d", req.body]
    return argv


def _gate_request(req: SmuggleRequest):
    from .models import ExecRequest

    argv = smuggle_argv_for(req)
    return ExecRequest(
        command=argv[0], args=argv[1:],
        approved=req.approved, dangerous_ack=req.dangerous_ack,
        engagement_id=req.engagement_id,
    )


def validate(req: SmuggleRequest):
    """The gate verdict, attacking nothing. PURE. Returns None when it passes.

    All four gates, in the executor's order, unchanged and with nothing added — so a UI can ask
    "would this be refused" without launching anything, the same split race/intruder make.
    """
    from . import executor

    return executor.validate_request(_gate_request(req))


# --------------------------------------------------------------------------- #
# planning — PURE, so what will be probed is inspectable before anything is
# --------------------------------------------------------------------------- #
def _stage_of(req: SmuggleRequest) -> tuple[str, str | None]:
    """``(stage, warning)``. An unknown stage falls back to detect (never escalates to confirm)."""
    stage = (req.stage or "").strip().lower()
    if stage not in STAGES:
        return DEFAULT_STAGE, (
            f"unknown stage {req.stage!r} — running the safe {DEFAULT_STAGE!r} path. "
            f"Known: {', '.join(STAGES)}"
        )
    return stage, None


def _mutations_of(req: SmuggleRequest) -> tuple[list[str], list[str]]:
    """``(mutations, warnings)``. Unknown names are dropped WITH a warning; empty picks the default
    set. Order preserved, de-duplicated. WARN AND CONTINUE — a typo never refuses the job."""
    warnings: list[str] = []
    picked = [str(m).strip().upper() for m in req.mutations if str(m).strip()]
    if not picked:
        return list(DEFAULT_MUTATIONS), warnings
    seen: set[str] = set()
    out: list[str] = []
    for m in picked:
        if m not in MUTATIONS:
            warnings.append(f"unknown mutation {m!r} — skipped. Known: {', '.join(MUTATIONS)}")
            continue
        if m not in seen:
            seen.add(m)
            out.append(m)
    if not out:
        warnings.append("no valid mutation left — falling back to the default set")
        out = list(DEFAULT_MUTATIONS)
    return out, warnings


def plan(req: SmuggleRequest) -> tuple[str, list[str], list[str]]:
    """``(stage, mutations, warnings)``. Probes nothing. WARN AND CONTINUE throughout."""
    warnings: list[str] = []
    stage, stage_warn = _stage_of(req)
    if stage_warn:
        warnings.append(stage_warn)
    mutations, mut_warn = _mutations_of(req)
    warnings.extend(mut_warn)
    if stage == "confirm":
        warnings.append(CO_TENANT_WARNING)
    return stage, mutations, warnings


# --------------------------------------------------------------------------- #
# verdicts — PURE, testable on a fixture timing set or an external transcript
# --------------------------------------------------------------------------- #
def verdict_for(mutation: str, baseline_ms: int, probe_ms: int, error: str = "") -> MutationVerdict:
    """One mutation's detection verdict from its timing pair. PURE — the single place the
    susceptibility threshold is applied. An error (connect failed / h2 inconclusive) is NEVER
    susceptible; it is reported as a note so an unreachable host does not read as a hit."""
    delta = int(probe_ms) - int(baseline_ms)
    if error:
        return MutationVerdict(
            mutation=mutation, susceptible=False, baseline_ms=int(baseline_ms),
            probe_ms=int(probe_ms), delta_ms=delta, error=error,
            note=f"inconclusive — {error}",
        )
    susceptible = delta >= SUSCEPTIBLE_DELTA_MS
    return MutationVerdict(
        mutation=mutation, susceptible=susceptible, baseline_ms=int(baseline_ms),
        probe_ms=int(probe_ms), delta_ms=delta,
        note=(
            f"probe hung {delta}ms over the baseline — a back-end waited for body bytes the "
            f"ambiguous framing never delivered, the signature of a {mutation} desync split."
            if susceptible else
            f"probe returned {delta}ms over the baseline (< {SUSCEPTIBLE_DELTA_MS}ms) — no desync "
            "delay observed; a single consistent parser handled the ambiguous request."
        ),
    )


def detection_verdicts(rows: list[dict[str, Any]]) -> list[MutationVerdict]:
    """A list of engine timing rows -> per-mutation verdicts. PURE. Each row is
    ``{mutation, baseline_ms, probe_ms, error}``; the threshold is applied by :func:`verdict_for`."""
    out: list[MutationVerdict] = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        out.append(verdict_for(
            str(r.get("mutation") or ""),
            int(r.get("baseline_ms") or 0),
            int(r.get("probe_ms") or 0),
            str(r.get("error") or ""),
        ))
    return out


def confirm_verdicts(rows: list[dict[str, Any]]) -> list[ConfirmVerdict]:
    """Engine confirm rows -> per-mutation confirmation verdicts. PURE."""
    out: list[ConfirmVerdict] = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        err = str(r.get("error") or "")
        poisoned = bool(r.get("poisoned")) and not err
        out.append(ConfirmVerdict(
            mutation=str(r.get("mutation") or ""),
            confirmed=poisoned,
            status=r.get("status"),
            evidence=str(r.get("evidence") or ""),
            error=err,
            note=(
                "socket poisoning desynchronised a follow-up on the shared connection — the "
                "desync is confirmed, not merely timing-suggested."
                if poisoned else
                ("inconclusive — " + err if err else
                 "the follow-up on the poisoned connection returned normally — not confirmed.")
            ),
        ))
    return out


def parse_engine_output(stdout: str, stage: str) -> tuple[list[MutationVerdict],
                                                          list[ConfirmVerdict], str]:
    """``(verdicts, confirms, error)`` from the engine's JSON (last line). Never raises."""
    try:
        data = json.loads(stdout.strip().splitlines()[-1]) if stdout.strip() else {}
    except (ValueError, IndexError):
        return [], [], "engine produced no parseable JSON"
    if not isinstance(data, dict):
        return [], [], "engine JSON was not an object"
    err = str(data.get("error") or "")
    if stage == "confirm":
        return [], confirm_verdicts(data.get("confirms") or []), err
    return detection_verdicts(data.get("verdicts") or []), [], err


#: defparam smuggler.py marks a hit with one of these on the line naming the mutation.
_SMUGGLER_HIT = re.compile(r"(?i)\b(vuln|vulnerable|potential|potentially|\[crit\]|\[high\]|desync|"
                           r"disconnect|timeout)\b")
_SMUGGLER_MUT = re.compile(r"(?i)\b(CL\.TE|TE\.CL|CL\.CL|TE\.TE|CL\.0|H2\.CL|H2\.TE|H2\.0)\b")


def parse_smuggler_output(text: str) -> list[MutationVerdict]:
    """An external `smuggler.py` transcript -> per-mutation verdicts, so a manual run in :kali can
    still land in the same table. PURE. A line that both names a mutation and carries a hit marker
    is susceptible; the mutation names it references are collected. Best-effort by construction — the
    gated in-repo path is the engine, this is the convenience bridge for a hand run."""
    hit: dict[str, str] = {}
    for line in (text or "").splitlines():
        muts = _SMUGGLER_MUT.findall(line)
        if muts and _SMUGGLER_HIT.search(line):
            for m in muts:
                hit[m.upper()] = line.strip()[:300]
    out: list[MutationVerdict] = []
    for m, evidence in hit.items():
        out.append(MutationVerdict(
            mutation=m, susceptible=True, note=f"smuggler.py flagged it: {evidence}",
        ))
    return out


# --------------------------------------------------------------------------- #
# the job registry — stop is a flag, and setting it is ungated
# --------------------------------------------------------------------------- #
_jobs: dict[str, SmuggleJob] = {}
_stops: dict[str, threading.Event] = {}
_lock = threading.Lock()


def get(job_id: str) -> SmuggleJob | None:
    with _lock:
        return _jobs.get(job_id)


def list_jobs(session_id: str | None = None) -> list[SmuggleJob]:
    with _lock:
        jobs = list(_jobs.values())
    if session_id:
        jobs = [j for j in jobs if j.request.session_id == session_id]
    return sorted(jobs, key=lambda j: j.started_at, reverse=True)


def stop(job_id: str) -> SmuggleJob | None:
    """Stop an in-flight sweep. NOT GATED — the panic button, exactly like `stop_scan`."""
    with _lock:
        ev = _stops.get(job_id)
        job = _jobs.get(job_id)
    if ev is not None:
        ev.set()
    return job


# --------------------------------------------------------------------------- #
# scope
# --------------------------------------------------------------------------- #
def _scope_ok(req: SmuggleRequest, url: str) -> tuple[bool, str]:
    """Per-sweep scope check on the URL that goes on the WIRE. Same matcher as everywhere else."""
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
def _cookie_header(req: SmuggleRequest, url: str) -> str:
    if not req.use_cookie_jar:
        return ""
    try:
        from . import cookiejar

        jar = cookiejar.jar_for(req.session_id)
        return jar.select(url, repeater_mod.typed_cookie_names(req)).header
    except Exception:  # noqa: BLE001 - the jar must never take the sweep down
        return ""


def _job_spec(req: SmuggleRequest, stage: str, mutations: list[str],
              cookie_header: str) -> dict[str, Any]:
    """The JSON the engine reads on STDIN. The request bytes travel here, never on the argv."""
    headers = [[h.name, h.value] for h in req.headers if (h.name or "").strip()]
    if cookie_header:
        typed = [h.value.strip().rstrip(";") for h in req.headers
                 if h.name.strip().lower() == "cookie" and h.value.strip()]
        merged = "; ".join(typed + [cookie_header])
        headers = [h for h in headers if h[0].strip().lower() != "cookie"]
        headers.append(["Cookie", merged])
    return {
        "url": req.url,
        "method": (req.method or "POST").strip().upper(),
        "headers": headers,
        "body": req.body or "",
        "mutations": mutations,
        "stage": stage,
        "insecure": bool(req.insecure),
        "timeout": config.clamp_timeout(req.timeout_seconds),
    }


def _engine_argv() -> list[str]:
    """``docker exec -i <open sandbox> smuggle-probe --job-stdin`` — argv-only, request on stdin."""
    return ["docker", "exec", "-i", *loot.exec_flags(loot.kali_workdir()),
            config.KALI_OPEN_CONTAINER, "smuggle-probe", "--job-stdin"]


def _write_finding(req: SmuggleRequest, stage: str, hits: list[str], confirmed: bool) -> bool:
    """A susceptible (or confirmed) desync -> a Finding in engagement state. Best-effort."""
    if not (hits and req.session_id):
        return False
    try:
        from state import store as state_store
        from state.models import Finding

        host = scope_mod.bare_host(req.url) or req.url
        muts = ", ".join(hits)
        if confirmed:
            title = "HTTP request smuggling — CONFIRMED (socket poisoning)"
            severity = "critical"
            evidence = (f"Socket-poisoning confirmation desynchronised a follow-up for {muts} "
                        f"({req.method} {req.url}). A smuggled partial request altered the next "
                        "response on the shared connection.")
        else:
            title = "HTTP request smuggling / desync — susceptible (timing-differential)"
            severity = "high"
            evidence = (f"Timing-differential detection: {muts} probe(s) hung "
                        f">= {SUSCEPTIBLE_DELTA_MS}ms over the baseline for {req.method} {req.url}, "
                        "the signature of a front-end/back-end framing disagreement.")
        state_store.upsert_findings([Finding(
            session_id=req.session_id,
            title=title,
            severity=severity,
            target=host,
            evidence=evidence,
            tool="smuggle-probe",
            vuln_class="request-smuggling",
            reference="CWE-444",
            attacker_path=(
                "Send a request whose front-end/back-end framing disagreement (CL vs TE, duplicate "
                "CL, obfuscated TE, or an HTTP/2->1 downgrade) leaves a partial request on the "
                "back-end connection, so a following request is prefixed with the smuggled bytes — "
                "used to bypass front-end access control, poison the response queue / cache, or "
                "capture another user's request."),
        )])
        return True
    except Exception:  # noqa: BLE001
        return False


def _run(job_id: str, req: SmuggleRequest, stage: str, mutations: list[str]) -> None:
    """The worker. Scope-checks the wire URL, runs the engine, verdicts it, writes a Finding."""
    stop_ev = _stops[job_id]

    # SCOPE ON THE WIRE, before anything is dispatched. All mutations share one URL, so one check
    # refuses the whole sweep — nothing is sent when the host is out of scope.
    ok, why = _scope_ok(req, req.url)
    if not ok:
        with _lock:
            j = _jobs[job_id]
            j.scope_refusals = len(mutations)
            j.warnings.append(f"URL host is off-scope: {why} — nothing was sent")
            j.state = "finished"
            j.finished_at = _now()
        return

    cookie_header = _cookie_header(req, req.url)
    spec = _job_spec(req, stage, mutations, cookie_header)
    timeout = config.clamp_timeout(req.timeout_seconds) + 30

    verdicts: list[MutationVerdict] = []
    confirms: list[ConfirmVerdict] = []
    engine_error = ""
    if not stop_ev.is_set():
        try:
            proc = subprocess.run(
                _engine_argv(), capture_output=True, text=True, timeout=timeout,
                input=json.dumps(spec),
            )
            verdicts, confirms, engine_error = parse_engine_output(proc.stdout, stage)
            if not verdicts and not confirms and proc.returncode != 0 and not engine_error:
                engine_error = (proc.stderr or f"engine exited {proc.returncode}").strip()[:500]
        except subprocess.TimeoutExpired:
            engine_error = f"engine exceeded {timeout}s and was killed"
        except FileNotFoundError:
            engine_error = "docker CLI not found on PATH"

    susceptible = [v.mutation for v in verdicts if v.susceptible]
    confirmed = [c.mutation for c in confirms if c.confirmed]
    if stage == "confirm":
        wrote = _write_finding(req, stage, confirmed, confirmed=True)
    else:
        wrote = _write_finding(req, stage, susceptible, confirmed=False)

    with _lock:
        j = _jobs[job_id]
        j.verdicts = verdicts
        j.confirms = confirms
        j.susceptible = susceptible
        j.confirmed = confirmed
        j.finding_written = wrote
        if engine_error:
            j.warnings.append(engine_error)
        j.state = "stopped" if stop_ev.is_set() else "finished"
        j.finished_at = _now()
        snapshot = j.model_copy(deep=True)

    # Audit — one run record for the WHOLE sweep, because it was one approval. `args` carries the
    # stage, the URL and the mutation set, and deliberately NOT the body or headers: report.py
    # renders a run record's command line verbatim, and a request body is occasionally session-bound.
    try:
        runstore.save_run(RunRecord(
            run_id=job_id, command="smuggle-probe",
            args=[stage, req.method.upper(), req.url, f"mutations={','.join(mutations)}",
                  f"susceptible={len(susceptible)}", f"confirmed={len(confirmed)}"],
            target=scope_mod.bare_host(req.url) or req.url,
            approved=True,
            exit_code=0,
            stdout=_summarise(snapshot), stderr="",
            started_at=snapshot.started_at, finished_at=snapshot.finished_at,
            session_id=req.session_id, step_id=None,
        ))
    except Exception:  # noqa: BLE001 - an audit failure must not lose the results
        pass


def _summarise(job: SmuggleJob) -> str:
    """A table an operator (and a report) can read."""
    lines = [f"smuggle {job.id}: stage={job.stage}, {len(job.mutations)} mutation(s) probed"]
    for v in job.verdicts:
        mark = "SUSCEPTIBLE" if v.susceptible else "clear"
        lines.append(f"  [{mark}] {v.mutation}: baseline={v.baseline_ms}ms probe={v.probe_ms}ms "
                     f"delta={v.delta_ms}ms {('- ' + v.error) if v.error else ''}")
    for c in job.confirms:
        mark = "CONFIRMED" if c.confirmed else "not confirmed"
        lines.append(f"  [{mark}] {c.mutation}: status={c.status} {c.evidence or c.error}")
    if job.susceptible:
        lines.append(f"SUSCEPTIBLE: {', '.join(job.susceptible)}")
    if job.confirmed:
        lines.append(f"CONFIRMED: {', '.join(job.confirmed)}")
    if job.scope_refusals:
        lines.append(f"{job.scope_refusals} probe(s) not sent — URL host left scope.")
    return "\n".join(lines)


def start(req: SmuggleRequest) -> SmuggleJob:
    """Validate, then run the sweep in the background. THE GATE RUNS BEFORE ANYTHING PROBES.

    Refuses (nothing sent) on any of the four gates, on a non-http(s) URL, or if the open sandbox
    is down. The stage is whatever the request asks — the router pins it per endpoint so the
    confirm stage is a DISTINCT approve-each carrying the co-tenant warning.
    """
    parsed = urlparse(req.url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise SmuggleRefused("input", f"URL must be an absolute http(s) URL — got {req.url!r}")

    verdict = validate(req)
    if verdict is not None and getattr(verdict, "rejected", False):
        raise SmuggleRefused(verdict.gate, verdict.reason, list(verdict.dangerous_flags or []))
    if not repeater_mod._container_running(config.KALI_OPEN_CONTAINER):
        raise SmuggleRefused(
            "unavailable",
            f"open sandbox '{config.KALI_OPEN_CONTAINER}' is not running — nothing was probed",
        )

    stage, mutations, warnings = plan(req)
    job_id = uuid.uuid4().hex[:12]
    job = SmuggleJob(
        id=job_id, request=req, container=config.KALI_OPEN_CONTAINER, stage=stage,
        started_at=_now(), mutations=mutations, warnings=warnings,
        co_tenant_warning=(CO_TENANT_WARNING if stage == "confirm" else ""),
    )
    with _lock:
        _jobs[job_id] = job
        _stops[job_id] = threading.Event()
    threading.Thread(target=_run, args=(job_id, req, stage, mutations), daemon=True,
                     name=f"smuggle-{job_id}").start()
    return job


def status() -> dict[str, Any]:
    """Availability of the detector's sandbox — drives the UI banner. Same box as the race tester."""
    up = repeater_mod._container_running(config.KALI_OPEN_CONTAINER)
    with _lock:
        running = sum(1 for j in _jobs.values() if j.state == "running")
    return {
        "container": config.KALI_OPEN_CONTAINER,
        "up": up, "ready": up, "running": running,
        "detail": "" if up else "open sandbox container is not running",
    }


def reset() -> None:
    """Drop all job state. Tests only — never called by the app."""
    with _lock:
        _jobs.clear()
        _stops.clear()
