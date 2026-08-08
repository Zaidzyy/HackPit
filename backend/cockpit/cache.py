"""The web-cache-poisoning / cache-deception detector — one gated job per stage, mirroring
nuclei.py + intruder + smuggle.py.

*** WHY THIS FITS THE APPROVAL MODEL — THE INTRUDER'S / SMUGGLE'S ARGUMENT, WORD FOR WORD. ***
HackPit refuses **batching across approvals** — an agent queueing five commands and a human clicking
once. It has never refused ONE approval that produces many requests, and could not: ``ffuf``,
``nuclei``, the ZAP active scanner, the intruder, the race tester and the smuggling sweep are each a
single approval buying many requests. A cache-poisoning sweep is that same shape — one probe per
candidate unkeyed input from one press: ONE gated job, gated by the SAME four gates, with NO new
ones.

TWO STAGES, and the split is the whole safety story of this build:

  * **DETECTION IS SAFE-BY-DEFAULT.** For each candidate unkeyed input the engine sends ONE request
    carrying a unique marker in that input and reports whether the marker is REFLECTED and whether
    the response is CACHEABLE. Reflected + cacheable ⇒ a candidate. It also runs the cache-DECEPTION
    path-confusion probes. **No cache entry is planted; nothing is served to anyone else** — the
    request is self-contained. This is the default path.
  * **CONFIRMATION IS A SEPARATE APPROVE-EACH WITH A CO-USER WARNING.** Confirmation PLANTS the
    poison: it primes the shared cache with the marker request, then sends a FRESH request that
    never carried the marker and checks whether the cache serves it back — *** the poisoned entry a
    fresh request receives is the same entry a real co-user would receive ***, so it is its own
    explicit approval carrying :data:`CO_USER_WARNING` in plain language. Still just approve-each;
    **no new gate class** — the standing rule is human-approval-only.

THE SPLIT, mirroring smuggle/race/intruder/nuclei:

  * PURE, INSPECTABLE HALF — :func:`cache_argv_for`, :func:`plan`, :func:`_job_spec`,
    :func:`candidate_of`, :func:`detection_verdicts`, :func:`deception_verdicts`,
    :func:`confirm_verdicts`, :func:`parse_engine_output`, :func:`parse_wcvs_output`. They build the
    argv/spec and turn the engine's JSON (or an external ``wcvs`` transcript) into per-input
    verdicts, and they execute NOTHING — so what will run and what a result means are both
    inspectable before anything spawns.
  * THE WORKER — :func:`start` validates through the gate BEFORE anything spawns, scope-checks the
    URL on the WIRE, runs ONE ``docker exec … cache-probe --job-stdin`` with the whole request +
    input set as JSON on stdin, parses the result and upserts a ``Finding`` on a hit.

CONTAINMENT, inherited wholesale from the smuggle detector and stated rather than assumed:

  * **HARDCODED CONTAINER** — every probe runs inside ``config.KALI_OPEN_CONTAINER``, a code
    constant no request field can redirect.
  * **ARGV-ONLY engine, the request on stdin** — ``docker exec -i … cache-probe --job-stdin``; the
    whole request (URL, headers, body, inputs, stage) is JSON on STDIN, no shell parses a byte.
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

#: Every candidate UNKEYED INPUT the detector offers — the header/param a cache commonly leaves out
#: of its key while the origin still trusts it. Header-shaped inputs reflect into absolute URLs;
#: ``param-cloak`` is a cloaked query parameter; ``fat-get-body`` is a body on a GET.
INPUTS: tuple[str, ...] = (
    "X-Forwarded-Host", "X-Forwarded-Scheme", "X-Forwarded-Proto", "X-Forwarded-Port",
    "X-Host", "X-Forwarded-Server", "X-Original-URL", "X-Rewrite-URL", "X-Forwarded-For",
    "Forwarded", "param-cloak", "fat-get-body",
)
#: The safe, high-signal default sweep — the headers that most commonly poison a real cache.
DEFAULT_INPUTS: tuple[str, ...] = (
    "X-Forwarded-Host", "X-Forwarded-Scheme", "X-Forwarded-Proto", "X-Host",
    "X-Original-URL", "X-Rewrite-URL", "param-cloak",
)

#: The two stages. detect is safe-by-default; confirm is the separately-approved poison-plant step.
#: An unknown stage falls back to detect and SAYS SO — it never escalates to confirm.
STAGES = ("detect", "confirm")
DEFAULT_STAGE = "detect"

#: The plain-language co-user warning surfaced on the CONFIRMATION stage's approval. It is a constant
#: so the UI, the preview and the job all show the SAME words, and a safety test pins that the
#: confirm path carries it.
CO_USER_WARNING = (
    "CONFIRMATION MAY SERVE A POISONED RESPONSE TO OTHER USERS OF THIS CACHE. It plants a poisoned "
    "entry (the marker request) then fetches it back with a request that never carried the marker — "
    "the poisoned entry a fresh request receives is the SAME entry a real co-user would receive "
    "until the cache expires. Only run it on a target you are authorised to poison, and expect to "
    "affect other traffic. Detection (reflection + cacheability) does not plant anything; this stage "
    "does. It is still approve-each — no new gate — you are the bound."
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------- #
# models
# --------------------------------------------------------------------------- #
class CacheRequest(BaseModel):
    """One cache job: a request template, a candidate-input checklist, a stage, and the gate fields.

    NO container/target field — the box is a code constant (rule #1), exactly like the intruder, the
    race tester and the smuggle detector. The same request template is probed against each chosen
    candidate input.
    """

    url: str = Field(..., min_length=1, description="Absolute http(s) URL the probes go to.")
    method: str = "GET"
    headers: list[repeater_mod.RepeaterHeader] = Field(default_factory=list)
    body: str = Field("", description="Request body used for the baseline / fat-GET template.")
    inputs: list[str] = Field(
        default_factory=list,
        description="Which candidate unkeyed inputs to probe (see INPUTS). Empty = the safe default.",
    )
    stage: str = Field(
        DEFAULT_STAGE,
        description="detect (safe reflection+cacheability, the default) or confirm (poison-plant, a "
        "SEPARATE approve-each with a co-user warning). Unknown falls back to detect.",
    )
    deception: bool = Field(
        True, description="Run the cache-deception path-confusion probes alongside detection.",
    )
    timeout_seconds: int | None = None
    insecure: bool = False
    follow_redirects: bool = False
    engagement_id: str | None = None
    session_id: str | None = None
    use_cookie_jar: bool = Field(
        True, description="Attach the repeater's session jar — a sensitive page is usually authed."
    )
    # THE GATE FIELDS — the scanner's / smuggle's, unchanged. Both default False so an omitted field
    # is REFUSED rather than granted.
    approved: bool = Field(False, description="Explicit human approval. Never defaulted true.")
    dangerous_ack: bool = Field(
        False,
        description="The red-confirm, WHEN THE GATE ASKS FOR IT. Not demanded unconditionally by "
        "this model: the four gates decide and they fire on request CONTENT. The confirmation "
        "stage's co-user risk is surfaced as a warning on its own approval, not as a new gate.",
    )


class InputVerdict(BaseModel):
    """One candidate input's DETECTION verdict — reflection + cacheability turned into candidate/not."""

    input: str
    reflected: bool = False
    cacheable: bool = False
    candidate: bool = False
    marker: str = ""
    indicator: str = ""
    status: int | None = None
    error: str = ""
    note: str = ""


class DeceptionVerdict(BaseModel):
    """One path-confusion probe's verdict — is a dynamic page cached under a static extension."""

    path: str
    extension: str = ""
    cached: bool = False
    status: int | None = None
    indicator: str = ""
    evidence: str = ""
    error: str = ""
    note: str = ""


class ConfirmVerdict(BaseModel):
    """One input's CONFIRMATION verdict — did planting the poison serve it to a fresh request."""

    input: str
    poisoned: bool = False
    status: int | None = None
    evidence: str = ""
    error: str = ""
    note: str = ""


class CacheJob(BaseModel):
    """The job. Counts are what HAPPENED, never what was planned."""

    id: str
    state: str = Field("running", description="running | finished | stopped | refused")
    stage: str = DEFAULT_STAGE
    request: CacheRequest
    container: str = ""
    started_at: str = ""
    finished_at: str = ""
    inputs: list[str] = Field(default_factory=list, description="The inputs actually probed.")
    verdicts: list[InputVerdict] = Field(default_factory=list, description="Detection results.")
    deceptions: list[DeceptionVerdict] = Field(
        default_factory=list, description="Cache-deception path-confusion results."
    )
    confirms: list[ConfirmVerdict] = Field(default_factory=list, description="Confirmation results.")
    candidates: list[str] = Field(
        default_factory=list, description="Inputs that were reflected AND cacheable."
    )
    confirmed: list[str] = Field(
        default_factory=list, description="Inputs a poison-plant confirmed."
    )
    co_user_warning: str = Field(
        "", description="Set on the confirm stage — the plain-language co-user risk. Empty on "
        "detect, which plants nothing."
    )
    warnings: list[str] = Field(default_factory=list)
    scope_refusals: int = Field(
        0, description="Probes NOT sent because the URL host left the engagement scope. When this "
        "fires the whole sweep is refused (all inputs share one URL) and nothing is sent."
    )
    finding_written: bool = Field(
        False, description="True when a candidate/deception/confirmed result was written as a Finding."
    )


class CacheRefused(RuntimeError):
    """Refused BEFORE anything ran. Carries the gate that refused it."""

    def __init__(self, gate: str, reason: str, dangerous_flags: list[str] | None = None) -> None:
        super().__init__(reason)
        self.gate = gate
        self.reason = reason
        self.dangerous_flags = dangerous_flags or []


# --------------------------------------------------------------------------- #
# the gate — THE SCANNER'S FOUR, UNCHANGED
# --------------------------------------------------------------------------- #
def cache_argv_for(req: CacheRequest) -> list[str]:
    """The command this job is EQUIVALENT TO, which is what the human approves.

    ``cache-probe`` because that IS what runs — the in-repo cache prober baked into the sandbox. NOT
    because it is "allowed": there is no tool allowlist in this product. The gates are approval,
    target, danger and isolation, and none consults a list of binaries — so the declared command only
    has to be HONEST, because that string is what a human approves and what the danger heuristic
    reads.

    The URL rides as ``-u`` (where the target handrail reads the host); the stage, the input set, the
    method, the body and every header travel verbatim so the surface is COMPLETE — the intruder's
    Critical-2 rule: nothing is summarised, so a body carrying a shell pattern reaches the danger gate
    rather than hiding behind a count.
    """
    argv = ["cache-probe", "-u", req.url, "--stage", _stage_of(req)[0]]
    # Inputs ride the surface lowercase (X-Forwarded-Host -> x-forwarded-host). Header names carry no
    # dotted TLD-shaped structure, so the target-lock's hostish scan does not read them as hosts (the
    # trap that bit the smuggle mutations); lowercasing is purely for a stable, honest surface.
    argv += ["--inputs", ",".join(i.lower() for i in _inputs_of(req)[0])]
    if req.deception:
        argv += ["--deception"]
    method = (req.method or "GET").strip().upper()
    if method != "GET":
        argv += ["-X", method]
    for h in req.headers:
        name = (h.name or "").strip()
        if name:
            argv += ["-H", f"{name}: {h.value}"]
    if req.body:
        argv += ["-d", req.body]
    return argv


def _gate_request(req: CacheRequest):
    from .models import ExecRequest

    argv = cache_argv_for(req)
    return ExecRequest(
        command=argv[0], args=argv[1:],
        approved=req.approved, dangerous_ack=req.dangerous_ack,
        engagement_id=req.engagement_id,
    )


def validate(req: CacheRequest):
    """The gate verdict, attacking nothing. PURE. Returns None when it passes.

    All four gates, in the executor's order, unchanged and with nothing added — so a UI can ask
    "would this be refused" without launching anything, the same split smuggle/race/intruder make.
    """
    from . import executor

    return executor.validate_request(_gate_request(req))


# --------------------------------------------------------------------------- #
# planning — PURE, so what will be probed is inspectable before anything is
# --------------------------------------------------------------------------- #
def _stage_of(req: CacheRequest) -> tuple[str, str | None]:
    """``(stage, warning)``. An unknown stage falls back to detect (never escalates to confirm)."""
    stage = (req.stage or "").strip().lower()
    if stage not in STAGES:
        return DEFAULT_STAGE, (
            f"unknown stage {req.stage!r} — running the safe {DEFAULT_STAGE!r} path. "
            f"Known: {', '.join(STAGES)}"
        )
    return stage, None


def _inputs_of(req: CacheRequest) -> tuple[list[str], list[str]]:
    """``(inputs, warnings)``. Unknown names are dropped WITH a warning; empty picks the default set.
    Order preserved, de-duplicated. WARN AND CONTINUE — a typo never refuses the job."""
    warnings: list[str] = []
    known = {i.lower(): i for i in INPUTS}
    picked = [str(i).strip() for i in req.inputs if str(i).strip()]
    if not picked:
        return list(DEFAULT_INPUTS), warnings
    seen: set[str] = set()
    out: list[str] = []
    for i in picked:
        canon = known.get(i.lower())
        if canon is None:
            warnings.append(f"unknown input {i!r} — skipped. Known: {', '.join(INPUTS)}")
            continue
        if canon not in seen:
            seen.add(canon)
            out.append(canon)
    if not out:
        warnings.append("no valid input left — falling back to the default set")
        out = list(DEFAULT_INPUTS)
    return out, warnings


def plan(req: CacheRequest) -> tuple[str, list[str], list[str]]:
    """``(stage, inputs, warnings)``. Probes nothing. WARN AND CONTINUE throughout."""
    warnings: list[str] = []
    stage, stage_warn = _stage_of(req)
    if stage_warn:
        warnings.append(stage_warn)
    inputs, in_warn = _inputs_of(req)
    warnings.extend(in_warn)
    if stage == "confirm":
        warnings.append(CO_USER_WARNING)
    return stage, inputs, warnings


# --------------------------------------------------------------------------- #
# verdicts — PURE, testable on fixture engine output or an external transcript
# --------------------------------------------------------------------------- #
def candidate_of(reflected: bool, cacheable: bool) -> bool:
    """The single rule that turns two observations into a candidate. THE one place a test pins it —
    a candidate is an unkeyed input that is BOTH reflected AND lands in a cacheable response."""
    return bool(reflected and cacheable)


def detection_verdicts(rows: list[dict[str, Any]]) -> list[InputVerdict]:
    """Engine detection rows -> per-input verdicts. PURE. Each row is
    ``{input, reflected, cacheable, marker, indicator, status, error}``; ``candidate`` is recomputed
    here by :func:`candidate_of` so the backend, not the engine, owns the rule. An error row is
    NEVER a candidate."""
    out: list[InputVerdict] = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        err = str(r.get("error") or "")
        refl = bool(r.get("reflected")) and not err
        cache = bool(r.get("cacheable")) and not err
        cand = candidate_of(refl, cache) and not err
        out.append(InputVerdict(
            input=str(r.get("input") or ""),
            reflected=refl, cacheable=cache, candidate=cand,
            marker=str(r.get("marker") or ""),
            indicator=str(r.get("indicator") or ""),
            status=r.get("status"),
            error=err,
            note=(
                f"marker reflected AND the response is cacheable ({r.get('indicator')}) — an unkeyed "
                f"{r.get('input')} would be stored and served to other requests." if cand else
                ("inconclusive — " + err if err else
                 ("reflected but not cacheable — no cache would store it" if refl else
                  ("cacheable but not reflected — the input does not reach the response" if cache else
                   "neither reflected nor cacheable — not a candidate")))),
        ))
    return out


def deception_verdicts(rows: list[dict[str, Any]]) -> list[DeceptionVerdict]:
    """Engine deception rows -> per-path verdicts. PURE. ``cached`` (a dynamic page stored under a
    static extension) is the hit; an error is inconclusive, never a hit."""
    out: list[DeceptionVerdict] = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        err = str(r.get("error") or "")
        cached = bool(r.get("cached")) and not err
        out.append(DeceptionVerdict(
            path=str(r.get("path") or ""),
            extension=str(r.get("extension") or ""),
            cached=cached,
            status=r.get("status"),
            indicator=str(r.get("indicator") or ""),
            evidence=str(r.get("evidence") or ""),
            error=err,
            note=(
                "a dynamic page is served for a static-looking path AND stored by the cache — "
                "sensitive content is now cacheable under an unauthenticated URL." if cached else
                ("inconclusive — " + err if err else
                 "not a deception hit — the static path did not yield cached dynamic content.")),
        ))
    return out


def confirm_verdicts(rows: list[dict[str, Any]]) -> list[ConfirmVerdict]:
    """Engine confirm rows -> per-input confirmation verdicts. PURE."""
    out: list[ConfirmVerdict] = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        err = str(r.get("error") or "")
        poisoned = bool(r.get("poisoned")) and not err
        out.append(ConfirmVerdict(
            input=str(r.get("input") or ""),
            poisoned=poisoned,
            status=r.get("status"),
            evidence=str(r.get("evidence") or ""),
            error=err,
            note=(
                "planting the poison served the marker to a fresh request that never sent it — the "
                "input is confirmed unkeyed and the cache is poisonable." if poisoned else
                ("inconclusive — " + err if err else
                 "the fresh request did not receive the marker — not confirmed (input likely keyed).")),
        ))
    return out


def parse_engine_output(stdout: str, stage: str) -> tuple[list[InputVerdict],
                                                          list[DeceptionVerdict],
                                                          list[ConfirmVerdict], str]:
    """``(verdicts, deceptions, confirms, error)`` from the engine's JSON (last line). Never raises."""
    try:
        data = json.loads(stdout.strip().splitlines()[-1]) if stdout.strip() else {}
    except (ValueError, IndexError):
        return [], [], [], "engine produced no parseable JSON"
    if not isinstance(data, dict):
        return [], [], [], "engine JSON was not an object"
    err = str(data.get("error") or "")
    if stage == "confirm":
        return [], [], confirm_verdicts(data.get("confirms") or []), err
    return (detection_verdicts(data.get("verdicts") or []),
            deception_verdicts(data.get("deceptions") or []), [], err)


#: A wcvs transcript marks a vulnerable header on the line naming it. POSITIVE markers only — a bare
#: "reflect" would fire on "no reflection", so we require wcvs's own hit tokens (`[+]`, vulnerable,
#: poison, hit).
_WCVS_HIT = re.compile(r"(?i)(vulnerab|poison|\[\+\]|\bhit\b)")
_WCVS_HDR = re.compile(r"(?i)\b(X-Forwarded-[A-Za-z-]+|X-Host|X-Original-URL|X-Rewrite-URL|Forwarded)\b")


def parse_wcvs_output(text: str) -> list[InputVerdict]:
    """An external ``wcvs`` transcript -> per-input verdicts, so a manual run in :kali can still land
    in the same table. PURE. A line that both names a header and carries a hit marker is a candidate.
    Best-effort by construction — the gated in-repo path is the engine, this is the bridge for a hand
    run."""
    hit: dict[str, str] = {}
    for line in (text or "").splitlines():
        hdrs = _WCVS_HDR.findall(line)
        if hdrs and _WCVS_HIT.search(line):
            for h in hdrs:
                hit[h] = line.strip()[:300]
    return [InputVerdict(input=h, reflected=True, cacheable=True, candidate=True,
                         indicator=f"wcvs flagged it: {ev}",
                         note=f"wcvs flagged {h} reflected + cacheable: {ev}")
            for h, ev in hit.items()]


# --------------------------------------------------------------------------- #
# the job registry — stop is a flag, and setting it is ungated
# --------------------------------------------------------------------------- #
_jobs: dict[str, CacheJob] = {}
_stops: dict[str, threading.Event] = {}
_lock = threading.Lock()


def get(job_id: str) -> CacheJob | None:
    with _lock:
        return _jobs.get(job_id)


def list_jobs(session_id: str | None = None) -> list[CacheJob]:
    with _lock:
        jobs = list(_jobs.values())
    if session_id:
        jobs = [j for j in jobs if j.request.session_id == session_id]
    return sorted(jobs, key=lambda j: j.started_at, reverse=True)


def stop(job_id: str) -> CacheJob | None:
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
def _scope_ok(req: CacheRequest, url: str) -> tuple[bool, str]:
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
def _cookie_header(req: CacheRequest, url: str) -> str:
    if not req.use_cookie_jar:
        return ""
    try:
        from . import cookiejar

        jar = cookiejar.jar_for(req.session_id)
        return jar.select(url, repeater_mod.typed_cookie_names(req)).header
    except Exception:  # noqa: BLE001 - the jar must never take the sweep down
        return ""


def _job_spec(req: CacheRequest, stage: str, inputs: list[str],
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
        "method": (req.method or "GET").strip().upper(),
        "headers": headers,
        "body": req.body or "",
        "inputs": inputs,
        "stage": stage,
        "deception": bool(req.deception),
        "insecure": bool(req.insecure),
        "timeout": config.clamp_timeout(req.timeout_seconds),
    }


def _engine_argv() -> list[str]:
    """``docker exec -i <open sandbox> cache-probe --job-stdin`` — argv-only, request on stdin."""
    return ["docker", "exec", "-i", *loot.exec_flags(loot.kali_workdir()),
            config.KALI_OPEN_CONTAINER, "cache-probe", "--job-stdin"]


def _write_finding(req: CacheRequest, stage: str, hits: list[str], kind: str) -> bool:
    """A candidate / deception / confirmed cache issue -> a Finding in engagement state. Best-effort.

    ``kind`` is one of ``candidate`` (detection, High), ``deception`` (detection, High) or
    ``confirmed`` (poison-plant, Critical)."""
    if not (hits and req.session_id):
        return False
    try:
        from state import store as state_store
        from state.models import Finding

        host = scope_mod.bare_host(req.url) or req.url
        joined = ", ".join(hits)
        if kind == "confirmed":
            title = "Web cache poisoning — CONFIRMED (unkeyed input served from cache)"
            severity = "critical"
            evidence = (f"Poison-plant confirmation: {joined} — a fresh request that never carried "
                        f"the marker received it from the cache for {req.method} {req.url}. The input "
                        "is unkeyed and the shared cache is poisonable.")
        elif kind == "deception":
            title = "Web cache deception — dynamic page cached under a static path"
            severity = "high"
            evidence = (f"Path confusion: {joined} served a dynamic page that the cache stored under "
                        f"a static extension for {req.url}. Sensitive content is now cacheable under "
                        "an unauthenticated URL.")
        else:
            title = "Web cache poisoning — unkeyed input reflected in a cacheable response (candidate)"
            severity = "high"
            evidence = (f"Reflected + cacheable: {joined} probe(s) put a marker into a cacheable "
                        f"response for {req.method} {req.url} via an unkeyed input — the signature of "
                        "a poisonable cache. Confirm with the separately-approved poison-plant stage.")
        state_store.upsert_findings([Finding(
            session_id=req.session_id,
            title=title,
            severity=severity,
            target=host,
            evidence=evidence,
            tool="cache-probe",
            vuln_class="cache-poisoning" if kind != "deception" else "cache-deception",
            reference="CWE-525",
            attacker_path=(
                "Send a request carrying attacker data in an input the shared cache omits from its "
                "cache key (X-Forwarded-Host and friends, a cloaked query parameter, a fat GET body) "
                "so the origin reflects it into a response the cache then stores under the base key — "
                "every subsequent user of that key is served the poisoned response (redirect to an "
                "attacker host, injected script, or a cached sensitive page under a static path)."),
        )])
        return True
    except Exception:  # noqa: BLE001
        return False


def _run(job_id: str, req: CacheRequest, stage: str, inputs: list[str]) -> None:
    """The worker. Scope-checks the wire URL, runs the engine, verdicts it, writes a Finding."""
    stop_ev = _stops[job_id]

    # SCOPE ON THE WIRE, before anything is dispatched. All inputs share one URL, so one check refuses
    # the whole sweep — nothing is sent when the host is out of scope.
    ok, why = _scope_ok(req, req.url)
    if not ok:
        with _lock:
            j = _jobs[job_id]
            j.scope_refusals = len(inputs)
            j.warnings.append(f"URL host is off-scope: {why} — nothing was sent")
            j.state = "finished"
            j.finished_at = _now()
        return

    cookie_header = _cookie_header(req, req.url)
    spec = _job_spec(req, stage, inputs, cookie_header)
    timeout = config.clamp_timeout(req.timeout_seconds) + 30

    verdicts: list[InputVerdict] = []
    deceptions: list[DeceptionVerdict] = []
    confirms: list[ConfirmVerdict] = []
    engine_error = ""
    if not stop_ev.is_set():
        try:
            proc = subprocess.run(
                _engine_argv(), capture_output=True, text=True, timeout=timeout,
                input=json.dumps(spec),
            )
            verdicts, deceptions, confirms, engine_error = parse_engine_output(proc.stdout, stage)
            if (not verdicts and not deceptions and not confirms
                    and proc.returncode != 0 and not engine_error):
                engine_error = (proc.stderr or f"engine exited {proc.returncode}").strip()[:500]
        except subprocess.TimeoutExpired:
            engine_error = f"engine exceeded {timeout}s and was killed"
        except FileNotFoundError:
            engine_error = "docker CLI not found on PATH"

    candidates = [v.input for v in verdicts if v.candidate]
    deception_hits = [d.path for d in deceptions if d.cached]
    confirmed = [c.input for c in confirms if c.poisoned]
    if stage == "confirm":
        wrote = _write_finding(req, stage, confirmed, kind="confirmed")
    else:
        wrote = _write_finding(req, stage, candidates, kind="candidate")
        if _write_finding(req, stage, deception_hits, kind="deception"):
            wrote = True

    with _lock:
        j = _jobs[job_id]
        j.verdicts = verdicts
        j.deceptions = deceptions
        j.confirms = confirms
        j.candidates = candidates
        j.confirmed = confirmed
        j.finding_written = wrote
        if engine_error:
            j.warnings.append(engine_error)
        j.state = "stopped" if stop_ev.is_set() else "finished"
        j.finished_at = _now()
        snapshot = j.model_copy(deep=True)

    # Audit — one run record for the WHOLE sweep, because it was one approval. `args` carries the
    # stage, the URL and the input set, and deliberately NOT the body or headers: report.py renders a
    # run record's command line verbatim, and a request body/header is occasionally session-bound.
    try:
        runstore.save_run(RunRecord(
            run_id=job_id, command="cache-probe",
            args=[stage, req.method.upper(), req.url, f"inputs={','.join(inputs)}",
                  f"candidates={len(candidates)}", f"deception={len(deception_hits)}",
                  f"confirmed={len(confirmed)}"],
            target=scope_mod.bare_host(req.url) or req.url,
            approved=True,
            exit_code=0,
            stdout=_summarise(snapshot), stderr="",
            started_at=snapshot.started_at, finished_at=snapshot.finished_at,
            session_id=req.session_id, step_id=None,
        ))
    except Exception:  # noqa: BLE001 - an audit failure must not lose the results
        pass


def _summarise(job: CacheJob) -> str:
    """A table an operator (and a report) can read."""
    lines = [f"cache {job.id}: stage={job.stage}, {len(job.inputs)} input(s) probed"]
    for v in job.verdicts:
        mark = "CANDIDATE" if v.candidate else "clear"
        lines.append(f"  [{mark}] {v.input}: reflected={v.reflected} cacheable={v.cacheable} "
                     f"{('- ' + v.error) if v.error else ('- ' + v.indicator)}")
    for d in job.deceptions:
        if d.cached:
            lines.append(f"  [DECEPTION] {d.path}: {d.evidence}")
    for c in job.confirms:
        mark = "POISONED" if c.poisoned else "not confirmed"
        lines.append(f"  [{mark}] {c.input}: status={c.status} {c.evidence or c.error}")
    if job.candidates:
        lines.append(f"CANDIDATES: {', '.join(job.candidates)}")
    if job.confirmed:
        lines.append(f"CONFIRMED: {', '.join(job.confirmed)}")
    if job.scope_refusals:
        lines.append(f"{job.scope_refusals} probe(s) not sent — URL host left scope.")
    return "\n".join(lines)


def start(req: CacheRequest) -> CacheJob:
    """Validate, then run the sweep in the background. THE GATE RUNS BEFORE ANYTHING PROBES.

    Refuses (nothing sent) on any of the four gates, on a non-http(s) URL, or if the open sandbox is
    down. The stage is whatever the request asks — the router pins it per endpoint so the confirm
    stage is a DISTINCT approve-each carrying the co-user warning.
    """
    parsed = urlparse(req.url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise CacheRefused("input", f"URL must be an absolute http(s) URL — got {req.url!r}")

    verdict = validate(req)
    if verdict is not None and getattr(verdict, "rejected", False):
        raise CacheRefused(verdict.gate, verdict.reason, list(verdict.dangerous_flags or []))
    if not repeater_mod._container_running(config.KALI_OPEN_CONTAINER):
        raise CacheRefused(
            "unavailable",
            f"open sandbox '{config.KALI_OPEN_CONTAINER}' is not running — nothing was probed",
        )

    stage, inputs, warnings = plan(req)
    job_id = uuid.uuid4().hex[:12]
    job = CacheJob(
        id=job_id, request=req, container=config.KALI_OPEN_CONTAINER, stage=stage,
        started_at=_now(), inputs=inputs, warnings=warnings,
        co_user_warning=(CO_USER_WARNING if stage == "confirm" else ""),
    )
    with _lock:
        _jobs[job_id] = job
        _stops[job_id] = threading.Event()
    threading.Thread(target=_run, args=(job_id, req, stage, inputs), daemon=True,
                     name=f"cache-{job_id}").start()
    return job


def status() -> dict[str, Any]:
    """Availability of the detector's sandbox — drives the UI banner. Same box as the smuggle
    detector."""
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
