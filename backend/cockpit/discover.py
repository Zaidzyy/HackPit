"""Parameter / content discovery as a first-class step (:discover — a :recon sibling).

*** WHY THIS IS ONE GATED JOB WITH NO NEW GATE, WRITTEN DOWN SO NOBODY RE-LITIGATES IT. ***
Finding an endpoint's HIDDEN parameters (arjun) and its HIDDEN paths (ffuf / feroxbuster) and its
HISTORICAL parameters (paramspider) is the manual step every hunt does by hand today. It is the
SAME shape :recon already runs: ONE human approval buys a discovery job that sends many requests —
exactly like ffuf, nuclei, the intruder and the ZAP active scanner, each a single approval buying
thousands. So this module adds NO new gate: one job, gated by the SAME `executor.validate_request`
every command clears, run BEFORE anything spawns, with an UNGATED stop.

*** DISCOVERIES ARE SUGGESTIONS HANDED TO OTHER SURFACES, NEVER AUTO-FIRED. ***
A discovered param becomes a pre-filled :intruder position; a discovered endpoint becomes a
:nuclei target / a :repeater request. The discovery job is the only thing approved — the attack
itself is still approve-each on the surface it was handed to. There is no autonomy here.

*** SCOPE-SAFETY BY CONSTRUCTION, mirroring :recon. ***
Discovery is ENGAGEMENT-BOUND: it needs the open, loot-mounted engagement sandbox (the tools reach
the target + the archives, and the SCOPE that decides what may be probed lives on the engagement
record). Two places enforce scope, neither an extra gate:

  * THE TARGET IS SCOPE-LOCKED BEFORE THE JOB RUNS. arjun/ffuf point at ONE url and paramspider at
    ONE domain; that host is checked against the engagement scope in :func:`start`, so a job can
    never be pointed off-scope. The words only fill path/param positions — they cannot move the host.
  * EVERY DISCOVERED URL/PARAM IS SCOPE-FILTERED BEFORE IT LANDS. paramspider mines archives that
    hold URLs on other hosts; :func:`filter_endpoints_in_scope` drops any endpoint whose host the
    scope does not cover, so nothing out-of-scope reaches the surface, the loot or engagement state.

*** THE CONTENT WORDLIST IS IN THE APPROVED SURFACE, INTRUDER-STYLE, NOT TRUNCATED. ***
For content discovery the operator's word list is the payload set, so — exactly like the intruder —
:func:`content_gate_argv` puts EVERY word into the gated command line, not a count and not a sample.
Rendering "…and 4,993 more" would let a word carrying `| sh` sit where the danger heuristic cannot
see it while the human approves a summary. That is the intruder's Critical-2, expressed for paths.

THE SPLIT, mirroring recon/nuclei/intruder:

  * PURE, INSPECTABLE HALF — the ``*_argv`` builders, :func:`filter_endpoints_in_scope`,
    :func:`_mark_param`, :func:`_interesting_*`. They build argv, sort by scope and label rows; they
    execute NOTHING. Regression-locked in test_discover_safety.py by an AST walk.
  * THE WORKER — :func:`start` validates through the gate BEFORE anything spawns, then a background
    thread runs the mode's `docker exec`s in the engagement sandbox, scope-filters what comes back,
    and upserts only in-scope endpoints (which raise the host's rank in the :recon surface).
"""

from __future__ import annotations

import re
import subprocess
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable, Sequence

from pydantic import BaseModel, Field

from state import store as state_store
from state.models import Endpoint, Finding
from state.parsers import (
    Parsed,
    parse_arjun,
    parse_feroxbuster,
    parse_ffuf,
    parse_urls,
)

from . import (
    config, engagement, loot, repeater as repeater_mod, runstore, scope as scope_mod, session_store,
)
from .models import RunRecord

#: The discovery modes. An unknown mode falls back to `params` and SAYS SO — it never refuses a typo.
MODES = ("params", "content", "historical")

#: Ceiling on words one approved content job may carry in its surface. NOT a refusal — the job runs
#: with the first this-many and REPORTS `capped`, exactly like the intruder's ceiling. A silent
#: truncation would tell the operator the whole list ran when it had not.
DISCOVER_MAX_WORDS = 10_000
#: Per-job transcript kept, in chars — a discovery transcript, not a data feed.
_OUTPUT_CAP = 400_000
#: The intruder's position marker, reused verbatim so a handed-off URL means the SAME thing in the
#: intruder panel: `[[…]]` is the span the payload set replaces.
POSITION_OPEN = "[["
POSITION_CLOSE = "]]"

#: A discovered ENDPOINT whose URL smells like a privileged / debug / secret-bearing surface — the
#: kind of hit that is itself a finding, not just more surface.
_INTERESTING_URL = re.compile(
    r"(admin|internal|/manage|/dashboard|actuator|swagger|graphql|phpinfo|console|"
    r"\.git|\.env|\.bak|\.old|\.sql|backup|/config|/debug|/dev|/staging|/test|"
    r"api[-_/]?key|/api/|/v\d+/|/private|/secret)",
    re.I,
)
#: A discovered PARAMETER name that is a classic injection/redirect/SSRF magnet.
_INTERESTING_PARAM = re.compile(
    r"^(debug|admin|test|cmd|exec|command|redirect|url|uri|dest|destination|next|return|returnurl|"
    r"callback|file|filename|path|template|include|page|load|fetch|proxy|feed|host|domain|"
    r"id|user|user_id|account|role|token|key|api_key|apikey|secret|password|passwd)$",
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
class DiscoverRequest(BaseModel):
    """One discovery job: the mode, what to point it at, and the gate fields."""

    mode: str = Field(
        "params",
        description="params (arjun — hidden GET/POST/JSON params) | content (ffuf/feroxbuster — "
        "hidden paths/dirs) | historical (paramspider — archived parameterised URLs). Unknown "
        "falls back to params and says so.",
    )
    url: str = Field(
        "", description="params/content: the IN-SCOPE url to point at. Its host is scope-locked "
        "before anything runs. content: a `FUZZ` keyword marks where paths go (else /FUZZ appended)."
    )
    domain: str = Field(
        "", description="historical: the in-scope domain paramspider mines. EMPTY = the "
        "engagement's declared target."
    )
    method: str = Field("GET", description="params: arjun -m (GET | POST | JSON).")
    tool: str = Field(
        "", description="content: ffuf (default) | feroxbuster. Ignored in the other modes."
    )
    words: list[str] = Field(
        default_factory=list,
        description="content: THE WORD LIST, verbatim. Every entry goes into the approved surface "
        "— see the module docstring for why it is never summarised there.",
    )
    wordlist: str = Field(
        "", description="content: a baked sandbox wordlist PATH (e.g. /usr/share/seclists/…) used "
        "when `words` is empty. Its bytes are not in the surface — prefer `words` for a complete one."
    )
    extensions: list[str] = Field(
        default_factory=list,
        description="content: file extensions to append (ffuf -e / feroxbuster -x), e.g. php,bak,old.",
    )
    param_wordlist: str = Field(
        "", description="params: arjun -w wordlist path. Blank = arjun's bundled list."
    )
    rate_limit: int | None = Field(
        None, ge=1, le=100000, description="Requests/sec cap. Pacing, not a gate."
    )
    impersonate: bool = Field(
        False,
        description="params/content: route the active tool (arjun/ffuf/feroxbuster) through the "
        "in-sandbox JA3 MITM proxy so a Cloudflare/Akamai-fronted target serves a browser "
        "handshake instead of 403-ing a plain fuzzer. Ignored for historical (paramspider is "
        "passive/archive-based). Beats JA3, not a JS challenge.",
    )
    timeout_seconds: int | None = None
    engagement_id: str | None = None
    session_id: str | None = None
    attach_session: bool = Field(
        False,
        description="params/content: run the tool AS the logged-in operator — merge the engagement's "
        "stored session (session_store) as auth headers (ffuf/feroxbuster -H, arjun --headers), so "
        "content/params behind login are discovered. The operator's OWN session, MASKED in the record. "
        "Ignored for historical (paramspider is archive-based).",
    )
    # THE GATE FIELDS — the executor's, unchanged. Both default False so an omitted field is
    # REFUSED rather than granted.
    approved: bool = Field(False, description="Explicit human approval. Never defaulted true.")
    dangerous_ack: bool = Field(
        False, description="The red-confirm, WHEN THE GATE ASKS FOR IT — decided by the four gates."
    )


class DiscoverStage(BaseModel):
    """One tool invocation inside a job — what it was and what happened."""

    tool: str
    argv: list[str] = Field(default_factory=list)
    state: str = Field("ran", description="ran | stopped | skipped")
    note: str = ""


class DiscoveredParam(BaseModel):
    """One endpoint with its DISCOVERED parameter names + the pre-filled hand-offs. Tagged discovery."""

    url: str
    method: str = "GET"
    params: list[str] = Field(default_factory=list)
    interesting: list[str] = Field(
        default_factory=list, description="Params that match the injection/SSRF/redirect magnet set."
    )
    tag: str = "discovery"
    #: HAND-OFFS — pre-filled, never fired. `intruder_url` marks the first param with the intruder's
    #: `[[…]]` position; `nuclei_target`/`repeater_url` hand the endpoint to those surfaces.
    intruder_url: str = ""
    nuclei_target: str = ""
    repeater_url: str = ""


class DiscoveredEndpoint(BaseModel):
    """One discovered path/dir + the pre-filled hand-offs. Tagged discovery."""

    url: str
    status: int | None = None
    length: int | None = None
    interesting: bool = False
    tag: str = "discovery"
    nuclei_target: str = ""
    repeater_url: str = ""


class DiscoverJob(BaseModel):
    """One discovery job. Counts are what HAPPENED, never what was planned."""

    id: str
    mode: str = Field("params", description="params | content | historical")
    state: str = Field("running", description="running | finished | stopped | refused")
    argv: list[str] = Field(default_factory=list, description="The approved entry command line.")
    url: str = ""
    domain: str = ""
    container: str = ""
    engagement_id: str | None = None
    session_id: str | None = None
    started_at: str = ""
    finished_at: str = ""
    stages: list[DiscoverStage] = Field(default_factory=list)
    params: list[DiscoveredParam] = Field(default_factory=list)
    endpoints: list[DiscoveredEndpoint] = Field(default_factory=list)
    discovered_out_of_scope: list[str] = Field(
        default_factory=list, description="Surfaced READ-ONLY — never handed off, never upserted."
    )
    new_endpoints: int = 0
    new_findings: int = 0
    words_in_surface: int = Field(
        0, description="content: how many words were in the approved surface (the whole list)."
    )
    capped: bool = Field(
        False, description="content: True when the word list was longer than DISCOVER_MAX_WORDS."
    )
    output_tail: str = ""
    warnings: list[str] = Field(default_factory=list)
    refused: str = Field("", description="Set when a gate refused the job — the reason.")
    refused_gate: str = ""


class DiscoverRefused(RuntimeError):
    """Refused BEFORE anything ran. Carries the gate that refused it."""

    def __init__(self, gate: str, reason: str, dangerous_flags: list[str] | None = None) -> None:
        super().__init__(reason)
        self.gate = gate
        self.reason = reason
        self.dangerous_flags = dangerous_flags or []


# --------------------------------------------------------------------------- #
# PURE: argv builders — the commands a job is EQUIVALENT TO. Never a shell.
# --------------------------------------------------------------------------- #
#: The in-sandbox JA3 MITM proxy (impersonate-proxy, baked in the image) the active discovery
#: tools route through when the operator ticks 'impersonate', so a Cloudflare/Akamai-fronted target
#: serves them a browser handshake instead of 403-ing a plain fuzzer. Same host+port for all tools.
IMPERSONATE_PROXY = "http://127.0.0.1:8899"


def _impersonate_flags(tool: str) -> list[str]:
    """Proxy flags that route ``tool`` through impersonate-proxy. The proxy presents its own MITM
    cert, so a tool that verifies TLS is told to accept it (ffuf ignores cert errors already)."""
    t = (tool or "").lower()
    if t == "ffuf":
        return ["-x", IMPERSONATE_PROXY]
    if t == "feroxbuster":
        return ["--proxy", IMPERSONATE_PROXY, "-k"]
    if t == "arjun":
        return ["--proxy", IMPERSONATE_PROXY]
    return []


def _auth_flags(tool: str, extra_headers: "Sequence[tuple[str, str]]") -> list[str]:
    """Auth-header flags for ``tool`` from the operator's attached session — ffuf/feroxbuster take a
    repeated ``-H "name: value"``, arjun takes one ``--headers`` with newline-joined pairs. Caller
    resolves the session (this stays a pure transform), and the values are masked in the job record."""
    if not extra_headers:
        return []
    t = (tool or "").lower()
    if t in ("ffuf", "feroxbuster"):
        out: list[str] = []
        for hn, hv in extra_headers:
            out += ["-H", f"{hn}: {hv}"]
        return out
    if t == "arjun":
        return ["--headers", "\n".join(f"{hn}: {hv}" for hn, hv in extra_headers)]
    return []


def arjun_argv(
    url: str, method: str, out_path: str, param_wordlist: str = "", rate_limit: int | None = None,
    impersonate: bool = False, extra_headers: "Sequence[tuple[str, str]]" = (),
) -> list[str]:
    """arjun worker argv: probe ONE url for hidden params, JSON to a loot file (`-oJ`).

    `-m` picks the request kind (GET/POST/JSON). arjun ships its own param wordlist; `-w` overrides
    it. The url is the ONLY host on the line, which is where `check_target_lock` reads it.
    """
    argv = ["arjun", "-u", url, "-m", (method or "GET").strip().upper() or "GET", "-oJ", out_path]
    if param_wordlist.strip():
        argv += ["-w", param_wordlist.strip()]
    if rate_limit:
        argv += ["--rate-limit", str(int(rate_limit))]
    if impersonate:
        argv += _impersonate_flags("arjun")
    argv += _auth_flags("arjun", extra_headers)
    return argv


def arjun_gate_argv(url: str, method: str) -> list[str]:
    """The command a params job is APPROVED as: `arjun -u <url> -m <method>`. The wordlist is
    arjun's bundled one (not operator bytes), so — like recon's subfinder — the entry command is the
    honest surface; there is no payload list to render complete here."""
    return ["arjun", "-u", url, "-m", (method or "GET").strip().upper() or "GET"]


def _fuzz_url(url: str) -> str:
    """Ensure a content-discovery url carries a `FUZZ` keyword for ffuf; append `/FUZZ` if not."""
    url = (url or "").strip()
    if "FUZZ" in url:
        return url
    return url.rstrip("/") + "/FUZZ"


def ffuf_argv(
    url: str, words_path: str, out_path: str, extensions: list[str], rate_limit: int | None = None,
    impersonate: bool = False, extra_headers: "Sequence[tuple[str, str]]" = (),
) -> list[str]:
    """ffuf worker argv: fuzz `FUZZ` in the url against a loot word file, JSON to a loot file."""
    argv = ["ffuf", "-u", _fuzz_url(url), "-w", words_path, "-mc", "all", "-o", out_path, "-of", "json"]
    exts = [e.strip().lstrip(".") for e in extensions if e.strip()]
    if exts:
        argv += ["-e", "," .join("." + e for e in exts)]
    if rate_limit:
        argv += ["-rate", str(int(rate_limit))]
    if impersonate:
        argv += _impersonate_flags("ffuf")
    argv += _auth_flags("ffuf", extra_headers)
    return argv


def feroxbuster_argv(
    url: str, words_path: str, out_path: str, extensions: list[str], rate_limit: int | None = None,
    impersonate: bool = False, extra_headers: "Sequence[tuple[str, str]]" = (),
) -> list[str]:
    """feroxbuster worker argv: recursive content discovery, JSONL to a loot file (`--json -o`)."""
    argv = ["feroxbuster", "-u", (url or "").strip(), "-w", words_path, "-d", "2",
            "--json", "-o", out_path, "--silent"]
    exts = [e.strip().lstrip(".") for e in extensions if e.strip()]
    if exts:
        argv += ["-x", ",".join(exts)]
    if rate_limit:
        argv += ["--rate-limit", str(int(rate_limit))]
    if impersonate:
        argv += _impersonate_flags("feroxbuster")
    argv += _auth_flags("feroxbuster", extra_headers)
    return argv


def paramspider_argv(domain: str, out_path: str = "") -> list[str]:
    """paramspider worker argv: mine web archives for parameterised URLs of ONE domain. PASSIVE —
    it queries archives, not the target. `-d <domain>` is the only host on the line."""
    argv = ["paramspider", "-d", (domain or "").strip()]
    if out_path:
        argv += ["-o", out_path]
    return argv


def content_gate_argv(req: "DiscoverRequest") -> list[str]:
    """The command a CONTENT job is APPROVED as — every word verbatim, intruder-style.

    Like `intruder_argv_for`, this puts the WHOLE word list on the line (`-w <word>` per word) so
    the danger heuristic reads the same bytes that get sent, and so the human approves the real set
    rather than a summary. When the operator named a baked `wordlist` path instead, the line carries
    that path — its bytes are not the operator's, exactly as recon trusts subfinder's own sources.
    """
    tool = "feroxbuster" if (req.tool or "").strip().lower() == "feroxbuster" else "ffuf"
    argv = [tool, "-u", (req.url or "").strip()]
    words = [w.strip() for w in req.words if w.strip()][:DISCOVER_MAX_WORDS]
    if words:
        for w in words:
            argv += ["-w", w]
    elif req.wordlist.strip():
        argv += ["-w", req.wordlist.strip()]
    exts = [e.strip().lstrip(".") for e in req.extensions if e.strip()]
    if exts:
        argv += ["-e", ",".join(exts)]
    return argv


def gate_argv(req: "DiscoverRequest", domain: str = "") -> list[str]:
    """The entry command a job is gated as, per mode. PURE."""
    mode = (req.mode or "").strip().lower()
    if mode == "content":
        return content_gate_argv(req)
    if mode == "historical":
        return paramspider_argv(domain or req.domain or "<domain>")
    return arjun_gate_argv((req.url or "").strip() or "<url>", req.method)


# --------------------------------------------------------------------------- #
# PURE: scope discipline + hand-off labelling — testable with no Docker
# --------------------------------------------------------------------------- #
def _endpoint_host(url: str) -> str:
    return scope_mod.bare_host(url).lower()


def filter_endpoints_in_scope(
    endpoints: list[Endpoint], matcher: scope_mod.ResolvedScope
) -> tuple[list[Endpoint], list[str]]:
    """Split discovered endpoints by the scope. IN-scope endpoints are kept (they may enter state
    and be handed off); OUT-of-scope hosts are collected read-only and their endpoints dropped.

    This is the enforced correctness property: nothing discovery surfaces — least of all a
    paramspider URL mined from an archive that spans other hosts — can reach the surface or state
    unless the declared scope already covered it. PURE.
    """
    kept: list[Endpoint] = []
    out_hosts: list[str] = []
    for e in endpoints:
        host = _endpoint_host(e.url)
        if host and matcher.in_scope(host):
            kept.append(e)
        elif host and host not in out_hosts:
            out_hosts.append(host)
    return kept, out_hosts


def _mark_param(url: str, param: str) -> str:
    """A url with `param` marked as an intruder `[[FUZZ]]` position — the pre-filled hand-off. PURE."""
    param = (param or "").strip()
    if not param:
        return url
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}{param}={POSITION_OPEN}FUZZ{POSITION_CLOSE}"


def _interesting_params(names: list[str]) -> list[str]:
    return [n for n in names if _INTERESTING_PARAM.match((n or "").strip())]


def _interesting_url(url: str) -> bool:
    return bool(_INTERESTING_URL.search(url or ""))


def _to_discovered_param(e: Endpoint) -> DiscoveredParam:
    interesting = _interesting_params(e.params)
    return DiscoveredParam(
        url=e.url, method=(e.method or "GET"), params=list(e.params), interesting=interesting,
        intruder_url=_mark_param(e.url, e.params[0]) if e.params else e.url,
        nuclei_target=e.url, repeater_url=e.url,
    )


def _to_discovered_endpoint(e: Endpoint) -> DiscoveredEndpoint:
    return DiscoveredEndpoint(
        url=e.url, status=e.status, length=e.length, interesting=_interesting_url(e.url),
        nuclei_target=e.url, repeater_url=e.url,
    )


def _findings_from(mode: str, endpoints: list[Endpoint], session_id: str, run_id: str) -> list[Finding]:
    """The discoveries of interest -> low `Finding`s (an admin endpoint, a debug param). PURE.

    Conservative: only an interesting URL or an interesting parameter name becomes a finding, so a
    plain `?page=` endpoint is surface, not noise in the findings list.
    """
    out: list[Finding] = []
    for e in endpoints:
        if mode == "content":
            if _interesting_url(e.url):
                out.append(Finding(
                    session_id=session_id, title=f"Sensitive endpoint discovered: {e.url}",
                    severity="low", target=e.url, tool="discover", vuln_class="content-discovery",
                    evidence=f"status={e.status} length={e.length}", source_run_id=run_id,
                ))
        else:
            hot = _interesting_params(e.params)
            if hot:
                out.append(Finding(
                    session_id=session_id,
                    title=f"Hidden parameter(s) discovered: {', '.join(hot[:8])}",
                    severity="low", target=e.url, tool="discover", vuln_class="param-discovery",
                    evidence=f"all discovered params: {', '.join(e.params[:40])}", source_run_id=run_id,
                ))
    return out


# --------------------------------------------------------------------------- #
# the gate — THE EXECUTOR'S, UNCHANGED
# --------------------------------------------------------------------------- #
def _exec_request(argv: list[str], req: "DiscoverRequest"):
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


def _resolve_domain(req: "DiscoverRequest", record) -> str:
    """The domain a historical job mines: the request's, else the engagement's declared target."""
    domain = (req.domain or "").strip()
    if not domain and record is not None:
        domain = (record.target or "").strip()
    return scope_mod.bare_host(domain).lower() if domain else ""


def validate(req: "DiscoverRequest") -> Any:
    """The gate verdict for a job, attacking nothing. PURE. Returns None when it passes.

    Gated against the mode's entry command — the same `executor.validate_request` a one-shot exec
    asks. A UI calls this to show 'would this be refused' before launching anything.
    """
    record = engagement.get_active(req.engagement_id) if req.engagement_id else None
    domain = _resolve_domain(req, record)
    return _gate(_exec_request(gate_argv(req, domain), req))


# --------------------------------------------------------------------------- #
# job registry — stop is a flag, and setting it is ungated
# --------------------------------------------------------------------------- #
_jobs: dict[str, DiscoverJob] = {}
_stops: dict[str, threading.Event] = {}
_procs: dict[str, subprocess.Popen] = {}
_lock = threading.Lock()


def get(job_id: str) -> DiscoverJob | None:
    with _lock:
        return _jobs.get(job_id)


def list_jobs(session_id: str | None = None) -> list[DiscoverJob]:
    with _lock:
        jobs = list(_jobs.values())
    if session_id:
        jobs = [j for j in jobs if j.session_id == session_id]
    return sorted(jobs, key=lambda j: j.started_at, reverse=True)


def stop(job_id: str) -> DiscoverJob | None:
    """Stop an in-flight job. NOT GATED — the panic button, like `stop_scan` and the intruder's
    stop. Sets the event and kills the current process; the worker ends the job."""
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
# shared preconditions — the recon/credattack model, one place
# --------------------------------------------------------------------------- #
def _require_engagement(engagement_id: str | None):
    """The active engagement record + its loot workdir, or refuse. Discovery is engagement-bound:
    the open, loot-mounted sandbox is where a real target/archives are reachable and where scope lives."""
    record = engagement.get_active(engagement_id) if engagement_id else None
    if record is None:
        raise DiscoverRefused(
            "engagement",
            "discovery runs in an active engagement — enter engagement mode first "
            "(POST /cockpit/engagement/enter). The isolated lab sandbox has no egress or loot.",
        )
    if not repeater_mod._container_running(config.ENGAGE_SANDBOX_CONTAINER):
        raise DiscoverRefused(
            "unavailable",
            f"engagement sandbox '{config.ENGAGE_SANDBOX_CONTAINER}' is not running — nothing ran",
        )
    try:
        workdir = loot.ensure(engagement_id or "")
    except loot.LootError as exc:
        raise DiscoverRefused("loot", f"could not prepare a loot directory: {exc}")
    return record, workdir


def _register(job: DiscoverJob) -> None:
    with _lock:
        _jobs[job.id] = job
        _stops[job.id] = threading.Event()


def _write_words(engagement_id: str, name: str, words: list[str]) -> str:
    """Write a word list to the engagement loot dir; returns its CONTAINER path. The file the
    content-discovery tool reads — every word the operator approved, one per line."""
    host_dir = loot.host_dir(engagement_id)
    host_dir.mkdir(parents=True, exist_ok=True)
    (host_dir / name).write_text("\n".join(words) + "\n", encoding="utf-8")
    return f"{loot.container_dir(engagement_id)}/{name}"


def _target_in_scope(record, host: str) -> bool:
    """Is a host in the engagement scope? The construction check the target-lock also makes."""
    if not host:
        return False
    return engagement.resolved_scope(record).in_scope(host)


# --------------------------------------------------------------------------- #
# start — GATE BEFORE ANYTHING SPAWNS; TARGET SCOPE-LOCKED BY CONSTRUCTION
# --------------------------------------------------------------------------- #
def start(req: DiscoverRequest) -> DiscoverJob:
    """Validate, scope-lock the target, then run ONE discovery job in the background.

    THE GATE RUNS BEFORE ANY SPAWN. Refuses (nothing runs) on any of the four gates, if the target
    host is out of scope, if the engagement sandbox is down, or on missing input. Otherwise the job
    is registered `running` and a worker execs the mode's tool(s), which is what makes `stop`
    meaningful: there is something to stop.
    """
    record, workdir = _require_engagement(req.engagement_id)
    mode = (req.mode or "").strip().lower()
    warnings: list[str] = []
    if mode not in MODES:
        warnings.append(f"unknown mode {req.mode!r} — running as 'params'. Known: {', '.join(MODES)}")
        mode = "params"

    domain = _resolve_domain(req, record)
    # SCOPE-LOCK THE TARGET BY CONSTRUCTION — a job can never be pointed off-scope.
    if mode == "historical":
        if not domain:
            raise DiscoverRefused("input", "historical discovery needs an in-scope domain (paramspider "
                                  "mines its archived URLs) — pass one, or set the engagement target")
        if not _target_in_scope(record, domain):
            raise DiscoverRefused("scope", f"{domain} is out of scope for {req.engagement_id}")
    else:
        url = (req.url or "").strip()
        host = scope_mod.bare_host(url).lower()
        if not url or not host:
            raise DiscoverRefused("input", f"{mode} discovery needs an in-scope url to point at")
        if not _target_in_scope(record, host):
            raise DiscoverRefused("scope", f"{host} is out of scope for {req.engagement_id}")
        if mode == "content" and not req.words and not req.wordlist.strip():
            raise DiscoverRefused("input", "content discovery needs a word list — paste `words` "
                                  "(the whole list rides in the approved surface) or name a `wordlist` path")

    argv = gate_argv(req, domain)
    rejected = _gate(_exec_request(argv, req))
    if rejected is not None:
        raise DiscoverRefused(rejected.gate, rejected.reason, list(rejected.dangerous_flags or []))

    words = [w.strip() for w in req.words if w.strip()]
    capped = len(words) > DISCOVER_MAX_WORDS
    if capped:
        warnings.append(f"{len(words)} words is over the {DISCOVER_MAX_WORDS} ceiling — the first "
                        f"{DISCOVER_MAX_WORDS} ride in the surface and run; it is NOT refused")
        words = words[:DISCOVER_MAX_WORDS]

    job = DiscoverJob(
        id=uuid.uuid4().hex[:12], mode=mode, argv=argv, url=(req.url or "").strip(), domain=domain,
        container=config.ENGAGE_SANDBOX_CONTAINER, engagement_id=req.engagement_id,
        session_id=req.session_id or req.engagement_id, started_at=_now(), warnings=warnings,
        words_in_surface=len(words) if mode == "content" else 0, capped=capped,
    )
    _register(job)
    threading.Thread(
        target=_run, args=(job.id, req, record, workdir, mode, domain, words),
        daemon=True, name=f"discover-{job.id}",
    ).start()
    return job


# --------------------------------------------------------------------------- #
# worker — one job = one approval; scope-filter everything that comes back
# --------------------------------------------------------------------------- #
def _run(job_id: str, req: DiscoverRequest, record, workdir: str, mode: str,
         domain: str, words: list[str]) -> None:
    """The worker. Runs the mode's tool(s), scope-filters, upserts in-scope endpoints. Never raises."""
    session_id = req.session_id or req.engagement_id or ""
    eng_id = req.engagement_id or ""
    matcher = engagement.resolved_scope(record)
    parsed = Parsed()
    last_text = ""
    # Authenticated discovery: the operator's attached session rides as -H/--headers on the active
    # tools (arjun/ffuf/feroxbuster). paramspider (historical) is archive-based and cannot auth.
    extra = session_store.header_pairs(eng_id) if req.attach_session else []

    # Bring the JA3 MITM proxy up before an impersonated fuzz — the active tools route through it.
    # paramspider (historical) is passive/archive-based, so it never needs the proxy.
    if req.impersonate and mode in ("params", "content"):
        _ensure_impersonate_proxy(config.ENGAGE_SANDBOX_CONTAINER)

    if mode == "params":
        out_name = f"discover-{job_id}-arjun.json"
        argv = arjun_argv((req.url or "").strip(), req.method,
                          f"{loot.container_dir(eng_id)}/{out_name}", req.param_wordlist,
                          req.rate_limit, impersonate=req.impersonate, extra_headers=extra)
        last_text = _spawn(job_id, argv, workdir, _timeout(req))
        file_text = _read_loot(eng_id, out_name)
        parsed.extend(parse_arjun(file_text or last_text, session_id, job_id))
        _add_stage(job_id, "arjun", session_store.mask_header_flag_values(argv),
                   "ran" if not _stopped(job_id) else "stopped",
                   f"{req.method.upper()} params on {req.url}")

    elif mode == "content":
        tool = "feroxbuster" if (req.tool or "").strip().lower() == "feroxbuster" else "ffuf"
        words_path = req.wordlist.strip()
        if words:
            words_path = _write_words(eng_id, f"discover-{job_id}-words.txt", words)
        out_name = f"discover-{job_id}-{'ferox' if tool == 'feroxbuster' else 'ffuf'}.json"
        out_path = f"{loot.container_dir(eng_id)}/{out_name}"
        builder = feroxbuster_argv if tool == "feroxbuster" else ffuf_argv
        argv = builder((req.url or "").strip(), words_path, out_path, req.extensions,
                       req.rate_limit, impersonate=req.impersonate, extra_headers=extra)
        last_text = _spawn(job_id, argv, workdir, _timeout(req) * 2)
        file_text = _read_loot(eng_id, out_name)
        p = parse_feroxbuster if tool == "feroxbuster" else parse_ffuf
        parsed.extend(p(file_text or last_text, session_id, job_id))
        _add_stage(job_id, tool, session_store.mask_header_flag_values(argv),
                   "ran" if not _stopped(job_id) else "stopped",
                   f"{len(words)} words · {req.url}")

    else:  # historical
        out_name = f"discover-{job_id}-params.txt"
        argv = paramspider_argv(domain, f"{loot.container_dir(eng_id)}/{out_name}")
        last_text = _spawn(job_id, argv, workdir, _timeout(req))
        file_text = _read_loot(eng_id, out_name)
        parsed.extend(parse_urls(file_text or last_text, session_id, job_id))
        # historical discovery can also reveal new in-scope hosts — feed the recon expansion.
        _safe_discoveries(record, f"{file_text}\n{last_text}", job_id)
        _add_stage(job_id, "paramspider", argv, "ran" if not _stopped(job_id) else "stopped",
                   f"archived params for {domain}")

    # SCOPE-FILTER EVERYTHING BEFORE IT LANDS — nothing out-of-scope reaches surface/state.
    kept, out_hosts = filter_endpoints_in_scope(parsed.endpoints, matcher)
    findings = _findings_from(mode, kept, session_id, job_id)

    new_ep = new_find = 0
    if session_id:
        try:
            new_ep = state_store.upsert_endpoints(kept)
            new_find = state_store.upsert_findings(findings)
        except Exception:  # noqa: BLE001 - a persistence hiccup must not lose the job
            pass

    _finish(job_id, session_id, mode, domain or (req.url or ""), kept, out_hosts,
            new_ep, new_find, last_text)


# --------------------------------------------------------------------------- #
# worker helpers
# --------------------------------------------------------------------------- #
def _timeout(req: DiscoverRequest) -> int:
    return config.clamp_timeout(req.timeout_seconds) * 3


def _ensure_impersonate_proxy(container: str) -> None:
    """Start impersonate-proxy in the sandbox if it isn't already up, then wait for it to bind 8899.

    Idempotent + best-effort: a second launch just fails to bind and is ignored; a start failure
    degrades to the tool going direct (and 403-ing), never a crashed job. Never raises."""
    try:
        subprocess.run(
            ["docker", "exec", "-d", container, "sh", "-c",
             "pgrep -f impersonate_proxy.py >/dev/null 2>&1 || "
             "impersonate-proxy >/tmp/impersonate-proxy.log 2>&1"],
            capture_output=True, timeout=15,
        )
    except Exception:  # noqa: BLE001 - a proxy start must never take the job down
        return
    for _ in range(20):  # mitmproxy takes ~1s to bind; wait up to 10s
        try:
            probe = subprocess.run(
                ["docker", "exec", container, "sh", "-c",
                 "ss -ltn 2>/dev/null | grep -q ':8899' && echo up"],
                capture_output=True, text=True, timeout=5,
            )
            if "up" in (probe.stdout or ""):
                return
        except Exception:  # noqa: BLE001
            pass
        time.sleep(0.5)


def _stopped(job_id: str) -> bool:
    ev = _stops.get(job_id)
    return ev is not None and ev.is_set()


def _safe_discoveries(record, text: str, run_id: str) -> dict:
    try:
        return engagement.record_discoveries(record, text, run_id)
    except Exception:  # noqa: BLE001 - expansion is best-effort, never load-bearing
        return {"added": [], "out_of_scope": [], "truncated": False}


def _read_loot(engagement_id: str, name: str) -> str:
    """Read a loot file one tool wrote (arjun/ffuf JSON, paramspider URLs). '' on any miss."""
    if not engagement_id:
        return ""
    try:
        path = loot.host_dir(engagement_id) / name
        if not path.is_file():
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _add_stage(job_id: str, tool: str, argv: list[str], state: str, note: str) -> None:
    with _lock:
        job = _jobs.get(job_id)
        if job is not None:
            job.stages.append(DiscoverStage(tool=tool, argv=argv, state=state, note=note))


def _finish(job_id: str, session_id: str, mode: str, target: str, kept: list[Endpoint],
            out_hosts: list[str], new_ep: int, new_find: int, text: str) -> None:
    """Close the job out, build the hand-off rows, persist one audit record. Never raises."""
    with _lock:
        job = _jobs.get(job_id)
        stopped = _stops.get(job_id)
        if job is not None:
            job.state = "stopped" if (stopped is not None and stopped.is_set()) else "finished"
            job.finished_at = _now()
            job.discovered_out_of_scope = _dedupe(out_hosts)
            job.new_endpoints = new_ep
            job.new_findings = new_find
            job.output_tail = text[-4000:]
            if mode in ("params", "historical"):
                job.params = [_to_discovered_param(e) for e in kept]
            else:
                job.endpoints = [_to_discovered_endpoint(e) for e in kept]
        argv = job.argv if job else [mode]
        _procs.pop(job_id, None)
    try:
        runstore.save_run(RunRecord(
            run_id=job_id, command=(argv[0] if argv else "discover"), args=argv[1:] if argv else [],
            target=scope_mod.bare_host(target) or target, approved=True, mode="engagement",
            exit_code=0, stdout=text[-8000:], stderr="",
            started_at=(job.started_at if job else _now()), finished_at=_now(),
            session_id=session_id or None, step_id=None,
        ))
    except Exception:  # noqa: BLE001 - an audit failure must not lose the results
        pass


def _spawn(job_id: str, argv: list[str], workdir: str, timeout: int) -> str:
    """Run ONE `docker exec <tool>` to completion (or until stop/timeout), capturing merged output.
    Never raises — a transport failure becomes a note in the transcript."""
    full = ["docker", "exec", *loot.exec_flags(workdir), config.ENGAGE_SANDBOX_CONTAINER, *argv]
    try:
        proc = subprocess.Popen(
            full, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
        )
    except FileNotFoundError:
        return "[discover] docker CLI not found on PATH\n"
    except Exception as exc:  # noqa: BLE001
        return f"[discover] could not start: {exc}\n"
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
        text += f"\n[discover] {argv[0]} timed out after {timeout}s\n"
    return text


def reset() -> None:
    """Drop all job state. Tests only — never called by the app."""
    with _lock:
        _jobs.clear()
        _stops.clear()
        _procs.clear()
