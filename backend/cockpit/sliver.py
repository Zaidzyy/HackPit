"""Sliver C2 — HUMAN-ONLY server lifecycle + GATED implant generation.

Sliver (Bishop Fox) is an adversary-emulation framework: you run a *server* that hosts
listeners, and you *generate* per-OS implants that call back to one of them. Those two
things carry completely different risk, so this module keeps them on two different
footings and NEVER collapses them:

SERVER LIFECYCLE — :func:`start_server` / :func:`stop_server` / :func:`list_servers`.
    HUMAN-ONLY, no gate beyond "a human clicked Start". A C2 server is OPERATOR
    INFRASTRUCTURE running on the operator's own box: it has no target, touches nothing
    belonging to the client, and starting it is not an action against a system under test.
    That is exactly the posture ``cockpit/tunnels.py`` gives a pivot listener, and this
    mirrors it structurally — a hardcoded container, a liveness probe, a live cap, a
    tracked process, a refusal that runs nothing. What makes it safe is the same thing
    that makes the tunnel listener safe: the autonomous path has ZERO route here. A C2
    server an agent could raise is an autonomous C2. Regression-locked by a source scan
    over the whole backend tree (test_sliver.py::test_sliver_surface_is_human_only), the
    same lock ``:kali``, the tunnels and live sessions have.

IMPLANT GENERATION — :func:`generate_implant`.
    A GATED COMMAND. It builds an :class:`ExecRequest` and runs the REAL
    ``executor.validate_request`` — not a copy — so a build clears exactly the gates a
    one-shot command clears, in the same order:
        LAB:        target-lock -> approval -> heuristic danger -> ISOLATION
        ENGAGEMENT: engagement  -> scope-lock -> approval -> danger
    A payload generator trips ``dangerous_command_heuristic``, so an explicit
    ``dangerous_ack`` red-confirm is required in practice: you cannot build a beacon by
    accident, and neither can an agent-proposed step sneak one through on a plain approval.
    This is NOT a new capability — it is a command that happens to produce a file.

    IT ONLY GENERATES. The output is an artifact in the run's loot directory. Delivering
    it to a host, executing it, catching the beacon and driving a live Sliver session are
    each a SEPARATE, separately-approved concern and are DEFERRED — the same posture the
    tunnels take toward the agent connect-back they cannot test.

``<listener>`` IS OPERATOR-SIDE AND PASSES THROUGH VERBATIM.
    The callback address belongs to the OPERATOR — a VPN/tun address on the operator's own
    box, as the implant will see it. It is never a value the system under test supplies and
    it is NEVER substituted with the engagement target. Substituting the target would point
    a beacon at the client's own network, which is both useless and harmful. The default
    ``<listener>`` placeholder therefore survives argv construction unchanged, and a literal
    operator address is carried through untouched too.

    Consequence, deliberately fail-closed: :func:`_gate_request` gates the SUPERSET (the
    argv plus the declared target), which is at-least-as-strict as gating the argv alone.
    So a literal callback address that is host-shaped and *outside* the engagement scope is
    REFUSED at the target gate. That is friction in the safe direction — the recommended
    shape is the ``<listener>`` placeholder, which names no host and passes cleanly.

CONTAINMENT, the rest of it:
    * argv lists only, handed to subprocess as a list. Never a shell string, so no request
      value can ever reach a shell.
    * The container is a CODE CONSTANT resolved from the execution mode
      (``executor.resolve_mode`` for a build, ``config.ENGAGE_SANDBOX_CONTAINER`` for the
      server) — never a request field. Neither request model has a container/sandbox field.
    * ``os`` / ``arch`` / ``format`` are validated against a FIXED SET, so nothing
      caller-supplied is interpolated into argv except the operator's own listener string.
    * The artifact path is SERVER-CHOSEN — a run-id-derived filename placed by
      ``loot.workdir_for`` (the engagement's loot tree in ENGAGEMENT mode; the container's
      own default directory in LAB, which has no loot mount by design). A caller cannot
      pick where the file lands.
    * Every start, stop and generate is recorded via ``runstore.save_run``.
    * :func:`_implant_argv` is PURE — argv construction, no execution, no I/O — so the UI
      can preview exactly what a build would run without running it.
"""

from __future__ import annotations

import os as _os
import subprocess
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field, field_validator

from . import config, executor, loot, runstore
from .models import ExecRejected, ExecRequest, RunRecord

# The two binaries, as they are named inside the sandbox image. Constants, never request
# fields — the same discipline the container names get.
SLIVER_SERVER_BIN = "sliver-server"
SLIVER_CLIENT_BIN = "sliver-client"

# The server's default daemon port (Sliver's own default multiplayer port).
SLIVER_DEFAULT_PORT = 31337

# Bounds. A C2 server is heavyweight; one is normal, a pile of them is a mistake.
MAX_LIVE_SERVERS = int(_os.environ.get("HACKPIT_MAX_SLIVER_SERVERS", "2"))

# How long one implant build may take before it is killed. A cross-compile is slow; this
# is not a safety property (the gates are), just a bound on a runaway build.
IMPLANT_BUILD_TIMEOUT_SECONDS = int(_os.environ.get("HACKPIT_IMPLANT_BUILD_TIMEOUT", "900"))

# Fixed sets — anything outside them is refused rather than interpolated into argv.
IMPLANT_OS = ("windows", "linux", "darwin")
IMPLANT_ARCH = ("amd64", "386", "arm64")
IMPLANT_FORMAT = ("exe", "shared", "service", "shellcode")

# The transports a build may point at. Each maps to the Sliver generate flag for it.
LISTENER_FLAGS = {"mtls": "--mtls", "https": "--http", "dns": "--dns", "wg": "--wg"}

# File extension per output format, so the artifact name reads correctly on disk.
_FORMAT_EXT = {"exe": "exe", "shared": "dll", "service": "exe", "shellcode": "bin"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------- #
# models
# --------------------------------------------------------------------------- #
class SliverServerRequest(BaseModel):
    """Start the operator's OWN Sliver server. NO container field — the box is a constant.

    There is no target here BY DEFINITION: the server listens on the operator's sandbox and
    nothing about starting it reaches a system under test. ``engagement_id`` only tags the
    record so the server shows up in the right engagement's audit trail; it does not gate
    anything and it cannot redirect where the server runs.
    """

    port: int | None = Field(
        None, ge=1, le=65535,
        description="Daemon port inside the engage sandbox. Omit for the Sliver default.",
    )
    engagement_id: str | None = Field(
        None, description="Engagement to record this server against (tagging only — not a gate)."
    )


class SliverServer(BaseModel):
    """One Sliver server this backend started. Operator infrastructure, not a target."""

    id: str
    status: str = Field(description="listening | down.")
    container: str
    port: int
    run_id: str
    started_at: str
    stopped_at: str | None = None
    engagement_id: str | None = None
    setup_note: str = ""


class ImplantRequest(BaseModel):
    """Generate ONE implant artifact. Gated exactly like a one-shot command.

    NOTE — deliberately there is NO container / sandbox field and no output-path field. The
    container comes from ``executor.resolve_mode`` and the artifact path from the run's loot
    directory; nothing in this request can redirect either.
    """

    os: str = Field("windows", description=f"Target OS — one of {IMPLANT_OS}.")
    arch: str = Field("amd64", description=f"Target architecture — one of {IMPLANT_ARCH}.")
    fmt: str = Field("exe", description=f"Output format — one of {IMPLANT_FORMAT}.")
    transport: str = Field(
        "mtls", description=f"Callback transport — one of {tuple(LISTENER_FLAGS)}."
    )
    listener: str = Field(
        "<listener>",
        min_length=1,
        description="The OPERATOR-SIDE callback address the implant beacons to — your own "
        "host/port as the implant will see it. Passed through VERBATIM and NEVER "
        "substituted with the target. Leave as the '<listener>' placeholder to build a "
        "preview whose callback you fill in on your own console.",
    )
    target: str = Field(
        "",
        description="The DECLARED target this build is for. Validated by the mode's "
        "target-lock (lab alias / in-scope host) — it is NOT written into the implant.",
    )
    engagement_id: str | None = Field(
        None, description="When set to an ACTIVE engagement id, build in engagement mode."
    )
    session_id: str | None = Field(None, description="Engagement to record the build against.")
    step_id: str | None = Field(None, description="Optional attack-path step id.")
    approved: bool = Field(
        False, description="Per-command human approval. Generation refuses unless true."
    )
    dangerous_ack: bool = Field(
        False,
        description="Explicit second confirmation. A payload generator trips the danger "
        "heuristic, so this is required in practice.",
    )

    @field_validator("os")
    @classmethod
    def _os_ok(cls, v: str) -> str:
        v = str(v).strip().lower()
        if v not in IMPLANT_OS:
            raise ValueError(f"os must be one of {IMPLANT_OS}")
        return v

    @field_validator("arch")
    @classmethod
    def _arch_ok(cls, v: str) -> str:
        v = str(v).strip().lower()
        if v not in IMPLANT_ARCH:
            raise ValueError(f"arch must be one of {IMPLANT_ARCH}")
        return v

    @field_validator("fmt")
    @classmethod
    def _fmt_ok(cls, v: str) -> str:
        v = str(v).strip().lower()
        if v not in IMPLANT_FORMAT:
            raise ValueError(f"fmt must be one of {IMPLANT_FORMAT}")
        return v

    @field_validator("transport")
    @classmethod
    def _transport_ok(cls, v: str) -> str:
        v = str(v).strip().lower()
        if v not in LISTENER_FLAGS:
            raise ValueError(f"transport must be one of {tuple(LISTENER_FLAGS)}")
        return v


class Implant(BaseModel):
    """One generated artifact. It exists on disk; nothing here delivers or runs it."""

    id: str
    run_id: str
    status: str = Field(description="generated | failed.")
    os: str
    arch: str
    fmt: str
    transport: str
    listener: str = Field(description="The operator-side callback, verbatim as requested.")
    target: str
    mode: str = Field(description="lab | engagement — whichever the gates resolved.")
    container: str
    artifact_path: str = Field(
        description="Where the artifact was written INSIDE the container: an absolute /loot "
        "path in ENGAGEMENT mode, a bare filename (the image's default working directory) in "
        "LAB, which has no loot mount by design and whose artifacts are not durable."
    )
    argv: list[str] = Field(description="The exact argv that ran — auditable, never a shell.")
    exit_code: int | None = None
    detail: str = ""
    generated_at: str
    engagement_id: str | None = None
    session_id: str | None = None
    step_id: str | None = None


class SliverRefused(RuntimeError):
    """Nothing ran / nothing was built. Carries the gate that refused it."""

    def __init__(self, reason: str, gate: str = "sliver"):
        super().__init__(reason)
        self.reason = reason
        self.gate = gate


# --------------------------------------------------------------------------- #
# registry
# --------------------------------------------------------------------------- #
@dataclass
class _LiveServer:
    model: SliverServer
    record: RunRecord
    proc: "subprocess.Popen[str] | None" = field(default=None)


_servers: dict[str, _LiveServer] = {}
_implants: dict[str, Implant] = {}
_lock = threading.Lock()


def _container_running(name: str) -> bool:
    """Liveness probe for a container. Read-only — inspects, never execs into it."""
    try:
        p = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", name],
            capture_output=True, text=True, timeout=10.0,
        )
        return p.returncode == 0 and p.stdout.strip() == "true"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _save(record: RunRecord) -> None:
    """Persist a run record. Never raises — recording must not break the surface."""
    try:
        runstore.save_run(record)
    except Exception:  # pragma: no cover - persistence is best-effort
        pass


# --------------------------------------------------------------------------- #
# SERVER LIFECYCLE — *** HUMAN-ONLY ***. Operator infrastructure, no target.
# --------------------------------------------------------------------------- #
def start_server(req: SliverServerRequest) -> SliverServer:
    """Start the operator's Sliver server in the ENGAGE sandbox. *** HUMAN-ONLY. ***

    Clicking Start IS the approval: this runs the operator's own C2 daemon on the
    operator's own sandbox, with no target, so no target-scope gate applies (the identical
    reasoning the pivot-listener lifecycle uses). Refuses — running
    nothing — if the sandbox is down, the live cap is hit, or the docker CLI is missing.

    The autonomous path must have NO route to this function; see the module docstring.
    """
    if not _container_running(config.ENGAGE_SANDBOX_CONTAINER):
        raise SliverRefused(
            f"engage sandbox '{config.ENGAGE_SANDBOX_CONTAINER}' is not running — bring the "
            "stack up (docker compose -f docker/docker-compose.yml up -d)",
            gate="unavailable",
        )
    with _lock:
        live = sum(1 for s in _servers.values() if s.model.status == "listening")
        if live >= MAX_LIVE_SERVERS:
            raise SliverRefused(
                f"too many live Sliver servers ({live}/{MAX_LIVE_SERVERS}) — stop one first",
                gate="limit",
            )

    port = req.port or SLIVER_DEFAULT_PORT
    sid = uuid.uuid4().hex[:12]
    run_id = uuid.uuid4().hex[:12]
    started_at = _now()
    server_args = ["daemon", "-l", "0.0.0.0", "-p", str(port)]
    argv = ["docker", "exec", config.ENGAGE_SANDBOX_CONTAINER, SLIVER_SERVER_BIN, *server_args]

    try:
        proc = subprocess.Popen(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError:
        raise SliverRefused("docker CLI not found on PATH", gate="unavailable")

    model = SliverServer(
        id=sid,
        status="listening",
        container=config.ENGAGE_SANDBOX_CONTAINER,
        port=port,
        run_id=run_id,
        started_at=started_at,
        engagement_id=req.engagement_id,
        setup_note=(
            f"Sliver server is up inside {config.ENGAGE_SANDBOX_CONTAINER} on port {port}. "
            "Create your listener from the Sliver console; the listener address is yours and "
            "is what an implant build's '<listener>' placeholder stands in for."
        ),
    )
    record = RunRecord(
        run_id=run_id,
        command=SLIVER_SERVER_BIN,
        args=server_args,
        # No target BY DEFINITION — this is the operator's own box. Recording the container
        # keeps the audit row honest instead of naming a system under test that was never
        # touched.
        target=config.ENGAGE_SANDBOX_CONTAINER,
        approved=True,  # a human clicked Start; that IS the approval for operator infra
        mode="engagement",
        started_at=started_at,
        session_id=req.engagement_id,
    )
    with _lock:
        _servers[sid] = _LiveServer(model=model, record=record, proc=proc)
    _save(record)
    return model


def list_servers() -> list[SliverServer]:
    """Every server this process knows about, refreshing liveness. Read-only."""
    with _lock:
        live = list(_servers.values())
    for ls in live:
        if ls.proc is not None and ls.proc.poll() is not None and ls.model.status != "down":
            ls.model.status = "down"
    return [ls.model for ls in live]


def get_server(sid: str) -> SliverServer | None:
    with _lock:
        ls = _servers.get(sid)
    return ls.model if ls else None


def stop_server(sid: str) -> SliverServer:
    """Stop a Sliver server (kill its process). HUMAN-ONLY. Idempotent.

    Closes the SAME run record the start opened (INSERT OR REPLACE), so the audit trail
    shows one server with a start and an end rather than two unrelated rows.
    """
    with _lock:
        ls = _servers.get(sid)
    if ls is None:
        raise SliverRefused(f"no Sliver server {sid}", gate="unknown")
    if ls.model.status == "down":
        return ls.model
    if ls.proc is not None:
        try:
            ls.proc.kill()
        except Exception:  # pragma: no cover - already dead
            pass
    ls.model.status = "down"
    ls.model.stopped_at = _now()
    ls.record.finished_at = ls.model.stopped_at
    ls.record.exit_code = ls.proc.poll() if ls.proc is not None else None
    _save(ls.record)
    return ls.model


# --------------------------------------------------------------------------- #
# IMPLANT GENERATION — a GATED command that happens to produce a file.
# --------------------------------------------------------------------------- #
def _implant_argv(req: ImplantRequest) -> list[str]:
    """The `sliver-client generate` argv for this request. *** PURE. ***

    Builds a LIST of argv tokens and nothing else: no execution, no filesystem, no network,
    no clock. Safe for the UI/preview path — the operator can see exactly what a build would
    run before approving it.

    The ``--save`` path is deliberately NOT here: it is server-chosen per run (see
    :func:`generate_implant`), so keeping it out is what makes this function pure.

    ``req.listener`` is emitted VERBATIM. ``req.target`` is NOT emitted at all — it exists
    to be scope-checked, never to become the implant's callback address.
    """
    return [
        SLIVER_CLIENT_BIN, "generate",
        "--os", req.os,
        "--arch", req.arch,
        "--format", req.fmt,
        LISTENER_FLAGS[req.transport], req.listener,
    ]


def _gate_request(req: ImplantRequest) -> ExecRequest:
    """The ExecRequest THE GATES SEE: the real argv PLUS the declared target.

    Gating the superset is strictly at-least-as-strict as gating the argv alone (the same
    reasoning ``session._gate_request`` documents): the extra token can only satisfy "a
    target was named" or add heuristic reasons — it can never mask a bad host sitting in
    the real args, which are still scanned and still rejected.
    """
    args = [*_implant_argv(req)[1:]]
    if req.target:
        args.append(req.target)
    return ExecRequest(
        command=SLIVER_CLIENT_BIN,
        args=args,
        approved=req.approved,
        dangerous_ack=req.dangerous_ack,
        engagement_id=req.engagement_id,
        session_id=req.session_id,
        step_id=req.step_id,
    )


def validate_generate(req: ImplantRequest) -> ExecRejected | None:
    """Run the mode's REAL gates against an implant build. None means it may run."""
    return executor.validate_request(_gate_request(req))


def _artifact_path(req: ImplantRequest, run_id: str, mode: str) -> str:
    """The SERVER-CHOSEN output path for this build's artifact. Never caller-supplied.

    The filename is always ``implant-<run_id>.<ext>``, so an artifact is traceable to the
    record that authorised it. WHERE it lands is decided by :func:`loot.workdir_for` — the
    same helper ``executor.iter_run`` uses to pick a run's working directory — so this
    module cannot disagree with the rest of the cockpit about where loot goes:

    ENGAGEMENT -> ``/loot/<engagement_id>/implant-….exe``. The engage sandbox bind-mounts
        the host's engagements directory, so the artifact is durable and lands in the
        engagement's own loot tree.

    LAB -> a BARE RELATIVE FILENAME, i.e. the image's default working directory INSIDE the
        container. The isolated lab sandbox deliberately has NO ``/loot`` mount (see
        loot.py's "which sandboxes get it — and the one that deliberately does not"): giving
        the egress-less box a writable host directory would widen its reach for no gain.
        Writing ``--save /loot/…`` there would have failed every lab build outright, and
        would have mkdir'd a host directory nothing could ever populate.

        Lab generation is kept WORKING rather than refused on purpose: the lab is the
        rehearsal surface. Refusing it would mean an operator's first-ever implant build
        happens against a real engagement, which is the outcome the lab exists to prevent.
        The trade-off is that a LAB artifact is NOT durable — it lives and dies with the
        container, exactly like every other lab-mode file. That is the correct posture for a
        practice beacon and matches what loot.py already says about lab output.

    ``workdir_for`` swallows a bad loot name / unwritable directory and returns None, so a
    loot problem degrades to the container-local path instead of dropping a build the human
    already approved — the same "a loot directory is a convenience, never a gate" rule the
    one-shot path follows.
    """
    ext = _FORMAT_EXT.get(req.fmt, "bin")
    name = f"implant-{run_id}.{ext}"
    workdir = loot.workdir_for(mode, req.engagement_id)
    return f"{workdir}/{name}" if workdir else name


def generate_implant(req: ImplantRequest) -> Implant:
    """Gate, then build ONE implant artifact in the mode's sandbox. Registers and returns it.

    Raises :class:`SliverRefused` — having run NOTHING — if any gate refuses or if docker is
    unavailable. A build that RUNS but fails (non-zero exit) is NOT a refusal: it is recorded
    with ``status='failed'`` and returned, because a tool failure is not a safety event.

    This GENERATES ONLY. Delivering the artifact to a host and running it are separate,
    separately-approved concerns and are deferred.
    """
    rejected = validate_generate(req)
    if rejected is not None:
        raise SliverRefused(rejected.reason, gate=rejected.gate)

    # The container comes from the SAME mapping one-shot runs use — never the request.
    try:
        resolved = executor.resolve_mode(_gate_request(req))
    except executor.EngagementInactive as exc:
        raise SliverRefused(str(exc), gate="engagement")

    run_id = uuid.uuid4().hex[:12]
    artifact = _artifact_path(req, run_id, resolved.mode)
    started_at = _now()
    argv = [
        "docker", "exec", resolved.container,
        *_implant_argv(req),
        "--save", artifact,
    ]

    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=IMPLANT_BUILD_TIMEOUT_SECONDS,
        )
        exit_code: int | None = proc.returncode
        stdout, stderr = proc.stdout or "", proc.stderr or ""
        detail = ""
    except FileNotFoundError:
        raise SliverRefused("docker CLI not found on PATH", gate="unavailable")
    except subprocess.TimeoutExpired:
        exit_code, stdout = None, ""
        stderr = detail = f"implant build timed out after {IMPLANT_BUILD_TIMEOUT_SECONDS}s"

    implant = Implant(
        id=uuid.uuid4().hex[:12],
        run_id=run_id,
        status="generated" if exit_code == 0 else "failed",
        os=req.os,
        arch=req.arch,
        fmt=req.fmt,
        transport=req.transport,
        listener=req.listener,  # verbatim — never the target
        target=resolved.target,
        mode=resolved.mode,
        container=resolved.container,
        artifact_path=artifact,
        argv=list(argv),
        exit_code=exit_code,
        detail=detail,
        generated_at=started_at,
        engagement_id=req.engagement_id,
        session_id=req.session_id,
        step_id=req.step_id,
    )
    _save(
        RunRecord(
            run_id=run_id,
            command="sliver-generate",
            args=[req.os, req.arch, req.fmt, req.transport],
            target=resolved.target,
            approved=True,  # it cleared the approval gate above
            mode=resolved.mode,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            started_at=started_at,
            finished_at=_now(),
            session_id=req.session_id,
            step_id=req.step_id,
        )
    )
    with _lock:
        _implants[implant.id] = implant
    return implant


def list_implants() -> list[Implant]:
    """Every implant built by this process, oldest first. Read-only."""
    with _lock:
        return sorted(_implants.values(), key=lambda i: i.generated_at)


def get_implant(iid: str) -> Implant | None:
    with _lock:
        return _implants.get(iid)


# --------------------------------------------------------------------------- #
# status + test helper
# --------------------------------------------------------------------------- #
def status() -> dict[str, Any]:
    """Availability + counts for the UI panel. Makes no isolation claim of its own."""
    up = _container_running(config.ENGAGE_SANDBOX_CONTAINER)
    return {
        "container": config.ENGAGE_SANDBOX_CONTAINER,
        "up": up,
        "live_servers": sum(1 for s in list_servers() if s.status == "listening"),
        "max_live_servers": MAX_LIVE_SERVERS,
        "implants": len(list_implants()),
        "detail": "" if up else "engage sandbox container is not running",
    }


def reset() -> None:  # test helper
    with _lock:
        for ls in _servers.values():
            if ls.proc is not None:
                try:
                    ls.proc.kill()
                except Exception:
                    pass
        _servers.clear()
        _implants.clear()
