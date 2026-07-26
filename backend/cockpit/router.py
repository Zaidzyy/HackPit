"""FastAPI routes for the Cockpit — mounted into main.py (M1.3).

Endpoints:
* ``GET  /cockpit/allowlist``        — the safe command set + fixed lab target.
* ``GET  /cockpit/status``           — sandbox up? isolation ok? (for the UI banner)
* ``POST /cockpit/exec``             — run ONE approved allowlisted cmd; streams SSE.
                                       403 (no run) if any safety gate fails.
* ``POST /cockpit/kali``             — :kali human-only shell: run ONE arbitrary command
                                       inside the isolated sandbox. 409 (no run) if the
                                       sandbox is not provably isolated.
* ``GET  /cockpit/runs/{run_id}``    — the persisted run-record, or live status while a
                                       backgrounded run is still going.
* ``GET  /cockpit/runs/{id}/stream`` — attach to a backgrounded run: replay its buffered
                                       output, then follow it live. Reconnect-safe.
* ``GET  /cockpit/jobs``             — backgrounded runs still in flight.
* ``GET  /cockpit/loot``             — where run artefacts land on the host.

NOTE: tool reconciliation (which catalogued tools the sandbox actually has) is served from
``GET /tools`` in main.py, NOT from here. The cockpit package stays blind to the tool
catalog — the execution gates must never become catalog-aware — and the catalog in turn
never imports the execution layer. Both directions are enforced by a safety test that
matches on a PLAIN SUBSTRING, so do not name that package anywhere in this file.
"""

from __future__ import annotations

import itertools
import json
from typing import Any, Iterator

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from . import allowlist, config, engagement, executor, jobs, loot, runstore
from . import session as live_session
from . import kali as kali_mod
from . import repeater as repeater_mod
from . import tunnels as tunnels_mod
from .kali import KaliRefused, KaliRequest, KaliResult, kali_status, run_kali
from .models import (
    AllowlistItem,
    AllowlistResponse,
    EngagementEnterRequest,
    EngagementRecord,
    ExecRequest,
    RunRecord,
)
from .sandbox import (
    SandboxError,
    assert_isolation_proven,
    is_engage_sandbox_up,
    is_sandbox_up,
)

router = APIRouter(prefix="/cockpit", tags=["cockpit"])


@router.get("/allowlist", response_model=AllowlistResponse)
def get_allowlist() -> AllowlistResponse:
    """SUGGESTED commands (informational hints) + the fixed lab target.

    There is no longer an allowlist gate — ANY binary may run (isolation + human approval
    + the heuristic red-confirm are the safety). This list is just UI convenience; the
    empty ``allowed_flags`` reflects that nothing is flag-restricted.
    """
    return AllowlistResponse(
        commands=[
            AllowlistItem(name=name, description=desc, allowed_flags=[])
            for name, desc in allowlist.SUGGESTED_COMMANDS
        ],
        lab_target=config.LAB_TARGET_HOST,
    )


@router.get("/status")
def get_status() -> dict[str, Any]:
    """Whether the sandbox is up and isolated — drives the UI's readiness banner."""
    up = is_sandbox_up()
    isolated = False
    detail = ""
    if up:
        try:
            assert_isolation_proven()
            isolated = True
        except SandboxError as exc:
            detail = str(exc)
    else:
        detail = "sandbox container is not running"
    return {
        "sandbox": config.SANDBOX_CONTAINER,
        "lab_target": config.LAB_TARGET_HOST,
        "up": up,
        "isolated": isolated,
        "ready": up and isolated,
        "detail": detail,
    }


def _sse(event: dict[str, Any]) -> str:
    return f"data: {json.dumps(event)}\n\n"


@router.post("/exec")
def exec_command(request: ExecRequest):
    """Run ONE approved command — LAB mode (isolated lab) or, when ``engagement_id`` names an
    active engagement, REAL-TARGET engagement mode (fully-open sandbox, no isolation floor).

    The mode's gates run first (lab: target→approval→danger→isolation; engagement:
    engagement→target→approval→danger). If any fails, nothing runs and a 403 is returned
    naming the gate. Otherwise the run streams back as Server-Sent Events.
    """
    rejected = executor.validate_request(request)
    if rejected is not None:
        raise HTTPException(
            status_code=403,
            detail={"gate": rejected.gate, "reason": rejected.reason},
        )

    stream = executor.iter_run(request, prevalidated=True)

    if request.background:
        # Pull ONLY the first event to learn the run_id. iter_run yields `start` before it
        # spawns anything, so this costs nothing and launches nothing; the background
        # thread does the actual work. Gates already ran above — detaching a run never
        # skips one.
        first = next(stream, None)
        if first is None:  # pragma: no cover - iter_run always yields at least one event
            raise HTTPException(status_code=500, detail="run produced no events")
        if first.get("type") == "rejected":
            raise HTTPException(
                status_code=403,
                detail={"gate": first.get("gate", "target"), "reason": first.get("reason", "")},
            )
        run_id = first["run_id"]
        jobs.start(run_id, itertools.chain([first], stream))
        return JSONResponse(
            status_code=202,
            content={
                "run_id": run_id,
                "background": True,
                "command": first.get("command"),
                "args": first.get("args", []),
                "target": first.get("target"),
                "mode": first.get("mode"),
                "started_at": first.get("started_at"),
                "timeout_seconds": first.get("timeout_seconds"),
                "workdir": first.get("workdir"),
                "stream_url": f"/cockpit/runs/{run_id}/stream",
            },
        )

    def gen() -> Iterator[str]:
        for event in stream:
            yield _sse(event)

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# --- Engagement mode (REAL targets — no isolation floor; Wall A + human-approve-each) --- #


@router.get("/engagement")
def get_engagement() -> dict[str, Any]:
    """The active engagement (if any) + sandbox availability — drives the UI mode indicator.

    Read-only. The UI must ALWAYS show which mode is active; when an engagement is active it
    shows the named target + that the sandbox is FULLY OPEN (Wall A down — the only guard is
    human-approve-each). This never enters/exits mode.
    """
    active = engagement.list_active()
    up = is_engage_sandbox_up()
    return {
        "active": [e.model_dump() for e in active],
        "sandbox": config.ENGAGE_SANDBOX_CONTAINER,
        "up": up,
        # Fully open: readiness is just availability (there is no Wall A / isolation to verify).
        "open": True,
        "ready": up,
        "detail": "" if up else "engagement sandbox is not running",
    }


@router.post("/engagement/enter", response_model=EngagementRecord)
def enter_engagement(req: EngagementEnterRequest) -> EngagementRecord:
    """DELIBERATELY enter real-target engagement mode. This is the explicit, warned switch
    that LEAVES THE ISOLATED LAB.

    The engagement sandbox is FULLY OPEN (Wall A down): it reaches the internet, your LAN, and
    your own machine. You are responsible for authorization and for staying in scope, and human
    approval of every command is the ONLY guard. Engagement mode is never hands-off.

    ``scope`` is the authorized PROGRAM SCOPE (hosts, *.wildcards, CIDRs, !exclusions); it
    defaults to the named target alone. It is parsed + resolved here and FAILS CLOSED — 422 if
    it is empty, malformed, wholly unresolvable, or does not contain the named target. Returns
    the engagement id the exec path must reference to run against that scope. 422 too if the
    target/authorization is missing (both required — mode cannot be entered by accident).
    """
    try:
        return engagement.enter(req.target, req.authorization, req.session_id, req.scope)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post("/engagement/{engagement_id}/exit")
def exit_engagement(engagement_id: str) -> dict[str, Any]:
    """Leave engagement mode for this id — no further engagement-mode runs against it."""
    exited = engagement.exit_engagement(engagement_id)
    if not exited:
        raise HTTPException(status_code=404, detail="no active engagement with that id")
    return {"engagement_id": engagement_id, "exited": True}


@router.get("/kali/status")
def get_kali_status() -> dict[str, Any]:
    """Availability of the :kali OPEN sandbox — drives the UI banner (no isolation claim)."""
    return kali_status()


@router.post("/kali", response_model=KaliResult)
def kali_shell(request: KaliRequest) -> KaliResult:
    """:kali — HUMAN-ONLY interactive shell into the OPEN (full-network-reach) sandbox.

    Runs ONE arbitrary command as ``docker exec <KALI_OPEN_CONTAINER> sh -c "<command>"``.
    The container is a code constant (config.KALI_OPEN_CONTAINER) — there is NO field in
    the request that can redirect it elsewhere. This sandbox is intentionally NOT isolated
    (it reaches the internet + host + LAN), so there is NO isolation gate here; the only
    pre-check is availability (409 if the open container isn't running).

    SECURITY — now far more load-bearing: this endpoint has NO auth, is a LOCALHOST DEV
    TOOL, and the shell it drives reaches your HOST and LAN (not just a disposable lab).
    It is human-driven ONLY — the autonomous orchestrator/agent/executor has NO code path
    to run_kali (regression-locked). If this app is ever exposed/deployed, this route MUST
    be put behind authentication first — exposure is far worse than before.
    """
    try:
        return run_kali(request)
    except KaliRefused as exc:
        # Open sandbox unavailable (not running) — nothing was executed.
        raise HTTPException(status_code=409, detail={"gate": "unavailable", "reason": str(exc)})


# --- Persistent :kali shell (step 13 — cd/env/jobs persist across commands) --------- #
#
# SAME containment as POST /cockpit/kali: hardcoded open container, human-only, no isolation
# gate (there is none for the open box), every command audited. The difference is ONE
# long-lived `docker exec -i sh` instead of a fresh exec per command, so state carries
# across commands. Still a LOCALHOST DEV TOOL with no auth — see the warning on /kali.


@router.post("/kali/shell", response_model=kali_mod.KaliShellInfo)
def start_kali_shell(req: kali_mod.KaliShellStartRequest) -> kali_mod.KaliShellInfo:
    """Open a persistent :kali shell. 409 if the open sandbox isn't running."""
    try:
        return kali_mod.start_shell(req)
    except kali_mod.KaliShellRefused as exc:
        raise HTTPException(status_code=409, detail={"gate": "unavailable", "reason": str(exc)})


@router.post("/kali/shell/{sid}/run", response_model=kali_mod.KaliCommandResult)
def run_in_kali_shell(sid: str, req: kali_mod.KaliShellInputRequest) -> kali_mod.KaliCommandResult:
    """Run one command in a persistent shell — state persists to the next call. Human-typed."""
    try:
        return kali_mod.run_in_shell(sid, req)
    except kali_mod.KaliShellRefused as exc:
        raise HTTPException(status_code=409, detail={"gate": "unavailable", "reason": str(exc)})


@router.get("/kali/shell", response_model=list[kali_mod.KaliShellInfo])
def list_kali_shells() -> list[kali_mod.KaliShellInfo]:
    """Every live persistent :kali shell. Read-only."""
    return kali_mod.list_shells()


@router.delete("/kali/shell/{sid}", response_model=kali_mod.KaliShellInfo)
def close_kali_shell(sid: str) -> kali_mod.KaliShellInfo:
    """Close a persistent shell (EOF stdin, then kill)."""
    try:
        return kali_mod.close_shell(sid)
    except kali_mod.KaliShellRefused as exc:
        raise HTTPException(status_code=404, detail={"reason": str(exc)})


# --- HTTP repeater (Phase 4 item 3 — compose / send / replay / diff) ---------------- #
#
# SAME containment as :kali: hardcoded open container, HUMAN-ONLY (the orchestrator/agent has
# ZERO path to repeater_mod.send — source-scan locked, test_repeater_is_human_only), audited to
# the run store. Two differences from :kali: it is ARGV-ONLY curl (no shell parses any request
# field), and it SCOPE-CHECKS the URL host when the send names an active engagement (out-of-
# scope is refused, nothing sent). Still a LOCALHOST DEV TOOL with no auth — see /kali.


@router.get("/repeater/status")
def get_repeater_status() -> dict[str, Any]:
    """Availability of the repeater's (open) sandbox — drives the UI banner."""
    return repeater_mod.status()


@router.post("/repeater/send", response_model=repeater_mod.RepeaterExchange)
def repeater_send(req: repeater_mod.RepeaterRequest) -> repeater_mod.RepeaterExchange:
    """Send ONE composed HTTP request from inside the open sandbox; return the parsed exchange.

    HUMAN-ONLY — a request the operator composed and sent IS the approval, so there is no
    per-send gate prompt. 409 if the open sandbox is down; 403 if the URL host is out of scope
    for a named active engagement (nothing is sent in either case).
    """
    try:
        return repeater_mod.send(req)
    except repeater_mod.RepeaterRefused as exc:
        reason = str(exc)
        # Out-of-scope is a scope refusal (403); everything else is availability (409).
        code = 403 if "OUT OF SCOPE" in reason or "not active" in reason else 409
        gate = "scope" if code == 403 else "unavailable"
        raise HTTPException(status_code=code, detail={"gate": gate, "reason": reason})


@router.get("/repeater/history", response_model=list[repeater_mod.RepeaterExchange])
def repeater_history(
    session_id: str | None = Query(None, description="Engagement whose send history to return."),
) -> list[repeater_mod.RepeaterExchange]:
    """Most-recent-first send history for a session — feeds the replay / diff panel. Read-only."""
    return repeater_mod.history(session_id)


# --- Pivot / tunnel routing (Phase 4 item 4 — chisel / ligolo-ng) ------------------- #
#
# HUMAN-ONLY listener lifecycle, like :kali/repeater (start/stop are source-scan locked). The
# ROUTE + REWRITE helpers are pure (compute the proxychains-wrapped command the human approves —
# nothing runs). A tunnel's internal subnet enters engagement scope ONLY via the explicit
# amendment below, never automatically.


@router.get("/tunnels/status")
def get_tunnels_status() -> dict[str, Any]:
    """Availability of the tunnels' (engage) sandbox + live count — drives the UI banner."""
    return tunnels_mod.status()


@router.post("/tunnels", response_model=tunnels_mod.Tunnel)
def start_tunnel(req: tunnels_mod.TunnelStartRequest) -> tunnels_mod.Tunnel:
    """Start a pivot listener (chisel server / ligolo proxy) and return the agent one-liner.

    HUMAN-ONLY. 409 if the engage sandbox is down or the live-tunnel cap is hit (nothing runs).
    Delivering the returned one-liner to the compromised host is the operator's manual step —
    HackPit cannot reach a machine it has not compromised.
    """
    try:
        return tunnels_mod.start_tunnel(req)
    except tunnels_mod.TunnelRefused as exc:
        raise HTTPException(status_code=409, detail={"gate": "unavailable", "reason": str(exc)})


@router.get("/tunnels", response_model=list[tunnels_mod.Tunnel])
def list_tunnels() -> list[tunnels_mod.Tunnel]:
    """Every tunnel (starting/listening/down). Read-only."""
    return tunnels_mod.list_tunnels()


@router.delete("/tunnels/{tid}", response_model=tunnels_mod.Tunnel)
def stop_tunnel(tid: str) -> tunnels_mod.Tunnel:
    """Stop a listener (kill its process). HUMAN-ONLY."""
    try:
        return tunnels_mod.stop_tunnel(tid)
    except tunnels_mod.TunnelRefused as exc:
        raise HTTPException(status_code=404, detail={"reason": str(exc)})


class RouteRequest(BaseModel):
    """Ask which tunnel (if any) routes to a host, and get the rewritten command to approve."""

    command: str = Field(..., description="The command's first token, e.g. 'nmap'.")
    args: list[str] = Field(default_factory=list)
    host: str = Field(..., description="The target host/IP — routing is decided on its address.")


@router.post("/tunnels/route")
def route_command(req: RouteRequest) -> dict[str, Any]:
    """Resolve the tunnel for ``host`` and return the proxychains-wrapped command to APPROVE.

    Pure — nothing runs. If a live tunnel covers the host, the response carries the rewritten
    ``command``/``args`` (with the proxychains prefix VISIBLE) so the human approves the exact
    string that will execute; otherwise ``routed`` is false and the command is unchanged.
    """
    tunnel = tunnels_mod.route_for(req.host)
    if tunnel is None:
        return {"routed": False, "command": req.command, "args": req.args, "tunnel": None, "note": ""}
    cmd, args, note = tunnels_mod.wrap_command(req.command, req.args, tunnel)
    return {"routed": True, "command": cmd, "args": args, "tunnel": tunnel.model_dump(), "note": note}


class PivotSubnetRequest(BaseModel):
    """DELIBERATELY add a pivot subnet to an active engagement's scope (a human amendment)."""

    engagement_id: str = Field(..., min_length=1)
    cidr: str = Field(..., description="The internal CIDR the pivot reaches, e.g. 172.16.0.0/24.")


@router.post("/tunnels/scope", response_model=EngagementRecord)
def add_pivot_subnet(req: PivotSubnetRequest) -> EngagementRecord:
    """Widen an active engagement's scope to include a pivot subnet — an explicit human action.

    This is the ONLY path that widens scope, kept separate from recon expansion (which cannot).
    422 on a bad CIDR or an inactive engagement; nothing changes on failure.
    """
    try:
        return engagement.add_pivot_subnet(req.engagement_id, req.cidr)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail={"reason": str(exc)})


# --- Live sessions (catch + drive ONE shell by hand — see cockpit/session.py) ------ #
#
# Two gates, both load-bearing:
#   START is a GATED COMMAND      -> POST /cockpit/session/start goes through the real
#                                    executor gates (approve-each + heuristic red-confirm
#                                    + mode gate, argv-only). No new capability.
#   STDIN is *** HUMAN-ONLY ***   -> POST /cockpit/session/{sid}/stdin is the ONLY path to
#                                    a live process's stdin and exists to serve a HUMAN's
#                                    UI action. The orchestrator/agent/loop has ZERO path
#                                    here (source-scan locked, like :kali). The loop may
#                                    propose starting a session; it can never drive one.


@router.get("/session/status")
def get_session_status() -> dict[str, Any]:
    """Live-session counts + bounds — drives the panel header. Read-only."""
    return live_session.session_status()


@router.get("/session", response_model=list[live_session.SessionInfo])
def list_live_sessions() -> list[live_session.SessionInfo]:
    """Every session this backend knows about (live and finished). Read-only."""
    return live_session.list_sessions()


@router.post("/session/start", response_model=live_session.SessionInfo)
def start_session(req: live_session.SessionStartRequest) -> live_session.SessionInfo:
    """Start ONE long-lived session — a GATED command that happens to outlive the request.

    Runs the mode's real gates first (lab: target→approval→danger→isolation; engagement:
    engagement→target→approval→danger). A listener/handler trips the danger heuristic, so
    ``dangerous_ack`` is required in practice. If any gate fails, NOTHING starts and a 403
    is returned naming the gate. The sandbox is derived from the mode, never the request.
    """
    try:
        return live_session.start(req)
    except live_session.SessionRefused as exc:
        status = 409 if exc.gate in {"unavailable", "limit"} else 403
        raise HTTPException(status_code=status, detail={"gate": exc.gate, "reason": exc.reason})


@router.get("/session/{sid}/stream")
def stream_session(sid: str, after: int = Query(-1, description="Resume after this seq.")):
    """Stream a session's output as SSE. Read-only — subscribing never writes to it.

    ``after`` resumes from a sequence number, so a reconnect replays the rolling tail
    instead of losing it. The stream closes when the session finishes.
    """
    try:
        events = live_session.iter_events(sid, after=after)
    except live_session.SessionNotFound:
        raise HTTPException(status_code=404, detail="no such session")

    def gen() -> Iterator[str]:
        for event in events:
            yield _sse(event)

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.post("/session/{sid}/stdin", response_model=live_session.SessionInfo)
def write_session_stdin(sid: str, req: live_session.SessionStdinRequest):
    """*** HUMAN-ONLY *** — write one line to a live session's stdin.

    THIS ROUTE IS THE INVARIANT. It exists to serve a HUMAN typing into the session
    panel, and it is the only path to a running process's stdin. The autonomous
    orchestrator/agent/loop has NO code path to ``session.write_stdin`` — regression-
    locked by a source scan across the backend tree, exactly like :kali. A live session
    is already-approved and already-running, so anything able to type into it would be
    executing un-gated commands; that must never be reachable by the agent.

    SECURITY: like the rest of the cockpit this is a LOCALHOST DEV TOOL with no auth. An
    exposed instance would hand a stranger a live shell in whatever the session is bound
    to — put it behind authentication before any exposure.
    """
    try:
        return live_session.write_stdin(sid, req.data)
    except live_session.SessionNotFound:
        raise HTTPException(status_code=404, detail="no such session")
    except live_session.SessionRefused as exc:
        raise HTTPException(
            status_code=409, detail={"gate": exc.gate, "reason": exc.reason}
        )


@router.post("/session/{sid}/kill", response_model=live_session.SessionInfo)
def kill_session(sid: str) -> live_session.SessionInfo:
    """Terminate a live session and flush its transcript to the record. Idempotent."""
    try:
        return live_session.kill(sid)
    except live_session.SessionNotFound:
        raise HTTPException(status_code=404, detail="no such session")


@router.get("/runs", response_model=list[RunRecord])
def list_runs(session_id: str = Query(..., description="Engagement to list runs for.")):
    """Every recorded run attached to an engagement, in execution order.

    Read-only: this is how the cockpit surfaces a session's runs as recorded
    engagement steps (UI list + report input). No execution happens here.
    """
    return runstore.list_runs_for_session(session_id)


@router.get("/runs/{run_id}")
def get_run(run_id: str):
    """The final, persisted record of a run — or its live status while it is still going.

    A backgrounded run has no persisted record until it exits, so polling this endpoint
    used to 404 for the entire life of the job. It now reports the in-flight job instead,
    which is what a poller actually wants to know.
    """
    record = runstore.get_run(run_id)
    if record is not None:
        return record
    live = jobs.status(run_id)
    if live is not None:
        return {
            "run_id": run_id,
            "running": live["running"],
            "events": live["events"],
            "truncated": live["truncated"],
            "detail": "background run in progress — attach to "
            f"/cockpit/runs/{run_id}/stream for output",
        }
    raise HTTPException(status_code=404, detail="run not found")


@router.get("/runs/{run_id}/stream")
def stream_run(run_id: str):
    """Attach to a backgrounded run: replay what it has already produced, then follow live.

    Reconnect-safe by construction — every attach starts from the beginning of the job's
    buffer, so a client that dropped mid-run ends up with the same transcript as one that
    never disconnected. Attaching is read-only: it starts nothing and approves nothing.
    """

    def gen() -> Iterator[str]:
        for event in jobs.follow(run_id):
            yield _sse(event)

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/jobs")
def list_jobs() -> dict[str, Any]:
    """Backgrounded runs still in flight — so the UI can show what is going."""
    return {"jobs": jobs.active()}


@router.get("/loot")
def get_loot() -> dict[str, Any]:
    """Where run artefacts land on the host, and which sandboxes have a loot mount."""
    return loot.describe()
