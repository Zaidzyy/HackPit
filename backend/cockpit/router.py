"""FastAPI routes for the Cockpit — mounted into main.py (M1.3).

Endpoints:
* ``GET  /cockpit/allowlist``        — the safe command set + fixed lab target.
* ``GET  /cockpit/status``           — sandbox up? isolation ok? (for the UI banner)
* ``POST /cockpit/exec``             — run ONE approved allowlisted cmd; streams SSE.
                                       403 (no run) if any safety gate fails.
* ``POST /cockpit/kali``             — :kali human-only shell: run ONE arbitrary command
                                       inside the isolated sandbox. 409 (no run) if the
                                       sandbox is not provably isolated.
* ``GET  /cockpit/runs/{run_id}``    — the persisted run-record.
"""

from __future__ import annotations

import json
from typing import Any, Iterator

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse

from . import allowlist, config, executor, runstore
from .kali import KaliRefused, KaliRequest, KaliResult, kali_status, run_kali
from .models import AllowlistItem, AllowlistResponse, ExecRequest, RunRecord
from .sandbox import SandboxError, assert_isolation_proven, is_sandbox_up

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
    """Run ONE approved, allowlisted, target-locked command against the lab.

    All four safety gates run first. If any fails, nothing runs and a 403 is returned
    naming the gate. Otherwise the run streams back as Server-Sent Events.
    """
    rejected = executor.validate_request(request)
    if rejected is not None:
        raise HTTPException(
            status_code=403,
            detail={"gate": rejected.gate, "reason": rejected.reason},
        )

    def gen() -> Iterator[str]:
        for event in executor.iter_run(request, prevalidated=True):
            yield _sse(event)

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


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


@router.get("/runs", response_model=list[RunRecord])
def list_runs(session_id: str = Query(..., description="Engagement to list runs for.")):
    """Every recorded run attached to an engagement, in execution order.

    Read-only: this is how the cockpit surfaces a session's runs as recorded
    engagement steps (UI list + report input). No execution happens here.
    """
    return runstore.list_runs_for_session(session_id)


@router.get("/runs/{run_id}")
def get_run(run_id: str):
    """The final, persisted record of a run."""
    record = runstore.get_run(run_id)
    if record is None:
        raise HTTPException(status_code=404, detail="run not found")
    return record
