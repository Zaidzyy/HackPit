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
from .kali import KaliRefused, KaliRequest, KaliResult, run_kali
from .models import AllowlistItem, AllowlistResponse, ExecRequest, RunRecord
from .sandbox import SandboxError, assert_isolation_proven, is_sandbox_up

router = APIRouter(prefix="/cockpit", tags=["cockpit"])


@router.get("/allowlist", response_model=AllowlistResponse)
def get_allowlist() -> AllowlistResponse:
    """The safe command set + the fixed lab target the UI may point at."""
    return AllowlistResponse(
        commands=[
            AllowlistItem(
                name=spec.name,
                description=spec.description,
                allowed_flags=sorted(spec.allowed_flags),
            )
            for spec in allowlist.ALLOWLIST.values()
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


@router.post("/kali", response_model=KaliResult)
def kali_shell(request: KaliRequest) -> KaliResult:
    """:kali — HUMAN-ONLY interactive shell into the isolated sandbox.

    Runs ONE arbitrary command as ``docker exec <SANDBOX_CONTAINER> sh -c "<command>"``.
    The container is a code constant (config.SANDBOX_CONTAINER) — there is NO field in
    the request that can redirect it elsewhere. Isolation is re-checked first; if the
    sandbox is not provably isolated, a 409 is returned and nothing runs.

    SECURITY: this endpoint has NO auth and is a LOCALHOST DEV TOOL. Arbitrary shell is
    safe here only because the sandbox is egress-less + hardened + disposable and target
    is hardcoded (see cockpit/kali.py). It is human-driven ONLY — the autonomous
    orchestrator has no path to it. If this app is ever exposed/deployed, this route MUST
    be put behind authentication first.
    """
    try:
        return run_kali(request)
    except KaliRefused as exc:
        # Isolation gate refused — nothing was executed.
        raise HTTPException(status_code=409, detail={"gate": "sandbox", "reason": str(exc)})


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
