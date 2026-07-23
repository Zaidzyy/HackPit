"""FastAPI routes for the Cockpit — defined here, mounted into main.py in M1.3.

M1.1 status: the router exists and imports cleanly, but is intentionally NOT included
in the app yet (main.py has no `include_router(cockpit_router)` until M1.3). The read-
only ``/cockpit/allowlist`` endpoint is safe and real; the execution endpoints return
501 until M1.3 wires them on top of the proven-isolated sandbox.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from . import allowlist, config
from .models import AllowlistItem, AllowlistResponse, ExecRequest

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


@router.post("/exec")
def exec_command(request: ExecRequest):
    """Run ONE approved allowlisted command against the lab. Wired in M1.3."""
    raise HTTPException(
        status_code=501,
        detail="cockpit execution is not enabled yet (wired in M1.3 after M1.2 proof)",
    )


@router.get("/exec/{run_id}/stream")
def stream_run(run_id: str):
    """SSE stream of a run's stdout/stderr/exit. Wired in M1.3/M1.4."""
    raise HTTPException(status_code=501, detail="run streaming is wired in M1.3/M1.4")
