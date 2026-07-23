"""Pydantic contracts for the Cockpit execution API.

Kept separate from main.py's models so the cockpit package is self-contained and
auditable. Field names/shape are the M1 sketch from docs/cockpit-plan.md §e and may
tighten in M1.3.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class ExecRequest(BaseModel):
    """A request to run ONE allowlisted command against the lab.

    ``approved`` MUST be explicitly true — there is no autonomous / approve-all path.
    """

    command: str = Field(..., description="Allowlisted command name, e.g. 'nmap'.")
    args: list[str] = Field(default_factory=list, description="Argv tokens (no shell).")
    approved: bool = Field(
        False, description="Per-command human approval. Execution refuses unless true."
    )
    session_id: str | None = Field(
        None, description="Optional engagement to attach the run-record to."
    )
    step_id: str | None = Field(
        None, description="Optional attack-path step id ({phase}-{n}) this run realizes."
    )


class ExecAccepted(BaseModel):
    """Returned when a command passed all gates and started running."""

    run_id: str
    command: str
    args: list[str]
    target: str
    started_at: str
    stream_url: str


class ExecRejected(BaseModel):
    """Returned (with 403) when a command fails a safety gate."""

    rejected: Literal[True] = True
    reason: str
    gate: Literal["allowlist", "target", "approval", "sandbox"] = "allowlist"


class RunRecord(BaseModel):
    """The final, persisted record of one command run."""

    run_id: str
    command: str
    args: list[str]
    target: str
    approved: bool
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    started_at: str
    finished_at: str | None = None
    session_id: str | None = None
    step_id: str | None = None


class AllowlistItem(BaseModel):
    """One entry in the safe command set, for the UI to render."""

    name: str
    description: str
    allowed_flags: list[str]


class AllowlistResponse(BaseModel):
    """The full safe command set + the (fixed) lab target the UI may point at."""

    commands: list[AllowlistItem]
    lab_target: str
