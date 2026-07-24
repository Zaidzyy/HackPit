"""Pydantic contracts for the Cockpit execution API.

Kept separate from main.py's models so the cockpit package is self-contained and
auditable. Field names/shape are the M1 sketch from docs/cockpit-plan.md §e and may
tighten in M1.3.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class ExecRequest(BaseModel):
    """A request to run ONE command in the sandbox — LAB mode (default) or ENGAGEMENT mode.

    ``approved`` MUST be explicitly true — there is no autonomous / approve-all path, in
    EITHER mode. When ``engagement_id`` names an ACTIVE, explicitly-entered engagement the
    command runs against that real target through the fully-open engagement sandbox; otherwise
    it runs against the isolated lab, entirely unchanged.
    """

    command: str = Field(..., description="Command name, e.g. 'nmap'.")
    args: list[str] = Field(default_factory=list, description="Argv tokens (no shell).")
    approved: bool = Field(
        False, description="Per-command human approval. Execution refuses unless true."
    )
    engagement_id: str | None = Field(
        None,
        description="When set to an ACTIVE engagement id, run in REAL-TARGET engagement mode "
        "(fully-open sandbox, no isolation floor) against that engagement's named target. Omit "
        "(the default) for isolated LAB mode. An unknown/exited id is refused (gate=engagement) "
        "— engagement mode cannot be entered by a bare exec; it must be explicitly entered first.",
    )
    dangerous_ack: bool = Field(
        False,
        description="Explicit second confirmation for a command that carries dangerous "
        "flags (--os-shell, -e, --file-write…). When the command has any dangerous flag, "
        "execution refuses at the danger gate unless this is true — you can't approve a "
        "shell by accident. Ignored (no effect) when the command has no dangerous flag.",
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
    # LAB gates: target -> approval -> danger -> sandbox (isolation).
    # ENGAGEMENT gates: engagement (explicit entry) -> target -> approval -> danger.
    # (No wall_a gate — engagement mode is fully open; human-approve-each is the only bound.)
    gate: Literal["target", "approval", "danger", "sandbox", "engagement"] = "target"
    # When gate == "danger": the heuristic reasons the command was flagged (for the confirm).
    dangerous_flags: list[str] = Field(default_factory=list)


class RunRecord(BaseModel):
    """The final, persisted record of one command run."""

    run_id: str
    command: str
    args: list[str]
    target: str
    approved: bool
    # "lab" (isolated lab target) or "engagement" (real authorized target, fully-open sandbox).
    # Drives how the report marks the run (a real-target engagement is called out as such).
    mode: str = "lab"
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    started_at: str
    finished_at: str | None = None
    session_id: str | None = None
    step_id: str | None = None


class EngagementEnterRequest(BaseModel):
    """DELIBERATE entry into real-target engagement mode.

    Both fields are required — this is the explicit, warned action that leaves the isolated
    lab. ``target`` is the human-named real host/URL the sandbox will be locked to; the
    ``authorization`` acknowledgement is the operator asserting they own or are authorized
    to test it and will stay in scope. There is no default; a bare exec can never enter mode.
    """

    target: str = Field(..., min_length=1, description="The real authorized target (host or URL).")
    authorization: str = Field(
        ..., min_length=1,
        description="Operator's authorization acknowledgement — you are responsible for "
        "authorization and for staying in scope; every command is yours to approve.",
    )
    session_id: str | None = Field(
        None, description="Optional engagement to attach runs + this mode record to."
    )


class EngagementRecord(BaseModel):
    """An entered engagement — the active-mode record the executor checks against.

    ``target`` is the operator's named scope (a single host/URL or a CIDR). ``resolved_scope``
    is the concrete firewall allow-list computed from it at entry (resolved IPs for a host, or
    the CIDR) — the exact destinations the scope-lock permits and that assert_scope_locked
    verifies before every exec. ``scope_kind`` is 'host' or 'cidr'.
    """

    engagement_id: str
    target: str
    authorization: str
    active: bool
    entered_at: str
    exited_at: str | None = None
    session_id: str | None = None
    resolved_scope: list[str] = Field(default_factory=list)
    scope_kind: str | None = None


class AllowlistItem(BaseModel):
    """One entry in the safe command set, for the UI to render."""

    name: str
    description: str
    allowed_flags: list[str]


class AllowlistResponse(BaseModel):
    """The full safe command set + the (fixed) lab target the UI may point at."""

    commands: list[AllowlistItem]
    lab_target: str
