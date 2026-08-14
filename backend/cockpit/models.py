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
    windows_profile_id: str | None = Field(
        None,
        description="When set to a saved Windows-target profile id, run in WINDOWS mode: the "
        "command is a PowerShell string executed ON that Windows box over WinRM (a new "
        "transport behind the SAME gates). The target is the profile's host — hardcoded by the "
        "profile, never a request field — so a run can never reach a box you did not pick. An "
        "unknown profile is refused (gate=windows). If an engagement_id is ALSO set, that "
        "engagement's scope must additionally permit the host (belt-and-suspenders).",
    )
    dangerous_ack: bool = Field(
        False,
        description="Explicit second confirmation for a command that carries dangerous "
        "flags (--os-shell, -e, --file-write…). When the command has any dangerous flag, "
        "execution refuses at the danger gate unless this is true — you can't approve a "
        "shell by accident. Ignored (no effect) when the command has no dangerous flag.",
    )
    scope_override: bool = Field(
        False,
        description="ENGAGEMENT MODE ONLY: explicit override to run a command whose target is "
        "OUTSIDE the declared program scope. The engagement target-lock is a HANDRAIL, not a wall "
        "(accepted policy: per-command human approval is the only bound) — so an off-scope target "
        "WARNS and refuses at the 'scope' gate unless this is true, exactly mirroring the "
        "dangerous-command red-confirm. Setting it asserts you are authorized for that host. No "
        "effect in lab / Windows mode (those locks stay hard) or when the target is in scope.",
    )
    session_id: str | None = Field(
        None, description="Optional engagement to attach the run-record to."
    )
    proxy: bool = Field(
        False,
        description="Route this run through the recording proxy so its requests and responses "
        "are captured (cockpit/proxy.py). Adds the tool's own proxy flag — an argument rewrite "
        "on an already-gated request, introducing no new capability and no new gate. The "
        "REWRITTEN argv is what the gates classify. A tool with no known proxy flag runs "
        "UNCHANGED and the response says so, rather than pretending it was captured.",
    )
    pace: int | None = Field(
        None,
        ge=1,
        le=10000,
        description="Throttle this run to roughly this many requests per second by adding "
        "the tool's OWN rate/delay flag (an argument rewrite on an already-gated request — "
        "no new capability, no new gate, and the REWRITTEN argv is what the gates classify). "
        "ENGAGEMENT MODE ONLY: lab runs and WinRM runs ignore it and say so. A tool with no "
        "known throttle flag, or one that already carries its own rate flag, runs UNCHANGED "
        "and the start event says so rather than pretending the run was paced. Not a safety "
        "control — a paced command is quieter, not safer, and every gate still applies.",
    )
    step_id: str | None = Field(
        None, description="Optional attack-path step id ({phase}-{n}) this run realizes."
    )
    timeout_seconds: int | None = Field(
        None,
        ge=1,
        description="How long this ONE command may run before it is killed. Omit for the "
        "180s default; values above the hard ceiling (3600s) are CLAMPED, not refused. Real "
        "work needs this — a full port sweep or nuclei run does not finish in 180s. This is "
        "not a safety control: every gate still applies regardless of the value.",
    )
    background: bool = Field(
        False,
        description="Run detached: the request returns a run_id immediately and the command "
        "keeps running server-side. Output buffers so it can be replayed from "
        "GET /cockpit/runs/{run_id}/stream, which survives a page reload or a dropped "
        "connection. Gates are identical — a backgrounded run is still individually approved "
        "BEFORE it starts, and nothing about detaching makes it hands-off.",
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
    # WINDOWS gates: windows (profile exists) -> target (host in engagement scope, if any)
    #   -> approval -> danger. No isolation gate (a real external box, like engagement).
    # (No wall_a gate — engagement mode is fully open; human-approve-each is the only bound.)
    gate: Literal["target", "approval", "danger", "sandbox", "engagement", "windows", "scope"] = "target"
    # When gate == "danger": the heuristic reasons the command was flagged (for the confirm).
    dangerous_flags: list[str] = Field(default_factory=list)


class RunRecord(BaseModel):
    """The final, persisted record of one command run."""

    run_id: str
    command: str
    args: list[str]
    target: str
    approved: bool
    # "lab" (isolated lab target), "engagement" (real authorized target, fully-open sandbox),
    # or "windows" (a PowerShell command run on a Windows target over WinRM). Drives how the
    # report marks the run (a real-target engagement / Windows box is called out as such).
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
    scope: str | None = Field(
        None,
        description="The authorized PROGRAM SCOPE: in-scope patterns separated by commas or "
        "spaces — '*' for everything, exact hosts, *.wildcards, CIDRs — plus !exclusions "
        "(e.g. '*' or 'example.com, *.example.com, 10.10.10.0/24, !admin.example.com'). "
        "'*' means every host is authorized: the target check passes everything, which is "
        "the same as having no scope at all — it must be typed deliberately and is recorded "
        "as 'scope: *'. A wildcard covers SUBdomains AND the apex. Omit to scope the "
        "engagement to the named target alone. Refused (422) if empty, malformed, wholly "
        "unresolvable, or if it does not contain the named target.",
    )
    session_id: str | None = Field(
        None, description="Optional engagement to attach runs + this mode record to."
    )


class EngagementRecord(BaseModel):
    """An entered engagement — the active-mode record the executor checks against.

    The scope fields are the resolved PROGRAM SCOPE (see cockpit/scope.py). They are
    MIGRATION-SAFE: a record written before the scope model reads back with its ``target`` as
    a single-host scope, which is exactly the old behaviour. ``allowed_hosts`` is the LIVE
    allowed set — the scope's exact hosts plus every in-scope host recon has since revealed.
    """

    engagement_id: str
    target: str
    authorization: str
    active: bool
    entered_at: str
    exited_at: str | None = None
    session_id: str | None = None
    # --- program scope (resolved at entry) ---
    scope: str = Field("", description="The scope spec exactly as the operator gave it.")
    scope_include: list[str] = Field(
        default_factory=list, description="IN-SCOPE patterns (hosts, *.wildcards, CIDRs)."
    )
    scope_exclude: list[str] = Field(
        default_factory=list, description="OUT-OF-SCOPE exclusions — these always win."
    )
    scope_ips: list[str] = Field(
        default_factory=list,
        description="Addresses the scope's exact hosts resolved to at entry (so an IP form "
        "of an in-scope host also passes the lock).",
    )
    # --- live sets (recon-driven expansion) ---
    allowed_hosts: list[str] = Field(
        default_factory=list,
        description="LIVE allowed set: the scope's exact hosts + every in-scope host recon "
        "has revealed. Every command against any of them still needs its own approval.",
    )
    discovered_in_scope: list[str] = Field(
        default_factory=list, description="Hosts recon revealed that the scope covers (added)."
    )
    discovered_out_of_scope: list[str] = Field(
        default_factory=list,
        description="Hosts recon revealed that the scope does NOT cover — surfaced read-only, "
        "never added and never targetable.",
    )
    # --- the WAF-bypass header (build #18 item 1) ---
    bypass_header_names: list[str] = Field(
        default_factory=list,
        description="NAMES of the WAF-bypass headers this engagement holds. The VALUES are "
        "credentials and are deliberately absent from this model — it is returned to the "
        "browser, joined into the LLM proposer context and rendered into reports. "
        "`engagement.bypass_headers()` is the one reader of the values, and its one caller "
        "puts them on ZAP's stdin rather than on any command line.",
    )


class AllowlistItem(BaseModel):
    """One entry in the safe command set, for the UI to render."""

    name: str
    description: str
    allowed_flags: list[str]


class AllowlistResponse(BaseModel):
    """The full safe command set + the (fixed) lab target the UI may point at."""

    commands: list[AllowlistItem]
    lab_target: str
