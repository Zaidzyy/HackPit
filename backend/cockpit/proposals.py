"""The approval queue — where a proposed command waits for a human. EXECUTES NOTHING.

This is the ONE write-shaped thing the MCP server can reach (build #19 item 6), and its entire
job is to be a piece of paper. An agent puts a command on it; a human reads it in the cockpit and
decides. Nothing in this module spawns a process, and a test asserts that by walking the AST.

*** WHY APPROVING A PROPOSAL DOES NOT RUN IT, AND MUST NOT. ***
The obvious next feature is "approve and run". It is deliberately absent. HackPit's execution
routes take ``approved`` and ``dangerous_ack`` IN THE REQUEST BODY, and the gate reads them from
there — so if approving a queue entry were wired to execution, this module would become a second
place that can set an approval field, reachable by anything that can reach the queue. The whole
point of item 6's line is that there is exactly one place approval is expressed: the human's own
request to the execution route.

So :func:`approve` marks a row *reviewed*, and that is all it does. To run the command the
operator sends it to `/cockpit/exec` like any other command, with the gate fields they set
themselves. The queue's value is that the agent's reasoning arrives WITH the command — the
rationale, what it expects to learn, which finding it follows from — rather than as a chat
message the operator has to transcribe.

STATE ONLY, LIKE `backend/state/`. Upsert, read, executes nothing.
"""

from __future__ import annotations

import threading
import uuid
from datetime import datetime, timezone

from pydantic import BaseModel, Field

#: How many proposals to keep. Oldest fall off — this is a working queue, not an audit log; the
#: audit log is the run store, and a command that actually ran is recorded there.
MAX_PROPOSALS = 500

#: A proposal's lifecycle. `pending` -> `approved` | `rejected`, and NOTHING ELSE. There is
#: deliberately no `executed` state: this module cannot observe execution, and a status field
#: that lies about whether something ran is worse than one that never claims to know.
STATUSES = ("pending", "approved", "rejected")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Proposal(BaseModel):
    """One proposed command awaiting a human.

    *** THERE ARE NO ``approved`` / ``dangerous_ack`` BOOLEANS ON THIS MODEL, ON PURPOSE. ***
    `status` is a reviewed-state, not a gate field. If this object carried the gate's own field
    names, the next person to wire it into an ExecRequest would do so by copying them across —
    and the agent would have written the value. The names are different because the concepts are
    different, and keeping them different is what stops the copy.
    """

    id: str
    command: str = Field(..., description="The binary. One command, never a pipeline.")
    args: list[str] = Field(default_factory=list)
    rationale: str = Field("", description="WHY. The reason this is worth a human's attention.")
    expected: str = Field("", description="What the proposer expects to learn from the output.")
    source: str = Field("mcp", description="Who proposed it — 'mcp', 'operator', 'orchestrator'.")
    session_id: str | None = None
    engagement_id: str | None = None
    status: str = "pending"
    created_at: str = ""
    reviewed_at: str = ""
    reviewer_note: str = ""

    def command_line(self) -> str:
        """For display. NOT for execution — nothing here builds an argv anyone runs."""
        return " ".join([self.command, *self.args])


_queue: dict[str, Proposal] = {}
_lock = threading.Lock()


def propose(command: str, args: list[str] | None = None, *, rationale: str = "",
            expected: str = "", source: str = "mcp", session_id: str | None = None,
            engagement_id: str | None = None) -> Proposal:
    """Put a command on the queue. RUNS NOTHING; there is no path from here to a subprocess.

    NOTHING IS REFUSED HERE. Not an unknown binary, not an off-scope target, not a dangerous
    shape. Two reasons, and both matter:

    * The gates that judge a command already exist and run at EXECUTION. Re-deciding here would
      be a second, weaker copy of them — and a proposal refused by a lesser gate teaches the
      proposer to phrase things differently rather than to propose better.
    * A proposal the gates WOULD refuse is exactly what a human should see. Filtering it out
      hides the disagreement; showing it, with the verdict beside it, is the useful version.
    """
    p = Proposal(
        id=uuid.uuid4().hex[:12], command=(command or "").strip(),
        args=[str(a) for a in (args or [])],
        rationale=rationale, expected=expected, source=source,
        session_id=session_id, engagement_id=engagement_id,
        status="pending", created_at=_now(),
    )
    with _lock:
        _queue[p.id] = p
        while len(_queue) > MAX_PROPOSALS:
            _queue.pop(next(iter(_queue)))
    return p


def gate_preview(p: Proposal) -> dict:
    """What the four gates WOULD say about this proposal, so the human sees it beside the ask.

    *** IT ASKS WITH ``approved=False`` AND ``dangerous_ack=False``, ALWAYS. ***
    That is not a placeholder to be filled in later — it is the point. A preview run with the
    flags set would answer "this would be allowed", which is a question nobody asked and an
    answer that reads as permission. Asking with both false yields the FIRST gate that stands in
    the way, which is the useful thing to show: "this needs a red-confirm" or "this target is out
    of scope".
    """
    from . import executor
    from .models import ExecRequest

    verdict = executor.validate_request(ExecRequest(
        command=p.command, args=p.args, approved=False, dangerous_ack=False,
        engagement_id=p.engagement_id,
    ))
    if verdict is None:
        return {"would_refuse": False, "gate": "", "reason": "", "dangerous_flags": []}
    return {
        "would_refuse": True, "gate": verdict.gate, "reason": verdict.reason,
        "dangerous_flags": list(verdict.dangerous_flags or []),
    }


def get(pid: str) -> Proposal | None:
    with _lock:
        return _queue.get(pid)


def listing(session_id: str | None = None, status: str = "") -> list[Proposal]:
    with _lock:
        rows = list(_queue.values())
    if session_id:
        rows = [r for r in rows if r.session_id == session_id]
    if status:
        rows = [r for r in rows if r.status == status]
    return sorted(rows, key=lambda r: r.created_at, reverse=True)


def review(pid: str, status: str, note: str = "") -> Proposal | None:
    """Mark a proposal reviewed. THIS RUNS NOTHING — see the module docstring.

    An unknown status is coerced to 'rejected' rather than raising: the only way to get here is a
    human pressing a button, and a 500 on a typo helps nobody. What it will never do is coerce to
    'approved'.
    """
    with _lock:
        p = _queue.get(pid)
        if p is None:
            return None
        p.status = status if status in STATUSES else "rejected"
        p.reviewed_at = _now()
        p.reviewer_note = note
        return p


def clear() -> int:
    with _lock:
        n = len(_queue)
        _queue.clear()
        return n
