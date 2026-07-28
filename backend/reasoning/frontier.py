"""2.3 — the candidate frontier: search over leads, don't guess greedily one step at a time.

A greedy proposer commits to the single best-looking next move and, when it dead-ends, loops.
The AD orchestrator already solved a narrow version of this — it derives the *frontier* of
abusable edges and picks over it. This generalizes that idea to a WHOLE-ENGAGEMENT frontier:
the proposer surfaces N candidate leads, each scored by (evidence strength × expected payoff),
the top one is pursued, and the REST are persisted so that when a line dead-ends the loop
recovers to the next-best untried lead instead of spinning.

INVARIANT 2, IN CAPITALS BECAUSE IT IS THE WHOLE POINT: the frontier is a set of UNTRIED LEADS,
never an execution queue. Nothing here runs a command, nothing here approves one, and there is
no "run them all" anything. A lead becomes a command only when the proposer surfaces it and a
human approves that single command through the already-gated executor. If this file ever grows a
way to fire a lead, that is the autonomous engine with extra steps — and test_frontier / the
source-scan lock exist to stop exactly that.

Persistence is the same ``sessions.db`` as everything else, scoped by ``session_id``.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .ledger import signature

DB_PATH = Path(__file__).resolve().parent.parent / "sessions.db"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def init_db() -> None:
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS reasoning_frontier (
                session_id  TEXT NOT NULL,
                signature   TEXT NOT NULL,
                hypothesis  TEXT NOT NULL DEFAULT '',
                command     TEXT NOT NULL DEFAULT '',
                args_json   TEXT NOT NULL DEFAULT '[]',
                evidence    REAL NOT NULL DEFAULT 0.5,
                payoff      REAL NOT NULL DEFAULT 0.5,
                score       REAL NOT NULL DEFAULT 0.25,
                status      TEXT NOT NULL DEFAULT 'open',   -- open | pursued | dead
                rationale   TEXT NOT NULL DEFAULT '',
                ts          TEXT NOT NULL,
                PRIMARY KEY (session_id, signature)
            )
            """
        )


def score_lead(evidence: float, payoff: float) -> float:
    """A lead's priority = how strong the evidence FOR it is × how much it would gain.

    Both inputs are clamped to [0, 1]; the product keeps a strong-evidence/low-payoff lead and a
    weak-evidence/high-payoff lead both mid-ranked, and only a lead that is BOTH well-supported
    and high-value floats to the top — which is the behaviour a search wants.
    """
    e = max(0.0, min(1.0, float(evidence)))
    p = max(0.0, min(1.0, float(payoff)))
    return round(e * p, 4)


@dataclass
class Lead:
    hypothesis: str = ""
    command: str = ""
    args: list[str] = field(default_factory=list)
    evidence: float = 0.5
    payoff: float = 0.5
    rationale: str = ""
    status: str = "open"
    signature: str = ""
    score: float = 0.0

    def scored(self) -> "Lead":
        self.score = score_lead(self.evidence, self.payoff)
        self.signature = signature(self.command, self.args)
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "hypothesis": self.hypothesis,
            "command": self.command,
            "args": list(self.args),
            "evidence": self.evidence,
            "payoff": self.payoff,
            "score": self.score,
            "status": self.status,
            "rationale": self.rationale,
            "signature": self.signature,
        }


def push(session_id: str, leads: Iterable[Lead]) -> int:
    """Persist candidate leads as OPEN, unless already present. Returns how many were newly added.

    Idempotent by signature: re-surfacing the same lead updates its score, it does not duplicate,
    and it never resurrects a lead already marked ``dead``.
    """
    if not session_id:
        return 0
    added = 0
    with _connect() as conn:
        for raw in leads:
            lead = raw.scored()
            if not lead.command.strip():
                continue
            existing = conn.execute(
                "SELECT status FROM reasoning_frontier WHERE session_id=? AND signature=?",
                (session_id, lead.signature),
            ).fetchone()
            if existing is not None and existing["status"] == "dead":
                continue
            if existing is None:
                added += 1
            conn.execute(
                """
                INSERT INTO reasoning_frontier
                    (session_id, signature, hypothesis, command, args_json, evidence, payoff,
                     score, status, rationale, ts)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(session_id, signature) DO UPDATE SET
                    evidence = excluded.evidence, payoff = excluded.payoff,
                    score = excluded.score, hypothesis = excluded.hypothesis,
                    rationale = excluded.rationale, ts = excluded.ts
                """,
                (
                    session_id, lead.signature, lead.hypothesis, lead.command,
                    json.dumps(lead.args), lead.evidence, lead.payoff, lead.score,
                    "open" if existing is None else existing["status"], lead.rationale, _now(),
                ),
            )
    return added


def _row_to_lead(r: sqlite3.Row) -> Lead:
    return Lead(
        hypothesis=r["hypothesis"], command=r["command"], args=json.loads(r["args_json"] or "[]"),
        evidence=r["evidence"], payoff=r["payoff"], rationale=r["rationale"],
        status=r["status"], signature=r["signature"], score=r["score"],
    )


def open_leads(session_id: str) -> list[Lead]:
    """Every untried lead, best score first. This is the search frontier."""
    if not session_id:
        return []
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM reasoning_frontier WHERE session_id=? AND status='open' "
            "ORDER BY score DESC, ts ASC",
            (session_id,),
        ).fetchall()
    return [_row_to_lead(r) for r in rows]


def top(session_id: str) -> Lead | None:
    leads = open_leads(session_id)
    return leads[0] if leads else None


def mark(session_id: str, command: str, args: Iterable[str], status: str) -> None:
    """Move a lead to ``pursued`` (it was proposed) or ``dead`` (it dead-ended). Never fires it."""
    if status not in ("open", "pursued", "dead") or not session_id:
        return
    with _connect() as conn:
        conn.execute(
            "UPDATE reasoning_frontier SET status=?, ts=? WHERE session_id=? AND signature=?",
            (status, _now(), session_id, signature(command, args)),
        )


def recover(session_id: str, avoid_signatures: Iterable[str] = ()) -> Lead | None:
    """Dead-end recovery: the best OPEN lead that is not one of ``avoid_signatures``.

    Called when the current line has dead-ended — instead of looping on the exhausted branch, the
    proposer pivots to the highest-scored untried lead the frontier is still holding. Returns a
    lead to PROPOSE (a human still approves it), never a command that runs.
    """
    skip = set(avoid_signatures or ())
    for lead in open_leads(session_id):
        if lead.signature not in skip:
            return lead
    return None


def clear(session_id: str) -> None:
    with _connect() as conn:
        conn.execute("DELETE FROM reasoning_frontier WHERE session_id=?", (session_id,))


_MAX_RENDERED = 8


def render(session_id: str) -> str:
    """The frontier block for the proposer prompt — the untried leads it may pivot to."""
    leads = open_leads(session_id)
    if not leads:
        return ""
    lines = [
        "",
        "CANDIDATE FRONTIER — untried leads kept from earlier turns, best first. These are NOT a "
        "queue and nothing here runs: if your current line is dead-ending, pivot to one of these "
        "instead of looping. Each still becomes one command the operator approves.",
    ]
    for lead in leads[:_MAX_RENDERED]:
        cmdline = " ".join([lead.command, *lead.args]).strip()
        lines.append(f"  (score {lead.score:.2f}) {lead.hypothesis[:80]} -> {cmdline[:100]}")
    return "\n".join(lines)
