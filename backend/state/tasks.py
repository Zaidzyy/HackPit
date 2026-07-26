"""The Pentest Task Tree — a plan that updates as results arrive.

WHY THIS EXISTS
HackPit's attack path was generated ONCE, up front, and never updated by what actually
happened. Steps carried a boolean `checked` and a pasted blob. There was no re-planning, no
sub-task expansion when recon revealed something, and no way to mark a branch dead. The
orchestrator compensated by re-reading stdout tails.

This is PentestGPT's central idea, which HackPit listed as a source and did not take:

    "The tasks are in layered structure, i.e., 1, 1.1, 1.1.1 ... Each task is one operation
     in penetration testing; task 1.1 should be a sub-task of task 1. Each task has a
     completion status: to-do, completed, or not applicable."

HOW IT UPDATES — and why not the way PentestGPT does it
PentestGPT hands the model the whole tree and takes back a rewritten one. That is simple,
and one malformed or lazy response silently rewrites the entire engagement plan with no
diff to review.

Here the model returns OPERATIONS — add_subtask / mark_done / mark_na / add_root — which
this module validates against the stored tree and applies. The tree is the durable record;
the model can only mutate it in defined ways. That matches how HackPit already treats model
output everywhere else: the AD orchestrator picks an EDGE, it never authors a command.
Worst case for a bad response is that the tree does not advance.

VALIDATION IS THE POINT. Unknown ids, bad statuses, absurd depth, oversized batches and
duplicate titles are all rejected individually, and a rejected op never stops the others
from applying. Every rejection is returned so the UI can show what the model got wrong.
"""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

from .store import DB_PATH

STATUS_TODO = "todo"
STATUS_DONE = "done"
STATUS_NA = "n/a"
STATUSES = (STATUS_TODO, STATUS_DONE, STATUS_NA)

# Bounds. A task tree is a plan a human reads — one that is 12 deep or 500 wide is a
# runaway, not a plan, and letting the model grow one unbounded would cost prompt budget
# that the state summary needs.
MAX_DEPTH = 4
MAX_CHILDREN = 24
MAX_TASKS = 300
MAX_OPS_PER_TURN = 24
MAX_TITLE_CHARS = 160

_ID_RE = re.compile(r"^\d+(?:\.\d+)*$")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Task:
    session_id: str
    task_id: str          # dotted path: "1", "1.2", "1.2.3"
    title: str
    status: str = STATUS_TODO
    why: str = ""         # why it is n/a, or what completed it
    evidence_run_id: str | None = None
    created_at: str = ""
    updated_at: str = ""

    @property
    def depth(self) -> int:
        return self.task_id.count(".") + 1

    @property
    def parent_id(self) -> str | None:
        return self.task_id.rsplit(".", 1)[0] if "." in self.task_id else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id, "title": self.title, "status": self.status,
            "why": self.why, "evidence_run_id": self.evidence_run_id,
            "depth": self.depth, "parent_id": self.parent_id,
            "created_at": self.created_at, "updated_at": self.updated_at,
        }


@dataclass
class ApplyResult:
    """What a batch of operations actually did. Rejections are returned, never swallowed."""

    applied: list[str] = field(default_factory=list)
    rejected: list[dict[str, str]] = field(default_factory=list)

    def reject(self, op: Any, reason: str) -> None:
        self.rejected.append({"op": str(op)[:200], "reason": reason})

    def to_dict(self) -> dict[str, Any]:
        return {"applied": self.applied, "rejected": self.rejected}


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def init_db() -> None:
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS state_tasks (
                session_id      TEXT NOT NULL,
                task_id         TEXT NOT NULL,
                title           TEXT NOT NULL,
                status          TEXT NOT NULL DEFAULT 'todo',
                why             TEXT NOT NULL DEFAULT '',
                evidence_run_id TEXT,
                created_at      TEXT NOT NULL,
                updated_at      TEXT NOT NULL,
                PRIMARY KEY (session_id, task_id)
            )
            """
        )


def _sort_key(task_id: str) -> tuple[int, ...]:
    """Sort 1.10 AFTER 1.9 — string ordering would not."""
    try:
        return tuple(int(p) for p in task_id.split("."))
    except ValueError:
        return (10**9,)


def load(session_id: str) -> list[Task]:
    if not session_id:
        return []
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM state_tasks WHERE session_id=?", (session_id,)
        ).fetchall()
    tasks = [
        Task(
            session_id=r["session_id"], task_id=r["task_id"], title=r["title"],
            status=r["status"], why=r["why"], evidence_run_id=r["evidence_run_id"],
            created_at=r["created_at"], updated_at=r["updated_at"],
        )
        for r in rows
    ]
    tasks.sort(key=lambda t: _sort_key(t.task_id))
    return tasks


def _write(conn: sqlite3.Connection, task: Task) -> None:
    conn.execute(
        """
        INSERT INTO state_tasks
            (session_id, task_id, title, status, why, evidence_run_id, created_at, updated_at)
        VALUES (?,?,?,?,?,?,?,?)
        ON CONFLICT(session_id, task_id) DO UPDATE SET
            title = excluded.title,
            status = excluded.status,
            why = excluded.why,
            evidence_run_id = COALESCE(excluded.evidence_run_id, state_tasks.evidence_run_id),
            updated_at = excluded.updated_at
        """,
        (
            task.session_id, task.task_id, task.title[:MAX_TITLE_CHARS], task.status,
            task.why[:400], task.evidence_run_id, task.created_at or _now(), _now(),
        ),
    )


def seed(session_id: str, titles: Iterable[str]) -> list[Task]:
    """Create the initial top-level tasks from a generated plan. Idempotent per session:
    seeding a session that already has tasks does nothing, so a re-plot cannot wipe the
    progress recorded against the existing tree."""
    existing = load(session_id)
    if existing:
        return existing
    made: list[Task] = []
    with _connect() as conn:
        for i, title in enumerate(t for t in titles if (t or "").strip()):
            if i >= MAX_CHILDREN:
                break
            task = Task(
                session_id=session_id, task_id=str(i + 1), title=str(title).strip(),
                created_at=_now(), updated_at=_now(),
            )
            _write(conn, task)
            made.append(task)
    return made


def _next_child_id(existing: dict[str, Task], parent_id: str | None) -> str | None:
    prefix = f"{parent_id}." if parent_id else ""
    depth = (parent_id.count(".") + 2) if parent_id else 1
    siblings = [
        t.task_id for t in existing.values()
        if t.parent_id == parent_id and t.depth == depth
    ]
    if len(siblings) >= MAX_CHILDREN:
        return None
    used = set()
    for sid in siblings:
        try:
            used.add(int(sid.rsplit(".", 1)[-1]))
        except ValueError:
            continue
    n = 1
    while n in used:
        n += 1
    return f"{prefix}{n}"


def apply_ops(session_id: str, ops: Any) -> ApplyResult:
    """Validate and apply model-proposed operations. Never raises.

    Each op is a dict: ``{"op": "...", ...}``. Supported:
        add_root    {title}
        add_subtask {parent, title}
        mark_done   {id, evidence_run?}
        mark_na     {id, why?}
        retitle     {id, title}

    A rejected op is recorded and skipped; the rest still apply. That matters because a
    model that gets one id wrong should not lose the four correct observations alongside it.
    """
    result = ApplyResult()
    if not session_id or not isinstance(ops, list):
        if ops:
            result.reject(ops, "operations must be a list")
        return result
    if len(ops) > MAX_OPS_PER_TURN:
        result.reject("<batch>", f"too many operations ({len(ops)} > {MAX_OPS_PER_TURN})")
        ops = ops[:MAX_OPS_PER_TURN]

    existing = {t.task_id: t for t in load(session_id)}

    try:
        with _connect() as conn:
            for op in ops:
                if not isinstance(op, dict):
                    result.reject(op, "operation must be an object")
                    continue
                kind = str(op.get("op") or "").strip().lower()

                if kind in ("add_root", "add_subtask"):
                    title = str(op.get("title") or "").strip()
                    if not title:
                        result.reject(op, "title is required")
                        continue
                    if len(existing) >= MAX_TASKS:
                        result.reject(op, f"tree is full ({MAX_TASKS} tasks)")
                        continue
                    parent_id: str | None = None
                    if kind == "add_subtask":
                        parent_id = str(op.get("parent") or "").strip()
                        if not _ID_RE.match(parent_id or ""):
                            result.reject(op, f"malformed parent id {parent_id!r}")
                            continue
                        if parent_id not in existing:
                            result.reject(op, f"unknown parent {parent_id}")
                            continue
                        if existing[parent_id].depth >= MAX_DEPTH:
                            result.reject(op, f"max depth {MAX_DEPTH} reached at {parent_id}")
                            continue
                    # A model that re-proposes an identical sibling every turn would grow
                    # the tree forever; treat a duplicate title under one parent as a no-op.
                    if any(
                        t.parent_id == parent_id and t.title.lower() == title.lower()
                        for t in existing.values()
                    ):
                        result.reject(op, "a sibling with this title already exists")
                        continue
                    new_id = _next_child_id(existing, parent_id)
                    if new_id is None:
                        result.reject(op, f"parent {parent_id or 'root'} already has {MAX_CHILDREN} children")
                        continue
                    task = Task(
                        session_id=session_id, task_id=new_id, title=title[:MAX_TITLE_CHARS],
                        created_at=_now(), updated_at=_now(),
                    )
                    _write(conn, task)
                    existing[new_id] = task
                    result.applied.append(f"add {new_id}: {task.title}")
                    continue

                if kind in ("mark_done", "mark_na", "retitle"):
                    tid = str(op.get("id") or "").strip()
                    if not _ID_RE.match(tid):
                        result.reject(op, f"malformed task id {tid!r}")
                        continue
                    task = existing.get(tid)
                    if task is None:
                        result.reject(op, f"unknown task {tid}")
                        continue
                    if kind == "mark_done":
                        task.status = STATUS_DONE
                        run = op.get("evidence_run")
                        if isinstance(run, str) and run.strip():
                            task.evidence_run_id = run.strip()[:64]
                        why = str(op.get("why") or "").strip()
                        if why:
                            task.why = why
                    elif kind == "mark_na":
                        task.status = STATUS_NA
                        task.why = str(op.get("why") or "").strip() or task.why
                    else:
                        new_title = str(op.get("title") or "").strip()
                        if not new_title:
                            result.reject(op, "title is required")
                            continue
                        task.title = new_title[:MAX_TITLE_CHARS]
                    _write(conn, task)
                    result.applied.append(f"{kind} {tid}")
                    continue

                result.reject(op, f"unknown operation {kind!r}")
    except sqlite3.Error as exc:
        result.reject("<batch>", f"database error: {exc}")
    return result


def render(session_id: str, max_lines: int = 60) -> str:
    """The tree as prompt/UI text. "" when there is none, so a caller with no tree
    produces byte-for-byte the prompt it produced before this existed."""
    tasks = load(session_id)
    if not tasks:
        return ""
    mark = {STATUS_TODO: "[ ]", STATUS_DONE: "[x]", STATUS_NA: "[-]"}
    lines: list[str] = []
    for t in tasks[:max_lines]:
        indent = "  " * (t.depth - 1)
        suffix = f"  ({t.why})" if t.why and t.status != STATUS_TODO else ""
        lines.append(f"{indent}{mark.get(t.status, '[ ]')} {t.task_id} {t.title}{suffix}")
    if len(tasks) > max_lines:
        lines.append(f"  … {len(tasks) - max_lines} more")
    return "\n".join(lines)


def open_tasks(session_id: str) -> list[Task]:
    return [t for t in load(session_id) if t.status == STATUS_TODO]


def progress(session_id: str) -> dict[str, int]:
    tasks = load(session_id)
    return {
        "total": len(tasks),
        "todo": sum(1 for t in tasks if t.status == STATUS_TODO),
        "done": sum(1 for t in tasks if t.status == STATUS_DONE),
        "na": sum(1 for t in tasks if t.status == STATUS_NA),
    }


def clear(session_id: str) -> None:
    with _connect() as conn:
        conn.execute("DELETE FROM state_tasks WHERE session_id=?", (session_id,))
