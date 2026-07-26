"""Backgrounded runs — a command that outlives the request that started it.

WHY THIS EXISTS
`/cockpit/exec` streams a run over SSE, which ties the process's lifetime to one HTTP
connection. That is right for a 20-second curl and wrong for everything real: a full TCP
sweep is 2-10 minutes, `-sU --top-ports 100` 5-20, ffuf on raft-medium 5-30, a full nuclei
run 10-60. Reload the page during one of those and you lose the output stream.

A background job detaches the process from the request. The caller gets a run_id
immediately; the command keeps running server-side with its output buffered, and any
number of clients can attach to `GET /cockpit/runs/{run_id}/stream` — which REPLAYS what
has already happened and then follows live. Reconnecting is therefore lossless, which is
the whole point.

WHAT THIS IS NOT
This is not autonomy and it does not touch a single gate. A backgrounded run is validated
and individually approved BEFORE it starts, exactly like a foreground one — `start()`
takes an already-gated iterator from the executor and does nothing but drain it. There is
no path here that begins a command; detaching changes when output is read, never whether
the command was allowed to run.

WHY NOT REUSE session.py
The live-session manager already has a process registry and a reaper, and a job looks a
lot like a session with no stdin. But sessions carry a HUMAN-ONLY stdin gate that is
source-scan locked, and threading a non-interactive path through that module would make
that gate harder to audit for no gain. Jobs are non-interactive by construction: there is
no stdin here at all.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Iterator

from . import config

# --------------------------------------------------------------------------- #
# state
# --------------------------------------------------------------------------- #


@dataclass
class Job:
    """One backgrounded run: its accumulated events and its liveness."""

    run_id: str
    events: list[dict[str, Any]] = field(default_factory=list)
    done: bool = False
    finished_at: float | None = None
    chars: int = 0
    truncated: bool = False
    # Signalled whenever an event is appended or the job finishes, so a follower wakes
    # immediately rather than polling on a timer.
    cond: threading.Condition = field(default_factory=threading.Condition)


_JOBS: dict[str, Job] = {}
_LOCK = threading.Lock()


def _reap_locked(now: float) -> None:
    """Drop finished jobs past the retention window. Caller holds _LOCK.

    The durable record is already in SQLite by the time a job finishes; this bounds only
    the in-memory replay buffer, so dropping it late costs a reconnecting client nothing
    but the live-tail convenience.
    """
    stale = [
        rid
        for rid, job in _JOBS.items()
        if job.done
        and job.finished_at is not None
        and now - job.finished_at > config.JOB_RETENTION_SECONDS
    ]
    for rid in stale:
        del _JOBS[rid]


# --------------------------------------------------------------------------- #
# starting
# --------------------------------------------------------------------------- #
def start(run_id: str, stream: Iterator[dict[str, Any]]) -> Job:
    """Drain an ALREADY-GATED event iterator on a background thread.

    ``stream`` must be the executor's ``iter_run`` output for a request that has already
    passed validation — this function performs no checks of its own and must never be
    handed a raw, unvalidated request. It is a consumer, not an entry point.
    """
    job = Job(run_id=run_id)
    with _LOCK:
        _reap_locked(time.time())
        _JOBS[run_id] = job

    def _drain() -> None:
        try:
            for event in stream:
                _append(job, event)
        except Exception as exc:  # a crashed drain must not leave a job hanging forever
            _append(job, {"type": "error", "reason": f"background run failed: {exc}"})
        finally:
            with job.cond:
                job.done = True
                job.finished_at = time.time()
                job.cond.notify_all()

    threading.Thread(target=_drain, name=f"job-{run_id}", daemon=True).start()
    return job


def _append(job: Job, event: dict[str, Any]) -> None:
    """Buffer one event, capping total buffered output.

    The cap protects the backend from a runaway producer (`yes`, a huge dump). Once hit,
    output lines are dropped but LIFECYCLE events still get through — a client must always
    learn that its job exited, even from a job that flooded.
    """
    with job.cond:
        if job.chars >= config.JOB_OUTPUT_CAP and event.get("type") in ("stdout", "stderr"):
            if not job.truncated:
                job.truncated = True
                job.events.append(
                    {"type": "stderr", "line": "…[output truncated: job buffer cap reached]…"}
                )
            job.cond.notify_all()
            return
        line = event.get("line")
        if isinstance(line, str):
            job.chars += len(line)
        job.events.append(event)
        job.cond.notify_all()


# --------------------------------------------------------------------------- #
# reading
# --------------------------------------------------------------------------- #
def get(run_id: str) -> Job | None:
    with _LOCK:
        return _JOBS.get(run_id)


def follow(run_id: str, poll_seconds: float = 1.0) -> Iterator[dict[str, Any]]:
    """Replay everything buffered for a job, then follow it live until it exits.

    This is what makes reconnecting lossless: a client that dropped mid-run gets the whole
    history before the live tail, so its transcript matches one that never disconnected.
    Yields a single ``error`` event for an unknown id — an expired or never-started job
    should read as an ordinary empty result, not an exception.
    """
    job = get(run_id)
    if job is None:
        yield {
            "type": "error",
            "reason": f"no background job {run_id} (unknown, or its buffer has expired — "
            "the run record itself is still at GET /cockpit/runs/{run_id})",
        }
        return

    sent = 0
    while True:
        with job.cond:
            while sent >= len(job.events) and not job.done:
                job.cond.wait(timeout=poll_seconds)
            pending = job.events[sent:]
            sent += len(pending)
            finished = job.done and sent >= len(job.events)
        for event in pending:
            yield event
        if finished:
            return


def status(run_id: str) -> dict[str, Any] | None:
    """Liveness for one job, without its output. None when unknown."""
    job = get(run_id)
    if job is None:
        return None
    with job.cond:
        return {
            "run_id": job.run_id,
            "running": not job.done,
            "events": len(job.events),
            "truncated": job.truncated,
        }


def active() -> list[dict[str, Any]]:
    """Every job still running — so the UI can show what is in flight."""
    with _LOCK:
        jobs = list(_JOBS.values())
    return [{"run_id": j.run_id, "events": len(j.events)} for j in jobs if not j.done]


def reset() -> None:
    """Drop all job state. Tests only — never called by the app."""
    with _LOCK:
        _JOBS.clear()
