"""2.1 — working memory: a tried / failed ledger. The single biggest anti-looping lever.

The old loop fed the model the tail of recent stdout and asked it to "adapt". It had no durable
memory of WHAT IT HAD ALREADY TRIED and how that turned out, so it re-proposed dead leads — the
signature failure of a shallow agent on a hard box.

This module gives the proposer that memory, in two parts:

* DERIVED, from what the loop already has. :func:`build` turns the session's runs (+ the
  operator's skip list) into a ledger of ``(command, outcome, detail)`` — outcome read from the
  exit code AND the output (a tool can exit 0 and still have failed). This is pure and needs no
  storage: the runs ARE the record.
* PERSISTED dead leads. :func:`record_dead` writes a lead the critic or the operator has ruled
  out to the same ``sessions.db``, so "we established this path is a dead end" survives even when
  no single run captures it. :func:`is_dead` / :func:`is_tried` answer "have we been here?".

:func:`render` turns the whole thing into the prompt block the proposer reads, headed with an
explicit instruction not to re-propose a dead lead. Nothing here executes anything.
"""

from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

DB_PATH = Path(__file__).resolve().parent.parent / "sessions.db"

# Output substrings that mean a run FAILED even if its exit code was 0. A ledger that trusts the
# exit code alone would file "connection refused" (curl exits 0 on some transports, sqlmap exits
# 0 having found nothing) as a success and let the model chase it again.
_FAILURE_MARKERS = (
    "connection refused",
    "could not resolve host",
    "name or service not known",
    "no route to host",
    "connection timed out",
    "timed out",
    "operation not permitted",
    "permission denied",
    "authentication failed",
    "login failed",
    "access denied",
    "command not found",
    "executable not found",
    "0 hosts up",
    "no data found",
    "unable to connect",
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def init_db() -> None:
    """Create the dead-leads table. Idempotent; safe on every startup."""
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS reasoning_dead_leads (
                session_id  TEXT NOT NULL,
                signature   TEXT NOT NULL,
                command     TEXT NOT NULL,
                args_json   TEXT NOT NULL DEFAULT '[]',
                why         TEXT NOT NULL DEFAULT '',
                source      TEXT NOT NULL DEFAULT '',
                ts          TEXT NOT NULL,
                PRIMARY KEY (session_id, signature)
            )
            """
        )


def signature(command: str, args: Iterable[str]) -> str:
    """A stable identity for a command+args, so re-orderings and value tweaks still count as the
    same lead. Lowercased command; args normalized (a target host/url kept, values collapsed).

    Deliberately loose: `sqlmap -u http://h/x?id=1 --batch` and `sqlmap --batch -u http://h/x?id=1`
    hash the same, because they ARE the same lead. Exact-match dedup would let a trivial re-order
    reopen a dead end.
    """
    cmd = (command or "").strip().lower()
    toks = sorted(_norm_tok(str(a)) for a in (args or []) if str(a).strip())
    return cmd + "|" + " ".join(toks)


def _norm_tok(tok: str) -> str:
    tok = tok.strip().lower()
    # collapse a query-string value so ?id=1 and ?id=999 are one lead, but keep the param name
    tok = re.sub(r"(=)[^=&/]+", r"\1", tok)
    return tok


@dataclass
class LedgerEntry:
    command: str
    args: list[str]
    outcome: str          # "success" | "failed" | "ran"
    detail: str = ""      # short why (the failure marker, or exit code)
    signature: str = ""


def classify_run(run: dict[str, Any]) -> tuple[str, str]:
    """Outcome for one recorded run: (outcome, detail). Pure — the same logic the test drives."""
    exit_code = run.get("exit_code")
    out = ((run.get("stdout") or "") + "\n" + (run.get("stderr") or "")).lower()
    marker = next((m for m in _FAILURE_MARKERS if m in out), "")
    if marker:
        return "failed", f"output: '{marker}'"
    if isinstance(exit_code, int) and exit_code != 0:
        return "failed", f"exit {exit_code}"
    if exit_code is None:
        return "ran", "no exit recorded"
    return "success", f"exit {exit_code}"


def build(runs: list[dict[str, Any]], avoid: Iterable[str] | None = None) -> list[LedgerEntry]:
    """The derived ledger: one entry per distinct command tried, plus operator skips as failed.

    De-duplicated by signature, most-recent outcome wins — if a command failed then later
    succeeded, it reads as success (and vice-versa), which is the true current state.
    """
    by_sig: dict[str, LedgerEntry] = {}
    for r in runs or []:
        command = str(r.get("command") or "").strip()
        if not command:
            continue
        args = [str(a) for a in (r.get("args") or [])]
        outcome, detail = classify_run(r)
        sig = signature(command, args)
        by_sig[sig] = LedgerEntry(command, args, outcome, detail, sig)
    for skipped in avoid or []:
        line = str(skipped).strip()
        if not line:
            continue
        parts = line.split()
        command, args = parts[0], parts[1:]
        sig = signature(command, args)
        # An operator skip is a human "no" — record it failed only if a real run hasn't since
        # succeeded on that exact signature.
        if by_sig.get(sig, LedgerEntry("", [], "")).outcome != "success":
            by_sig[sig] = LedgerEntry(command, args, "failed", "operator skipped this lead", sig)
    return list(by_sig.values())


# --------------------------------------------------------------------------- #
# persisted dead leads
# --------------------------------------------------------------------------- #
def record_dead(session_id: str, command: str, args: Iterable[str], why: str, source: str = "critic") -> None:
    """Persist a lead ruled out (by the critic, or the operator). Upsert on signature."""
    if not (session_id and (command or "").strip()):
        return
    args = [str(a) for a in (args or [])]
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO reasoning_dead_leads (session_id, signature, command, args_json, why, source, ts)
            VALUES (?,?,?,?,?,?,?)
            ON CONFLICT(session_id, signature) DO UPDATE SET
                why = excluded.why, source = excluded.source, ts = excluded.ts
            """,
            (session_id, signature(command, args), command, json.dumps(args), why or "", source, _now()),
        )


def dead_leads(session_id: str) -> list[LedgerEntry]:
    if not session_id:
        return []
    with _connect() as conn:
        rows = conn.execute(
            "SELECT command, args_json, why, signature FROM reasoning_dead_leads WHERE session_id=?",
            (session_id,),
        ).fetchall()
    return [
        LedgerEntry(r[0], json.loads(r[1] or "[]"), "failed", r[2], r[3]) for r in rows
    ]


def is_dead(session_id: str, command: str, args: Iterable[str]) -> bool:
    if not session_id:
        return False
    sig = signature(command, args)
    with _connect() as conn:
        row = conn.execute(
            "SELECT 1 FROM reasoning_dead_leads WHERE session_id=? AND signature=?",
            (session_id, sig),
        ).fetchone()
    return row is not None


def is_tried(runs: list[dict[str, Any]], command: str, args: Iterable[str],
             session_id: str = "") -> bool:
    """Has this exact lead already been tried (in the runs) or ruled dead (persisted)?"""
    sig = signature(command, args)
    if any(e.signature == sig for e in build(runs)):
        return True
    return bool(session_id) and is_dead(session_id, command, args)


def clear(session_id: str) -> None:
    with _connect() as conn:
        conn.execute("DELETE FROM reasoning_dead_leads WHERE session_id=?", (session_id,))


# --------------------------------------------------------------------------- #
# prompt rendering
# --------------------------------------------------------------------------- #
_MAX_LEDGER = 30


def render(runs: list[dict[str, Any]], avoid: Iterable[str] | None = None,
           session_id: str = "") -> str:
    """The ledger block for the proposer prompt. "" when nothing has been tried yet, so an empty
    session produces the prompt it produced before this module existed."""
    entries = build(runs, avoid)
    dead = dead_leads(session_id) if session_id else []
    if not entries and not dead:
        return ""
    lines = [
        "",
        "TRIED / FAILED LEDGER — your working memory. Do NOT re-propose a command that already "
        "FAILED or is marked a DEAD END; propose a different lead or a diagnostic instead.",
    ]
    for e in entries[:_MAX_LEDGER]:
        tag = {"success": "OK", "failed": "FAILED", "ran": "ran"}.get(e.outcome, e.outcome)
        cmdline = " ".join([e.command, *e.args]).strip()
        lines.append(f"  [{tag}] {cmdline[:160]}" + (f"  — {e.detail}" if e.detail else ""))
    for e in dead[:_MAX_LEDGER]:
        cmdline = " ".join([e.command, *e.args]).strip()
        lines.append(f"  [DEAD END] {cmdline[:160]}" + (f"  — {e.detail}" if e.detail else ""))
    return "\n".join(lines)
