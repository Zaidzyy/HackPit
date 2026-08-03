"""Engagement-mode registry — the DELIBERATE, explicit switch into real-target mode.

Real-target ("engagement") mode removes the isolation floor: the cockpit execs against a
human-named REAL target through the fully-open sandbox. Because that is the highest-risk path,
entering it must be a conscious act, not something a bare exec can trip into. This module is
that gate's state:

* :func:`enter` records an engagement — the named ``target``, the operator's ``authorization``
  acknowledgement and the PROGRAM SCOPE (see ``scope.py``) — and returns an ``engagement_id``.
  Only an exec that references an ACTIVE engagement id runs in engagement mode; everything
  else is lab mode, unchanged.
* :func:`get_active` is what the executor consults on every exec — it returns the record ONLY
  while active, so an exited/unknown engagement fails closed (the executor refuses).
* :func:`exit_engagement` ends an engagement (no more engagement-mode runs against it).
* :func:`record_discoveries` is RECON-DRIVEN EXPANSION: hosts mined out of a run's output are
  validated against the scope; in-scope ones join the engagement's LIVE ALLOWED SET, out-of-
  scope ones are recorded read-only (surfaced, never auto-added). Adding a host never widens
  the scope — a discovery can only be added if the scope already covered it.

Records persist in the shared ``sessions.db`` (gitignored) so they survive a reload AND leave
an audit trail (who entered mode against what, with what scope, and when). This module holds
NO execution — it only answers "is this engagement explicitly, currently entered, and what may
it touch?".
"""

from __future__ import annotations

import ipaddress
import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone

from . import scope as scope_mod
from .models import EngagementRecord
from .runstore import DB_PATH  # same single-file SQLite store as the run records

_write_lock = threading.Lock()

# Recon-driven expansion caps (logged when hit, so a truncation is never silent).
MAX_ADDED_PER_RUN = 25       # in-scope hosts a single run may add to the live allowed set
MAX_SEEN_PER_RUN = 50        # out-of-scope hosts a single run may record read-only
MAX_DISCOVERED_TOTAL = 500   # hard ceiling on rows per engagement


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def init_db() -> None:
    """Create/upgrade the engagement tables if absent. Safe to call repeatedly.

    MIGRATION-SAFE: the scope columns are added to an existing engagement_mode table with
    ALTER TABLE, so a database written before the scope model still opens. A pre-scope record
    reads back with its ``target`` as its (single-host) scope — exactly the old behaviour.
    """
    with _write_lock, _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS engagement_mode (
                engagement_id TEXT PRIMARY KEY,
                target        TEXT NOT NULL,
                authorization TEXT NOT NULL,
                active        INTEGER NOT NULL,
                entered_at    TEXT NOT NULL,
                exited_at     TEXT,
                session_id    TEXT
            )
            """
        )
        have = {r["name"] for r in conn.execute("PRAGMA table_info(engagement_mode)")}
        if "scope_spec" not in have:
            conn.execute("ALTER TABLE engagement_mode ADD COLUMN scope_spec TEXT")
        if "scope_ips" not in have:
            conn.execute("ALTER TABLE engagement_mode ADD COLUMN scope_ips TEXT")
        # Recon-driven expansion: every host a run's output revealed, with the scope verdict
        # recorded at the moment it was seen. in_scope=1 rows form the LIVE ALLOWED SET.
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS engagement_discovered (
                engagement_id TEXT NOT NULL,
                host          TEXT NOT NULL,
                in_scope      INTEGER NOT NULL,
                first_seen    TEXT NOT NULL,
                run_id        TEXT,
                PRIMARY KEY (engagement_id, host)
            )
            """
        )


def _valid_target(target: str) -> str:
    """Normalise + sanity-check the named target. Not a security control (the target-lock +
    Wall A are), just a guard against an empty/obviously-broken target so mode entry is honest.
    """
    t = (target or "").strip()
    if not t or any(ch.isspace() for ch in t):
        raise ValueError("target must be a single non-empty host or URL (no spaces)")
    return t


def enter(
    target: str,
    authorization: str,
    session_id: str | None = None,
    scope_spec: str | None = None,
) -> EngagementRecord:
    """Explicitly enter engagement mode against ``target`` + its scope; return the record.

    Requires a non-empty ``authorization`` acknowledgement — this is the deliberate, warned
    action of leaving the isolated lab. ``scope_spec`` is the PROGRAM SCOPE (hosts, wildcards,
    CIDRs, !exclusions — see ``scope.py``); when omitted it defaults to the single named
    target, i.e. exactly the pre-scope behaviour. The scope is parsed + resolved HERE and
    fails closed (ValueError) if it is empty, malformed or wholly unresolvable — so an
    engagement can never be entered with a scope that means nothing.
    """
    t = _valid_target(target)
    auth = (authorization or "").strip()
    if not auth:
        raise ValueError(
            "authorization acknowledgement is required to enter engagement mode — you are "
            "responsible for authorization and staying in scope"
        )
    spec = (scope_spec or "").strip() or t
    resolved = scope_mod.parse_scope(spec)  # fail-closed; resolves exact-host includes
    if not resolved.in_scope(t):
        raise ValueError(
            f"the named target '{t}' is not inside the scope '{spec}' — add it to the scope "
            "(a target outside its own scope could never be run)"
        )
    engagement_id = "eng-" + uuid.uuid4().hex[:12]
    entered_at = _now()
    with _write_lock, _connect() as conn:
        conn.execute(
            "INSERT INTO engagement_mode "
            "(engagement_id, target, authorization, active, entered_at, exited_at, session_id, "
            " scope_spec, scope_ips) "
            "VALUES (?, ?, ?, 1, ?, NULL, ?, ?, ?)",
            (
                engagement_id, t, auth, entered_at, session_id,
                resolved.raw, json.dumps(list(resolved.seed_ips)),
            ),
        )
    return EngagementRecord(
        engagement_id=engagement_id,
        target=t,
        authorization=auth,
        active=True,
        entered_at=entered_at,
        exited_at=None,
        session_id=session_id,
        scope=resolved.raw,
        scope_include=resolved.includes(),
        scope_exclude=resolved.excludes(),
        scope_ips=list(resolved.seed_ips),
        allowed_hosts=list(resolved.seed_hosts),
    )


def add_pivot_subnet(engagement_id: str, cidr: str) -> EngagementRecord:
    """DELIBERATELY widen an active engagement's scope to include a pivot subnet.

    This is the ONE path that widens scope, and it is a distinct, explicit, audited human action
    — NOT recon-driven expansion (which still can only add hosts the scope already covered). When
    a pivot reaches an internal network the operator is authorized for (an OSCP/PNPT internal
    segment), they declare it here by hand; a command routed to that subnet then passes the scope
    gate like any other in-scope target. The CIDR is validated and appended to ``scope_spec``.

    Fails closed: an unknown/inactive engagement or a malformed CIDR raises, and nothing changes.
    """
    net = ipaddress.ip_network(str(cidr).strip(), strict=False)  # raises on a bad CIDR
    rec = get_active(engagement_id)
    if rec is None:
        raise ValueError(f"engagement {engagement_id!r} is not active — cannot amend its scope")
    existing = (rec.scope or rec.target).strip()
    # Idempotent: if the exact CIDR is already a scope token, do not append it twice.
    tokens = [t.strip() for t in existing.replace("\n", ",").split(",") if t.strip()]
    if str(net) in tokens:
        return rec
    new_spec = existing + ", " + str(net)
    resolved = scope_mod.parse_scope(new_spec, resolve=False)
    with _write_lock, _connect() as conn:
        conn.execute(
            "UPDATE engagement_mode SET scope_spec = ? WHERE engagement_id = ? AND active = 1",
            (resolved.raw, engagement_id),
        )
    amended = get_active(engagement_id)
    assert amended is not None  # it was active a moment ago and we only touched scope_spec
    return amended


def get_active(engagement_id: str) -> EngagementRecord | None:
    """The engagement record ONLY while it is active (else None — fail closed)."""
    if not engagement_id:
        return None
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM engagement_mode WHERE engagement_id = ? AND active = 1",
            (engagement_id,),
        ).fetchone()
    return _row(row) if row else None


def exit_engagement(engagement_id: str) -> bool:
    """End an engagement — no further engagement-mode runs against it. True if one was active."""
    with _write_lock, _connect() as conn:
        cur = conn.execute(
            "UPDATE engagement_mode SET active = 0, exited_at = ? "
            "WHERE engagement_id = ? AND active = 1",
            (_now(), engagement_id),
        )
        return cur.rowcount > 0


def list_active() -> list[EngagementRecord]:
    """All currently-active engagements (for the status endpoint / UI mode indicator)."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM engagement_mode WHERE active = 1 ORDER BY entered_at DESC"
        ).fetchall()
    return [_row(r) for r in rows]


def session_ids() -> dict[str, str]:
    """engagement_id -> session_id, for EVERY engagement, active or exited.

    Deliberately not filtered to the active ones. An out-of-band callback is the case this
    exists for: a blind SSRF routed through a queue can land ten minutes — or a day — after
    the test that caused it, by which point the engagement it belongs to has very often been
    exited. Filtering here would file those hits nowhere and report them as unattributable,
    which is precisely the evidence the canary was built to stop losing.

    Engagements with no session attached are omitted rather than mapped to an empty id: there
    is nowhere to file their findings, and the caller reports that as its own outcome.
    """
    try:
        with _connect() as conn:
            rows = conn.execute(
                "SELECT engagement_id, session_id FROM engagement_mode WHERE session_id IS NOT NULL"
            ).fetchall()
    except sqlite3.OperationalError:  # table not created yet — no engagements, no mapping
        return {}
    return {r["engagement_id"]: r["session_id"] for r in rows if r["session_id"]}


def _col(row: sqlite3.Row, name: str) -> str | None:
    """A column that may not exist on a pre-migration row (migration-safe reads)."""
    try:
        return row[name]
    except (IndexError, KeyError):
        return None


def _row(row: sqlite3.Row) -> EngagementRecord:
    """Hydrate a record, including its resolved scope + live allowed/discovered sets.

    A pre-scope row (no scope_spec) reads back as a single-host scope on its target — the
    old behaviour, unchanged. A scope that somehow fails to re-parse degrades the same way
    (fail-closed to the named target only), never to "everything".
    """
    target = row["target"]
    spec = (_col(row, "scope_spec") or "").strip() or target
    try:
        ips = tuple(json.loads(_col(row, "scope_ips") or "[]"))
    except (ValueError, TypeError):
        ips = ()
    try:
        parsed = scope_mod.parse_scope(spec, resolve=False)
    except ValueError:
        parsed = scope_mod.parse_scope(scope_mod.bare_host(target) or target, resolve=False)
    in_scope, out_scope = _discovered(row["engagement_id"])
    seeds = [h for h in parsed.seed_hosts]
    return EngagementRecord(
        engagement_id=row["engagement_id"],
        target=target,
        authorization=row["authorization"],
        active=bool(row["active"]),
        entered_at=row["entered_at"],
        exited_at=row["exited_at"],
        session_id=row["session_id"],
        scope=parsed.raw,
        scope_include=parsed.includes(),
        scope_exclude=parsed.excludes(),
        scope_ips=[str(i) for i in ips],
        allowed_hosts=seeds + [h for h in in_scope if h not in seeds],
        discovered_in_scope=in_scope,
        discovered_out_of_scope=out_scope,
    )


def resolved_scope(record: EngagementRecord) -> scope_mod.ResolvedScope:
    """The engagement's scope as a live matcher (no DNS — the seed IPs were resolved at entry).

    Fails closed: an unparseable stored scope degrades to the named target alone, never to a
    wider one.
    """
    try:
        parsed = scope_mod.parse_scope(record.scope or record.target, resolve=False)
    except ValueError:  # pragma: no cover - defensive; enter() already validated
        parsed = scope_mod.parse_scope(
            scope_mod.bare_host(record.target) or record.target, resolve=False
        )
    return scope_mod.ResolvedScope(
        raw=parsed.raw,
        include=parsed.include,
        exclude=parsed.exclude,
        seed_hosts=parsed.seed_hosts,
        seed_ips=tuple(record.scope_ips),
    )


def _discovered(engagement_id: str) -> tuple[list[str], list[str]]:
    """(in-scope, out-of-scope) hosts recon has revealed for this engagement, oldest first."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT host, in_scope FROM engagement_discovered WHERE engagement_id = ? "
            "ORDER BY first_seen, host",
            (engagement_id,),
        ).fetchall()
    return (
        [r["host"] for r in rows if r["in_scope"]],
        [r["host"] for r in rows if not r["in_scope"]],
    )


def record_discoveries(
    record: EngagementRecord, output: str, run_id: str | None = None
) -> dict[str, list[str] | bool]:
    """RECON-DRIVEN EXPANSION — mine ``output`` for hosts and sort them by the scope.

    In-scope hosts are added to the engagement's LIVE ALLOWED SET (so the proposer can pivot
    to them and the argv target-lock names them); out-of-scope hosts are recorded read-only
    and surfaced, NEVER added. This can only ever add something the scope ALREADY covered —
    it does not widen the scope, and it does not approve anything: every command that touches
    a newly-discovered host still needs its own individual human approval.

    Returns ``{"added": [...], "out_of_scope": [...], "truncated": bool}`` (only hosts seen
    for the FIRST time appear). Never raises — expansion must not break a run.
    """
    added: list[str] = []
    seen_out: list[str] = []
    truncated = False
    try:
        matcher = resolved_scope(record)
        known_in, known_out = _discovered(record.engagement_id)
        known = set(known_in) | set(known_out) | {h.lower() for h in matcher.seed_hosts}
        known.add(scope_mod.bare_host(record.target).lower())
        total = len(known_in) + len(known_out)
        for host in scope_mod.extract_hosts(output or ""):
            if host in known:
                continue
            if total >= MAX_DISCOVERED_TOTAL:
                truncated = True
                break
            if matcher.in_scope(host):
                if len(added) >= MAX_ADDED_PER_RUN:
                    truncated = True
                    continue
                added.append(host)
            else:
                if len(seen_out) >= MAX_SEEN_PER_RUN:
                    truncated = True
                    continue
                seen_out.append(host)
            known.add(host)
            total += 1
        if added or seen_out:
            now = _now()
            rows = [(record.engagement_id, h, 1, now, run_id) for h in added]
            rows += [(record.engagement_id, h, 0, now, run_id) for h in seen_out]
            with _write_lock, _connect() as conn:
                conn.executemany(
                    "INSERT OR IGNORE INTO engagement_discovered "
                    "(engagement_id, host, in_scope, first_seen, run_id) VALUES (?, ?, ?, ?, ?)",
                    rows,
                )
    except Exception:  # pragma: no cover - expansion is best-effort, never load-bearing
        return {"added": added, "out_of_scope": seen_out, "truncated": truncated}
    return {"added": added, "out_of_scope": seen_out, "truncated": truncated}
