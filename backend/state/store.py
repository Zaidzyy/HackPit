"""Persistence for the engagement state — the same SQLite file everything else uses.

Shares ``backend/sessions.db`` with the run records, engagement-mode records and AD graphs,
so one engagement is one file and a backup is a copy. Gitignored: it holds real target data
and, deliberately, real captured credentials.

EVERY WRITE IS AN UPSERT. Re-running a scan must correct what is known, not duplicate it —
a second `nmap` over the same host updates ports and bumps `last_seen`, and a finding
re-detected by a later scan stays one row. That property is what makes it safe to ingest
the output of every run unconditionally, which is exactly what ingest.py does.

Nothing here executes anything or reaches the network.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .models import (
    Credential,
    Endpoint,
    Finding,
    Host,
    Service,
    StateSummary,
    severity_rank,
)

DB_PATH = Path(__file__).parent.parent / "sessions.db"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def init_db() -> None:
    """Create the state tables. Idempotent; safe to call on every startup."""
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS state_hosts (
                session_id    TEXT NOT NULL,
                address       TEXT NOT NULL,
                hostname      TEXT NOT NULL DEFAULT '',
                os            TEXT NOT NULL DEFAULT '',
                status        TEXT NOT NULL DEFAULT '',
                source_run_id TEXT,
                first_seen    TEXT NOT NULL,
                last_seen     TEXT NOT NULL,
                PRIMARY KEY (session_id, address)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS state_services (
                session_id    TEXT NOT NULL,
                address       TEXT NOT NULL,
                port          INTEGER NOT NULL,
                proto         TEXT NOT NULL DEFAULT 'tcp',
                name          TEXT NOT NULL DEFAULT '',
                product       TEXT NOT NULL DEFAULT '',
                version       TEXT NOT NULL DEFAULT '',
                state         TEXT NOT NULL DEFAULT 'open',
                banner        TEXT NOT NULL DEFAULT '',
                source_run_id TEXT,
                first_seen    TEXT NOT NULL,
                last_seen     TEXT NOT NULL,
                PRIMARY KEY (session_id, address, port, proto)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS state_endpoints (
                session_id    TEXT NOT NULL,
                url           TEXT NOT NULL,
                method        TEXT NOT NULL DEFAULT 'GET',
                status        INTEGER,
                title         TEXT NOT NULL DEFAULT '',
                length        INTEGER,
                tech          TEXT NOT NULL DEFAULT '',
                params        TEXT NOT NULL DEFAULT '[]',
                source_run_id TEXT,
                first_seen    TEXT NOT NULL,
                last_seen     TEXT NOT NULL,
                PRIMARY KEY (session_id, url, method)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS state_credentials (
                session_id    TEXT NOT NULL,
                kind          TEXT NOT NULL,
                principal     TEXT NOT NULL,
                domain        TEXT NOT NULL DEFAULT '',
                secret        TEXT NOT NULL DEFAULT '',
                validated     INTEGER,
                note          TEXT NOT NULL DEFAULT '',
                source_run_id TEXT,
                first_seen    TEXT NOT NULL,
                last_seen     TEXT NOT NULL,
                PRIMARY KEY (session_id, kind, principal, domain)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS state_findings (
                session_id    TEXT NOT NULL,
                fingerprint   TEXT NOT NULL,
                title         TEXT NOT NULL,
                severity      TEXT NOT NULL DEFAULT 'info',
                target        TEXT NOT NULL DEFAULT '',
                evidence      TEXT NOT NULL DEFAULT '',
                tool          TEXT NOT NULL DEFAULT '',
                reference     TEXT NOT NULL DEFAULT '',
                source_run_id TEXT,
                first_seen    TEXT NOT NULL,
                last_seen     TEXT NOT NULL,
                PRIMARY KEY (session_id, fingerprint)
            )
            """
        )
        # MIGRATION-SAFE: proof/local flags (Phase 4 item 5) added to an existing hosts table.
        have = {r[1] for r in conn.execute("PRAGMA table_info(state_hosts)")}
        if "local_txt" not in have:
            conn.execute("ALTER TABLE state_hosts ADD COLUMN local_txt TEXT NOT NULL DEFAULT ''")
        if "proof_txt" not in have:
            conn.execute("ALTER TABLE state_hosts ADD COLUMN proof_txt TEXT NOT NULL DEFAULT ''")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS ix_state_services_session "
            "ON state_services(session_id, address)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS ix_state_findings_session "
            "ON state_findings(session_id, severity)"
        )


# --------------------------------------------------------------------------- #
# writes — all upserts
# --------------------------------------------------------------------------- #
def upsert_hosts(items: Iterable[Host]) -> int:
    rows = [h for h in items if h.session_id and h.address.strip()]
    if not rows:
        return 0
    now = _now()
    with _connect() as conn:
        for h in rows:
            _, address = h.key()
            conn.execute(
                """
                INSERT INTO state_hosts
                    (session_id, address, hostname, os, status, local_txt, proof_txt,
                     source_run_id, first_seen, last_seen)
                VALUES (?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(session_id, address) DO UPDATE SET
                    -- COALESCE-style: a later run that learned nothing new must not blank
                    -- a field an earlier run filled in.
                    hostname  = CASE WHEN excluded.hostname != '' THEN excluded.hostname
                                     ELSE state_hosts.hostname END,
                    os        = CASE WHEN excluded.os != '' THEN excluded.os
                                     ELSE state_hosts.os END,
                    status    = CASE WHEN excluded.status != '' THEN excluded.status
                                     ELSE state_hosts.status END,
                    local_txt = CASE WHEN excluded.local_txt != '' THEN excluded.local_txt
                                     ELSE state_hosts.local_txt END,
                    proof_txt = CASE WHEN excluded.proof_txt != '' THEN excluded.proof_txt
                                     ELSE state_hosts.proof_txt END,
                    source_run_id = COALESCE(excluded.source_run_id, state_hosts.source_run_id),
                    last_seen = excluded.last_seen
                """,
                (h.session_id, address, h.hostname, h.os, h.status, h.local_txt, h.proof_txt,
                 h.source_run_id, now, now),
            )
    return len(rows)


def upsert_services(items: Iterable[Service]) -> int:
    rows = [s for s in items if s.session_id and s.address.strip() and s.port]
    if not rows:
        return 0
    now = _now()
    with _connect() as conn:
        for s in rows:
            _, address, port, proto = s.key()
            conn.execute(
                """
                INSERT INTO state_services
                    (session_id, address, port, proto, name, product, version, state,
                     banner, source_run_id, first_seen, last_seen)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(session_id, address, port, proto) DO UPDATE SET
                    name    = CASE WHEN excluded.name != '' THEN excluded.name
                                   ELSE state_services.name END,
                    product = CASE WHEN excluded.product != '' THEN excluded.product
                                   ELSE state_services.product END,
                    version = CASE WHEN excluded.version != '' THEN excluded.version
                                   ELSE state_services.version END,
                    state   = excluded.state,
                    banner  = CASE WHEN excluded.banner != '' THEN excluded.banner
                                   ELSE state_services.banner END,
                    source_run_id = COALESCE(excluded.source_run_id, state_services.source_run_id),
                    last_seen = excluded.last_seen
                """,
                (
                    s.session_id, address, port, proto, s.name, s.product, s.version,
                    s.state, s.banner[:500], s.source_run_id, now, now,
                ),
            )
    return len(rows)


def upsert_endpoints(items: Iterable[Endpoint]) -> int:
    rows = [e for e in items if e.session_id and e.url.strip()]
    if not rows:
        return 0
    now = _now()
    with _connect() as conn:
        for e in rows:
            _, url, method = e.key()
            conn.execute(
                """
                INSERT INTO state_endpoints
                    (session_id, url, method, status, title, length, tech, params,
                     source_run_id, first_seen, last_seen)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(session_id, url, method) DO UPDATE SET
                    status = COALESCE(excluded.status, state_endpoints.status),
                    title  = CASE WHEN excluded.title != '' THEN excluded.title
                                  ELSE state_endpoints.title END,
                    length = COALESCE(excluded.length, state_endpoints.length),
                    tech   = CASE WHEN excluded.tech != '' THEN excluded.tech
                                  ELSE state_endpoints.tech END,
                    params = CASE WHEN excluded.params != '[]' THEN excluded.params
                                  ELSE state_endpoints.params END,
                    source_run_id = COALESCE(excluded.source_run_id, state_endpoints.source_run_id),
                    last_seen = excluded.last_seen
                """,
                (
                    e.session_id, url, method, e.status, e.title[:300], e.length, e.tech,
                    json.dumps(sorted(set(e.params))), e.source_run_id, now, now,
                ),
            )
    return len(rows)


def upsert_credentials(items: Iterable[Credential]) -> int:
    rows = [c for c in items if c.session_id and c.principal.strip() and c.kind.strip()]
    if not rows:
        return 0
    now = _now()
    with _connect() as conn:
        for c in rows:
            _, kind, principal, domain = c.key()
            conn.execute(
                """
                INSERT INTO state_credentials
                    (session_id, kind, principal, domain, secret, validated, note,
                     source_run_id, first_seen, last_seen)
                VALUES (?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(session_id, kind, principal, domain) DO UPDATE SET
                    secret    = CASE WHEN excluded.secret != '' THEN excluded.secret
                                     ELSE state_credentials.secret END,
                    -- validated is EVIDENCE: only overwrite when the new record actually
                    -- tested it, so a fresh dump never resets a known-good credential.
                    validated = COALESCE(excluded.validated, state_credentials.validated),
                    note      = CASE WHEN excluded.note != '' THEN excluded.note
                                     ELSE state_credentials.note END,
                    source_run_id = COALESCE(excluded.source_run_id, state_credentials.source_run_id),
                    last_seen = excluded.last_seen
                """,
                (
                    c.session_id, kind, principal, domain, c.secret,
                    None if c.validated is None else int(c.validated),
                    c.note, c.source_run_id, now, now,
                ),
            )
    return len(rows)


def upsert_findings(items: Iterable[Finding]) -> int:
    rows = [f for f in items if f.session_id and f.title.strip()]
    if not rows:
        return 0
    now = _now()
    with _connect() as conn:
        for f in rows:
            conn.execute(
                """
                INSERT INTO state_findings
                    (session_id, fingerprint, title, severity, target, evidence, tool,
                     reference, source_run_id, first_seen, last_seen)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(session_id, fingerprint) DO UPDATE SET
                    severity  = excluded.severity,
                    evidence  = CASE WHEN excluded.evidence != '' THEN excluded.evidence
                                     ELSE state_findings.evidence END,
                    source_run_id = COALESCE(excluded.source_run_id, state_findings.source_run_id),
                    last_seen = excluded.last_seen
                """,
                (
                    f.session_id, f.fingerprint(), f.title[:300], f.severity, f.target,
                    f.evidence[:2000], f.tool, f.reference, f.source_run_id, now, now,
                ),
            )
    return len(rows)


# --------------------------------------------------------------------------- #
# reads
# --------------------------------------------------------------------------- #
def load(session_id: str) -> StateSummary:
    """Everything known for one session. Empty summary for an unknown id."""
    if not session_id:
        return StateSummary()
    with _connect() as conn:
        hosts = [
            Host(
                session_id=r["session_id"], address=r["address"], hostname=r["hostname"],
                os=r["os"], status=r["status"],
                local_txt=(r["local_txt"] if "local_txt" in r.keys() else "") or "",
                proof_txt=(r["proof_txt"] if "proof_txt" in r.keys() else "") or "",
                source_run_id=r["source_run_id"],
                first_seen=r["first_seen"], last_seen=r["last_seen"],
            )
            for r in conn.execute(
                "SELECT * FROM state_hosts WHERE session_id=? ORDER BY address", (session_id,)
            )
        ]
        services = [
            Service(
                session_id=r["session_id"], address=r["address"], port=r["port"],
                proto=r["proto"], name=r["name"], product=r["product"], version=r["version"],
                state=r["state"], banner=r["banner"], source_run_id=r["source_run_id"],
                first_seen=r["first_seen"], last_seen=r["last_seen"],
            )
            for r in conn.execute(
                "SELECT * FROM state_services WHERE session_id=? ORDER BY address, port",
                (session_id,),
            )
        ]
        endpoints = [
            Endpoint(
                session_id=r["session_id"], url=r["url"], method=r["method"],
                status=r["status"], title=r["title"], length=r["length"], tech=r["tech"],
                params=json.loads(r["params"] or "[]"), source_run_id=r["source_run_id"],
                first_seen=r["first_seen"], last_seen=r["last_seen"],
            )
            for r in conn.execute(
                "SELECT * FROM state_endpoints WHERE session_id=? ORDER BY url", (session_id,)
            )
        ]
        creds = [
            Credential(
                session_id=r["session_id"], kind=r["kind"], principal=r["principal"],
                domain=r["domain"], secret=r["secret"],
                validated=None if r["validated"] is None else bool(r["validated"]),
                note=r["note"], source_run_id=r["source_run_id"],
                first_seen=r["first_seen"], last_seen=r["last_seen"],
            )
            for r in conn.execute(
                "SELECT * FROM state_credentials WHERE session_id=? ORDER BY principal",
                (session_id,),
            )
        ]
        findings = [
            Finding(
                session_id=r["session_id"], title=r["title"], severity=r["severity"],
                target=r["target"], evidence=r["evidence"], tool=r["tool"],
                reference=r["reference"], source_run_id=r["source_run_id"],
                first_seen=r["first_seen"], last_seen=r["last_seen"],
            )
            for r in conn.execute(
                "SELECT * FROM state_findings WHERE session_id=?", (session_id,)
            )
        ]
    findings.sort(key=lambda f: (severity_rank(f.severity), f.title))
    return StateSummary(
        hosts=hosts, services=services, endpoints=endpoints,
        credentials=creds, findings=findings,
    )


def set_proof(session_id: str, address: str, kind: str, value: str) -> Host:
    """Set a host's local.txt/proof.txt flag by hand (the operator pastes it). Upsert.

    ``kind`` is 'local' or 'proof'. Creates the host row if the flag was captured before any
    scan recorded it. Returns the resulting Host.
    """
    addr = (address or "").strip()
    val = (value or "").strip()
    if not (session_id and addr):
        raise ValueError("session_id and address are required")
    k = (kind or "").strip().lower()
    if k not in ("local", "proof"):
        raise ValueError("kind must be 'local' or 'proof'")
    host = Host(session_id=session_id, address=addr)
    if k == "proof":
        host.proof_txt = val
    else:
        host.local_txt = val
    upsert_hosts([host])
    return next(h for h in load(session_id).hosts if h.address.strip().lower() == addr.lower())


def services_for(session_id: str, address: str) -> list[Service]:
    return [s for s in load(session_id).services if s.address.lower() == address.strip().lower()]


def clear(session_id: str) -> None:
    """Drop one session's state. Used by tests and by an explicit operator reset."""
    with _connect() as conn:
        for table in (
            "state_hosts", "state_services", "state_endpoints",
            "state_credentials", "state_findings",
        ):
            conn.execute(f"DELETE FROM {table} WHERE session_id=?", (session_id,))
