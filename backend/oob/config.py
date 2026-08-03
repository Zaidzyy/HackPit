"""The canary's configuration — one record, and the thing that makes deploy host-locked.

WHAT THIS IS FOR
----------------
Three separate pieces of build #13 part 3 all need to know the same two facts: *where the
canary is* and *what secret reads it*. The poll client (§3.3) needs them to fetch hits, the
payload templates (§3.4) need the zone to render a name, and the deploy path (§3.5) needs the
address to ship a file to. Left to each caller, "where" would be a parameter — and a
parameter is a request field one refactor later.

So it is a record, resolved server-side, exactly the way ``cockpit/winprofiles.py`` resolves a
Windows target from an id instead of taking a host. That is not a stylistic echo: the
containment argument for the SSH deploy in §3.5 is *entirely* "the destination is read from
here, and there is no argument that can override it". :func:`deploy_target` is the single
accessor for that, and ``test_oob_deploy_safety.py`` asserts the executor's deploy function
takes no host of any kind.

ONE RECORD, NOT A LIST
----------------------
Unlike Windows profiles there is exactly one canary. An operator owns one VPS and one
NS-delegated zone; a picker over a list would imply a fleet, and a fleet of internet-facing
listeners holding client evidence is a materially different thing to own. The row id is a
constant.

SECRETS
-------
``read_secret`` is the bearer token the deployed server checks (its ``HACKPIT_OOB_TOKEN``). It
is write-only here: stored in the gitignored ``sessions.db``, never returned by any public
view, and read only by the poll client and the deploy path via :func:`read_secret`. The SSH
private key is never stored at all — only a PATH to a key file already on the operator's disk,
so HackPit never becomes a keystore.

This module executes nothing and opens no socket.
"""

from __future__ import annotations

import re
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# The same gitignored single-file store the rest of the engagement records use, resolved the
# same way tokens.py resolves it rather than imported from another package.
DB_PATH = Path(__file__).parent.parent / "sessions.db"

_write_lock = threading.Lock()

# There is one canary. See the module docstring for why this is a constant and not an id.
ROW_ID = "canary"

DEFAULT_HTTP_PORT = 80
DEFAULT_DNS_PORT = 53
DEFAULT_SSH_PORT = 22
DEFAULT_SSH_USER = "root"
# Where server.py lands on the VPS. A constant for the same reason the container name in
# cockpit/kali.py is a constant: a caller-supplied destination path is an arbitrary-write
# primitive wearing a deploy button.
REMOTE_DIR = "/opt/hackpit-oob"

# A hostname or dotted-quad, nothing else. This value is spliced into an ssh argv and into a
# URL, so the grammar is deliberately narrower than either would strictly require: letters,
# digits, dots and hyphens. Every character excluded here is one that cannot then appear in an
# argument, a Host header or a shell someone adds later.
_HOST_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9.-]{0,253}[a-zA-Z0-9])?$")
# The delegated zone: at least two labels, so `oob` alone (which would never be delegable)
# fails at configure time rather than at the registrar.
_ZONE_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?)+$")

# Matches the deployable's own floor (oob/server.py MIN_SECRET). Checked HERE too, because a
# secret that the server will refuse to start with should fail when it is typed, not on the
# first deploy.
MIN_SECRET = 16


class ConfigError(ValueError):
    """The configuration was refused. Carries a message meant for the operator."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def init_db() -> None:
    """Create the config table. Idempotent; safe to call on every startup."""
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS oob_config (
                row_id       TEXT PRIMARY KEY,
                zone         TEXT NOT NULL,
                host         TEXT NOT NULL,
                answer_ip    TEXT NOT NULL DEFAULT '',
                http_port    INTEGER NOT NULL DEFAULT 80,
                dns_port     INTEGER NOT NULL DEFAULT 53,
                ssh_user     TEXT NOT NULL DEFAULT 'root',
                ssh_port     INTEGER NOT NULL DEFAULT 22,
                ssh_key_path TEXT NOT NULL DEFAULT '',
                read_secret  TEXT NOT NULL DEFAULT '',
                cursor       INTEGER NOT NULL DEFAULT 0,
                deployed_at  TEXT NOT NULL DEFAULT '',
                updated_at   TEXT NOT NULL
            )
            """
        )


def _valid_host(value: str) -> bool:
    return bool(_HOST_RE.match((value or "").strip()))


def _valid_zone(value: str) -> bool:
    return bool(_ZONE_RE.match((value or "").strip().rstrip(".").lower()))


def _valid_port(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 65535


def validate(
    *,
    zone: str,
    host: str,
    answer_ip: str = "",
    http_port: int = DEFAULT_HTTP_PORT,
    dns_port: int = DEFAULT_DNS_PORT,
    ssh_user: str = DEFAULT_SSH_USER,
    ssh_port: int = DEFAULT_SSH_PORT,
    ssh_key_path: str = "",
    read_secret: str = "",
    existing_secret: str = "",
) -> None:
    """Refuse a configuration that could not work, or that would deploy unsafely.

    Every check here fails at CONFIGURE time — the moment the operator can still fix it —
    rather than at deploy time on a box they reach by SSH once. ``existing_secret`` lets an
    edit that leaves the secret field blank keep the stored one instead of being told it is
    missing.
    """
    if not _valid_zone(zone):
        raise ConfigError(
            f"zone must be a delegable domain with at least two labels (e.g. oob.example.net), "
            f"got {zone!r}"
        )
    if not _valid_host(host):
        raise ConfigError(
            f"host must be a single hostname or IP address with no spaces or shell characters, "
            f"got {host!r}"
        )
    if answer_ip and not _valid_host(answer_ip):
        raise ConfigError(f"answer_ip must be an IPv4 address, got {answer_ip!r}")
    for label, port in (("http_port", http_port), ("dns_port", dns_port), ("ssh_port", ssh_port)):
        if not _valid_port(port):
            raise ConfigError(f"{label} must be a TCP/UDP port between 1 and 65535, got {port!r}")
    if not (ssh_user or "").strip() or any(c.isspace() for c in ssh_user):
        raise ConfigError("ssh_user must be a single username with no spaces")
    if ssh_key_path and any(c in ssh_key_path for c in ";|&$`\n"):
        raise ConfigError("ssh_key_path must be a plain filesystem path")
    secret = read_secret or existing_secret
    if not secret:
        raise ConfigError(
            "a read secret is required — the hit log holds a target's internal hostnames and "
            "is never served unauthenticated"
        )
    if len(secret) < MIN_SECRET:
        raise ConfigError(
            f"the read secret is {len(secret)} characters; the minimum is {MIN_SECRET}. This "
            f"endpoint is on the public internet."
        )


def save(
    *,
    zone: str,
    host: str,
    answer_ip: str = "",
    http_port: int = DEFAULT_HTTP_PORT,
    dns_port: int = DEFAULT_DNS_PORT,
    ssh_user: str = DEFAULT_SSH_USER,
    ssh_port: int = DEFAULT_SSH_PORT,
    ssh_key_path: str = "",
    read_secret: str = "",
) -> dict[str, Any]:
    """Write the canary configuration. Returns the PUBLIC view (secret masked).

    An empty ``read_secret`` KEEPS the stored one — so editing the zone does not silently
    wipe the credential the deployed server is already checking against, which would leave a
    running canary that the poll client can no longer read.
    """
    init_db()
    current = _raw()
    existing = (current["read_secret"] if current else "") or ""
    validate(
        zone=zone, host=host, answer_ip=answer_ip, http_port=http_port, dns_port=dns_port,
        ssh_user=ssh_user, ssh_port=ssh_port, ssh_key_path=ssh_key_path,
        read_secret=read_secret, existing_secret=existing,
    )
    secret = read_secret or existing
    # A cursor is a position in ONE server's hit log. Pointing the config at a different host
    # or zone makes that position meaningless, so it resets rather than skipping the new
    # server's first N hits — silently missing the first hits of a fresh canary is the exact
    # failure this whole part exists to prevent.
    moved = current is not None and (
        current["host"] != host.strip() or current["zone"] != zone.strip().rstrip(".").lower()
    )
    cursor = 0 if (current is None or moved) else int(current["cursor"])
    with _write_lock, _connect() as conn:
        conn.execute(
            """
            INSERT INTO oob_config
                (row_id, zone, host, answer_ip, http_port, dns_port, ssh_user, ssh_port,
                 ssh_key_path, read_secret, cursor, deployed_at, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(row_id) DO UPDATE SET
                zone=excluded.zone, host=excluded.host, answer_ip=excluded.answer_ip,
                http_port=excluded.http_port, dns_port=excluded.dns_port,
                ssh_user=excluded.ssh_user, ssh_port=excluded.ssh_port,
                ssh_key_path=excluded.ssh_key_path, read_secret=excluded.read_secret,
                cursor=excluded.cursor, updated_at=excluded.updated_at
            """,
            (
                ROW_ID, zone.strip().rstrip(".").lower(), host.strip(), (answer_ip or "").strip(),
                int(http_port), int(dns_port), (ssh_user or DEFAULT_SSH_USER).strip(),
                int(ssh_port), (ssh_key_path or "").strip(), secret, cursor,
                (current["deployed_at"] if current else ""), _now(),
            ),
        )
    pub = public()
    assert pub is not None
    return pub


def _raw() -> sqlite3.Row | None:
    try:
        with _connect() as conn:
            return conn.execute(
                "SELECT * FROM oob_config WHERE row_id = ?", (ROW_ID,)
            ).fetchone()
    except sqlite3.OperationalError:
        # The table is created at startup; treat "not yet" as "not configured" rather than
        # crashing a gate check that only wanted to know whether a canary exists.
        return None


def public() -> dict[str, Any] | None:
    """The masked view — everything except the secret. None when unconfigured.

    This is what every API response and every UI serialises. The secret is reported only as
    ``has_secret``, the same shape ``winprofiles`` uses, because the endpoint that returns a
    stored credential is the build #9 defect.
    """
    row = _raw()
    if row is None:
        return None
    d = dict(row)
    return {
        "zone": d["zone"],
        "host": d["host"],
        "answer_ip": d["answer_ip"] or "",
        "http_port": int(d["http_port"]),
        "dns_port": int(d["dns_port"]),
        "ssh_user": d["ssh_user"],
        "ssh_port": int(d["ssh_port"]),
        "ssh_key_path": d["ssh_key_path"] or "",
        "has_secret": bool(d["read_secret"]),
        "cursor": int(d["cursor"]),
        "deployed_at": d["deployed_at"] or "",
        "updated_at": d["updated_at"],
    }


def is_configured() -> bool:
    """True when there is a canary to poll, deploy to or render a payload for."""
    return _raw() is not None


def zone() -> str:
    """The delegated zone, or '' when unconfigured. Safe to show — it is a public DNS name."""
    row = _raw()
    return (row["zone"] if row else "") or ""


def read_secret() -> str:
    """The raw bearer secret — for the poll client and the deploy path ONLY.

    Never serialise the result of this. The public surfaces call :func:`public`.
    """
    row = _raw()
    return (row["read_secret"] if row else "") or ""


def base_url() -> str:
    """The canary's HTTP base, derived from the STORED host. '' when unconfigured.

    Built here rather than by the caller so there is exactly one place a URL for this server
    comes from, and it is not a caller's string.
    """
    row = _raw()
    if row is None:
        return ""
    port = int(row["http_port"])
    suffix = "" if port == 80 else f":{port}"
    return f"http://{row['host']}{suffix}"


def ns_delegation() -> dict[str, Any] | None:
    """The exact records to paste at the registrar, or None when unconfigured.

    THIS IS THE STEP PEOPLE GET WRONG, and it is worth being precise about because the failure
    is silent: an A record pointed at the VPS makes ``oob.example.net`` resolve, so it *looks*
    configured, while every ``<token>.oob.example.net`` query still goes to the parent zone's
    nameservers and never reaches the canary. Only NS delegation hands the whole subtree over.

    Two records, in the PARENT zone (``example.net``), not in the canary's zone:

      * an ``NS`` record delegating the child label to a nameserver name, and
      * an ``A`` glue record giving that nameserver's address — required because the
        nameserver's own name lives inside the zone it is authoritative for, so without glue
        a resolver has no way to find it.
    """
    row = _raw()
    if row is None:
        return None
    zone_name = row["zone"]
    address = (row["answer_ip"] or row["host"]).strip()
    labels = zone_name.split(".")
    child, parent = labels[0], ".".join(labels[1:])
    ns_name = f"ns1.{zone_name}"
    return {
        "zone": zone_name,
        "parent_zone": parent,
        "records": [
            {"name": child, "type": "NS", "value": f"{ns_name}.",
             "note": "delegates the whole subtree, including every <token>. name under it"},
            {"name": f"ns1.{child}", "type": "A", "value": address,
             "note": "glue — without it the nameserver's own name cannot be resolved"},
        ],
        "zonefile": (
            f"; add these two records to the {parent} zone at your registrar\n"
            f"{child}\tIN\tNS\t{ns_name}.\n"
            f"ns1.{child}\tIN\tA\t{address}\n"
        ),
        "warning": (
            "An A record on its own is not enough and is the usual mistake: the name will "
            "resolve while every token subdomain still goes to the parent's nameservers."
        ),
    }


class DeployTarget:
    """Where a deploy goes. Constructed only by :func:`deploy_target`, never by a caller.

    A plain object rather than a dict so that a caller cannot build one out of request fields
    and hand it to the executor — the whole containment argument in spec §4 is that the
    destination comes from the store.
    """

    __slots__ = ("host", "user", "port", "key_path", "remote_dir", "zone", "answer_ip",
                 "dns_port", "http_port", "secret")

    def __init__(self, row: sqlite3.Row) -> None:
        self.host = row["host"]
        self.user = row["ssh_user"]
        self.port = int(row["ssh_port"])
        self.key_path = row["ssh_key_path"] or ""
        self.remote_dir = REMOTE_DIR
        self.zone = row["zone"]
        self.answer_ip = row["answer_ip"] or row["host"]
        self.dns_port = int(row["dns_port"])
        self.http_port = int(row["http_port"])
        self.secret = row["read_secret"] or ""

    def describe(self) -> dict[str, Any]:
        """A record-safe description: destination without the secret."""
        return {
            "host": self.host,
            "user": self.user,
            "port": self.port,
            "remote_dir": self.remote_dir,
            "zone": self.zone,
        }


def deploy_target() -> DeployTarget | None:
    """THE resolved deploy destination, or None when unconfigured.

    The single accessor the gated deploy path uses. It takes no arguments on purpose: there
    is no way to express "deploy somewhere else", which is what host-locking means here.
    """
    row = _raw()
    return DeployTarget(row) if row is not None else None


def set_cursor(value: int) -> None:
    """Advance the poll cursor. Monotonic — it never moves backwards.

    Never rewinding matters because the cursor is what stops a hit being ingested twice.
    A caller that passed a stale value (a racing poll, a restart mid-flight) would otherwise
    replay a burst of hits into the engagement state as new findings.
    """
    with _write_lock, _connect() as conn:
        conn.execute(
            "UPDATE oob_config SET cursor = MAX(cursor, ?) WHERE row_id = ?",
            (max(0, int(value)), ROW_ID),
        )


def cursor() -> int:
    """The last hit sequence number this HackPit has ingested."""
    row = _raw()
    return int(row["cursor"]) if row else 0


def mark_deployed(at: str | None = None) -> None:
    """Record that a deploy completed, for the panel's "last shipped" line."""
    with _write_lock, _connect() as conn:
        conn.execute(
            "UPDATE oob_config SET deployed_at = ? WHERE row_id = ?", (at or _now(), ROW_ID)
        )


def clear() -> bool:
    """Forget the canary configuration. True if one was removed.

    Removes HackPit's knowledge of the canary; it does not stop a server already running on
    the VPS. The panel says so, because a config delete that read as "the listener is down"
    would leave an internet-facing daemon nobody is watching.
    """
    with _write_lock, _connect() as conn:
        return conn.execute("DELETE FROM oob_config WHERE row_id = ?", (ROW_ID,)).rowcount > 0
