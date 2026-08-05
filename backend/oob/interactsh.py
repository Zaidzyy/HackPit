"""interact.sh — the second OOB backend (spec 2026-08-06).

The self-hosted canary (``oob/server.py`` + ``backend/oob/config.py``) is the private, owned
option. This is the zero-infrastructure one: ProjectDiscovery's public OOB service, the same
shape as Burp Collaborator. It works INVERSELY to the self-hosted canary — interact.sh assigns
the correlation-id and encrypts every callback to a public key we register, so this module owns
a keypair and a session, not a VPS and a zone.

HOW THE PROTOCOL WORKS
----------------------
* ``register``  — POST a base64'd PKIX public key + a secret + a 20-char correlation-id.
* payloads      — ``<correlation-id><13-char suffix>.<server>``; the suffix distinguishes mints.
* ``poll``      — GET ``/poll?id=<cid>&secret=<sk>``; the answer carries an RSA-OAEP-SHA256
                  wrapped AES key and AES-256-CFB encrypted interaction blobs, decrypted here.
* ``deregister``— POST the correlation-id + secret.

CONTAINMENT — identical to ``poll.py``, because this is a new backend OUTBOUND egress:
  * the destination is the CONFIGURED server, resolved from the store, never a request field;
  * no redirect is followed (a tampered/proxied server answering ``302 http://169.254.169.254/``
    must be an error, not an SSRF from the backend host);
  * no ambient proxy is honoured; the response is byte-capped; JSON is parsed, never executed;
  * every decrypted interaction is untrusted input — capped and validated before it is a record.

SECRETS
-------
The RSA private key, the secret-key and any self-hosted auth token are bearer secrets: anyone
holding them can read a client's callbacks, which carry a target's internal hostnames. They live
in the gitignored ``sessions.db``, are write-only, and are never returned by :func:`session_public`.

This module opens outbound sockets. It runs NO command, reaches NO execution surface, and no
agent/orchestrator/loop imports it (asserted by the safety scan).
"""

from __future__ import annotations

import base64
import json
import re
import secrets
import sqlite3
import string
import threading
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

# interact.sh uses AES-CFB, which cryptography is relocating to ``decrepit`` (the mode is old,
# not the library's choice — it is the wire format). Import from the new home when it exists so
# no deprecation warning fires, and fall back for older cryptography.
try:  # cryptography >= 43
    from cryptography.hazmat.decrepit.ciphers.modes import CFB
except ImportError:  # pragma: no cover - older cryptography
    from cryptography.hazmat.primitives.ciphers.modes import CFB

DEFAULT_SERVER = "oast.fun"

# interact.sh subdomains are lowercase alphanumeric. The correlation-id is 20 chars and each
# payload appends a 13-char suffix (20 + 13 = 33), so the suffix is what tells one mint from
# another under a single registration.
_ALNUM = string.ascii_lowercase + string.digits
CORRELATION_LEN = 20
SUFFIX_LEN = 13

# An interaction blob is a captured request excerpt — tiny by nature. Cap hard: a poll answer
# that decrypts to something enormous is a compromised or misbehaving endpoint, not a canary.
MAX_INTERACTION_BYTES = 64 * 1024


class InteractshError(RuntimeError):
    """An interact.sh operation failed. Carries a message meant for the operator."""


def _rand(n: int) -> str:
    """``n`` lowercase-alphanumeric characters from ``secrets`` — never ``random``.

    These become a correlation-id and per-payload suffixes that travel as DNS labels and act as
    bearer identifiers in the DNS; a predictable one lets a stranger read or poison callbacks.
    """
    return "".join(secrets.choice(_ALNUM) for _ in range(n))


def new_correlation_id() -> str:
    return _rand(CORRELATION_LEN)


def new_suffix() -> str:
    return _rand(SUFFIX_LEN)


def new_keypair() -> tuple[str, str]:
    """``(private_pem, public_key_b64)``.

    ``public_key_b64`` is base64 of the PKIX (SubjectPublicKeyInfo) PEM — the exact wire form
    interact.sh expects in the ``public-key`` field of a registration.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, base64.b64encode(public_pem).decode()


def decrypt_aes_key(private_pem: str, aes_key_b64: str) -> bytes:
    """Unwrap the per-poll AES key: RSA-OAEP-SHA256 decrypt, with our private key.

    interact.sh encrypts one AES key per poll answer with ``EncryptOAEP(sha256, ...)``; the
    matching decrypt is OAEP with an SHA-256 MGF1 and SHA-256 hash, no label.
    """
    try:
        priv = serialization.load_pem_private_key(private_pem.encode(), password=None)
        wrapped = base64.b64decode(aes_key_b64)
        return priv.decrypt(
            wrapped,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )
    except Exception as exc:  # narrow to a named module error for the caller
        raise InteractshError(f"could not unwrap the AES key: {exc}") from exc


def decrypt_interaction(aes_key: bytes, data_b64: str) -> dict:
    """Decrypt one interaction blob: base64 -> ``IV(16) || ciphertext``, AES-256-CFB.

    Treats the input as hostile: caps the decoded length before touching it and returns a named
    error rather than a raw exception for anything malformed, because this data arrived from the
    internet through a server we do not run.
    """
    try:
        blob = base64.b64decode(data_b64)
        if len(blob) > MAX_INTERACTION_BYTES:
            raise InteractshError("interaction exceeds the cap — refusing")
        iv, ciphertext = blob[:16], blob[16:]
        dec = Cipher(algorithms.AES(aes_key), CFB(iv)).decryptor()
        plaintext = dec.update(ciphertext) + dec.finalize()
        obj = json.loads(plaintext.decode("utf-8", "replace"))
    except InteractshError:
        raise
    except Exception as exc:
        raise InteractshError(f"could not decrypt an interaction: {exc}") from exc
    if not isinstance(obj, dict):
        raise InteractshError("a decrypted interaction was not a JSON object")
    return obj


# --------------------------------------------------------------------------- #
# session store — one interact.sh registration, in the gitignored sessions.db
# --------------------------------------------------------------------------- #
# Resolved the same way the sibling modules resolve it (tokens.py:46), not imported from another
# package for a path both already know.
DB_PATH = Path(__file__).parent.parent / "sessions.db"

_write_lock = threading.Lock()

# There is one interact.sh session, like there is one canary. The row id is a constant.
ROW_ID = "interactsh"

# A hostname, nothing else — this value is spliced into a URL, so the grammar excludes every
# character that could then appear anywhere but a host label. Matches config._HOST_RE.
_HOST_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9.-]{0,253}[a-zA-Z0-9])?$")

# Containment ceilings, matching poll.py.
TIMEOUT_SECONDS = 15
MAX_RESPONSE_BYTES = 4 * 1024 * 1024


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def init_db() -> None:
    """Create the interact.sh tables. Idempotent; safe to call on every startup.

    Three tables: the single session row, the per-mint suffix->step correlation map, and the
    seen-interaction set that makes re-polling idempotent.
    """
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS oob_interactsh (
                row_id         TEXT PRIMARY KEY,
                server         TEXT NOT NULL,
                correlation_id TEXT NOT NULL,
                secret_key     TEXT NOT NULL,
                private_key    TEXT NOT NULL,
                auth_token     TEXT NOT NULL DEFAULT '',
                registered_at  TEXT NOT NULL,
                last_poll      TEXT NOT NULL DEFAULT '',
                generated      INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS oob_interactsh_map (
                suffix        TEXT PRIMARY KEY,
                engagement_id TEXT NOT NULL,
                step_id       TEXT,
                note          TEXT NOT NULL DEFAULT '',
                at            TEXT NOT NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS oob_interactsh_map_eng ON oob_interactsh_map (engagement_id)"
        )
        conn.execute(
            "CREATE TABLE IF NOT EXISTS oob_interactsh_seen (uid TEXT PRIMARY KEY, at TEXT NOT NULL)"
        )


def _raw() -> sqlite3.Row | None:
    try:
        with _connect() as conn:
            return conn.execute(
                "SELECT * FROM oob_interactsh WHERE row_id = ?", (ROW_ID,)
            ).fetchone()
    except sqlite3.OperationalError:
        return None


def is_registered() -> bool:
    """True when there is an interact.sh session to generate payloads under or poll."""
    return _raw() is not None


def server() -> str:
    row = _raw()
    return (row["server"] if row else "") or ""


def correlation_id() -> str:
    row = _raw()
    return (row["correlation_id"] if row else "") or ""


def _secret_key() -> str:
    row = _raw()
    return (row["secret_key"] if row else "") or ""


def _private_key() -> str:
    row = _raw()
    return (row["private_key"] if row else "") or ""


def _auth_token() -> str:
    row = _raw()
    return (row["auth_token"] if row else "") or ""


def session_public() -> dict[str, Any] | None:
    """The masked view — never a secret. None when not registered.

    Reports the correlation-id as ``correlation_prefix`` (it is a public DNS label anyway) and
    the presence of a secret as ``has_secret``, the same shape ``config.public`` uses. The
    secret-key, private key and auth token are never serialised.
    """
    row = _raw()
    if row is None:
        return None
    d = dict(row)
    return {
        "server": d["server"],
        "correlation_prefix": d["correlation_id"],
        "generated": int(d["generated"]),
        "registered_at": d["registered_at"],
        "last_poll": d["last_poll"] or "",
        "has_secret": bool(d["secret_key"] and d["private_key"]),
    }


def _forget() -> None:
    """Drop the session and everything scoped to it (map + seen). Used on rotate and deregister."""
    with _write_lock, _connect() as conn:
        conn.execute("DELETE FROM oob_interactsh WHERE row_id = ?", (ROW_ID,))
        conn.execute("DELETE FROM oob_interactsh_map")
        conn.execute("DELETE FROM oob_interactsh_seen")


# --------------------------------------------------------------------------- #
# contained HTTP — the same shape poll.py uses, for the same reasons
# --------------------------------------------------------------------------- #
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuses to redirect. SUBCLASSES the default so build_opener does not re-add one.

    A poll that followed a ``302 http://169.254.169.254/...`` from a tampered or proxied server
    would become an SSRF from the backend host. Returning None makes urllib raise for the 3xx.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


def _opener() -> urllib.request.OpenerDirector:
    """Follows NO redirect and honours NO ambient proxy — both load-bearing, see poll.py."""
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


def _base() -> str:
    host = server()
    if not host:
        raise InteractshError("no interact.sh session — register one first")
    return f"https://{host}"


def _headers() -> dict[str, str]:
    headers = {"Accept": "application/json"}
    token = _auth_token()
    if token:
        headers["Authorization"] = token
    return headers


def _read(response) -> dict[str, Any]:
    raw = response.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise InteractshError("interact.sh returned more than this client will read — refusing")
    if not raw:
        return {}
    try:
        payload = json.loads(raw.decode("utf-8", "replace"))
    except ValueError as exc:
        raise InteractshError("interact.sh returned something that is not JSON") from exc
    if not isinstance(payload, dict):
        raise InteractshError("interact.sh returned JSON that is not an object")
    return payload


def _http_post(path: str, body: dict[str, Any]) -> dict[str, Any]:
    """POST JSON to a fixed path on the CONFIGURED server. No redirect, no ambient proxy."""
    data = json.dumps(body).encode()
    request = urllib.request.Request(
        _base() + path,
        data=data,
        headers={**_headers(), "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with _opener().open(request, timeout=TIMEOUT_SECONDS) as response:
            return _read(response)
    except urllib.error.HTTPError as exc:
        if 300 <= exc.code < 400:
            raise InteractshError(
                f"interact.sh answered a redirect ({exc.code}), which is never followed"
            ) from exc
        raise InteractshError(f"interact.sh answered HTTP {exc.code} on {path}") from exc
    except urllib.error.URLError as exc:
        raise InteractshError(f"could not reach interact.sh at {server()}: {exc.reason}") from exc
    except OSError as exc:  # pragma: no cover - socket-level failures
        raise InteractshError(f"could not reach interact.sh at {server()}: {exc}") from exc


def _http_get(path: str, query: str = "") -> dict[str, Any]:
    """GET a fixed path + query from the CONFIGURED server. No redirect, no ambient proxy."""
    request = urllib.request.Request(_base() + path + query, headers=_headers(), method="GET")
    try:
        with _opener().open(request, timeout=TIMEOUT_SECONDS) as response:
            return _read(response)
    except urllib.error.HTTPError as exc:
        if 300 <= exc.code < 400:
            raise InteractshError(
                f"interact.sh answered a redirect ({exc.code}), which is never followed"
            ) from exc
        raise InteractshError(f"interact.sh answered HTTP {exc.code} on {path}") from exc
    except urllib.error.URLError as exc:
        raise InteractshError(f"could not reach interact.sh at {server()}: {exc.reason}") from exc
    except OSError as exc:  # pragma: no cover - socket-level failures
        raise InteractshError(f"could not reach interact.sh at {server()}: {exc}") from exc


# --------------------------------------------------------------------------- #
# register / deregister
# --------------------------------------------------------------------------- #
def register(server_host: str = DEFAULT_SERVER, auth_token: str = "") -> dict[str, Any]:
    """Start (or rotate) an interact.sh session and register the keypair with the server.

    Rotating replaces any prior session and clears its correlation map + seen set — a new
    correlation-id means the old suffixes belong to a session that no longer exists. The row is
    written BEFORE the network call so ``_base`` can resolve the destination; on a failed
    ``/register`` it is rolled back, so a half-registered session is never left behind.
    """
    host = (server_host or DEFAULT_SERVER).strip().lower()
    if not _HOST_RE.match(host):
        raise InteractshError(f"interact.sh server must be a hostname, got {server_host!r}")
    priv_pem, pub_b64 = new_keypair()
    cid, sk = new_correlation_id(), secrets.token_hex(16)
    _forget()
    with _write_lock, _connect() as conn:
        conn.execute(
            "INSERT INTO oob_interactsh (row_id, server, correlation_id, secret_key, private_key, "
            "auth_token, registered_at, last_poll, generated) VALUES (?,?,?,?,?,?,?,?,0)",
            (ROW_ID, host, cid, sk, priv_pem, (auth_token or "").strip(), _now(), ""),
        )
    body = {"public-key": pub_b64, "secret-key": sk, "correlation-id": cid}
    try:
        _http_post("/register", body)
    except InteractshError:
        _forget()  # do not leave a session the server never accepted
        raise
    pub = session_public()
    assert pub is not None
    return pub


def deregister() -> bool:
    """Best-effort deregister on the server, then forget locally. True if a session existed."""
    if not is_registered():
        return False
    body = {"correlation-id": correlation_id(), "secret-key": _secret_key()}
    try:
        _http_post("/deregister", body)
    except InteractshError:
        pass  # the server may already have expired the session; forgetting locally is the point
    _forget()
    return True


# --------------------------------------------------------------------------- #
# payload generation + correlation — the part that turns a hit into evidence
# --------------------------------------------------------------------------- #
# What a suffix must look like coming back off the wire. Anyone on the internet can query
# anything under interact.sh's zone, so every candidate reaches this before the database.
_SUFFIX_RE = re.compile(r"^[a-z0-9]{13}$")


def generate(engagement_id: str, step_id: str | None = None, note: str = "") -> dict[str, Any]:
    """Mint a payload host under the session and record what it is for.

    Returns ``{host, suffix, correlation_id}``. The host is
    ``<correlation-id><suffix>.<server>``; the suffix is the per-mint marker that a returning
    callback carries, so storing ``suffix -> (engagement, step, note)`` is what later lets a hit
    resolve back to the test that caused it — the correlation is the product, not the hit.
    """
    cid = correlation_id()
    if not cid:
        raise InteractshError("no interact.sh session — register one first")
    suffix = new_suffix()
    host = f"{cid}{suffix}.{server()}"
    with _write_lock, _connect() as conn:
        conn.execute(
            "INSERT INTO oob_interactsh_map (suffix, engagement_id, step_id, note, at) "
            "VALUES (?,?,?,?,?)",
            (suffix, engagement_id, step_id, note, _now()),
        )
        conn.execute(
            "UPDATE oob_interactsh SET generated = generated + 1 WHERE row_id = ?", (ROW_ID,)
        )
    return {"host": host, "suffix": suffix, "correlation_id": cid}


def correlate_suffix(suffix: str) -> dict[str, Any] | None:
    """Resolve a per-mint suffix seen on the wire back to the step that minted it.

    Called with attacker-influenced input (the suffix is extracted from a queried name), so it
    folds case, rejects anything outside the 13-char label grammar, and returns None rather than
    raising for all of it.
    """
    if not isinstance(suffix, str):
        return None
    candidate = suffix.strip().lower()
    if not _SUFFIX_RE.match(candidate):
        return None
    with _connect() as conn:
        row = conn.execute(
            "SELECT engagement_id, step_id, note, at FROM oob_interactsh_map WHERE suffix = ?",
            (candidate,),
        ).fetchone()
    return dict(row) if row else None


def clear(engagement_id: str) -> None:
    """Drop one engagement's suffix mappings. Used when an engagement is deleted, and by tests."""
    with _write_lock, _connect() as conn:
        conn.execute("DELETE FROM oob_interactsh_map WHERE engagement_id = ?", (engagement_id,))
