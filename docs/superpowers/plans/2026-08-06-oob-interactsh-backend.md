# interact.sh Second OOB Backend — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add ProjectDiscovery's interact.sh as a second, parallel OOB backend alongside the self-hosted canary, so blind-vuln callbacks can be caught with zero infrastructure, with auto-poll and send-to-repeater convenience — without crossing the propose-only invariant.

**Architecture:** interact.sh is a new transport (`backend/oob/interactsh.py`) under the *unchanged* correlation→findings→state pipeline. Both backends can be configured and live at once; a new `poll.poll_all()` sweeps both and merges. A background lifespan timer auto-polls (read-only). Send-to-repeater is frontend-only (no backend coupling, so the repeater's human-only guard is untouched).

**Tech Stack:** Python 3 / FastAPI backend, `cryptography` (already in venv) for RSA-OAEP-SHA256 + AES-256-CFB, stdlib `urllib` for contained HTTP, SQLite (`sessions.db`), Next.js/React frontend.

## Global Constraints

- **`secrets`, never `random`** for correlation-id / secret-key / suffix generation (asserted structurally, matching `tokens.py`).
- **Secrets are write-only**: `secret_key`, `private_key` (PEM), `auth_token` stored gitignored in `sessions.db`, never returned by any view (the `has_secret` pattern in `config.py`).
- **Contained outbound egress** (matching `poll.py`): destination resolved server-side from the store, never a request field; **no redirects followed**; **no ambient proxy**; response byte-capped; JSON parsed, never executed; decrypted data treated as untrusted and capped before becoming a record.
- **No agent/orchestrator/loop reach** to `interactsh.py` or the auto-poll task; neither contains an execution primitive or a delivery surface.
- **No new gated command.** register/poll/deregister are contained backend calls; the SSH deploy gate is untouched.
- **Default interact.sh server** `oast.fun`, overridable, with optional `auth_token` for a self-hosted interactsh-server.
- **DB path** resolved as the siblings do: `Path(__file__).parent.parent / "sessions.db"`.
- Tests run under `sh backend/run_safety_tests.sh`; hermetic (no network). The live oast.fun round-trip is a **proof**, not in the hermetic suite.

---

## File Structure

- **Create** `backend/oob/interactsh.py` — protocol client, crypto, session store, correlation map, normalizer.
- **Create** `backend/oob/settings.py` — the `oob_settings` row (auto-poll enabled + interval). Small, single-purpose; kept out of `config.py` (which is self-hosted-canary-specific).
- **Create** `backend/oob/autopoll.py` — the background sweep loop (thread), started from the lifespan.
- **Modify** `backend/oob/poll.py` — add `poll_all()`.
- **Modify** `backend/oob/templates.py` — `Callback` interact.sh shape.
- **Modify** `backend/oob/router.py` — interact.sh routes, autopoll route, backend-aware mint/poll/verify, status in `GET /oob`.
- **Modify** `backend/oob/verify.py` — interact.sh live check.
- **Modify** `backend/main.py` — init the new tables, start the auto-poll thread in lifespan.
- **Modify** `backend/cockpit/repeater.py` — fix the stale "deferred" docstring note.
- **Create** `backend/test_oob_interactsh.py` — hermetic unit tests (crypto, store, generate, poll, containment).
- **Modify** `backend/test_oob_deploy_safety.py` — extend to assert interactsh + autopoll reach no execution surface (or add `backend/test_oob_interactsh_safety.py`).
- **Create** `docs/proof/oob_interactsh_proof.py` — live oast.fun round-trip.
- **Modify** frontend `frontend/src/components/OOBCanaryScreen.tsx` — interact.sh config/status, auto-poll toggle, send-to-repeater button.
- **Modify** `docs/ASSESSMENT-2026-07-26.md` (+ regen html/pdf).

---

## Task 1: interact.sh crypto + id generation (pure functions)

**Files:**
- Create: `backend/oob/interactsh.py`
- Test: `backend/test_oob_interactsh.py`

**Interfaces:**
- Produces:
  - `DEFAULT_SERVER = "oast.fun"`
  - `class InteractshError(RuntimeError)`
  - `new_correlation_id() -> str` — 20 lowercase alnum chars, `secrets`-based.
  - `new_suffix() -> str` — 13 lowercase alnum chars, `secrets`-based.
  - `new_keypair() -> tuple[str, str]` — `(private_pem, public_key_b64)` where `public_key_b64` is base64 of the PKIX PEM public key (interact.sh's wire form).
  - `decrypt_aes_key(private_pem: str, aes_key_b64: str) -> bytes` — RSA-OAEP-SHA256 decrypt.
  - `decrypt_interaction(aes_key: bytes, data_b64: str) -> dict` — base64 → `IV(16)||ciphertext`, AES-256-CFB decrypt, JSON parse. Raises `InteractshError` on any malformed input.

- [ ] **Step 1: Write the failing test (crypto round-trip + id shape)**

```python
# backend/test_oob_interactsh.py
import base64, json
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

import oob.interactsh as ish


def test_id_generation_shapes():
    cid = ish.new_correlation_id()
    suf = ish.new_suffix()
    assert len(cid) == 20 and cid.isalnum() and cid.islower()
    assert len(suf) == 13 and suf.isalnum() and suf.islower()
    # distinct across calls
    assert ish.new_correlation_id() != cid


def _server_encrypt(public_key_b64: str, interaction: dict):
    """Act as interact.sh: encrypt an interaction the way the server does."""
    pem = base64.b64decode(public_key_b64)
    pub = serialization.load_pem_public_key(pem)
    aes_key = os.urandom(32)
    iv = os.urandom(16)
    enc = Cipher(algorithms.AES(aes_key), modes.CFB(iv)).encryptor()
    blob = iv + enc.update(json.dumps(interaction).encode()) + enc.finalize()
    aes_key_b64 = base64.b64encode(
        pub.encrypt(aes_key, padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    ).decode()
    return aes_key_b64, base64.b64encode(blob).decode()


def test_crypto_round_trip():
    priv_pem, pub_b64 = ish.new_keypair()
    interaction = {"protocol": "dns", "unique-id": "x" * 33, "remote-address": "1.2.3.4"}
    aes_key_b64, data_b64 = _server_encrypt(pub_b64, interaction)
    aes_key = ish.decrypt_aes_key(priv_pem, aes_key_b64)
    got = ish.decrypt_interaction(aes_key, data_b64)
    assert got["protocol"] == "dns"
    assert got["remote-address"] == "1.2.3.4"


def test_decrypt_rejects_garbage():
    priv_pem, _ = ish.new_keypair()
    import pytest
    with pytest.raises(ish.InteractshError):
        ish.decrypt_interaction(b"\x00" * 32, "not-base64-@@@")
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd backend && python -m pytest test_oob_interactsh.py -v`
Expected: FAIL — `oob.interactsh` has no such attributes.

- [ ] **Step 3: Implement the crypto + id functions**

```python
# backend/oob/interactsh.py  (top of file)
"""interact.sh — the second OOB backend (spec 2026-08-06).

The self-hosted canary (oob/server.py + backend/oob/config.py) is the private, owned option.
This is the zero-infrastructure one: ProjectDiscovery's public OOB service. It works INVERSELY —
interact.sh assigns the correlation-id and encrypts every callback to a public key we register,
so this module owns a keypair and a session, not a VPS.

CONTAINMENT — identical to poll.py, because this is a new backend OUTBOUND egress:
  * the destination is the CONFIGURED server, resolved from the store, never a request field;
  * no redirect is followed (a tampered/proxied server answering 302 http://169.254.169.254/...
    must be an error, not an SSRF from the backend host);
  * no ambient proxy; response byte-capped; JSON parsed, never executed;
  * every decrypted interaction is untrusted input — capped and validated before it is a record.

This module opens outbound sockets. It runs NO command and reaches NO execution surface, and no
agent/orchestrator/loop imports it (asserted by the safety scan).
"""
from __future__ import annotations

import base64
import json
import secrets
import string

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

DEFAULT_SERVER = "oast.fun"

# interact.sh subdomains are lowercase alphanumeric; the correlation-id is 20 chars and each
# payload appends a 13-char suffix (20 + 13 = 33), so the suffix is what distinguishes mints.
_ALNUM = string.ascii_lowercase + string.digits
CORRELATION_LEN = 20
SUFFIX_LEN = 13

# Interaction blobs are tiny (a captured request excerpt). Cap hard: a poll answer that streams
# forever is a compromised or misbehaving endpoint, not a canary.
MAX_INTERACTION_BYTES = 64 * 1024


class InteractshError(RuntimeError):
    """An interact.sh operation failed. Carries a message meant for the operator."""


def _rand(n: int) -> str:
    return "".join(secrets.choice(_ALNUM) for _ in range(n))


def new_correlation_id() -> str:
    return _rand(CORRELATION_LEN)


def new_suffix() -> str:
    return _rand(SUFFIX_LEN)


def new_keypair() -> tuple[str, str]:
    """(private_pem, public_key_b64). public_key_b64 is base64 of the PKIX PEM — the wire form."""
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
    try:
        blob = base64.b64decode(data_b64)
        if len(blob) > MAX_INTERACTION_BYTES:
            raise InteractshError("interaction exceeds the cap — refusing")
        iv, ciphertext = blob[:16], blob[16:]
        dec = Cipher(algorithms.AES(aes_key), modes.CFB(iv)).decryptor()
        plaintext = dec.update(ciphertext) + dec.finalize()
        obj = json.loads(plaintext.decode("utf-8", "replace"))
    except InteractshError:
        raise
    except Exception as exc:
        raise InteractshError(f"could not decrypt an interaction: {exc}") from exc
    if not isinstance(obj, dict):
        raise InteractshError("a decrypted interaction was not a JSON object")
    return obj
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd backend && python -m pytest test_oob_interactsh.py -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add backend/oob/interactsh.py backend/test_oob_interactsh.py
git commit -m "feat(oob): interact.sh crypto + id generation"
```

---

## Task 2: interact.sh session store + register/deregister (contained HTTP)

**Files:**
- Modify: `backend/oob/interactsh.py`
- Test: `backend/test_oob_interactsh.py`

**Interfaces:**
- Consumes: `new_correlation_id`, `new_suffix`, `new_keypair` (Task 1).
- Produces:
  - `init_db() -> None` — creates `oob_interactsh`, `oob_interactsh_map`, `oob_interactsh_seen`.
  - `is_registered() -> bool`
  - `server() -> str`, `correlation_id() -> str`, `_secret_key() -> str`, `_private_key() -> str`, `_auth_token() -> str` (private accessors for this module only).
  - `session_public() -> dict | None` — masked: `{server, correlation_prefix, generated, registered_at, last_poll, has_secret}`.
  - `register(server=DEFAULT_SERVER, auth_token="") -> dict` — keypair+ids, POST `/register`, store, return masked. Rotates (replaces) any existing session and clears its map/seen.
  - `deregister() -> bool` — POST `/deregister` (best-effort), then forget locally.
  - Contained HTTP seams (monkeypatchable): `_http_post(path, body) -> dict`, `_http_get(path, query) -> dict`.

**Contained-HTTP note:** build `_http_post`/`_http_get` with the same opener shape as `poll.py`: `urllib.request.build_opener(ProxyHandler({}), _NoRedirect())`, byte-capped read, `Authorization` header when an auth token is stored, base target from `server()` as `https://<server>`.

- [ ] **Step 1: Write the failing test (register stores, masks secrets, rotates)**

```python
def test_register_stores_and_masks(tmp_path, monkeypatch):
    monkeypatch.setattr(ish, "DB_PATH", tmp_path / "s.db")
    posted = {}
    monkeypatch.setattr(ish, "_http_post", lambda path, body: posted.update({"path": path, "body": body}) or {"message": "registration successful"})
    ish.init_db()
    pub = ish.register(server="oast.fun")
    assert posted["path"] == "/register"
    assert posted["body"]["correlation-id"] == pub["correlation_prefix"]  # 20-char id
    assert "secret-key" in posted["body"] and "public-key" in posted["body"]
    # masked view never leaks secrets
    assert set(pub) == {"server", "correlation_prefix", "generated", "registered_at", "last_poll", "has_secret"}
    assert pub["has_secret"] is True
    assert ish.is_registered() is True


def test_register_rotates(tmp_path, monkeypatch):
    monkeypatch.setattr(ish, "DB_PATH", tmp_path / "s.db")
    monkeypatch.setattr(ish, "_http_post", lambda path, body: {"message": "ok"})
    ish.init_db()
    first = ish.register()
    second = ish.register()
    assert first["correlation_prefix"] != second["correlation_prefix"]
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd backend && python -m pytest test_oob_interactsh.py -k register -v`
Expected: FAIL — no `init_db`/`register`.

- [ ] **Step 3: Implement store + register/deregister + contained HTTP**

Add to `interactsh.py`: `DB_PATH`, `_connect`, `init_db` (three tables — `oob_interactsh(row_id PK, server, correlation_id, secret_key, private_key, auth_token, registered_at, last_poll, generated)`, `oob_interactsh_map(suffix PK, engagement_id, step_id, note, at)`, `oob_interactsh_seen(uid PK, at)`), the accessors, `session_public`, the `_NoRedirect`/`_opener`/`_http_post`/`_http_get` (copy the containment shape from `poll.py`, base = `https://<server()>`), and:

```python
def register(server: str = DEFAULT_SERVER, auth_token: str = "") -> dict:
    server = (server or DEFAULT_SERVER).strip().lower()
    if not _HOST_RE.match(server):  # reuse config._HOST_RE grammar, defined locally
        raise InteractshError(f"interact.sh server must be a hostname, got {server!r}")
    priv_pem, pub_b64 = new_keypair()
    cid, sk = new_correlation_id(), secrets.token_hex(16)
    _forget()  # drop any prior session + its map/seen (rotation)
    with _write_lock, _connect() as conn:
        conn.execute(
            "INSERT INTO oob_interactsh (row_id, server, correlation_id, secret_key, private_key, "
            "auth_token, registered_at, last_poll, generated) VALUES (?,?,?,?,?,?,?,?,0)",
            (ROW_ID, server, cid, sk, priv_pem, (auth_token or "").strip(), _now(), ""),
        )
    body = {"public-key": pub_b64, "secret-key": sk, "correlation-id": cid}
    resp = _http_post("/register", body)
    # interact.sh returns {"message": "registration successful"}; a non-2xx already raised.
    return session_public()  # type: ignore[return-value]
```

`deregister()` POSTs `{"correlation-id": cid, "secret-key": sk}` to `/deregister` (best-effort — swallow `InteractshError`), then `_forget()`.

- [ ] **Step 4: Run to verify it passes**

Run: `cd backend && python -m pytest test_oob_interactsh.py -k register -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/oob/interactsh.py backend/test_oob_interactsh.py
git commit -m "feat(oob): interact.sh session store + register/deregister"
```

---

## Task 3: interact.sh generate + correlation map

**Files:**
- Modify: `backend/oob/interactsh.py`
- Test: `backend/test_oob_interactsh.py`

**Interfaces:**
- Consumes: session store (Task 2), `new_suffix` (Task 1).
- Produces:
  - `generate(engagement_id: str, step_id: str | None = None, note: str = "") -> dict` — returns `{"host": "<cid><suffix>.<server>", "suffix": suffix, "correlation_id": cid}`; stores the suffix→step mapping; increments `generated`. Raises `InteractshError` if not registered.
  - `correlate_suffix(suffix: str) -> dict | None` — resolve a suffix to `{engagement_id, step_id, note, at}` or None (case-folded, grammar-checked).
  - `clear(engagement_id: str) -> None` — drop one engagement's map rows (parallel to `tokens.clear`).

- [ ] **Step 1: Write the failing test**

```python
def test_generate_and_correlate(tmp_path, monkeypatch):
    monkeypatch.setattr(ish, "DB_PATH", tmp_path / "s.db")
    monkeypatch.setattr(ish, "_http_post", lambda path, body: {"message": "ok"})
    ish.init_db(); ish.register(server="oast.fun")
    g = ish.generate("eng-1", "step-7", "blind ssrf on avatar url")
    assert g["host"].endswith(".oast.fun")
    assert g["host"].startswith(ish.correlation_id())
    assert len(g["suffix"]) == 13
    rec = ish.correlate_suffix(g["suffix"])
    assert rec["engagement_id"] == "eng-1" and rec["step_id"] == "step-7"
    assert ish.correlate_suffix("nope") is None
```

- [ ] **Step 2: Run to verify it fails** — `-k generate`, expect FAIL.

- [ ] **Step 3: Implement generate + correlate_suffix + clear**

```python
def generate(engagement_id: str, step_id: str | None = None, note: str = "") -> dict:
    cid = correlation_id()
    if not cid:
        raise InteractshError("no interact.sh session — register one first")
    suffix = new_suffix()
    host = f"{cid}{suffix}.{server()}"
    with _write_lock, _connect() as conn:
        conn.execute(
            "INSERT INTO oob_interactsh_map (suffix, engagement_id, step_id, note, at) "
            "VALUES (?,?,?,?,?)", (suffix, engagement_id, step_id, note, _now()),
        )
        conn.execute("UPDATE oob_interactsh SET generated = generated + 1 WHERE row_id = ?", (ROW_ID,))
    return {"host": host, "suffix": suffix, "correlation_id": cid}
```

`correlate_suffix` folds case, validates against `^[a-z0-9]{13}$`, returns the row dict or None.

- [ ] **Step 4: Run to verify it passes** — `-k generate`, expect PASS.

- [ ] **Step 5: Commit**

```bash
git commit -am "feat(oob): interact.sh payload generate + correlation map"
```

---

## Task 4: interact.sh poll → decrypt → normalize → correlate

**Files:**
- Modify: `backend/oob/interactsh.py`
- Test: `backend/test_oob_interactsh.py`

**Interfaces:**
- Consumes: `_http_get` (Task 2), `decrypt_aes_key`/`decrypt_interaction` (Task 1), `correlate_suffix` (Task 3).
- Produces:
  - `poll_correlated() -> list[dict]` — GET `/poll?id=<cid>&secret=<sk>`, decrypt each interaction, dedup via `oob_interactsh_seen`, normalize into the hit dict `poll.findings_for` consumes, correlate by suffix. Returns correlated hit dicts. Returns `[]` when not registered. Advances `last_poll`.
  - `_normalize(interaction: dict) -> dict` — map interact.sh fields to the shared hit shape.

**Shared hit dict shape** (what `findings_for` reads): keys `kind` (`"dns"`/`"http"`), `qname`, `qtype`, `host`, `method`, `path`, `source_ip`, `at`, `body` (capped), `token` (the suffix, for display), plus correlation fields added here: `correlated`, `engagement_id`, `step_id`, `note`, `minted_at`.

- [ ] **Step 1: Write the failing test (end-to-end decrypt+correlate with a fake server)**

```python
def test_poll_correlated_decrypts_and_correlates(tmp_path, monkeypatch):
    monkeypatch.setattr(ish, "DB_PATH", tmp_path / "s.db")
    monkeypatch.setattr(ish, "_http_post", lambda path, body: {"message": "ok"})
    ish.init_db(); ish.register(server="oast.fun")
    g = ish.generate("eng-1", "step-7", "blind ssrf")
    uid = ish.correlation_id() + g["suffix"]
    interaction = {"protocol": "dns", "unique-id": uid, "q-type": "A",
                   "remote-address": "10.1.2.3", "timestamp": "2026-08-06T00:00:00Z"}
    pub_b64 = None
    # capture the public key the client registered by re-reading it is not exposed; instead
    # encrypt with a fresh server keypair is wrong — must use the CLIENT public key. Read it:
    import sqlite3
    with sqlite3.connect(ish.DB_PATH) as c:
        priv_pem = c.execute("SELECT private_key FROM oob_interactsh").fetchone()[0]
    from cryptography.hazmat.primitives import serialization
    pub = serialization.load_pem_private_key(priv_pem.encode(), password=None).public_key()
    pub_b64 = base64.b64encode(pub.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
    aes_key_b64, data_b64 = _server_encrypt(pub_b64, interaction)
    monkeypatch.setattr(ish, "_http_get", lambda path, query: {"data": [data_b64], "aes_key": aes_key_b64})
    hits = ish.poll_correlated()
    assert len(hits) == 1
    h = hits[0]
    assert h["kind"] == "dns" and h["source_ip"] == "10.1.2.3"
    assert h["correlated"] is True and h["engagement_id"] == "eng-1" and h["step_id"] == "step-7"
    # dedup: a second identical poll yields nothing new
    assert ish.poll_correlated() == []
```

- [ ] **Step 2: Run to verify it fails** — `-k poll_correlated`, expect FAIL.

- [ ] **Step 3: Implement `_normalize` + `poll_correlated`**

`_normalize` reads `protocol`→`kind`, `q-type`→`qtype`, `unique-id`→derive `qname`(dns)/`host`(http) and the suffix (chars `CORRELATION_LEN:CORRELATION_LEN+SUFFIX_LEN`), `remote-address`→`source_ip`, `timestamp`→`at`, a capped excerpt of `raw-request`→`body`. `poll_correlated` decrypts the `aes_key` once, iterates `data`, skips uids already in `oob_interactsh_seen`, normalizes, `correlate_suffix`, appends `correlated`/`engagement_id`/`step_id`/`note`/`minted_at`, records the uid in `seen`, updates `last_poll`.

- [ ] **Step 4: Run to verify it passes** — `-k poll_correlated`, expect PASS.

- [ ] **Step 5: Commit**

```bash
git commit -am "feat(oob): interact.sh poll → decrypt → normalize → correlate"
```

---

## Task 5: containment tests for the interact.sh HTTP seam

**Files:**
- Modify: `backend/test_oob_interactsh.py`

**Interfaces:** Consumes the `_opener`/`_http_get` from Task 2.

- [ ] **Step 1: Write the tests**

```python
def test_opener_follows_no_redirect_and_no_proxy():
    op = ish._opener()
    handlers = {type(h).__name__ for h in op.handlers}
    assert "_NoRedirect" in handlers
    # ProxyHandler present but empty (no ambient proxy honoured)
    proxies = [h for h in op.handlers if type(h).__name__ == "ProxyHandler"]
    assert proxies and proxies[0].proxies == {}


def test_session_public_never_returns_secrets(tmp_path, monkeypatch):
    monkeypatch.setattr(ish, "DB_PATH", tmp_path / "s.db")
    monkeypatch.setattr(ish, "_http_post", lambda p, b: {"message": "ok"})
    ish.init_db(); ish.register(auth_token="supersecrettoken")
    pub = ish.session_public()
    blob = repr(pub)
    assert "supersecrettoken" not in blob
    assert "secret_key" not in pub and "private_key" not in pub and "auth_token" not in pub
```

- [ ] **Step 2: Run — expect PASS** (these assert already-built behaviour; if either fails, fix `interactsh.py`, not the test).

- [ ] **Step 3: Commit**

```bash
git commit -am "test(oob): interact.sh containment + secret-masking"
```

---

## Task 6: `poll.poll_all()` — sweep both backends, merge, file

**Files:**
- Modify: `backend/oob/poll.py`
- Test: `backend/test_oob_poll.py`

**Interfaces:**
- Consumes: existing `fetch`, `correlate`, `ingest`, `config` (self-hosted); `interactsh.is_registered`, `interactsh.poll_correlated` (Tasks 2/4).
- Produces: `poll_all(sessions: dict[str, str] | None = None, after: int | None = None) -> dict` returning `{"self_hosted": {...}|None, "interactsh": {...}|None, "hits": [...], "filed": int, "unfiled": [...], "errors": [...]}`.

**Behaviour:** gather correlated dicts from each configured backend independently; a backend that raises records an entry in `errors` and does **not** stop the other or advance its own cursor. `ingest()` is called once on the merged list. Self-hosted cursor advances only on its own success (unchanged rule); interact.sh dedup is handled inside `poll_correlated` via `seen`.

- [ ] **Step 1: Write the failing test**

```python
# backend/test_oob_poll.py (add)
import oob.poll as poll_mod
import oob.interactsh as ish

def test_poll_all_merges_both(monkeypatch):
    monkeypatch.setattr(poll_mod.config, "is_configured", lambda: True)
    monkeypatch.setattr(poll_mod, "fetch", lambda after=None: {"hits": [{"token": "aaaa", "kind": "dns"}], "cursor": 5, "after": 0})
    monkeypatch.setattr(poll_mod, "correlate", lambda hits: [{**h, "correlated": False, "engagement_id": None, "step_id": None, "note": "", "minted_at": None} for h in hits])
    monkeypatch.setattr(poll_mod.config, "set_cursor", lambda v: None)
    monkeypatch.setattr(ish, "is_registered", lambda: True)
    monkeypatch.setattr(ish, "poll_correlated", lambda: [{"kind": "http", "correlated": True, "engagement_id": "e1", "step_id": "s1", "note": "x", "host": "h", "source_ip": "1.1.1.1", "at": "t"}])
    filed = {"count": 0}
    monkeypatch.setattr(poll_mod, "ingest", lambda correlated, sessions: {"filed": len(list(correlated)), "unfiled": []})
    out = poll_mod.poll_all(sessions={"e1": "sess-1"})
    assert len(out["hits"]) == 2
    assert out["self_hosted"] is not None and out["interactsh"] is not None


def test_poll_all_one_backend_error_does_not_stop_other(monkeypatch):
    monkeypatch.setattr(poll_mod.config, "is_configured", lambda: True)
    def boom(after=None): raise poll_mod.PollError("down")
    monkeypatch.setattr(poll_mod, "fetch", boom)
    monkeypatch.setattr(ish, "is_registered", lambda: True)
    monkeypatch.setattr(ish, "poll_correlated", lambda: [{"kind": "dns", "correlated": True, "engagement_id": "e1", "step_id": None, "note": "", "source_ip": "2.2.2.2", "at": "t"}])
    monkeypatch.setattr(poll_mod, "ingest", lambda correlated, sessions: {"filed": len(list(correlated)), "unfiled": []})
    out = poll_mod.poll_all(sessions={"e1": "sess-1"})
    assert any("down" in e["reason"] for e in out["errors"])
    assert out["filed"] == 1  # interact.sh hit still filed
```

- [ ] **Step 2: Run to verify it fails** — expect FAIL (`poll_all` undefined).

- [ ] **Step 3: Implement `poll_all`** (guard each backend in try/except, merge, single `ingest`, advance self-hosted cursor only on success).

- [ ] **Step 4: Run to verify it passes.**

- [ ] **Step 5: Commit**

```bash
git commit -am "feat(oob): poll_all sweeps self-hosted + interact.sh and merges"
```

---

## Task 7: `templates.py` — interact.sh callback shape

**Files:**
- Modify: `backend/oob/templates.py`
- Test: `backend/test_oob_templates.py`

**Interfaces:**
- Produces: `Callback.for_host(host: str) -> Callback` classmethod (or an `interactsh_host` field) so `fqdn` returns the full interact.sh host and the per-class catalog renders unchanged. `render_all(token=None, *, host=None, vuln_class=None)` accepts either a self-hosted `(token+zone)` or an interact.sh `host`.

- [ ] **Step 1: Write the failing test**

```python
import oob.templates as t
def test_render_all_for_interactsh_host():
    payloads = t.render_all(host="abc123def456.oast.fun")
    assert payloads, "expected a catalog"
    joined = " ".join(p["payload"] for p in payloads)
    assert "abc123def456.oast.fun" in joined
    assert "<token>" not in joined
```

- [ ] **Step 2: Run — expect FAIL.**

- [ ] **Step 3: Implement** the `host=` path in `Callback`/`render_all`; when `host` is given, `fqdn == host` and any zone-derived shapes use the host directly. Keep the existing `token`+zone path untouched.

- [ ] **Step 4: Run — expect PASS.** Also run the full `test_oob_templates.py` to confirm the render-a-string boundary test still passes.

- [ ] **Step 5: Commit**

```bash
git commit -am "feat(oob): templates render for an interact.sh host"
```

---

## Task 8: settings + auto-poll background loop

**Files:**
- Create: `backend/oob/settings.py`
- Create: `backend/oob/autopoll.py`
- Test: `backend/test_oob_interactsh.py` (settings) + `backend/test_oob_poll.py` (loop tick)

**Interfaces:**
- `settings.init_db()`, `settings.get() -> {"enabled": bool, "interval": int}`, `settings.set(enabled: bool, interval: int) -> dict`. Interval floored at 30s. Default `enabled=True` (auto-enable), `interval=60`.
- `autopoll.tick() -> dict` — one sweep: resolve `engagement.session_ids()`, call `poll.poll_all(...)`, swallow+log errors, return the result. Pure enough to unit-test.
- `autopoll.start(app) -> None` — spawn a daemon thread that loops `tick()` every `settings.get()["interval"]` while `enabled` and at least one backend is configured. Started from the lifespan; mirrors `cockpit_reconcile.check_in_background`'s thread pattern.

- [ ] **Step 1: Write the failing tests**

```python
# settings
import oob.settings as st
def test_settings_default_and_floor(tmp_path, monkeypatch):
    monkeypatch.setattr(st, "DB_PATH", tmp_path / "s.db")
    st.init_db()
    assert st.get() == {"enabled": True, "interval": 60}
    assert st.set(enabled=False, interval=5)["interval"] == 30  # floored

# tick
import oob.autopoll as ap
def test_tick_calls_poll_all(monkeypatch):
    called = {}
    monkeypatch.setattr(ap.poll_mod, "poll_all", lambda sessions, after=None: called.update(sessions=sessions) or {"filed": 0, "hits": [], "unfiled": [], "errors": []})
    monkeypatch.setattr(ap.engagement_mod, "session_ids", lambda: {"e1": "s1"})
    out = ap.tick()
    assert called["sessions"] == {"e1": "s1"}
    assert out["filed"] == 0
```

- [ ] **Step 2: Run — expect FAIL.**

- [ ] **Step 3: Implement** `settings.py` (single-row table `oob_settings`), `autopoll.tick()` and `autopoll.start()` (daemon thread; guard: do nothing when both backends unconfigured; catch every exception per tick and continue).

- [ ] **Step 4: Run — expect PASS.**

- [ ] **Step 5: Commit**

```bash
git commit -am "feat(oob): auto-poll settings + background sweep loop"
```

---

## Task 9: router — interact.sh routes, autopoll, backend-aware mint/poll/verify

**Files:**
- Modify: `backend/oob/router.py`
- Modify: `backend/oob/verify.py`
- Test: `backend/test_oob_server.py` or a router test using FastAPI `TestClient`.

**Interfaces:**
- `GET /oob` — add `"interactsh": interactsh.session_public()` and `"autopoll": settings.get()`.
- `POST /oob/interactsh/register` (body: `{server?, auth_token?}`) → `interactsh.register(...)`.
- `DELETE /oob/interactsh` → `interactsh.deregister()`.
- `POST /oob/autopoll` (body: `{enabled: bool, interval: int}`) → `settings.set(...)`.
- `POST /oob/mint` — after minting the self-hosted token/payloads (only if `config.is_configured()`), also, if `interactsh.is_registered()`, call `interactsh.generate(...)` and `templates.render_all(host=...)`; return `{"backends": {"self_hosted": {...}|None, "interactsh": {...}|None}}`. **At least one backend must be configured** or 400 (reason names both options).
- `POST /oob/poll` → `poll_mod.poll_all(engagement_mod.session_ids(), after=req.after)`.
- `POST /oob/verify` → `verify.verify()` now includes an interact.sh live check.

- [ ] **Step 1: Write the failing test (register + status via TestClient, HTTP mocked)**

```python
from fastapi.testclient import TestClient
def test_register_and_status(monkeypatch, tmp_path):
    import oob.interactsh as ish, oob.settings as st
    monkeypatch.setattr(ish, "DB_PATH", tmp_path / "s.db")
    monkeypatch.setattr(st, "DB_PATH", tmp_path / "s.db")
    monkeypatch.setattr(ish, "_http_post", lambda p, b: {"message": "ok"})
    ish.init_db(); st.init_db()
    from main import app
    c = TestClient(app)
    r = c.post("/oob/interactsh/register", json={"server": "oast.fun"})
    assert r.status_code == 200 and r.json()["has_secret"] is True
    g = c.get("/oob").json()
    assert g["interactsh"]["server"] == "oast.fun"
    assert "autopoll" in g
```

- [ ] **Step 2: Run — expect FAIL.**

- [ ] **Step 3: Implement** the routes + Pydantic models (`InteractshRegisterRequest`, `AutopollRequest`), backend-aware `post_mint`, `post_poll`→`poll_all`, and the interact.sh check in `verify.py` (register-if-needed → generate → probe by resolving/HTTPing the host → poll → assert correlated; report each step; it may run live, unlike the self-hosted check 3).

- [ ] **Step 4: Run — expect PASS.**

- [ ] **Step 5: Commit**

```bash
git commit -am "feat(oob): router + verify wired for interact.sh, autopoll, dual-backend mint"
```

---

## Task 10: wire into main.py lifespan

**Files:**
- Modify: `backend/main.py`

- [ ] **Step 1** (no test — integration): in `lifespan`, after the existing `oob_*.init_db()` calls (~line 320), add `oob_interactsh.init_db()` and `oob_settings.init_db()`; after the reconcile thread (~line 358) add `oob_autopoll.start(app)`. Add the imports near lines 94-96.

- [ ] **Step 2: Verify the app boots** — `cd backend && python -c "import main; print('ok')"` and `python -m pytest test_oob_server.py -q`.

- [ ] **Step 3: Commit**

```bash
git commit -am "feat(oob): init interact.sh tables + start auto-poll in lifespan"
```

---

## Task 11: safety-scan parity + repeater docstring drift fix

**Files:**
- Modify: `backend/test_oob_deploy_safety.py` (or create `backend/test_oob_interactsh_safety.py`)
- Modify: `backend/cockpit/repeater.py`

**Interfaces:** the existing whole-tree scans (`test_scans.py`) auto-cover new modules; these tests add interact.sh-specific assertions.

- [ ] **Step 1: Write the tests**

```python
def test_interactsh_reaches_no_execution_surface():
    src = (Path(__file__).parent / "oob" / "interactsh.py").read_text()
    for banned in ("subprocess", "os.system", "run_kali", "executor", "docker exec", "eval(", "exec("):
        assert banned not in src, f"interactsh.py must not reference {banned}"

def test_autopoll_reaches_no_execution_surface():
    src = (Path(__file__).parent / "oob" / "autopoll.py").read_text()
    for banned in ("subprocess", "run_kali", "executor", "eval(", "exec("):
        assert banned not in src

def test_oob_does_not_import_repeater():
    for name in ("interactsh", "poll", "router", "autopoll"):
        src = (Path(__file__).parent / "oob" / f"{name}.py").read_text()
        assert "repeater" not in src, f"{name}.py must not couple to the repeater (human-only guard)"
```

- [ ] **Step 2: Run — expect PASS** (fix source if any fails).

- [ ] **Step 3: Fix the repeater docstring** — replace the stale lines ~41-44 ("still deferred until bounty work needs it (D2)") with a note that the OOB canary shipped (build #13 part 3) and now has two backends; the repeater still only sends and reads the direct response.

- [ ] **Step 4: Run the full safety suite** — `sh backend/run_safety_tests.sh`, expect all green.

- [ ] **Step 5: Commit**

```bash
git commit -am "test(oob): interact.sh safety parity; fix stale repeater callback note"
```

---

## Task 12: frontend — interact.sh config/status, auto-poll toggle, send-to-repeater

**Files:**
- Modify: `frontend/src/components/OOBCanaryScreen.tsx`

**Constraint:** follow the `hp-tn-*` class vocabulary (see the frontend memory) — bare `.hp-card` renders invisible. A frontend change is not verified until it has been LOOKED AT in the browser.

- [ ] **Step 1** Add an "interact.sh" section: register form (server default `oast.fun`, optional auth token), status line (server, correlation prefix, generated count, last poll) from `GET /oob`.`interactsh`, and a deregister button.
- [ ] **Step 2** Add an auto-poll toggle + interval bound to `POST /oob/autopoll`, reading `GET /oob`.`autopoll`.
- [ ] **Step 3** In the mint result, render both backends' payloads (labeled). Add a **"Send to repeater"** button per payload that navigates to the repeater screen with the payload pre-filled (client-side state seed — no backend call).
- [ ] **Step 4** Verify in the browser: `npm --prefix frontend run dev`, open the OOB screen, confirm the section renders (not invisible), register against oast.fun, mint, see both payload sets, click send-to-repeater and confirm it lands pre-filled.
- [ ] **Step 5: Commit**

```bash
git commit -am "feat(oob): interact.sh panel, auto-poll toggle, send-to-repeater"
```

---

## Task 13: live network proof against oast.fun

**Files:**
- Create: `docs/proof/oob_interactsh_proof.py`

- [ ] **Step 1** Write a standalone script (run outside the hermetic suite) that: `register()` against `oast.fun`, `generate()` a host, DNS-resolves that host (or HTTP-GETs it) to trigger a real interaction, sleeps briefly, `poll_correlated()`, and asserts exactly one correlated hit came back and decrypted. Print PASS/FAIL with the hit. This is the "it actually works" proof the self-hosted backend cannot run without a VPS.
- [ ] **Step 2** Run it live: `cd backend && python ../docs/proof/oob_interactsh_proof.py` (needs outbound DNS+HTTP). If the classifier blocks it, hand Zaid the `!` line. Record the log under `docs/proof/`.
- [ ] **Step 3: Commit**

```bash
git add docs/proof/oob_interactsh_proof.py
git commit -m "proof(oob): live interact.sh round-trip against oast.fun"
```

---

## Task 14: assessment doc + PDF regen

**Files:**
- Modify: `docs/ASSESSMENT-2026-07-26.md`
- Regenerate: `.html` + `.pdf`

- [ ] **Step 1** Add to the OOB section: OOB now has **two backends**; the interact.sh backend catches callbacks with zero infrastructure but **transits a third party** (ProjectDiscovery) — the privacy tradeoff stated plainly, which is why the owned self-hosted backend remains; the new outbound poll's containment matches the self-hosted poll; **auto-poll** is read-only automation (reads the operator's own callbacks) and does **not** cross the propose-only invariant; **send-to-repeater** keeps delivery a human action.
- [ ] **Step 2** Regenerate: `python docs/build-assessment.py`. Verify against the **HTML** and the page-count delta — never grep the PDF.
- [ ] **Step 3: Commit** (assessment md + html + pdf in one commit).

```bash
git add docs/ASSESSMENT-2026-07-26.md docs/ASSESSMENT-2026-07-26.html docs/ASSESSMENT-2026-07-26.pdf
git commit -m "docs: record interact.sh second OOB backend + auto-poll in the assessment"
```

---

## Self-Review

**Spec coverage:** §2 in→ Tasks 1-9,12-14; §4.1 interactsh.py→ Tasks 1-4; §4.2 poll_all→ Task 6; §4.3 templates→ Task 7; §4.4 auto-poll→ Task 8; §4.5 send-to-repeater→ Task 12; §4.6 router→ Task 9; §5 containment→ Tasks 5,11; §6 verify hermetic+proof→ Tasks 4,9,13; §7 docs + repeater drift→ Tasks 11,14. All covered.

**Placeholder scan:** no TBD/TODO; each code step carries real code or a precise field-level spec.

**Type consistency:** the shared hit dict keys (`kind`/`qname`/`host`/`source_ip`/`at`/`correlated`/`engagement_id`/`step_id`/`note`/`minted_at`) match what `poll.findings_for()` reads (verified against `poll.py:237-301`). `register`/`generate`/`poll_correlated`/`poll_all`/`session_public` signatures are consistent across Tasks 2-9.
