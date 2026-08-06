"""Hermetic tests for the interact.sh OOB backend (backend/oob/interactsh.py).

No network: the interact.sh server is simulated in-process. ``_server_encrypt`` does exactly
what the real server does to an interaction — AES-256-CTR the JSON, RSA-OAEP-SHA256 the AES key
with the client's registered public key — so the crypto round-trip is exercised for real.

Standalone by convention (the safety runner executes ``python test_x.py``, not pytest): no
fixtures, a context manager points DB_PATH at a temp file and stubs the HTTP seam, and a
``__main__`` block runs every test.

Run: python test_oob_interactsh.py
"""

from __future__ import annotations

import base64
import contextlib
import json
import os
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding  # noqa: E402
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa: E402

from oob import interactsh as ish  # noqa: E402


# --------------------------------------------------------------------------- #
# harness — a temp DB + a stubbed HTTP seam, restored on exit
# --------------------------------------------------------------------------- #
@contextlib.contextmanager
def session(*, post=None, get=None):
    d = tempfile.mkdtemp()
    saved = (ish.DB_PATH, ish._http_post, ish._http_get)
    ish.DB_PATH = Path(d) / "s.db"
    if post is not None:
        ish._http_post = post
    if get is not None:
        ish._http_get = get
    try:
        ish.init_db()
        yield
    finally:
        ish.DB_PATH, ish._http_post, ish._http_get = saved
        shutil.rmtree(d, ignore_errors=True)


def _ok(path, body):
    return {"message": "ok"}


@contextlib.contextmanager
def raises(exc):
    try:
        yield
    except exc:
        return
    raise AssertionError(f"expected {exc.__name__}")


# --------------------------------------------------------------------------- #
# a stand-in for the interact.sh server side
# --------------------------------------------------------------------------- #
def _server_encrypt(public_key_b64: str, interaction: dict) -> tuple[str, str]:
    """Encrypt an interaction the way interact.sh does. Returns (aes_key_b64, data_b64)."""
    pem = base64.b64decode(public_key_b64)
    pub = serialization.load_pem_public_key(pem)
    aes_key = os.urandom(32)
    iv = os.urandom(16)
    enc = Cipher(algorithms.AES(aes_key), modes.CTR(iv)).encryptor()
    blob = iv + enc.update(json.dumps(interaction).encode()) + enc.finalize()
    aes_key_b64 = base64.b64encode(
        pub.encrypt(
            aes_key,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )
    ).decode()
    return aes_key_b64, base64.b64encode(blob).decode()


def _public_key_b64_from_db() -> str:
    with sqlite3.connect(ish.DB_PATH) as conn:
        priv_pem = conn.execute("SELECT private_key FROM oob_interactsh").fetchone()[0]
    pub = serialization.load_pem_private_key(priv_pem.encode(), password=None).public_key()
    return base64.b64encode(
        pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    ).decode()


# --------------------------------------------------------------------------- #
# Task 1 — crypto + id generation
# --------------------------------------------------------------------------- #
def test_id_generation_shapes():
    cid = ish.new_correlation_id()
    suf = ish.new_suffix()
    assert len(cid) == 20 and cid.isalnum() and cid.islower()
    assert len(suf) == 13 and suf.isalnum() and suf.islower()
    assert ish.new_correlation_id() != cid


def test_crypto_round_trip():
    priv_pem, pub_b64 = ish.new_keypair()
    interaction = {"protocol": "dns", "unique-id": "x" * 33, "remote-address": "1.2.3.4"}
    aes_key_b64, data_b64 = _server_encrypt(pub_b64, interaction)
    aes_key = ish.decrypt_aes_key(priv_pem, aes_key_b64)
    got = ish.decrypt_interaction(aes_key, data_b64)
    assert got["protocol"] == "dns"
    assert got["remote-address"] == "1.2.3.4"


def test_decrypt_rejects_garbage():
    with raises(ish.InteractshError):
        ish.decrypt_interaction(b"\x00" * 32, "not-base64-@@@")


# --------------------------------------------------------------------------- #
# Task 2 — session store + register/deregister
# --------------------------------------------------------------------------- #
def test_register_stores_and_masks():
    posted = {}

    def capture(path, body):
        posted.update({"path": path, "body": body})
        return {"message": "ok"}

    with session(post=capture):
        pub = ish.register(server_host="oast.fun")
    assert posted["path"] == "/register"
    assert posted["body"]["correlation-id"] == pub["correlation_prefix"]
    assert "secret-key" in posted["body"] and "public-key" in posted["body"]
    assert set(pub) == {
        "server", "correlation_prefix", "generated", "registered_at", "last_poll", "has_secret",
    }
    assert pub["has_secret"] is True


def test_register_rotates():
    with session(post=_ok):
        first = ish.register()
        second = ish.register()
        assert first["correlation_prefix"] != second["correlation_prefix"]


def test_register_rolls_back_on_server_refusal():
    def boom(path, body):
        raise ish.InteractshError("server said no")

    with session(post=boom):
        with raises(ish.InteractshError):
            ish.register()
        assert ish.is_registered() is False


def test_deregister_forgets():
    with session(post=_ok):
        ish.register()
        assert ish.deregister() is True
        assert ish.is_registered() is False
        assert ish.deregister() is False


# --------------------------------------------------------------------------- #
# Task 3 — generate + correlation map
# --------------------------------------------------------------------------- #
def test_generate_and_correlate():
    with session(post=_ok):
        ish.register(server_host="oast.fun")
        g = ish.generate("eng-1", "step-7", "blind ssrf on avatar url")
        assert g["host"].endswith(".oast.fun")
        assert g["host"].startswith(ish.correlation_id())
        assert len(g["suffix"]) == 13
        rec = ish.correlate_suffix(g["suffix"])
        assert rec["engagement_id"] == "eng-1" and rec["step_id"] == "step-7"
        assert rec["note"] == "blind ssrf on avatar url"
        assert ish.correlate_suffix("nope") is None
        assert ish.correlate_suffix(g["suffix"].upper()) is not None  # case-folded
        assert ish.session_public()["generated"] == 1


def test_generate_requires_session():
    with session():
        with raises(ish.InteractshError):
            ish.generate("eng-1")


def test_clear_drops_engagement_map():
    with session(post=_ok):
        ish.register()
        g = ish.generate("eng-1", "step-1")
        ish.clear("eng-1")
        assert ish.correlate_suffix(g["suffix"]) is None


# --------------------------------------------------------------------------- #
# Task 4 — poll -> decrypt -> normalize -> correlate
# --------------------------------------------------------------------------- #
def test_poll_correlated_decrypts_and_correlates():
    holder = {}

    def get(path, query):
        return holder["answer"]

    with session(post=_ok, get=get):
        ish.register(server_host="oast.fun")
        g = ish.generate("eng-1", "step-7", "blind ssrf")
        uid = ish.correlation_id() + g["suffix"]
        interaction = {
            "protocol": "dns", "unique-id": uid, "q-type": "A",
            "remote-address": "10.1.2.3", "timestamp": "2026-08-06T00:00:00Z",
        }
        aes_key_b64, data_b64 = _server_encrypt(_public_key_b64_from_db(), interaction)
        holder["answer"] = {"data": [data_b64], "aes_key": aes_key_b64}
        hits = ish.poll_correlated()
        assert len(hits) == 1
        h = hits[0]
        assert h["kind"] == "dns" and h["source_ip"] == "10.1.2.3"
        assert h["qname"] == f"{uid}.oast.fun"
        assert h["correlated"] is True
        assert h["engagement_id"] == "eng-1" and h["step_id"] == "step-7" and h["note"] == "blind ssrf"
        # dedup: the same answer yields nothing new
        assert ish.poll_correlated() == []


def test_poll_keeps_uncorrelated_hit():
    holder = {}

    def get(path, query):
        return holder["answer"]

    with session(post=_ok, get=get):
        ish.register(server_host="oast.fun")
        uid = ish.correlation_id() + "zzzzzzzzzzzzz"  # a suffix we never minted
        interaction = {
            "protocol": "http", "unique-id": uid,
            "raw-request": "GET /probe HTTP/1.1\r\nHost: x\r\n",
            "remote-address": "8.8.8.8", "timestamp": "2026-08-06T01:00:00Z",
        }
        aes_key_b64, data_b64 = _server_encrypt(_public_key_b64_from_db(), interaction)
        holder["answer"] = {"data": [data_b64], "aes_key": aes_key_b64}
        hits = ish.poll_correlated()
        assert len(hits) == 1
        assert hits[0]["correlated"] is False
        assert hits[0]["method"] == "GET" and hits[0]["path"] == "/probe"


def test_poll_empty_when_no_session():
    with session():
        assert ish.poll_correlated() == []


# --------------------------------------------------------------------------- #
# Task 5 — containment + secret masking
# --------------------------------------------------------------------------- #
def test_opener_follows_no_redirect_and_no_proxy():
    op = ish._opener()
    names = {type(h).__name__ for h in op.handlers}
    assert "_NoRedirect" in names
    # No ProxyHandler at all: an empty ProxyHandler({}) registers no *_open methods, so
    # build_opener drops it — which is the intended "honour no ambient proxy" (same as poll.py).
    assert "ProxyHandler" not in names


def test_session_public_never_returns_secrets():
    with session(post=_ok):
        ish.register(auth_token="supersecrettoken0000")
        pub = ish.session_public()
        assert "supersecrettoken0000" not in repr(pub)
        assert "secret_key" not in pub and "private_key" not in pub and "auth_token" not in pub


if __name__ == "__main__":
    print("== interact.sh OOB backend (spec 2026-08-06) ==")
    test_id_generation_shapes()
    test_crypto_round_trip()
    test_decrypt_rejects_garbage()
    test_register_stores_and_masks()
    test_register_rotates()
    test_register_rolls_back_on_server_refusal()
    test_deregister_forgets()
    test_generate_and_correlate()
    test_generate_requires_session()
    test_clear_drops_engagement_map()
    test_poll_correlated_decrypts_and_correlates()
    test_poll_keeps_uncorrelated_hit()
    test_poll_empty_when_no_session()
    test_opener_follows_no_redirect_and_no_proxy()
    test_session_public_never_returns_secrets()
    print("ALL interact.sh backend tests pass")
