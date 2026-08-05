"""Hermetic tests for the interact.sh OOB backend (backend/oob/interactsh.py).

No network: the interact.sh server is simulated in-process. ``_server_encrypt`` does exactly
what the real server does to an interaction — AES-256-CFB the JSON, RSA-OAEP-SHA256 the AES key
with the client's registered public key — so the crypto round-trip is exercised for real.
"""

import base64
import json
import os
import sqlite3

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

try:
    from cryptography.hazmat.decrepit.ciphers.modes import CFB
except ImportError:  # pragma: no cover
    from cryptography.hazmat.primitives.ciphers.modes import CFB

import oob.interactsh as ish


# --------------------------------------------------------------------------- #
# a stand-in for the interact.sh server side
# --------------------------------------------------------------------------- #
def _server_encrypt(public_key_b64: str, interaction: dict) -> tuple[str, str]:
    """Encrypt an interaction the way interact.sh does. Returns (aes_key_b64, data_b64)."""
    pem = base64.b64decode(public_key_b64)
    pub = serialization.load_pem_public_key(pem)
    aes_key = os.urandom(32)
    iv = os.urandom(16)
    enc = Cipher(algorithms.AES(aes_key), CFB(iv)).encryptor()
    blob = iv + enc.update(json.dumps(interaction).encode()) + enc.finalize()
    aes_key_b64 = base64.b64encode(
        pub.encrypt(
            aes_key,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )
    ).decode()
    return aes_key_b64, base64.b64encode(blob).decode()


def _public_key_b64_from_db(db_path) -> str:
    """Re-derive the base64 PKIX public key from the private key the client stored."""
    with sqlite3.connect(db_path) as conn:
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
    assert ish.new_correlation_id() != cid  # distinct across calls


def test_crypto_round_trip():
    priv_pem, pub_b64 = ish.new_keypair()
    interaction = {"protocol": "dns", "unique-id": "x" * 33, "remote-address": "1.2.3.4"}
    aes_key_b64, data_b64 = _server_encrypt(pub_b64, interaction)
    aes_key = ish.decrypt_aes_key(priv_pem, aes_key_b64)
    got = ish.decrypt_interaction(aes_key, data_b64)
    assert got["protocol"] == "dns"
    assert got["remote-address"] == "1.2.3.4"


def test_decrypt_rejects_garbage():
    with pytest.raises(ish.InteractshError):
        ish.decrypt_interaction(b"\x00" * 32, "not-base64-@@@")


# --------------------------------------------------------------------------- #
# Task 2 — session store + register/deregister
# --------------------------------------------------------------------------- #
def test_register_stores_and_masks(tmp_path, monkeypatch):
    monkeypatch.setattr(ish, "DB_PATH", tmp_path / "s.db")
    posted = {}
    monkeypatch.setattr(
        ish, "_http_post",
        lambda path, body: posted.update({"path": path, "body": body}) or {"message": "ok"},
    )
    ish.init_db()
    pub = ish.register(server_host="oast.fun")
    assert posted["path"] == "/register"
    assert posted["body"]["correlation-id"] == pub["correlation_prefix"]
    assert "secret-key" in posted["body"] and "public-key" in posted["body"]
    assert set(pub) == {
        "server", "correlation_prefix", "generated", "registered_at", "last_poll", "has_secret",
    }
    assert pub["has_secret"] is True
    assert ish.is_registered() is True
    assert ish.server() == "oast.fun"


def test_register_rotates(tmp_path, monkeypatch):
    monkeypatch.setattr(ish, "DB_PATH", tmp_path / "s.db")
    monkeypatch.setattr(ish, "_http_post", lambda path, body: {"message": "ok"})
    ish.init_db()
    first = ish.register()
    second = ish.register()
    assert first["correlation_prefix"] != second["correlation_prefix"]


def test_register_rolls_back_on_server_refusal(tmp_path, monkeypatch):
    monkeypatch.setattr(ish, "DB_PATH", tmp_path / "s.db")

    def boom(path, body):
        raise ish.InteractshError("server said no")

    monkeypatch.setattr(ish, "_http_post", boom)
    ish.init_db()
    with pytest.raises(ish.InteractshError):
        ish.register()
    assert ish.is_registered() is False  # no half-registered session left behind


def test_deregister_forgets(tmp_path, monkeypatch):
    monkeypatch.setattr(ish, "DB_PATH", tmp_path / "s.db")
    monkeypatch.setattr(ish, "_http_post", lambda path, body: {"message": "ok"})
    ish.init_db()
    ish.register()
    assert ish.deregister() is True
    assert ish.is_registered() is False
    assert ish.deregister() is False  # nothing to do the second time


# --------------------------------------------------------------------------- #
# Task 3 — generate + correlation map
# --------------------------------------------------------------------------- #
def test_generate_and_correlate(tmp_path, monkeypatch):
    monkeypatch.setattr(ish, "DB_PATH", tmp_path / "s.db")
    monkeypatch.setattr(ish, "_http_post", lambda path, body: {"message": "ok"})
    ish.init_db()
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


def test_generate_requires_session(tmp_path, monkeypatch):
    monkeypatch.setattr(ish, "DB_PATH", tmp_path / "s.db")
    ish.init_db()
    with pytest.raises(ish.InteractshError):
        ish.generate("eng-1")


def test_clear_drops_engagement_map(tmp_path, monkeypatch):
    monkeypatch.setattr(ish, "DB_PATH", tmp_path / "s.db")
    monkeypatch.setattr(ish, "_http_post", lambda path, body: {"message": "ok"})
    ish.init_db()
    ish.register()
    g = ish.generate("eng-1", "step-1")
    ish.clear("eng-1")
    assert ish.correlate_suffix(g["suffix"]) is None
