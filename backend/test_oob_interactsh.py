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
