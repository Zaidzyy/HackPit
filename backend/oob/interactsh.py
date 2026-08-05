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
import secrets
import string

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
