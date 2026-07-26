"""Credential vault — fill the <user> / <password> / <hash> placeholders from state.

The AD templates in the arsenal carry literal ``<PASSWORD>`` / ``<NTLM-HASH>`` / ``<USER>``
placeholders that the operator had to retype every single time — the hash from a
secretsdump run, the username, the domain. Phase 2 already CAPTURES those into the state
credential store; this maps a stored credential onto the placeholders a command uses, so
filling one is a click instead of copy-paste.

ONE SOURCE OF TRUTH. The placeholder-to-field mapping lives here and only here. The UI does
not re-implement it — it POSTs the command + which credential to use and gets the filled
command back — so the mapping cannot drift between front and back (the trap that bit the
arsenal response model). See [[attack-step-schema-three-places]] in spirit.

SCOPE OF WHAT IT FILLS. Credential placeholders only: user, password, hash, domain. It does
NOT touch ``<target>`` (that is the composer's job, host-locked) or operational placeholders
like ``<lport>``. Filling is opt-in per command (the operator clicks "use" on a specific
credential) — nothing auto-substitutes a secret behind their back, which is the whole reason
the recommended design was click-to-insert rather than silent template auto-fill.

This module executes nothing. It maps a data record to string substitutions.
"""

from __future__ import annotations

import re
from typing import Iterable

from .models import Credential

# Every placeholder spelling a template might use for a given credential field, lower-cased.
# A tool's template may say <user>, <username>, <spn-user> — all mean "the account name".
# Matched case-insensitively so <PASSWORD> and <password> both fill.
_USER_KEYS = ("user", "username", "spn-user", "principal", "account")
_PASS_KEYS = ("password", "pass", "pwd")
_HASH_KEYS = ("hash", "ntlm-hash", "nt-hash", "nthash", "ntlm")
_DOMAIN_KEYS = ("domain", "realm")

_PLACEHOLDER_RE = re.compile(r"<([a-zA-Z][a-zA-Z0-9-]*)>")


def _values_for(cred: Credential) -> dict[str, str]:
    """The concrete substitutions a single credential offers, by placeholder-name.

    A credential fills the fields it actually HAS. A password credential fills <password>
    but not <hash>; an ntlm credential fills <hash> but not <password>. The account name
    and domain come from every kind. Empty values are never offered — an unfilled
    placeholder must stay visible rather than become an empty string in the command.
    """
    out: dict[str, str] = {}
    kind = (cred.kind or "").lower()

    if cred.principal:
        for k in _USER_KEYS:
            out[k] = cred.principal
    if cred.domain:
        for k in _DOMAIN_KEYS:
            out[k] = cred.domain

    if cred.secret:
        if kind in ("password", "cleartext", "plaintext"):
            for k in _PASS_KEYS:
                out[k] = cred.secret
        elif kind in ("ntlm", "hash", "nt", "ntlm-hash"):
            for k in _HASH_KEYS:
                out[k] = cred.secret
        else:
            # Unknown kind (ticket, key, token): offer it as the generic secret spellings,
            # so a template with <token> or <key> can still be filled, but never as a
            # password/hash it is not.
            out[kind] = cred.secret
    return out


def fill(command: str, cred: Credential) -> tuple[str, list[str]]:
    """Substitute ``cred``'s values into ``command``. Returns (filled, filled_placeholders).

    Case-insensitive on the placeholder name, so ``<PASSWORD>`` and ``<password>`` both fill
    and the original casing in the command is what gets replaced. A placeholder this
    credential has no value for is left untouched — visible and unfilled, never blanked.
    """
    values = _values_for(cred)
    filled: list[str] = []

    def _sub(match: re.Match[str]) -> str:
        name = match.group(1).lower()
        if name in values:
            filled.append(match.group(0))
            return values[name]
        return match.group(0)

    return _PLACEHOLDER_RE.sub(_sub, command or ""), filled


def fillable(command: str, cred: Credential) -> list[str]:
    """Which placeholders in ``command`` this credential COULD fill — for a UI hint, without
    mutating the command."""
    values = _values_for(cred)
    seen: list[str] = []
    for m in _PLACEHOLDER_RE.finditer(command or ""):
        tok = m.group(0)
        if m.group(1).lower() in values and tok not in seen:
            seen.append(tok)
    return seen


def credential_placeholders(command: str) -> list[str]:
    """Every credential-shaped placeholder in a command (regardless of any specific cred),
    so the UI can show 'this command wants a credential' before one is chosen."""
    cred_keys = set(_USER_KEYS + _PASS_KEYS + _HASH_KEYS + _DOMAIN_KEYS)
    out: list[str] = []
    for m in _PLACEHOLDER_RE.finditer(command or ""):
        if m.group(1).lower() in cred_keys and m.group(0) not in out:
            out.append(m.group(0))
    return out


def best_matches(command: str, creds: Iterable[Credential]) -> list[Credential]:
    """Credentials that can fill at least one placeholder in the command, most-useful first
    (a credential that fills more placeholders ranks higher). Empty when the command needs
    no credential."""
    scored = [(len(fillable(command, c)), c) for c in creds]
    scored = [(n, c) for n, c in scored if n > 0]
    scored.sort(key=lambda t: -t[0])
    return [c for _, c in scored]
