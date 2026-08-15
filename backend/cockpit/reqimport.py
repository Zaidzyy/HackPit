"""Import a captured HTTP request — the paste-and-parse that turns a request copied from a proxy
(mitmproxy / Burp "copy as raw", or a curl command) into the repeater's structured fields, and
flags WHICH header is the shared app auth key vs the per-user session token.

That classification is the whole point for a mobile API like Fishbowl: the ``Invalid auth key``
401 gate is ONE header (shared by every install), while the thing a cross-account IDOR test swaps
is a DIFFERENT per-user token. Telling them apart by hand is error-prone — so:

  * one capture  -> a heuristic guess by header name, plus every credential-looking header listed.
  * TWO captures (account A + account B) -> a DETERMINISTIC verdict: a header IDENTICAL across both
    accounts is the shared app key; one that DIFFERS is the per-user session token. This also
    answers Step 3 ("is the auth key static?") without guessing.

PURE + inspectable: no I/O, no execution. The backend endpoint calls the functions here and hands
the result to the repeater form and/or the loop's operator-context.
"""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

#: Header names that look like a shared app/API key (the gate that returns "Invalid auth key").
_AUTHKEY_NAME = re.compile(
    r"^(x-)?(auth[-_]?key|api[-_]?key|app[-_]?key|apikey|client[-_]?key|x-app-token)$", re.I
)
#: Header names / schemes that look like a per-user session or bearer token.
_SESSION_NAME = re.compile(
    r"^(authorization|cookie|x-session[-_]?token|x-user[-_]?token|x-session|session|"
    r"x-access[-_]?token|x-auth[-_]?token|x-token|token)$", re.I
)
#: Headers that carry no credential and only add noise to the classification.
_BORING = {
    "host", "content-length", "content-type", "accept", "accept-encoding", "accept-language",
    "user-agent", "connection", "cache-control", "pragma", "origin", "referer", "date",
    "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "sec-fetch-dest", "sec-fetch-mode",
    "sec-fetch-site", "upgrade-insecure-requests", "te", "dnt",
}


@dataclass
class ImportedHeader:
    name: str
    value: str


@dataclass
class ImportedRequest:
    """A parsed capture, ready to fill the repeater + a first-pass credential classification."""

    method: str = "GET"
    url: str = ""
    headers: list[ImportedHeader] = field(default_factory=list)
    body: str = ""
    #: header name that looks like the SHARED app auth key (best single-capture guess).
    auth_key_header: str = ""
    #: header names that look like a per-user session / bearer / cookie credential.
    session_headers: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "url": self.url,
            "headers": [{"name": h.name, "value": h.value} for h in self.headers],
            "body": self.body,
            "auth_key_header": self.auth_key_header,
            "session_headers": self.session_headers,
            "notes": self.notes,
            "error": self.error,
        }


def _classify(headers: list[ImportedHeader]) -> tuple[str, list[str], list[str]]:
    """Best single-capture guess: (auth_key_header, session_headers, notes). Heuristic — the
    two-capture diff is what's authoritative."""
    auth_key = ""
    sessions: list[str] = []
    notes: list[str] = []
    for h in headers:
        low = h.name.strip().lower()
        if low in _BORING:
            continue
        if _AUTHKEY_NAME.match(low) and not auth_key:
            auth_key = h.name
        elif _SESSION_NAME.match(low):
            sessions.append(h.name)
        elif low.startswith("x-") and len(h.value.strip()) >= 12:
            # an unknown x- header carrying a long value is a credential candidate worth flagging.
            notes.append(f"'{h.name}' looks credential-like (long x- header) — confirm its role")
    if not auth_key and not sessions:
        notes.append("No obvious auth-key/session header by name — capture BOTH accounts and diff "
                     "to find them deterministically.")
    return auth_key, sessions, notes


def parse_capture(text: str) -> ImportedRequest:
    """Parse a raw HTTP request OR a curl command into structured fields + a credential guess."""
    text = (text or "").strip()
    if not text:
        return ImportedRequest(error="empty capture")
    try:
        if re.match(r"^\s*curl(_[a-z0-9]+)?\b", text) or " -H " in text or " --header " in text:
            req = _parse_curl(text)
        else:
            req = _parse_raw_http(text)
    except Exception as exc:  # noqa: BLE001 - a bad paste must return an error, never raise
        return ImportedRequest(error=f"could not parse the capture: {exc}")
    if not req.url:
        req.error = req.error or "no URL found in the capture"
        return req
    req.auth_key_header, req.session_headers, req.notes = _classify(req.headers)
    return req


def _parse_raw_http(text: str) -> ImportedRequest:
    """A raw HTTP request as a proxy 'copy as raw' emits it: request line, headers, blank, body."""
    lines = text.replace("\r\n", "\n").split("\n")
    m = re.match(r"^([A-Z]+)\s+(\S+)\s+HTTP/", lines[0].strip())
    if not m:
        raise ValueError("first line is not 'METHOD path HTTP/x'")
    method, target = m.group(1), m.group(2)
    headers: list[ImportedHeader] = []
    i = 1
    for i in range(1, len(lines)):
        line = lines[i]
        if line.strip() == "":
            break
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        headers.append(ImportedHeader(name.strip(), value.strip()))
    body = "\n".join(lines[i + 1:]).strip() if i + 1 < len(lines) else ""
    # reconstruct an absolute URL: absolute-form target wins; else scheme + Host + path.
    if target.lower().startswith(("http://", "https://")):
        url = target
    else:
        host = next((h.value for h in headers if h.name.lower() == "host"), "")
        url = f"https://{host}{target}" if host else target
    return ImportedRequest(method=method, url=url, headers=headers, body=body)


def _parse_curl(text: str) -> ImportedRequest:
    """A curl (or curl_chrome116) command line: -X, -H/--header, -b/--cookie, --data*, the URL."""
    tokens = shlex.split(text.replace("\\\n", " "))
    method = ""
    url = ""
    body = ""
    headers: list[ImportedHeader] = []
    it = iter(range(len(tokens)))
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if t in ("-X", "--request") and i + 1 < len(tokens):
            method = tokens[i + 1].upper(); i += 2; continue
        if t in ("-H", "--header") and i + 1 < len(tokens):
            name, _, value = tokens[i + 1].partition(":")
            if name.strip():
                headers.append(ImportedHeader(name.strip(), value.strip()))
            i += 2; continue
        if t in ("-b", "--cookie") and i + 1 < len(tokens):
            headers.append(ImportedHeader("Cookie", tokens[i + 1].strip())); i += 2; continue
        if t in ("-d", "--data", "--data-raw", "--data-binary", "--data-ascii") and i + 1 < len(tokens):
            body = tokens[i + 1]; i += 2; continue
        if t == "--url" and i + 1 < len(tokens):
            url = tokens[i + 1]; i += 2; continue
        if t.lower().startswith(("http://", "https://")) and not url:
            url = t; i += 1; continue
        i += 1
    if not method:
        method = "POST" if body else "GET"
    return ImportedRequest(method=method, url=url, headers=headers, body=body)


def diff_captures(text_a: str, text_b: str) -> dict[str, Any]:
    """Two captures (account A, account B) -> the DETERMINISTIC verdict.

    A credential header IDENTICAL across both accounts is the SHARED app key (it gates the API but
    isn't per-user); one that DIFFERS is the PER-USER session token — exactly what a cross-account
    IDOR test swaps. This is not a guess: it is what the two captures literally show.
    """
    a = parse_capture(text_a)
    b = parse_capture(text_b)
    if a.error or b.error:
        return {"error": a.error or b.error, "a": a.to_dict(), "b": b.to_dict()}

    def cred_headers(req: ImportedRequest) -> dict[str, str]:
        return {h.name.lower(): h.value for h in req.headers if h.name.lower() not in _BORING}

    ca, cb = cred_headers(a), cred_headers(b)
    shared_names = sorted(set(ca) & set(cb))
    identical = [n for n in shared_names if ca[n] == cb[n] and ca[n].strip()]
    differing = [n for n in shared_names if ca[n] != cb[n]]

    app_key = next((n for n in identical if _AUTHKEY_NAME.match(n)), identical[0] if identical else "")
    session = next((n for n in differing if _SESSION_NAME.match(n)), differing[0] if differing else "")
    notes: list[str] = []
    if app_key:
        notes.append(f"'{app_key}' is IDENTICAL across both accounts -> the shared app auth key "
                     "(static, not per-user). Access control must rest on the session token.")
    if session:
        notes.append(f"'{session}' DIFFERS between accounts -> the per-user session token. This is "
                     "the header a cross-account IDOR test swaps (A's id, B's token).")
    if not differing:
        notes.append("No credential header differs between the two accounts — either both captures "
                     "are the same account, or the session lives somewhere else (a body field / a "
                     "cookie sub-value). Re-check the captures.")
    return {
        "error": "",
        "identical_headers": identical,   # candidates for the shared app key
        "differing_headers": differing,   # candidates for the per-user session token
        "likely_app_key": app_key,
        "likely_session_token": session,
        "notes": notes,
        "a": a.to_dict(),
        "b": b.to_dict(),
    }
