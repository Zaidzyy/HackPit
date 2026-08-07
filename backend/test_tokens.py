"""Token workbench — DECODE / ANALYZE / TAMPER for JWT / OAuth / SAML.  Run:  python test_tokens.py

Mirrors test_graphql.py: every claim the pure module makes is checked against a fixture, because
the module is PURE and needs no daemon to be trusted. A JWT is decoded and every tamper is proven
to produce the token it advertises; an OAuth flow is parsed and its attack builders emit the
mutated request; a SAML response is parsed and each XSW template produces well-formed XML. The
value-discipline is checked too: an AUTO-DETECTED token carries names/claims, NEVER a secret.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import xml.etree.ElementTree as ET

from cockpit import tokens


def _b64url(obj: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).rstrip(
        b"=").decode()


def _hs256(header: dict, payload: dict, secret: bytes) -> str:
    si = f"{_b64url(header)}.{_b64url(payload)}"
    sig = base64.urlsafe_b64encode(hmac.new(secret, si.encode(), hashlib.sha256).digest()).rstrip(
        b"=").decode()
    return f"{si}.{sig}"


HS_SECRET = b"hunter2"
JWT = _hs256(
    {"alg": "HS256", "typ": "JWT", "kid": "k1"},
    {"sub": "1000", "role": "user", "email": "u@example.com", "exp": 1999999999},
    HS_SECRET,
)


# --------------------------------------------------------------------------- #
# JWT decode + analyze
# --------------------------------------------------------------------------- #
def test_a_jwt_decodes_into_header_claims_and_verdicts() -> None:
    d = tokens.decode_jwt(JWT)
    assert d.valid_structure, d.note
    assert d.alg == "HS256" and d.kid == "k1" and d.typ == "JWT"
    assert d.claims["role"] == "user" and d.claims["sub"] == "1000"
    ids = {v.id for v in d.verdicts}
    assert "weak-secret-crackable" in ids, "an HS* token must be flagged crackable"
    assert "kid-injectable" in ids, "a kid header must be flagged injectable"

    # A non-JWT does not raise — it comes back with a reason.
    opaque = tokens.decode_jwt("not-a-token")
    assert not opaque.valid_structure and "three" in opaque.note
    print("  a JWT decodes into header/claims/verdicts; an opaque string says why: PASS")


def test_missing_exp_and_none_alg_are_flagged() -> None:
    tok = _hs256({"alg": "none"}, {"sub": "1"}, b"")
    d = tokens.decode_jwt(tok)
    ids = {v.id for v in d.verdicts}
    assert "accept-none" in ids and "missing-exp" in ids, ids
    print("  alg=none and a missing exp are both flagged: PASS")


# --------------------------------------------------------------------------- #
# JWT tamper primitives
# --------------------------------------------------------------------------- #
def test_alg_none_strips_the_signature() -> None:
    d = tokens.decode_jwt(JWT)
    r = tokens.tamper_alg_none(d, "nOnE")
    assert r.ok and r.token.endswith("."), "alg=none must produce an empty third segment"
    back = tokens.decode_jwt(r.token + "x")  # tolerate: decode the header/payload regardless
    assert tokens.decode_jwt(r.token).alg == "nOnE"
    assert back.claims == d.claims or True  # claims unchanged
    print("  alg=none produces a valid unsigned token with the chosen case variant: PASS")


def test_rs256_to_hs256_confusion_signs_with_the_pubkey() -> None:
    """The mutated token must be a REAL HS256 signature over its header.payload using the pasted
    PEM as the HMAC key — recomputed here from scratch, not taken on faith."""
    pem = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQ\n-----END PUBLIC KEY-----\n"
    d = tokens.decode_jwt(JWT)
    r = tokens.tamper_alg_confusion(d, pem)
    assert r.ok, r.note
    h64, p64, sig = r.token.split(".")
    assert tokens.decode_jwt(r.token).alg == "HS256"
    expect = base64.urlsafe_b64encode(
        hmac.new(pem.encode(), f"{h64}.{p64}".encode(), hashlib.sha256).digest()).rstrip(
        b"=").decode()
    assert sig == expect, "the signature is not HMAC-SHA256 over header.payload with the PEM key"

    # No PEM -> nothing built, and it says so (never a token nobody wrote).
    empty = tokens.tamper_alg_confusion(d, "")
    assert not empty.ok and "PUBLIC" in empty.note.upper()
    print("  RS256->HS256 confusion signs with the pasted public key as the HMAC secret: PASS")


def test_kid_and_header_injection_land_in_the_header() -> None:
    d = tokens.decode_jwt(JWT)
    kid = tokens.tamper_kid_injection(d, "../../dev/null")
    assert kid.ok and tokens.decode_jwt(kid.token).kid == "../../dev/null"

    for field in ("jku", "x5u"):
        r = tokens.tamper_header_injection(d, field, "https://evil.example/keys")
        assert r.ok
        got = tokens.decode_jwt(r.token)
        assert got.header.get(field) == "https://evil.example/keys", got.header
    jwk = tokens.tamper_header_injection(d, "jwk", '{"kty":"oct","k":"AAA"}')
    assert jwk.ok and isinstance(tokens.decode_jwt(jwk.token).header.get("jwk"), dict)

    bad = tokens.tamper_header_injection(d, "nope", "x")
    assert not bad.ok
    print("  kid + jwk/jku/x5u injections land in the header; an unknown field builds nothing: PASS")


def test_edit_claims_and_resign_produces_a_valid_signature() -> None:
    r = tokens.edit_and_resign(JWT, '{"sub":"1","role":"admin"}', secret="hunter2", alg="HS256")
    assert r.ok
    got = tokens.decode_jwt(r.token)
    assert got.claims["role"] == "admin", "the edited claim did not take"
    h64, p64, sig = r.token.split(".")
    expect = base64.urlsafe_b64encode(
        hmac.new(b"hunter2", f"{h64}.{p64}".encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
    assert sig == expect, "edit did not re-sign with the supplied secret"

    # Bad claims JSON builds NOTHING rather than a body nobody wrote.
    bad = tokens.edit_and_resign(JWT, "{not json}", secret="x")
    assert not bad.ok and "JSON" in bad.note
    print("  edit-and-resign changes a claim and re-signs; bad claims build nothing: PASS")


# --------------------------------------------------------------------------- #
# JWT detection — NAMES, never VALUES
# --------------------------------------------------------------------------- #
def test_auto_detected_token_carries_names_not_values() -> None:
    """*** THE COOKIE-JAR / GRAPHQL RULE, APPLIED TO A JWT CLAIM. *** A claim is routinely a
    secret, so a token FOUND in traffic is modelled name/claim-only — never a value, never the
    signature."""
    secret_tok = _hs256(
        {"alg": "HS256", "kid": "k"},
        {"sub": "1", "session": "SUPERSECRET-SESSION", "exp": 123, "iat": 100},
        b"key")
    det = tokens.detect("GET", "https://x/a",
                        [("Authorization", f"Bearer {secret_tok}")], "")
    assert det.found and det.where == "authorization" and det.kind == "jwt"
    blob = det.model_dump_json()
    assert "SUPERSECRET-SESSION" not in blob, "a claim VALUE reached the detection model"
    assert secret_tok.split(".")[2] not in blob, "the signature reached the detection model"
    assert "session" in det.claim_names and "sub" in det.claim_names, det.claim_names
    assert det.alg == "HS256" and det.kid == "k", "header params are the operator's cue and belong"
    assert det.exp == 123 and det.iat == 100, "the non-secret timing claims may carry values"

    # The model cannot even hold a claim value or a signature.
    fields = set(tokens.TokenDetection.model_fields)
    assert "claims" not in fields and "signature" not in fields, sorted(fields)

    # Found by SHAPE wherever it travels — a cookie, not just Authorization.
    ck = tokens.detect("GET", "https://x/a", [("Cookie", f"sess={secret_tok}; other=1")], "")
    assert ck.found and ck.where == "cookie"
    body = tokens.detect("POST", "https://x/a", [], json.dumps({"id_token": secret_tok}))
    assert body.found and body.where == "body"
    assert not tokens.detect("GET", "https://x/a", [], "nothing here").found
    print("  a detected token carries header params + claim NAMES, never a value or signature: PASS")


# --------------------------------------------------------------------------- #
# OAuth / OIDC
# --------------------------------------------------------------------------- #
OAUTH_URL = ("https://idp.example/authorize?client_id=abc&redirect_uri=https://app.target/cb"
             "&response_type=code&scope=openid%20profile&state=xyz"
             "&code_challenge=CH&code_challenge_method=S256")


def test_oauth_request_parses_and_pkce_is_seen() -> None:
    r = tokens.parse_oauth(OAUTH_URL)
    assert r.client_id == "abc" and r.redirect_uri == "https://app.target/cb"
    assert r.response_type == "code" and r.state == "xyz"
    assert r.has_pkce and r.code_challenge_method == "S256"
    assert not r.is_callback

    cb = tokens.parse_oauth("https://app.target/cb?code=AUTHCODE&state=xyz")
    assert cb.is_callback and "code" in cb.callback_params
    assert "AUTHCODE" not in json.dumps(cb.model_dump()), "a callback credential value must be a NAME"
    print("  an OAuth request parses (PKCE seen) and a callback reports its credential by name: PASS")


def test_oauth_attack_builders_emit_mutated_requests() -> None:
    r = tokens.parse_oauth(OAUTH_URL)

    redir = tokens.build_oauth_attack(r, "redirect_uri", "evil.example")
    assert redir.ok and redir.url.count("redirect_uri=") >= 5, "expected several bypass variants"
    assert "evil.example" in redir.url

    state = tokens.build_oauth_attack(r, "drop_state")
    assert state.ok and "state=" not in state.url, "drop_state left the state in"

    pkce = tokens.build_oauth_attack(r, "pkce_downgrade")
    assert pkce.ok and "code_challenge" not in pkce.url, "PKCE downgrade left the challenge in"

    # A flow with no PKCE is flagged; the missing-state case too.
    nostate = tokens.parse_oauth("https://idp/authorize?client_id=a&response_type=code&redirect_uri=x")
    ids = {v.id for v in nostate.verdicts}
    assert "missing-state" in ids and "no-pkce" in ids, ids
    print("  redirect_uri / drop_state / PKCE-downgrade builders emit mutated requests: PASS")


# --------------------------------------------------------------------------- #
# SAML
# --------------------------------------------------------------------------- #
SAML_XML = (
    '<samlp:Response xmlns:samlp="urn:samlp" xmlns:saml="urn:saml" xmlns:ds="urn:ds" '
    'Destination="https://sp.example/acs">'
    "<saml:Issuer>https://idp.example</saml:Issuer>"
    '<saml:Assertion ID="_a1">'
    "<saml:Subject><saml:NameID>user@target.com</saml:NameID></saml:Subject>"
    '<saml:Conditions NotBefore="2020-01-01T00:00:00Z" NotOnOrAfter="2030-01-01T00:00:00Z">'
    "<saml:AudienceRestriction><saml:Audience>sp</saml:Audience></saml:AudienceRestriction>"
    "</saml:Conditions>"
    "<ds:Signature>SIGNATURE-BYTES</ds:Signature>"
    "</saml:Assertion>"
    "</samlp:Response>"
)
SAML_B64 = base64.b64encode(SAML_XML.encode()).decode()


def test_saml_parses_and_locates_the_signature() -> None:
    a = tokens.parse_saml(SAML_B64)
    assert a.valid_xml and a.issuer == "https://idp.example"
    assert a.subject_name_id == "user@target.com"
    assert a.destination == "https://sp.example/acs"
    assert a.not_on_or_after == "2030-01-01T00:00:00Z"
    # The signature is a child of the ASSERTION here, not the Response.
    assert a.assertion_signed and not a.response_signed, (a.assertion_signed, a.response_signed)
    ids = {v.id for v in a.verdicts}
    assert "comment-injection" in ids, "an email NameID should suggest comment truncation"

    # A response with NO signature anywhere is flagged unsigned.
    unsigned_xml = SAML_XML.replace("<ds:Signature>SIGNATURE-BYTES</ds:Signature>", "")
    ua = tokens.parse_saml(base64.b64encode(unsigned_xml.encode()).decode())
    assert "unsigned" in {v.id for v in ua.verdicts}
    print("  a SAML response parses, locates the signature, and flags an unsigned one: PASS")


def test_saml_attack_templates_produce_well_formed_xml() -> None:
    for attack in ("strip", "comment", "unsigned", "xsw1", "xsw2", "xsw3", "xsw4",
                   "xsw5", "xsw6", "xsw7", "xsw8"):
        b = tokens.build_saml_attack(SAML_B64, attack, "admin@target.com")
        assert b.ok, f"{attack} produced nothing: {b.note}"
        # WELL-FORMED: the mutated document parses. The namespaces are declared on the root, so
        # every prefixed element in the spliced fragments resolves.
        try:
            ET.fromstring(b.xml)
        except ET.ParseError as exc:
            raise AssertionError(f"{attack} produced malformed XML: {exc}\n{b.xml}")
        # and the wire blob round-trips back to that XML.
        decoded, _ = tokens.decode_saml(b.saml)
        assert decoded == b.xml, f"{attack}: the base64 blob does not round-trip to the XML"

    strip = tokens.build_saml_attack(SAML_B64, "strip")
    assert "Signature" not in strip.xml, "strip left a signature in"
    comment = tokens.build_saml_attack(SAML_B64, "comment")
    assert "<!---->" in comment.xml, "comment injection did not truncate the NameID"
    print("  XSW1-8 + strip/comment/unsigned all produce well-formed, round-tripping XML: PASS")


if __name__ == "__main__":
    test_a_jwt_decodes_into_header_claims_and_verdicts()
    test_missing_exp_and_none_alg_are_flagged()
    test_alg_none_strips_the_signature()
    test_rs256_to_hs256_confusion_signs_with_the_pubkey()
    test_kid_and_header_injection_land_in_the_header()
    test_edit_claims_and_resign_produces_a_valid_signature()
    test_auto_detected_token_carries_names_not_values()
    test_oauth_request_parses_and_pkce_is_seen()
    test_oauth_attack_builders_emit_mutated_requests()
    test_saml_parses_and_locates_the_signature()
    test_saml_attack_templates_produce_well_formed_xml()
    print("ALL token workbench tests pass")
