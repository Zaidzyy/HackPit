"""Repeater cookie-jar locks (build #19 item 2).  Run:  python test_cookiejar.py

THE INVARIANT: the jar may change a request, and it may never do so invisibly or hand a value to
anything that writes it down.

IT IS NOT A GATE. There is no confirm, no acknowledgement and no refusal anywhere in the jar. A
malformed `Set-Cookie`, a `Domain` a response had no right to set, an unreadable expiry — each is
skipped or clamped and REPORTED, and the send goes anyway. A test that demanded an approval for
attaching a cookie would be a harness inventing a prohibition the product does not have.
"""

from __future__ import annotations

import ast
import inspect
from datetime import datetime, timedelta, timezone

from cockpit import cookiejar, repeater


def _jar() -> cookiejar.CookieJar:
    return cookiejar.CookieJar()


def test_a_cookie_is_stored_and_comes_back_on_the_next_request() -> None:
    """The whole point: the SECOND request carries the session the FIRST one was given."""
    jar = _jar()
    jar.ingest(["sid=abc123; Path=/"], "https://app.example.com/login")
    sel = jar.select("https://app.example.com/account")
    assert sel.header == "sid=abc123", sel.header
    assert [a.name for a in sel.attached] == ["sid"]
    print("  a Set-Cookie on one response reaches the next request: PASS")


def test_the_disclosure_carries_NO_VALUE_FIELD_AT_ALL() -> None:
    """*** THE LOAD-BEARING ONE. *** The attachment model is serialised into an API response and
    onto a screen. Build #18's rule: never handing a secret over cannot regress, while redacting
    it afterwards depends on a redactor being correct forever."""
    assert "value" not in cookiejar.CookieAttachment.model_fields, (
        "CookieAttachment grew a `value` field — a session token would now travel in every "
        "repeater response body"
    )
    jar = _jar()
    jar.ingest(["sid=SUPERSECRET; Path=/"], "https://h/x")
    dumped = str([a.model_dump() for a in jar.disclosure()])
    assert "SUPERSECRET" not in dumped, dumped
    sel = jar.select("https://h/x")
    assert "SUPERSECRET" not in str([a.model_dump() for a in sel.attached])
    # ...and the value IS still there to be sent, or the feature would not work.
    assert "SUPERSECRET" in sel.header
    print("  the disclosure has no value field and never leaks one; the header still has it: PASS")


def test_a_response_cannot_set_a_cookie_for_someone_elses_domain() -> None:
    """RFC 6265 §5.3 step 6, and a real control: a jar that let `evil.example.com` set a cookie
    for `example.com` would forward the operator's session for one host onto another."""
    jar = _jar()
    warnings = jar.ingest(["sid=x; Domain=example.com"], "https://evil.notexample.com/p")
    assert jar.cookies() == [], "a cross-domain Set-Cookie was stored"
    assert any("not a suffix" in w for w in warnings), warnings
    # control: the legitimate case still works
    jar2 = _jar()
    jar2.ingest(["sid=x; Domain=example.com"], "https://api.example.com/p")
    assert [c.name for c in jar2.cookies()] == ["sid"]
    print("  a cross-domain Set-Cookie is refused storage; the legitimate one is kept: PASS")


def test_domain_matching_is_DOT_ANCHORED() -> None:
    """`notexample.com` ends with `example.com` as a string. This repo has been bitten by a
    fragment match in both directions already (build #18's fronting module)."""
    assert cookiejar._domain_match("api.example.com", "example.com")
    assert cookiejar._domain_match("example.com", "example.com")
    assert not cookiejar._domain_match("notexample.com", "example.com")
    assert not cookiejar._domain_match("example.com.evil.net", "example.com")
    print("  domain matching is dot-anchored in both directions: PASS")


def test_a_host_only_cookie_does_NOT_go_to_subdomains() -> None:
    """No `Domain` attribute means THAT EXACT HOST (RFC 6265 §5.3). Sending it to a subdomain
    would widen where a credential travels, which is the one thing a jar must not do quietly."""
    jar = _jar()
    jar.ingest(["sid=x"], "https://example.com/p")          # no Domain -> host-only
    assert jar.select("https://example.com/p").header == "sid=x"
    assert jar.select("https://api.example.com/p").header == "", "host-only cookie leaked to a subdomain"
    print("  a host-only cookie stays on its exact host: PASS")


def test_path_matching_does_not_treat_foobar_as_under_foo() -> None:
    assert cookiejar._path_match("/foo", "/foo")
    assert cookiejar._path_match("/foo/bar", "/foo")
    assert cookiejar._path_match("/foo/", "/foo")
    assert not cookiejar._path_match("/foobar", "/foo")
    print("  /foobar is not under /foo: PASS")


def test_the_default_path_is_the_DIRECTORY_not_the_request_path() -> None:
    """RFC 6265 §5.1.4. `/a/b` defaults to `/a`. Getting this wrong makes a cookie set on one
    page invisible on its siblings, which reads as the session having been dropped."""
    assert cookiejar._default_path("https://h/a/b") == "/a"
    assert cookiejar._default_path("https://h/a") == "/"
    assert cookiejar._default_path("https://h/") == "/"
    print("  the default path is the directory, not the request path: PASS")


def test_an_expired_cookie_DELETES_rather_than_being_stored() -> None:
    """That is how a server logs you out. A jar that kept it would silently re-authenticate the
    next request — the exact 'state that changes a request invisibly' this module exists to avoid."""
    jar = _jar()
    jar.ingest(["sid=x; Path=/"], "https://h/")
    assert jar.select("https://h/").header == "sid=x"
    past = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%a, %d %b %Y %H:%M:%S GMT")
    jar.ingest([f"sid=x; Path=/; Expires={past}"], "https://h/")
    assert jar.select("https://h/").header == "", "an expired cookie survived"
    print("  an expired Set-Cookie deletes the cookie: PASS")


def test_a_Secure_cookie_is_withheld_from_http_AND_REPORTED() -> None:
    jar = _jar()
    jar.ingest(["sid=x; Path=/; Secure"], "https://h/")
    sel = jar.select("http://h/")
    assert sel.header == ""
    assert sel.skipped_secure == ["sid"], sel.skipped_secure
    assert jar.select("https://h/").header == "sid=x", "the control failed — https should carry it"
    print("  a Secure cookie is withheld from http and says so; https still carries it: PASS")


def test_the_operators_OWN_cookie_wins_and_the_suppression_is_reported() -> None:
    """An explicit `Cookie: sid=...` is the operator testing a specific value. A jar that
    overwrote it would make the request under test unreachable."""
    jar = _jar()
    jar.ingest(["sid=fromjar; Path=/", "other=keep; Path=/"], "https://h/")
    sel = jar.select("https://h/", frozenset({"sid"}))
    assert "fromjar" not in sel.header, sel.header
    assert "other=keep" in sel.header
    assert sel.suppressed == ["sid"], sel.suppressed
    print("  a typed cookie beats the jar's copy, and the suppression is named: PASS")


def test_typed_cookie_names_reads_EVERY_cookie_header() -> None:
    """curl sends every `-H "Cookie: ..."`, so reading only the first would suppress the wrong set."""
    req = repeater.RepeaterRequest(
        url="https://h/", headers=[
            repeater.RepeaterHeader(name="Cookie", value="a=1; b=2"),
            repeater.RepeaterHeader(name="cookie", value="c=3"),
        ])
    assert repeater.typed_cookie_names(req) == frozenset({"a", "b", "c"})
    print("  every Cookie header is read, case-insensitively: PASS")


def test_ONE_cookie_header_goes_on_the_wire_never_two() -> None:
    """*** RFC 6265 §5.4 says a user agent MUST NOT send two, and servers disagree about what to
    do when one arrives. *** Two headers would make the request's meaning depend on the target's
    parser, which is a silent wrong answer of exactly the shape this repo keeps finding."""
    req = repeater.RepeaterRequest(
        url="https://h/", headers=[repeater.RepeaterHeader(name="Cookie", value="typed=1")])
    argv = repeater._build_curl(req, "S", url="https://h/", has_body=False,
                                cookie_header="jar=2")
    cookie_args = [argv[i + 1] for i, a in enumerate(argv)
                   if a == "-H" and argv[i + 1].lower().startswith("cookie:")]
    assert len(cookie_args) == 1, f"{len(cookie_args)} Cookie headers on the wire: {cookie_args}"
    assert "typed=1" in cookie_args[0] and "jar=2" in cookie_args[0], cookie_args
    # ...and with NO jar contribution the operator's headers go out EXACTLY as typed, duplicates
    # included — two Cookie headers may be precisely what they are testing.
    req2 = repeater.RepeaterRequest(
        url="https://h/", headers=[repeater.RepeaterHeader(name="Cookie", value="a=1"),
                                   repeater.RepeaterHeader(name="Cookie", value="b=2")])
    argv2 = repeater._build_curl(req2, "S", url="https://h/", has_body=False, cookie_header="")
    plain = [argv2[i + 1] for i, a in enumerate(argv2)
             if a == "-H" and argv2[i + 1].lower().startswith("cookie:")]
    assert len(plain) == 2, "the operator's own duplicate Cookie headers were collapsed"
    print("  the jar merges into ONE header; untouched requests keep their duplicates: PASS")


def test_the_run_record_carries_NO_COOKIE_and_that_matters_because_of_report_py() -> None:
    """*** MEASURED, NOT ASSUMED (the spec said to check). ***
    `report.py::_run_cmdline` renders a run record's command line VERBATIM into a report, and
    `redact_captured_body` — the redactor that knows the word "cookie" — is never called on it.
    So the run record must not carry one in the first place."""
    src = inspect.getsource(repeater.send)
    record = src[src.find("RunRecord("):]
    record = record[:record.find(")\n") + 1]
    for bad in ("cookie", "Cookie", "selection", "jar"):
        assert bad not in record, f"the run record mentions {bad!r}: {record}"
    assert "sent_url" in record and "shapes_applied" in record

    import report

    rendered = inspect.getsource(report)
    assert "redact_captured_body" in rendered
    # The redactor exists; nothing in the product calls it on a run record. That is exactly why
    # the record has to be clean rather than cleaned.
    tree = ast.parse(rendered)
    calls = [n for n in ast.walk(tree)
             if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "redact_captured_body"]
    assert not calls, (
        "report.py now CALLS redact_captured_body — good, but this lock's argument changes: "
        "re-read whether the run record still needs to be cookie-free by construction"
    )
    print("  no cookie reaches the run record, which is what a report renders verbatim: PASS")


def test_sending_WITHOUT_the_jar_does_not_empty_it() -> None:
    """Testing what an unauthenticated caller sees is a real test, and it must not cost the
    operator the session they spent five minutes establishing by hand."""
    cookiejar.reset_all()
    jar = cookiejar.jar_for("s1")
    jar.ingest(["sid=x; Path=/"], "https://h/")
    src = inspect.getsource(repeater.send)
    assert "if req.use_cookie_jar:" in src, "send() no longer honours use_cookie_jar"
    # the jar object is fetched regardless, and only SELECTION is skipped
    assert "CookieSelection()" in src, (
        "the no-jar path does something other than an empty selection — check it does not clear"
    )
    assert len(jar.cookies()) == 1
    print("  a no-jar send leaves the jar intact: PASS")


def test_the_jar_adds_no_gate_field_and_refuses_no_send() -> None:
    """*** THE UNRESTRICTIVE REQUIREMENT, ASSERTED. ***"""
    for name in ("approved", "dangerous_ack", "cookie_ack", "confirm"):
        assert name not in repeater.RepeaterRequest.model_fields, (
            f"RepeaterRequest grew a {name!r} field — the repeater is human-only and gates none "
            "of its sends"
        )
    tree = ast.parse(inspect.getsource(cookiejar))
    raises = [n for n in ast.walk(tree) if isinstance(n, ast.Raise)]
    assert not raises, (
        f"cookiejar.py raises ({len(raises)} sites) — a malformed cookie is skipped and WARNED "
        "about, never refused. The send must go anyway."
    )
    print("  no gate field, and the jar refuses nothing: PASS")


def test_a_broken_cookie_does_not_lose_the_good_ones() -> None:
    jar = _jar()
    warnings = jar.ingest(["good=1; Path=/", "utterly broken", "also=2; Path=/"], "https://h/")
    names = sorted(c.name for c in jar.cookies())
    assert names == ["also", "good"], names
    assert any("no name=value" in w for w in warnings), warnings
    print("  one unparseable Set-Cookie does not discard the others: PASS")


if __name__ == "__main__":
    print("== repeater cookie jar (build #19 item 2) ==")
    test_a_cookie_is_stored_and_comes_back_on_the_next_request()
    test_the_disclosure_carries_NO_VALUE_FIELD_AT_ALL()
    test_a_response_cannot_set_a_cookie_for_someone_elses_domain()
    test_domain_matching_is_DOT_ANCHORED()
    test_a_host_only_cookie_does_NOT_go_to_subdomains()
    test_path_matching_does_not_treat_foobar_as_under_foo()
    test_the_default_path_is_the_DIRECTORY_not_the_request_path()
    test_an_expired_cookie_DELETES_rather_than_being_stored()
    test_a_Secure_cookie_is_withheld_from_http_AND_REPORTED()
    test_the_operators_OWN_cookie_wins_and_the_suppression_is_reported()
    test_typed_cookie_names_reads_EVERY_cookie_header()
    test_ONE_cookie_header_goes_on_the_wire_never_two()
    test_the_run_record_carries_NO_COOKIE_and_that_matters_because_of_report_py()
    test_sending_WITHOUT_the_jar_does_not_empty_it()
    test_the_jar_adds_no_gate_field_and_refuses_no_send()
    test_a_broken_cookie_does_not_lose_the_good_ones()
    print("ALL cookie-jar locks pass")
