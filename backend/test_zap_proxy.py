"""ZAP proxy history parsing.  Run:  python test_zap_proxy.py

The fixture is a VERBATIM capture from a real ZAP 2.17.0 daemon proxying real requests inside the
Kali image against the Juice Shop lab target. Every other input in this file is one this repo
wrote, which is exactly the blind spot that let the build #9 ingest gap survive a green suite:
a hermetic test that invents its input tests the invention.

It was captured deliberately to carry three shapes worth covering:
  * a GET whose response line is malformed ("HTTP/1.0 0") — ZAP records failed exchanges too
  * a GET with a query string — the Endpoint params path
  * a POST carrying a password in its body — the raw-storage decision (spec §6)
"""

from __future__ import annotations

import json
from pathlib import Path

from cockpit import proxy

FIXTURE = Path(__file__).parent / "test_support" / "zap_proxy_message_fixture.json"


def _messages() -> list[dict]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))["messages"]


def _by_method(method: str) -> dict:
    for m in _messages():
        if m.get("requestHeader", "").split()[:1] == [method]:
            return m
    raise AssertionError(f"the fixture carries no {method} — recapture it")


def test_a_real_message_becomes_an_exchange() -> None:
    ex = proxy.parse_message(_by_method("POST"), "hackpit-kali-sandbox")
    assert ex is not None, "a real ZAP message parsed to nothing"
    assert ex.request.method == "POST", f"method: {ex.request.method!r}"
    assert ex.request.url.startswith("http://hackpit-lab-target"), ex.request.url
    assert ex.response.status == 401, f"status: {ex.response.status!r}"
    assert ex.container == "hackpit-kali-sandbox"
    assert ex.request.headers, "no request headers parsed"
    print(f"  a real message -> {ex.request.method} {ex.request.url[:44]} "
          f"-> {ex.response.status}: PASS")


def test_a_malformed_response_line_still_yields_the_request() -> None:
    """ZAP records exchanges that never completed. The request half is still worth having, so a
    missing/garbage status must not throw the whole record away."""
    msgs = [m for m in _messages()
            if (m.get("responseHeader") or "").split()[1:2] in ([], ["0"])]
    assert msgs, "the fixture no longer carries a malformed response — recapture or drop this"
    ex = proxy.parse_message(msgs[0], "c")
    assert ex is not None, "a malformed response line discarded the whole exchange"
    assert ex.request.url.startswith("http"), ex.request.url
    assert ex.response.status is None, f"a bogus status was parsed as {ex.response.status!r}"
    print("  a malformed response line keeps the request and nulls the status: PASS")


def test_malformed_messages_never_raise() -> None:
    """A parser must never break a completed run."""
    for junk in ({}, {"requestHeader": ""}, {"requestHeader": "GARBAGE"},
                 {"requestHeader": "GET"}, {"requestHeader": "GET http://x HTTP/1.1",
                                            "responseHeader": "nonsense"},
                 {"requestHeader": None}, {"requestHeader": "GET http://x", "rtt": "abc"}):
        proxy.parse_message(junk, "c")  # must not raise
    print("  7 malformed messages parse without raising: PASS")


def test_bodies_are_kept_raw() -> None:
    """DECISION (2026-08-03, Zaid): store raw, redact only in reports. Redacting on ingest
    defeats the feature — the request that matters is usually the one carrying the token.

    The fixture's POST really does carry a password, so this asserts against real captured
    traffic rather than a planted string.
    """
    ex = proxy.parse_message(_by_method("POST"), "c")
    assert "password=hunter2" in ex.request.body, (
        f"the captured body was altered on ingest: {ex.request.body!r} — redaction belongs at "
        "the REPORT boundary only (spec §6)"
    )
    print("  captured bodies are stored raw, password intact: PASS")


def test_captured_requests_become_endpoints() -> None:
    exchanges = [proxy.parse_message(m, "c") for m in _messages()]
    eps = proxy.endpoints_from(exchanges, session_id="s1", run_id="r1")
    assert eps, "no endpoints from a real capture"
    assert all(e.url.startswith("http") for e in eps), [e.url for e in eps]
    assert all(e.session_id == "s1" and e.source_run_id == "r1" for e in eps)

    with_params = [e for e in eps if e.params]
    assert with_params, f"no query params extracted: {[(e.url, e.params) for e in eps]}"
    assert "q" in with_params[0].params, with_params[0].params
    print(f"  {len(eps)} captured request(s) -> Endpoints, params extracted: PASS")


def test_history_survives_a_dead_daemon() -> None:
    """The reader talks to a container that may not exist. It must return [] rather than raise —
    a panel refresh against a stopped proxy is normal, not an error."""
    assert proxy.history("hackpit-no-such-container-xyz", 8090) == []
    assert proxy.captured_count("hackpit-no-such-container-xyz", 8090) == 0
    print("  history against a dead container returns empty, never raises: PASS")


if __name__ == "__main__":
    test_a_real_message_becomes_an_exchange()
    test_a_malformed_response_line_still_yields_the_request()
    test_malformed_messages_never_raise()
    test_bodies_are_kept_raw()
    test_captured_requests_become_endpoints()
    test_history_survives_a_dead_daemon()
    print("ALL ZAP proxy history tests pass")
