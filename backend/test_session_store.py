"""Regression-lock for the operator-session attach feature (cockpit/session_store.py + the repeater
attach path in the router).

Invariants:
  1. EXTRACT: the session/cookie headers are pulled out of a captured request (same classifier as
     :repeater import); non-credential headers are not.
  2. MEMORY-ONLY + MASKED: set/get/clear roundtrip; the masked view NEVER contains the token value.
  3. ATTACH: session headers are merged into a send ONLY when attach_session is set, and a TYPED
     header always wins over the stored one (no silent override, no duplicate credential).

Run:  python test_session_store.py
"""
from __future__ import annotations

import json

from cockpit import session_store as ss
from cockpit.repeater import RepeaterHeader, RepeaterRequest
from cockpit.router import _attach_session

CAP = (
    "curl 'https://api.example.com/v4/me' "
    "-H 'app-platform: web' "
    "-b 'session_key=SECRET-TOKEN-123; other=x' "
    "-H 'authorization: Bearer BEARER-XYZ'"
)


def test_extracts_session_headers_from_capture() -> None:
    hdrs = ss.session_from_capture(CAP)
    names = {n.lower() for n, _ in hdrs}
    assert "cookie" in names, names
    assert "authorization" in names, names
    assert "app-platform" not in names, "a non-credential header must not be attached"
    print("  session_from_capture pulls cookie + authorization, not app-platform: PASS")


def test_set_get_clear_roundtrip() -> None:
    ss.set_session("eng1", [("Cookie", "session_key=SECRET-TOKEN-123")], "account A")
    s = ss.get_session("eng1")
    assert s and s.headers[0] == ("Cookie", "session_key=SECRET-TOKEN-123")
    assert s.label == "account A"
    assert ss.clear_session("eng1") is True
    assert ss.get_session("eng1") is None
    assert ss.clear_session("eng1") is False
    print("  set / get / clear roundtrip: PASS")


def test_masked_view_never_leaks_the_token() -> None:
    ss.set_session("eng2", [("Cookie", "session_key=SUPER-SECRET-999")])
    v = ss.masked_view("eng2")
    assert v is not None
    assert "SUPER-SECRET-999" not in json.dumps(v), "masked view must never contain the token value"
    assert v["headers"][0]["name"] == "Cookie"
    assert v["attached"] is True
    ss.clear_session("eng2")
    print("  masked_view hides the token value: PASS")


def test_attach_merges_only_when_flagged_and_typed_wins() -> None:
    ss.set_session("eng3", [("Cookie", "session_key=STORED"), ("X-App", "k")])
    # not flagged -> unchanged (identity)
    r0 = RepeaterRequest(url="https://api.example.com/x", engagement_id="eng3", attach_session=False)
    assert _attach_session(r0) is r0

    # flagged -> stored session headers added
    r1 = RepeaterRequest(url="https://api.example.com/x", engagement_id="eng3", attach_session=True)
    names = {h.name.lower(): h.value for h in _attach_session(r1).headers}
    assert names.get("cookie") == "session_key=STORED"
    assert names.get("x-app") == "k"

    # a TYPED header wins: the operator's own Cookie is neither overridden nor duplicated
    r2 = RepeaterRequest(
        url="https://api.example.com/x", engagement_id="eng3", attach_session=True,
        headers=[RepeaterHeader(name="Cookie", value="session_key=MINE")],
    )
    cookies = [h.value for h in _attach_session(r2).headers if h.name.lower() == "cookie"]
    assert cookies == ["session_key=MINE"], cookies

    # no session stored for an engagement -> unchanged
    r3 = RepeaterRequest(url="https://api.example.com/x", engagement_id="none", attach_session=True)
    assert _attach_session(r3) is r3

    ss.clear_session("eng3")
    print("  attach merges only when flagged; typed headers win: PASS")


if __name__ == "__main__":
    test_extracts_session_headers_from_capture()
    test_set_get_clear_roundtrip()
    test_masked_view_never_leaks_the_token()
    test_attach_merges_only_when_flagged_and_typed_wins()
    print("ALL session-store tests pass")
