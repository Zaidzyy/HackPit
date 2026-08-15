"""Locks for the captured-request importer (cockpit/reqimport.py). Pure parsing — no I/O."""
from __future__ import annotations

from cockpit import reqimport as R


def test_parses_a_raw_http_request() -> None:
    raw = (
        "GET /bowl/list HTTP/2\r\n"
        "Host: api.fishbowlapp.com\r\n"
        "X-Auth-Key: APP-SHARED-KEY-123\r\n"
        "Authorization: Bearer SESSIONTOKEN-A\r\n"
        "User-Agent: Fishbowl/9\r\n"
        "\r\n"
    )
    req = R.parse_capture(raw)
    assert req.error == "", req.error
    assert req.method == "GET"
    assert req.url == "https://api.fishbowlapp.com/bowl/list", req.url
    assert any(h.name == "X-Auth-Key" for h in req.headers)
    # heuristic: the app-key header is spotted, the bearer is a session candidate.
    assert req.auth_key_header == "X-Auth-Key", req.auth_key_header
    assert "Authorization" in req.session_headers, req.session_headers
    print("  raw HTTP -> method/url/headers + heuristic auth-key + session guess: PASS")


def test_parses_a_curl_command() -> None:
    cmd = (
        "curl_chrome116 -X POST 'https://api.fishbowlapp.com/user/newSession' "
        "-H 'X-Auth-Key: APP-SHARED-KEY-123' -H 'Content-Type: application/json' "
        "--data '{\"x\":1}'"
    )
    req = R.parse_capture(cmd)
    assert req.error == "" and req.method == "POST", req.error or req.method
    assert req.url == "https://api.fishbowlapp.com/user/newSession", req.url
    assert req.body == '{"x":1}', req.body
    assert req.auth_key_header == "X-Auth-Key"
    print("  curl line -> method/url/body/headers parsed: PASS")


def test_diff_two_accounts_finds_shared_key_and_per_user_token() -> None:
    """The deterministic verdict: a header identical across A and B is the SHARED app key; one that
    differs is the per-user session token that a cross-account IDOR test swaps."""
    a = (
        "GET /bowl/list HTTP/2\nHost: api.fishbowlapp.com\n"
        "X-Auth-Key: SHARED-APP-KEY\nX-Session-Token: TOKEN-FOR-A\n\n"
    )
    b = (
        "GET /bowl/list HTTP/2\nHost: api.fishbowlapp.com\n"
        "X-Auth-Key: SHARED-APP-KEY\nX-Session-Token: TOKEN-FOR-B\n\n"
    )
    out = R.diff_captures(a, b)
    assert out["error"] == "", out["error"]
    assert out["likely_app_key"] == "x-auth-key", out["likely_app_key"]
    assert out["likely_session_token"] == "x-session-token", out["likely_session_token"]
    assert "x-auth-key" in out["identical_headers"] and "x-session-token" in out["differing_headers"]
    print("  diff two accounts -> shared app key (identical) vs per-user session token (differs): PASS")


def test_bad_paste_returns_error_never_raises() -> None:
    assert R.parse_capture("").error
    assert R.parse_capture("not a request at all").error
    print("  a bad paste returns an error, never raises: PASS")


if __name__ == "__main__":
    test_parses_a_raw_http_request()
    test_parses_a_curl_command()
    test_diff_two_accounts_finds_shared_key_and_per_user_token()
    test_bad_paste_returns_error_never_raises()
    print("ALL reqimport tests pass")
