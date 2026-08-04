"""AUTHENTICATED-SCAN SESSION EXPIRY — detect and warn.

Build #15's AJAX spider crawls behind a login by inheriting a session the human established
by hand in a real browser. It added no ZAP context, no session management and no
authentication handling. That is fine, and is not what this is about.

**What happens when that session expires mid-scan is.** The active scanner does not stop. It
keeps firing SQLi and XSS payloads at what are now login redirects, matches nothing in them,
and finishes cleanly reporting **zero findings** — which is indistinguishable from *"the
application is secure"*. Not a crash, not an error: a confident and wrong answer, of the kind
nobody has a reason to doubt.

This detects it and says so. It does NOT re-authenticate, maintain a session or build a ZAP
context — a separate decision, deliberately not taken here. Converting a silent failure into
a visible one is the entire goal.

The invariants:
  * each of the three expiry SHAPES is caught (login redirect / login form / 401-403 wall),
    plus the collapse-to-one-response-shape case the first three miss;
  * a healthy authenticated scan is NOT flagged, or the warning gets ignored on the run that
    matters;
  * too little traffic yields `unknown`, never `ok` — a false all-clear re-creates exactly
    the confidence this removes;
  * a `suspect` verdict reaches the REPORT, next to the finding count it should be read with.

Hermetic — synthetic exchanges, no ZAP, no network. Run:  python test_scan_session_health.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import report as R  # noqa: E402
from cockpit import proxy as P  # noqa: E402


def _ex(status: int, *, location: str = "", body: str = "", url: str = "", size: int = 0):
    headers = [P.CapturedHeader(name="Location", value=location)] if location else []
    return P.CapturedExchange(
        id=f"e{status}-{url or location or len(body)}",
        request=P.CapturedRequest(method="GET", url=url or "https://app.test/x"),
        response=P.CapturedResponse(
            status=status, headers=headers, body=body,
            size_bytes=size or len(body),
        ),
    )


def _healthy(n: int = 30) -> list:
    """A varied, authenticated-looking scan: real pages of differing sizes."""
    return [
        _ex(200, url=f"https://app.test/orders/{i}", body="x" * (500 + i * 137))
        for i in range(n)
    ]


def test_a_healthy_authenticated_scan_is_not_flagged() -> None:
    """The control that keeps the warning worth reading."""
    h = P.session_health(_healthy())
    assert h["verdict"] == "ok", h
    assert h["reasons"] == [], h
    assert h["sampled"] == 30
    print("  a varied authenticated scan is NOT flagged: PASS")


def test_a_login_redirect_wall_is_caught() -> None:
    traffic = _healthy(15) + [
        _ex(302, location="https://app.test/login?returnUrl=%2Forders", url=f"/o/{i}")
        for i in range(15)
    ]
    h = P.session_health(traffic)
    assert h["verdict"] == "suspect", h
    assert h["login_redirects"] == 15, h
    assert any("login-shaped" in r for r in h["reasons"]), h["reasons"]
    print("  a wall of redirects to a login path is caught: PASS")


def test_a_login_form_in_the_body_is_caught() -> None:
    """The friendlier failure: HTTP 200, and the body is the login page."""
    login = '<form action="/signin"><input type="password" name="password"></form>'
    traffic = _healthy(10) + [_ex(200, body=login, url=f"/o/{i}") for i in range(15)]
    h = P.session_health(traffic)
    assert h["verdict"] == "suspect", h
    assert h["login_bodies"] == 15, h
    print("  a 200 that is really the login page is caught: PASS")


def test_an_auth_rejection_wall_is_caught() -> None:
    traffic = _healthy(15) + [_ex(401, url=f"/o/{i}", body="nope") for i in range(15)]
    h = P.session_health(traffic)
    assert h["verdict"] == "suspect", h
    assert h["auth_rejections"] == 15, h
    assert any("401/403" in r for r in h["reasons"]), h["reasons"]
    print("  a wall of 401/403 is caught: PASS")


def test_a_collapse_to_one_response_shape_is_caught() -> None:
    """The case the first three miss: a login wall that renders a plain page with no password
    field, at 200, with no redirect. The tell is that a VARIED scan stopped getting varied
    answers — the app is no longer distinguishing between the requests."""
    same = "<html>Please sign in to continue</html>"
    traffic = [_ex(200, body=same, url=f"https://app.test/orders/{i}") for i in range(30)]
    h = P.session_health(traffic)
    assert h["verdict"] == "suspect", h
    assert any("collapsed to one shape" in r for r in h["reasons"]), h["reasons"]
    assert h["uniform_share"] >= 0.9, h
    print("  a collapse to a single response shape is caught: PASS")


def test_too_little_traffic_is_unknown_not_ok() -> None:
    """*** A FALSE ALL-CLEAR IS THE FAILURE THIS EXISTS TO REMOVE. ***"""
    for n in (0, 1, 5, 9):
        h = P.session_health(_healthy(n))
        assert h["verdict"] == "unknown", (n, h)
        assert "too few to judge" in " ".join(h["reasons"]), h
    # ...and at the threshold it will commit to a verdict
    assert P.session_health(_healthy(10))["verdict"] == "ok"
    print("  fewer than 10 responses yields `unknown`, never `ok`: PASS")


def test_a_partial_expiry_still_trips_it() -> None:
    """A session that dies a third of the way in still leaves two thirds of good traffic."""
    traffic = _healthy(20) + [
        _ex(302, location="/login", url=f"/o/{i}") for i in range(10)
    ]
    h = P.session_health(traffic)
    assert h["verdict"] == "suspect", h
    # ...but a couple of stray login redirects in an otherwise healthy scan is NOT expiry.
    # An app can legitimately redirect a handful of admin URLs.
    minor = _healthy(30) + [_ex(302, location="/login", url="/admin")]
    assert P.session_health(minor)["verdict"] == "ok", P.session_health(minor)
    print("  a third of the scan going login-shaped trips it; a stray redirect does not: PASS")


def test_the_warning_reaches_the_report() -> None:
    """A detection nobody reads is not a warning. It has to land next to the finding count."""
    suspect = P.session_health(
        _healthy(10) + [_ex(302, location="/login", url=f"/o/{i}") for i in range(15)]
    )
    block = R.build_session_health_block({"scan_session_health": suspect})
    assert "AUTHENTICATED SESSION MAY HAVE EXPIRED" in block, block
    assert "not that the application is secure" in block, (
        "the report does not say what a zero finding count might actually mean"
    )
    assert "Re-establish the session and re-run" in block, block

    # `unknown` warns more softly, but still warns
    unk = R.build_session_health_block({"scan_session_health": P.session_health(_healthy(3))})
    assert "UNKNOWN" in unk and "not evidence of a secure application" in unk, unk

    # a healthy scan adds NOTHING to the report — a banner on every report is wallpaper
    assert R.build_session_health_block({"scan_session_health": P.session_health(_healthy())}) == ""
    assert R.build_session_health_block({}) == ""
    print("  a suspect (and an unknown) verdict reaches the report; a healthy one does not: PASS")


def test_the_detector_only_reads() -> None:
    """It notices. It does not re-authenticate, log in, or drive the browser — that was
    explicitly scoped OUT, and a detector that could would be a different feature."""
    import ast
    import inspect
    import textwrap

    # AST, NOT A SUBSTRING SCAN. The first version of this check asserted on the source text
    # and failed on its own docstring — "does this traffic still look authenticated?" contains
    # the word `authenticate`. A grep cannot tell a sentence from a call, which is why this
    # repo's rule is to scan the call graph.
    tree = ast.parse(textwrap.dedent(inspect.getsource(P.session_health)))
    called: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Name):
                called.add(fn.id)
            elif isinstance(fn, ast.Attribute):
                called.add(fn.attr)
    # Named precisely. `get`, `post` and `run` are NOT here: `shapes.get(key, 0)` is a dict
    # lookup, and a forbidden-list that fires on it would be switched off within a week —
    # the same reason the scope check does not flag every dotted token as a host.
    forbidden = {
        "_api_get", "urlopen", "urlretrieve", "Popen", "check_output", "check_call",
        "start_scan", "stop_scan", "history", "connect", "send", "sendall",
    }
    leaked = called & forbidden
    assert not leaked, (
        f"session_health calls {sorted(leaked)} — it must only read the exchanges it was "
        "handed, never fetch, run or re-authenticate anything"
    )
    # POSITIVE CONTROL — the scan really is looking at calls.
    assert "max" in called or "len" in called, (
        f"the AST walk found no calls at all, so it would pass a function that made them: "
        f"{sorted(called)}"
    )
    traffic = _healthy(12)
    before = [e.model_dump() for e in traffic]
    P.session_health(traffic)
    assert [e.model_dump() for e in traffic] == before, "the detector mutated its input"
    print("  the detector reads its input and nothing else: PASS")


if __name__ == "__main__":
    test_a_healthy_authenticated_scan_is_not_flagged()
    test_a_login_redirect_wall_is_caught()
    test_a_login_form_in_the_body_is_caught()
    test_an_auth_rejection_wall_is_caught()
    test_a_collapse_to_one_response_shape_is_caught()
    test_too_little_traffic_is_unknown_not_ok()
    test_a_partial_expiry_still_trips_it()
    test_the_warning_reaches_the_report()
    test_the_detector_only_reads()
    print("ALL scan session-health tests pass")
