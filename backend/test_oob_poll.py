"""Build #13 part 3 — the poll client and state ingest (spec §3.3).

A canary that records a hit nobody reads is a canary that produced nothing. This file locks
the half that turns a line in a JSONL file on a VPS into a finding in a report:

  * **Correlation is the product.** A hit arrives with no memory of why it was caused. Joining
    it back to the step that minted the token is the whole value; a hit that cannot be joined
    is still kept, because "something reached the internet" and "nothing arrived" are different
    findings and must not look the same.
  * **Nothing is silently dropped.** A hit whose engagement has no state session cannot be
    filed anywhere — so it is REPORTED as unfiled rather than discarded. Silence is the failure
    mode this whole part exists to remove; reintroducing it in the ingest would be perverse.
  * **The cursor only moves forward, and only after the ingest.** It is the sole thing stopping
    a burst of hits being replayed as new findings on the next poll, and the sole thing
    stopping a mid-flight failure from skipping hits nobody ever sees.
  * **The outbound request cannot be redirected.** This is the one that would actually bite: a
    poll that followed a 3xx would issue a second request to an address the canary chose, from
    the backend process, on the operator's own machine.

Hermetic: no socket is bound and no request leaves. The HTTP paths are exercised through the
module's real opener machinery with the transport stubbed; the live end-to-end lives in
docker/proof/oob_loopback_proof.py.

Run: python test_oob_poll.py
"""

from __future__ import annotations

import ast
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from oob import config as oob_config  # noqa: E402
from oob import poll, tokens  # noqa: E402

BACKEND = Path(__file__).resolve().parent
POLL_PATH = BACKEND / "oob" / "poll.py"

# SCRATCH STORE. These tests call save() and clear() on the canary configuration, and the real
# store is the operator's own: clearing it would destroy the read secret of a LIVE canary,
# which is not recoverable from anything HackPit keeps (the matching value lives in a 0700 file
# on a VPS). A suite that can damage the thing it is testing is not hermetic, whatever else it
# asserts — so both stores are pointed at a temporary database for the run.
_SCRATCH = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
oob_config.DB_PATH = Path(_SCRATCH.name) / "oob-test.db"
tokens.DB_PATH = oob_config.DB_PATH

ENGAGEMENT = "_test-oob-poll"
SESSION = "_test-oob-poll-session"
ZONE = "oob.example.net"


def _configured() -> None:
    """Point the module at a canary that does not exist. Nothing here connects."""
    oob_config.init_db()
    tokens.init_db()
    oob_config.save(zone=ZONE, host="203.0.113.10", read_secret="s" * 32)


def _cleanup() -> None:
    tokens.clear(ENGAGEMENT)
    oob_config.clear()


# --------------------------------------------------------------------------- #
# correlation
# --------------------------------------------------------------------------- #
def test_a_hit_is_joined_back_to_the_step_that_minted_it() -> None:
    """The correlation IS the deliverable — without it a hit is an anonymous packet."""
    _configured()
    minted = tokens.mint(ENGAGEMENT, "step-7", "blind SSRF on the avatar importer")
    token = minted["token"]

    joined = poll.correlate([
        {"kind": "dns", "token": token, "qname": f"{token}.{ZONE}", "qtype": "A",
         "source_ip": "198.51.100.9", "at": "2026-08-03T10:00:00+00:00", "seq": 1},
    ])
    (hit,) = joined
    assert hit["correlated"] is True, hit
    assert hit["engagement_id"] == ENGAGEMENT, hit
    assert hit["step_id"] == "step-7", hit
    assert hit["note"] == "blind SSRF on the avatar importer", hit
    assert hit["minted_at"], "the mint time is what makes a ten-minute-late hit legible"
    _cleanup()
    print("  a hit resolves back to the engagement, step and note that minted it: PASS")


def test_an_unknown_or_absent_token_is_kept_never_dropped() -> None:
    """Stray hits are the ONLY way to see a zone being crawled, or a payload landing at the
    wrong name. Dropping them makes a misconfigured payload indistinguishable from a target
    that was not vulnerable."""
    _configured()
    joined = poll.correlate([
        {"kind": "dns", "token": None, "qname": f"www.{ZONE}", "source_ip": "1.1.1.1", "seq": 1},
        {"kind": "dns", "token": "neverminted1", "qname": "x", "source_ip": "1.1.1.1", "seq": 2},
        {"kind": "http", "token": "not a token at all", "path": "/", "source_ip": "1.1.1.1", "seq": 3},
    ])
    assert len(joined) == 3, f"{3 - len(joined)} hit(s) were dropped: {joined}"
    assert [h["correlated"] for h in joined] == [False, False, False], joined
    assert all(h["engagement_id"] is None for h in joined), joined
    _cleanup()
    print("  uncorrelated and malformed hits are kept and marked, never dropped: PASS")


# --------------------------------------------------------------------------- #
# what gets filed, and what is reported instead
# --------------------------------------------------------------------------- #
def test_a_correlated_hit_becomes_a_high_severity_finding() -> None:
    _configured()
    minted = tokens.mint(ENGAGEMENT, "step-7", "blind SSRF on the avatar importer")
    token = minted["token"]
    joined = poll.correlate([
        {"kind": "dns", "token": token, "qname": f"{token}.{ZONE}", "qtype": "A",
         "source_ip": "198.51.100.9", "at": "2026-08-03T10:00:00+00:00", "seq": 1},
    ])
    findings, unfiled = poll.findings_for(joined, {ENGAGEMENT: SESSION})
    assert not unfiled, unfiled
    (finding,) = findings
    assert finding.session_id == SESSION, finding
    assert finding.severity == "high", (
        f"severity {finding.severity!r} — a callback from inside a target's network is the "
        f"proof for the entire blind class; grading it down understates every one of them"
    )
    assert token in finding.reference, "the token must be on the finding or it cannot be traced"
    assert "blind SSRF on the avatar importer" in finding.title, finding.title
    assert "198.51.100.9" in finding.evidence, finding.evidence
    assert "2026-08-03T10:00:00+00:00" in finding.evidence, finding.evidence
    _cleanup()
    print("  a correlated hit becomes a high-severity finding carrying source, time, token: PASS")


def test_a_hit_with_nowhere_to_file_is_reported_not_swallowed() -> None:
    """The two ways a hit can fail to become a finding are DIFFERENT, and both are reported.

    An engagement with no state session has nowhere to put the finding; a token this HackPit
    never minted cannot be attributed at all. Neither may vanish — the operator has to be able
    to tell "no callback" from "a callback I could not place".
    """
    _configured()
    minted = tokens.mint(ENGAGEMENT, None, "no session attached")
    joined = poll.correlate([
        {"kind": "dns", "token": minted["token"], "qname": "x", "source_ip": "1.1.1.1", "seq": 1},
        {"kind": "dns", "token": "neverminted1", "qname": "y", "source_ip": "1.1.1.1", "seq": 2},
    ])
    findings, unfiled = poll.findings_for(joined, {})  # no engagement -> session mapping
    assert findings == [], findings
    assert len(unfiled) == 2, unfiled
    reasons = [u["reason"] for u in unfiled]
    assert any("session" in r for r in reasons), reasons
    assert any("never minted" in r for r in reasons), reasons
    _cleanup()
    print("  both un-fileable shapes are reported with distinct reasons, never swallowed: PASS")


# --------------------------------------------------------------------------- #
# the cursor
# --------------------------------------------------------------------------- #
def test_the_cursor_never_moves_backwards() -> None:
    """A stale cursor written by a racing poll would REPLAY a burst of hits as new findings."""
    _configured()
    oob_config.set_cursor(50)
    assert oob_config.cursor() == 50
    oob_config.set_cursor(10)
    assert oob_config.cursor() == 50, (
        f"the cursor rewound to {oob_config.cursor()} — every hit between 10 and 50 would be "
        f"re-ingested on the next poll"
    )
    oob_config.set_cursor(51)
    assert oob_config.cursor() == 51
    _cleanup()
    print("  the poll cursor is monotonic; a stale write cannot rewind it: PASS")


def test_a_failed_poll_leaves_the_cursor_untouched() -> None:
    """Re-reading hits is free (findings upsert on a fingerprint). Missing one is not.

    So the cursor advances only AFTER the ingest returns. This drives the real `poll()` with
    the fetch raised, and asserts the position did not move.
    """
    _configured()
    oob_config.set_cursor(7)
    original = poll.fetch

    def _boom(*args, **kwargs):
        raise poll.PollError("the canary is unreachable")

    poll.fetch = _boom  # type: ignore[assignment]
    try:
        try:
            poll.poll({})
        except poll.PollError:
            pass
        else:
            raise AssertionError("a failing fetch did not surface as a PollError")
    finally:
        poll.fetch = original  # type: ignore[assignment]
    assert oob_config.cursor() == 7, (
        f"the cursor moved to {oob_config.cursor()} despite the poll failing — the hits in "
        f"between would never be read by anything"
    )
    _cleanup()
    print("  a poll that fails anywhere leaves the cursor exactly where it was: PASS")


def test_an_explicit_after_never_advances_the_stored_cursor() -> None:
    """`verify` and the panel read with an explicit `after`. If that moved the cursor, a
    verify run would consume a genuine callback that arrived in the same window."""
    _configured()
    oob_config.set_cursor(3)
    original = poll.fetch
    poll.fetch = lambda after=None, limit=200: {"hits": [], "cursor": 99, "after": after or 0}  # type: ignore[assignment]
    try:
        poll.poll({}, after=0)
    finally:
        poll.fetch = original  # type: ignore[assignment]
    assert oob_config.cursor() == 3, (
        f"an explicit-after read advanced the shared cursor to {oob_config.cursor()}"
    )
    _cleanup()
    print("  reading with an explicit `after` does not touch the shared cursor: PASS")


# --------------------------------------------------------------------------- #
# the outbound request
# --------------------------------------------------------------------------- #
def test_the_poll_client_refuses_to_follow_a_redirect() -> None:
    """THE one that would actually bite.

    A canary answering `302 http://169.254.169.254/latest/meta-data/` would otherwise turn a
    poll into an SSRF from the backend process, on the operator's own machine. This is not
    asserted by reading the code: `build_opener` RE-ADDS every default handler that is not
    overridden, so leaving the redirect handler out would have followed redirects while the
    docstring said otherwise. The real opener is built and interrogated.
    """
    opener = poll._opener()
    redirectors = [
        h for h in opener.handlers if isinstance(h, urllib.request.HTTPRedirectHandler)
    ]
    assert redirectors, "no redirect handler at all — build_opener would re-add the default"
    for handler in redirectors:
        assert isinstance(handler, poll._NoRedirect), (
            f"{type(handler).__name__} would FOLLOW a 3xx to an address the canary chose"
        )
        assert handler.redirect_request(None, None, 302, "Found", {}, "http://169.254.169.254/") is None, (
            "the redirect handler returned a request — the poll would follow it"
        )

    # ...and NOTHING will proxy this request, so an ambient http_proxy in the operator's
    # environment cannot re-route one that carries the read secret. Asserted as "no handler
    # holds a proxy" rather than "a ProxyHandler is present": an empty ProxyHandler defines no
    # `*_open` methods and so is never registered at all, which is the same guarantee reached
    # a different way — and asserting the presence of an object would have failed on working
    # code while passing on broken code the day it started proxying.
    proxied = [
        h.proxies for h in opener.handlers
        if isinstance(h, urllib.request.ProxyHandler) and h.proxies
    ]
    assert not proxied, f"a proxy is honoured for a request carrying the read secret: {proxied}"

    # POSITIVE CONTROL — the same predicate must fire on an opener that DOES proxy.
    leaky = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": "http://127.0.0.1:9"})
    )
    assert [
        h.proxies for h in leaky.handlers
        if isinstance(h, urllib.request.ProxyHandler) and h.proxies
    ], "the proxy check cannot fail — it would pass on an opener that proxies"
    print("  redirects are refused and nothing proxies the poll (real opener + control): PASS")


def test_the_destination_is_the_stored_host_and_the_paths_are_constants() -> None:
    """There is no argument to this module that can change WHERE it connects.

    The base comes from the config store and the path from a module constant, so the two
    halves of a URL are both out of a caller's reach.
    """
    _configured()
    seen: list[str] = []

    class _Fake:
        def open(self, request, timeout=None):
            seen.append(request.full_url)
            raise urllib.error.URLError("stopped before any socket")

    original = poll._opener
    poll._opener = lambda: _Fake()  # type: ignore[assignment]
    try:
        for call in (lambda: poll.fetch(after=5), poll.health):
            try:
                call()
            except poll.PollError:
                pass
    finally:
        poll._opener = original  # type: ignore[assignment]

    assert seen == [
        "http://203.0.113.10/_hp/hits?after=5&limit=200",
        "http://203.0.113.10/_hp/health",
    ], seen
    assert all(u.startswith("http://203.0.113.10/_hp/") for u in seen), seen
    _cleanup()
    print(f"  both routes address the STORED host under /_hp/ and nothing else: PASS")


def test_the_bearer_secret_is_sent_and_never_returned() -> None:
    _configured()
    headers: list[dict] = []

    class _Fake:
        def open(self, request, timeout=None):
            headers.append(dict(request.headers))
            raise urllib.error.URLError("stopped")

    original = poll._opener
    poll._opener = lambda: _Fake()  # type: ignore[assignment]
    try:
        try:
            poll.fetch()
        except poll.PollError:
            pass
    finally:
        poll._opener = original  # type: ignore[assignment]

    (sent,) = headers
    assert sent.get("Authorization") == "Bearer " + "s" * 32, sent
    # ...and the masked view never carries it.
    public = oob_config.public()
    assert "s" * 32 not in str(public), public
    assert public["has_secret"] is True, public
    _cleanup()
    print("  the read secret goes out as a bearer and never appears in the public view: PASS")


def test_probe_takes_a_minted_token_and_nothing_else() -> None:
    """`probe` is the one request that is deliberately unauthenticated, so its path has to be
    incapable of naming anything but a token — otherwise it is a fetch-arbitrary-path button."""
    _configured()
    for bad in ("", "../../etc/passwd", "_hp/hits", "a", "UPPERCASE123", "tok with space"):
        try:
            poll.probe(bad)
        except poll.PollError:
            continue
        raise AssertionError(f"probe accepted {bad!r} as a path")
    _cleanup()
    print("  probe refuses every non-token path it was offered: PASS")


# --------------------------------------------------------------------------- #
# the module runs nothing
# --------------------------------------------------------------------------- #
_BANNED_CALLS = {"eval", "exec", "compile", "system", "popen", "Popen", "run", "check_output"}
_BANNED_IMPORTS = {"subprocess", "os", "pickle", "shutil", "ctypes"}


def test_the_poll_client_executes_nothing() -> None:
    """It parses JSON off the internet. A module that also had a shell would be a bad place
    for a parser bug to land."""
    tree = ast.parse(POLL_PATH.read_text(encoding="utf-8"))
    offences: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            offences += [f"line {node.lineno}: import {a.name}"
                         for a in node.names if a.name.split(".")[0] in _BANNED_IMPORTS]
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            if root in _BANNED_IMPORTS:
                offences.append(f"line {node.lineno}: from {node.module} import ...")
        elif isinstance(node, ast.Call):
            name = ""
            if isinstance(node.func, ast.Name):
                name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                name = node.func.attr
            if name in _BANNED_CALLS:
                offences.append(f"line {node.lineno}: {name}()")
    assert not offences, "the poll client is not inert:\n  " + "\n  ".join(offences)

    # POSITIVE CONTROL — the same walk must flag each planted form.
    for planted in ("import subprocess\n", "def f(x):\n    return eval(x)\n",
                    "import os\nos.system('id')\n"):
        found = False
        for node in ast.walk(ast.parse(planted)):
            if isinstance(node, ast.Import):
                found |= any(a.name.split(".")[0] in _BANNED_IMPORTS for a in node.names)
            elif isinstance(node, ast.Call):
                fn = node.func
                found |= isinstance(fn, ast.Name) and fn.id in _BANNED_CALLS
                found |= isinstance(fn, ast.Attribute) and fn.attr in _BANNED_CALLS
        assert found, f"the inertness scan missed a planted {planted!r}"
    print("  the poll client imports no shell and makes no execution call (3 controls): PASS")


if __name__ == "__main__":
    print("== OOB canary poll client + state ingest (spec §3.3) ==")
    test_a_hit_is_joined_back_to_the_step_that_minted_it()
    test_an_unknown_or_absent_token_is_kept_never_dropped()
    test_a_correlated_hit_becomes_a_high_severity_finding()
    test_a_hit_with_nowhere_to_file_is_reported_not_swallowed()
    test_the_cursor_never_moves_backwards()
    test_a_failed_poll_leaves_the_cursor_untouched()
    test_an_explicit_after_never_advances_the_stored_cursor()
    test_the_poll_client_refuses_to_follow_a_redirect()
    test_the_destination_is_the_stored_host_and_the_paths_are_constants()
    test_the_bearer_secret_is_sent_and_never_returned()
    test_probe_takes_a_minted_token_and_nothing_else()
    test_the_poll_client_executes_nothing()
    print("ALL OOB poll client tests pass")
