"""HTTP repeater containment + behaviour (cockpit/repeater.py) — Phase 4 item 3.

The repeater mirrors :kali's containment and adds a scope check. These tests fail loudly if any
of that is weakened:

  1. HARDCODED CONTAINER. No request field can change it; the argv always execs
     config.KALI_OPEN_CONTAINER, even when the URL smuggles another container name.
  2. ARGV-ONLY. No request field (URL, header, body) ever reaches a shell — the body goes on
     stdin, and there is no `sh -c` anywhere in the argv.
  3. HUMAN-ONLY. repeater.send may be referenced ONLY by the route (router.py) + this test —
     never the executor/orchestrator/agent path. Scanned across the source tree.
  4. SCOPE-CHECKED. A send naming an active engagement whose scope excludes the URL host is
     REFUSED, and nothing runs. A send with no engagement runs free (like :kali).
  5. AVAILABILITY + AUDIT. If the open container is down, the send refuses. Every send is
     recorded to the run store.

Hermetic: _container_running, subprocess.run and runstore.save_run are monkeypatched. No Docker
daemon, no real DB. Run:  python test_repeater.py
"""
from __future__ import annotations

import subprocess
import types
from pathlib import Path

from cockpit import config
from cockpit import repeater as RP
from cockpit.repeater import (RepeaterHeader, RepeaterRefused, RepeaterRequest, send)
from test_support import scans


class _Spy:
    """Swaps availability, subprocess.run and save_run for fakes."""

    def __init__(self, *, up=True, stdout="", stderr="", rc=0, timeout=False):
        self.up = up
        self.stdout = stdout
        self.stderr = stderr
        self.rc = rc
        self.timeout = timeout
        self.argv = None
        self.input = None
        self.ran = False
        self.saved = None
        self._orig = (RP._container_running, RP.subprocess.run, RP.runstore.save_run)

    def __enter__(self):
        def fake_up(name):
            return self.up

        def fake_run(argv, **kwargs):
            self.ran = True
            self.argv = argv
            self.input = kwargs.get("input")
            if self.timeout:
                raise subprocess.TimeoutExpired(cmd=argv, timeout=kwargs.get("timeout", 60))
            return types.SimpleNamespace(stdout=self.stdout, stderr=self.stderr, returncode=self.rc)

        def fake_save(record):
            self.saved = record

        RP._container_running = fake_up
        RP.subprocess.run = fake_run
        RP.runstore.save_run = fake_save
        return self

    def __exit__(self, *exc):
        RP._container_running, RP.subprocess.run, RP.runstore.save_run = self._orig


_OK_RESPONSE = (
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/html\r\n"
    "Server: nginx\r\n"
    "\r\n"
    "<html>hi</html>"
)


def _resp_with_sentinel(body_block: str, code=200, t=0.12, size=15, url="http://t/") -> str:
    # Emulate curl -D - -o - -w "<sentinel> ...": the parser finds the sentinel by prefix.
    return body_block + f"\n{RP._SENTINEL_TMPL.format('X')} {code} {t} {size} {url}\n"


# --------------------------------------------------------------------------- #
# 1. hardcoded container
# --------------------------------------------------------------------------- #
def test_container_is_hardcoded_never_from_the_request() -> None:
    with _Spy(stdout=_OK_RESPONSE) as spy:
        # A URL that names the isolated sandbox must NOT redirect the exec there.
        send(RepeaterRequest(method="GET", url="http://hackpit-kali-sandbox/x"))
    argv = spy.argv
    assert argv[:3] == ["docker", "exec", "-i"], argv[:3]
    assert config.KALI_OPEN_CONTAINER in argv, "must exec the OPEN sandbox"
    assert "hackpit-kali-sandbox" not in argv[: argv.index("curl")], \
        "the URL host must never become the exec target container"
    print("  the exec container is the hardcoded open box, never a request field: PASS")


# --------------------------------------------------------------------------- #
# 2. argv-only — nothing reaches a shell
# --------------------------------------------------------------------------- #
def test_no_shell_and_body_goes_on_stdin() -> None:
    with _Spy(stdout=_OK_RESPONSE) as spy:
        send(RepeaterRequest(
            method="POST", url="https://t/login",
            headers=[RepeaterHeader(name="X-Evil", value="a; rm -rf /")],
            body="user=a&pw=b; cat /etc/passwd",
        ))
    argv = spy.argv
    assert "sh" not in argv and "-c" not in argv, "the repeater must never invoke a shell"
    assert argv[argv.index("curl")] == "curl"
    # the body is on stdin, never in the argv
    assert spy.input == "user=a&pw=b; cat /etc/passwd"
    assert not any("rm -rf" in tok and tok != "X-Evil: a; rm -rf /" for tok in argv), argv
    # the evil header is a single -H token, literal — not split into extra argv
    assert "-H" in argv and "X-Evil: a; rm -rf /" in argv
    print("  argv-only: no shell, header/body are literal tokens, body on stdin: PASS")


def test_method_and_url_are_validated() -> None:
    with _Spy(stdout=_OK_RESPONSE):
        for bad in [
            RepeaterRequest(method="FROBNICATE", url="http://t/"),
            RepeaterRequest(method="GET", url="file:///etc/passwd"),
            RepeaterRequest(method="GET", url="not-a-url"),
        ]:
            try:
                send(bad)
                assert False, f"should have refused {bad.method} {bad.url}"
            except RepeaterRefused:
                pass
    print("  an unknown method or non-http(s) URL is refused before anything runs: PASS")


# --------------------------------------------------------------------------- #
# 3. human-only (source-scan lock)
# --------------------------------------------------------------------------- #
# `cockpit/repeater.py` is NOT allow-listed: the patterns are all QUALIFIED references
# (`repeater.send`, `cockpit.repeater`) which the defining module never writes about itself.
# An allow-list entry that can never match reads as coverage while providing none, so it is
# scanned like any other module — and comes back clean, which is the honest result.
_REPEATER_ALLOWED = {"cockpit/router.py"}
_REPEATER_PATTERNS = [
    r"repeater\.send", r"\bimport repeater\b", r"from \.repeater", r"cockpit\.repeater",
]
_REPEATER_AST_TARGETS = ["cockpit.repeater"]


def test_repeater_is_human_only() -> None:
    """repeater.send must be reachable ONLY from the route + this test — NEVER the agent path.

    Whole tree, path-keyed allow-list, AST pass. The old form covered 30 of 69 modules.
    """
    res = scans.scan_source_tree(
        patterns=_REPEATER_PATTERNS, allowed=_REPEATER_ALLOWED,
        ast_targets=_REPEATER_AST_TARGETS,
    )
    scans.assert_clean(
        res,
        what="the repeater must be HUMAN-ONLY",
        must_have_scanned=["orchestrator.py", "adgraph/orchestrator.py", "cockpit/executor.py"],
        min_checked=60,
    )
    scans.assert_catches_a_planted_violation(
        plant="from cockpit.repeater import send",
        patterns=_REPEATER_PATTERNS, allowed=_REPEATER_ALLOWED,
        ast_targets=_REPEATER_AST_TARGETS,
    )
    from cockpit import executor as EX
    assert not hasattr(EX, "repeater") and not hasattr(EX, "send"), \
        "the executor must not reference the repeater"
    print(f"  the repeater is human-only across all {len(res.checked)} backend modules "
          "(+ planted-violation control): PASS")


# --------------------------------------------------------------------------- #
# 4. scope
# --------------------------------------------------------------------------- #
def test_out_of_scope_send_is_refused_and_nothing_runs() -> None:
    from cockpit import scope as scope_mod

    class _Eng:  # a stand-in EngagementRecord — only resolved_scope is consulted
        pass

    resolved = scope_mod.parse_scope("target.com, *.target.com", resolve=False)
    orig_active, orig_scope = RP.engagement.get_active, RP.engagement.resolved_scope
    try:
        RP.engagement.get_active = lambda eid: _Eng() if eid == "e1" else None
        RP.engagement.resolved_scope = lambda eng: resolved
        with _Spy(stdout=_OK_RESPONSE) as spy:
            # out of scope -> refused, nothing sent
            try:
                send(RepeaterRequest(url="https://evil.example/x", engagement_id="e1"))
                assert False, "out-of-scope send must be refused"
            except RepeaterRefused as exc:
                assert "OUT OF SCOPE" in str(exc)
            assert not spy.ran, "nothing may run on an out-of-scope refusal"

            # in scope -> allowed
            send(RepeaterRequest(url="https://api.target.com/x", engagement_id="e1"))
            assert spy.ran, "an in-scope send must proceed"

            # inactive engagement id -> fail closed (refused), does not run unbounded
            spy.ran = False
            try:
                send(RepeaterRequest(url="https://anything/x", engagement_id="nope"))
                assert False, "an inactive engagement id must fail closed"
            except RepeaterRefused as exc:
                assert "not active" in str(exc)
            assert not spy.ran
    finally:
        RP.engagement.get_active, RP.engagement.resolved_scope = orig_active, orig_scope
    print("  out-of-scope + inactive-engagement sends are refused; in-scope proceeds: PASS")


def test_no_engagement_means_no_scope_check() -> None:
    with _Spy(stdout=_OK_RESPONSE) as spy:
        send(RepeaterRequest(url="https://anywhere.example/x"))  # no engagement_id
    assert spy.ran, "without an engagement the repeater runs free, like :kali"
    print("  a send with no engagement runs unbounded (no scope applies): PASS")


# --------------------------------------------------------------------------- #
# 5. availability + audit
# --------------------------------------------------------------------------- #
def test_refuses_when_sandbox_down() -> None:
    with _Spy(up=False, stdout=_OK_RESPONSE) as spy:
        try:
            send(RepeaterRequest(url="http://t/"))
            assert False, "must refuse when the sandbox is down"
        except RepeaterRefused:
            pass
        assert not spy.ran, "nothing runs when the sandbox is down"
    print("  a down sandbox refuses the send; nothing runs: PASS")


def test_every_send_is_recorded() -> None:
    with _Spy(stdout=_resp_with_sentinel(_OK_RESPONSE)) as spy:
        ex = send(RepeaterRequest(method="POST", url="http://t/api", session_id="s1"))
    assert spy.saved is not None, "every send must be recorded to the run store"
    rec = spy.saved
    assert rec.command == "http" and rec.args == ["POST", "http://t/api"]
    assert rec.approved is True and rec.session_id == "s1"
    assert ex.run_id == rec.run_id
    print("  every send is recorded to the run store (audit): PASS")


# --------------------------------------------------------------------------- #
# 6. response parsing + history
# --------------------------------------------------------------------------- #
def test_response_is_parsed() -> None:
    raw = _resp_with_sentinel(_OK_RESPONSE, code=200, t=0.234, size=15)
    resp = RP._parse_response(raw, RP._SENTINEL_TMPL.format("X"))
    assert resp.status == 200
    assert resp.reason == "OK"
    assert resp.time_ms == 234
    assert {h.name for h in resp.headers} == {"Content-Type", "Server"}
    assert resp.body == "<html>hi</html>"
    print("  the response is parsed into status/headers/body/timing: PASS")


def test_redirect_takes_the_final_response_headers() -> None:
    chained = (
        "HTTP/1.1 301 Moved Permanently\r\nLocation: /new\r\n\r\n"
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
        '{"ok":true}'
    )
    resp = RP._parse_response(_resp_with_sentinel(chained, code=200), RP._SENTINEL_TMPL.format("X"))
    assert resp.status == 200 and resp.reason == "OK"
    assert {h.name for h in resp.headers} == {"Content-Type"}, "must keep the FINAL hop's headers"
    assert resp.body == '{"ok":true}'
    print("  with -L the parser keeps the final response's headers + body: PASS")


def test_history_is_per_session_and_newest_first() -> None:
    RP._history.clear()
    with _Spy(stdout=_resp_with_sentinel(_OK_RESPONSE)):
        send(RepeaterRequest(url="http://t/1", session_id="hs"))
        send(RepeaterRequest(url="http://t/2", session_id="hs"))
        send(RepeaterRequest(url="http://t/other", session_id="zz"))
    hs = RP.history("hs")
    assert [e.request.url for e in hs] == ["http://t/2", "http://t/1"], "newest first, per session"
    assert len(RP.history("zz")) == 1
    print("  history is per-session and newest-first: PASS")


if __name__ == "__main__":
    test_container_is_hardcoded_never_from_the_request()
    test_no_shell_and_body_goes_on_stdin()
    test_method_and_url_are_validated()
    test_repeater_is_human_only()
    test_out_of_scope_send_is_refused_and_nothing_runs()
    test_no_engagement_means_no_scope_check()
    test_refuses_when_sandbox_down()
    test_every_send_is_recorded()
    test_response_is_parsed()
    test_redirect_takes_the_final_response_headers()
    test_history_is_per_session_and_newest_first()
    print("ALL repeater tests pass")
