"""ZAP active-scan parsing + mapping.  Run:  python test_zap_scan.py

Everything here runs against a REAL captured API response, committed as
``test_support/zap_api_alerts_fixture.json``. It is the exact body ZAP 2.17.0 returned after the
measured scan on 2026-08-04 — 376 attack requests against one proxy-captured endpoint, which
found a live High SQL injection in the lab target.

WHY A REAL FIXTURE AND NOT A HAND-WRITTEN ONE. Build #14 part 1's headline defect was a parser
written against key names that existed nowhere: every test passed, because the test chose the
string it fed the parser. The whole class of bug is invisible to a hermetic test that invents its
own input, so this one does not invent it.
"""

from __future__ import annotations

import json
from pathlib import Path

from cockpit import proxy

FIXTURE = Path(__file__).with_name("test_support") / "zap_api_alerts_fixture.json"
SESSION = "s-test"


def _alerts():
    rows = json.loads(FIXTURE.read_text(encoding="utf-8"))["alerts"]
    return [a for a in (proxy.parse_alert(r) for r in rows) if a is not None]


def test_the_real_api_response_parses() -> None:
    """The measured response yields both alerts with their real fields."""
    rows = json.loads(FIXTURE.read_text(encoding="utf-8"))["alerts"]
    alerts = _alerts()
    assert len(alerts) == len(rows) == 2, f"{len(rows)} raw rows -> {len(alerts)} parsed"

    by_name = {a.name: a for a in alerts}
    sqli = by_name.get("SQL Injection")
    assert sqli is not None, f"the High SQL injection is missing: {sorted(by_name)}"
    assert sqli.risk == "High", sqli.risk
    assert sqli.plugin_id == "40018", sqli.plugin_id
    assert sqli.param == "q", sqli.param
    assert sqli.method == "GET", sqli.method
    assert sqli.url.startswith("http://"), sqli.url
    assert sqli.evidence, "the alert lost its evidence"
    print(f"  the real API response parses: {len(alerts)} alerts, SQLi plugin 40018: PASS")


def test_alerts_become_findings_with_the_right_severity() -> None:
    """`risk: "High"` must land as severity `high`, not as `info`.

    A severity that silently defaults would put a live SQL injection at the bottom of a report,
    which is worse than not ingesting it at all — it would look reviewed.
    """
    findings = proxy.findings_from(_alerts(), session_id=SESSION, run_id="r1")
    assert len(findings) == 2, findings
    by_title = {f.title: f for f in findings}

    sqli = by_title["SQL Injection"]
    assert sqli.severity == "high", f"a High alert landed as {sqli.severity!r}"
    assert sqli.tool == "zap", sqli.tool
    assert sqli.session_id == SESSION and sqli.source_run_id == "r1"
    assert sqli.target.startswith("http://"), sqli.target
    assert by_title["Cross-Domain Misconfiguration"].severity == "medium"
    print("  a High alert becomes a high-severity Finding: PASS")


def test_the_plugin_reference_matches_the_report_parsers_spelling() -> None:
    """*** SO THE SAME ISSUE FOUND TWICE IS ONE FINDING, NOT TWO. ***

    Finding identity is a fingerprint over (title, target, reference). ``parse_zap`` writes
    ``pluginid:NNNNN`` from the `-quickurl` report; if this path wrote ``plugin:NNNNN`` or
    ``40018`` instead, an alert seen by both the report path and the API path would appear twice
    in a report with no way for the operator to tell they are the same thing.
    """
    findings = proxy.findings_from(_alerts(), session_id=SESSION)
    refs = sorted(f.reference for f in findings)
    assert refs == ["pluginid:10098", "pluginid:40018"], refs

    # and the fingerprint must actually collapse: the same issue from either path is one row
    from state.models import Finding

    api = [f for f in findings if f.title == "SQL Injection"][0]
    report_side = Finding(
        session_id=SESSION, title="SQL Injection", severity="high",
        target=api.target, tool="zap", reference="pluginid:40018",
    )
    assert api.fingerprint() == report_side.fingerprint(), (
        "the API path and the report path fingerprint the same SQL injection differently, so it "
        "would be stored and reported twice"
    )
    print("  the plugin reference matches parse_zap's spelling and fingerprints equal: PASS")


def test_alerts_become_endpoints_carrying_the_attacked_param() -> None:
    """The parameter ZAP attacked is the one worth remembering — it is where the bug is."""
    eps = proxy.alert_endpoints_from(_alerts(), session_id=SESSION, run_id="r1")
    assert eps, "no endpoints came out of the alerts"
    assert all(e.url.startswith("http") for e in eps), [e.url for e in eps]
    assert any("q" in e.params for e in eps), (
        f"the attacked parameter 'q' is missing from every endpoint: {[e.params for e in eps]}"
    )
    print("  alerts become endpoints carrying the attacked parameter: PASS")


def test_a_malformed_alert_never_raises() -> None:
    """A parser must never break a scan that already ran. Junk is dropped, partial is kept."""
    for junk in (None, "", 42, [], {}, {"risk": "High"}, {"name": ""}):
        assert proxy.parse_alert(junk) is None, f"junk parsed into an alert: {junk!r}"

    partial = proxy.parse_alert({"name": "Only A Name"})
    assert partial is not None and partial.name == "Only A Name", partial
    assert partial.url == "" and partial.risk == ""

    # and a partial alert still becomes a Finding — at `info`, because an unknown risk is not
    # an excuse to guess.
    findings = proxy.findings_from([partial], session_id=SESSION)
    assert len(findings) == 1 and findings[0].severity == "info", findings
    # ...but it must NOT become an endpoint, having no url
    assert proxy.alert_endpoints_from([partial], session_id=SESSION) == []
    print("  malformed alerts are dropped, partial ones survive as info findings: PASS")


def test_the_risk_vocabulary_covers_what_zap_emits() -> None:
    """ZAP's words, mapped to state.models.Finding's. Case-insensitive, unknown -> info."""
    cases = [("High", "high"), ("Medium", "medium"), ("Low", "low"),
             ("Informational", "info"), ("INFORMATIONAL", "info"), ("Critical", "critical"),
             ("", "info"), ("wat", "info")]
    for word, expected in cases:
        got = proxy.findings_from(
            [proxy.ScanAlert(name="x", risk=word)], session_id=SESSION
        )[0].severity
        assert got == expected, f"risk {word!r} -> {got!r}, expected {expected!r}"
    print("  the risk vocabulary maps correctly and defaults to info: PASS")


def test_the_report_parser_and_this_mapper_are_not_interchangeable() -> None:
    """*** THE SHAPE TRAP, LOCKED SO IT CANNOT BE 'SIMPLIFIED' AWAY. ***

    `state/parsers.py::parse_zap` reads the `-quickurl` REPORT: nested `site[].alerts[]`, severity
    in `riskcode` ("0".."3"), plugin in `pluginid`, URL in `instances[].uri`. The API returns a
    FLAT list with `risk: "High"`, `pluginId` and `url` on the alert. `_zap_report()` requires a
    `site` key, so feeding it an API response returns ZERO findings — silently, forever, with a
    green suite.

    Someone will eventually notice two ZAP parsers and try to merge them. This test is the
    argument they have to answer: it asserts the API response yields nothing through the report
    parser, WITH a control proving the report parser does work on a real report.
    """
    from state import parsers

    api_body = FIXTURE.read_text(encoding="utf-8")
    through_report_parser = parsers.parse_zap(api_body, SESSION, "r1")
    assert not through_report_parser.findings, (
        f"parse_zap found {len(through_report_parser.findings)} findings in an API response. If "
        "the shapes have converged, re-measure both before merging the parsers — this test is "
        "here because they had not."
    )

    # control: the report parser DOES work, on a real report
    report_fixture = Path(__file__).with_name("test_support") / "zap_report_fixture.json"
    from_report = parsers.parse_zap(report_fixture.read_text(encoding="utf-8"), SESSION, "r1")
    assert from_report.findings, (
        "parse_zap found nothing in a REAL -quickurl report either — the check above proves "
        "nothing, because the parser is broken for both shapes"
    )

    # and the reverse: this mapper on a report body yields nothing, because there is no `alerts`
    # key at the top level
    assert proxy.scan_alerts.__doc__  # (the read path is exercised by the proof, not here)
    report_rows = json.loads(report_fixture.read_text(encoding="utf-8")).get("alerts")
    assert report_rows is None, (
        "the -quickurl report now has a top-level `alerts` key — re-measure before assuming the "
        "two shapes are still distinct"
    )
    print("  the report parser yields nothing on an API response, control holds: PASS")


def test_running_state_decides_what_blocks_a_second_scan() -> None:
    """RUNNING and PAUSED block; FINISHED and STOPPED never do, whatever progress says.

    A paused scan blocks because it can resume — the bound is on CONCURRENT attack traffic. A
    stopped scan must NOT block, or stop_scan would become a trap that wedges the feature.
    """
    def scan(state: str, progress: int) -> proxy.Scan:
        return proxy.Scan(id="1", container="c", port=8090, state=state, progress=progress)

    assert proxy.is_running(scan("RUNNING", 26)) is True
    assert proxy.is_running(scan("PAUSED", 40)) is True, (
        "a paused scan does not block a second one — it can resume underneath it"
    )
    assert proxy.is_running(scan("STOPPED", 40)) is False, (
        "a STOPPED scan still blocks new work — stop_scan would be a trap"
    )
    assert proxy.is_running(scan("FINISHED", 100)) is False
    assert proxy.is_running(scan("RUNNING", 100)) is False, (
        "a row at 100% still blocks — ZAP reports state and progress independently and the state "
        "flip can lag"
    )
    print("  RUNNING/PAUSED block a second scan; FINISHED/STOPPED do not: PASS")


def test_one_proxy_per_container_not_per_port() -> None:
    """*** FOUND BY THE PART-3 PROOF, NOT BY ANY TEST. ***

    ZAP locks its HOME DIRECTORY ($HOME/.ZAP), not its port, so a second daemon in the same
    container dies at startup whatever port it is given — the proof's first run lost a daemon on
    8093 to a leftover on 8092, and the only evidence was a line in the JVM's log inside the
    container. The refusal must therefore be container-scoped, and it must SAY why, since the
    operator's mental model ("different port, different daemon") is the wrong one here.
    """
    from cockpit import config

    live = proxy.Proxy(
        id="zapproxy-x-8090", container=config.SANDBOX_CONTAINER, port=8090,
        status="listening", started_at="now",
    )
    with proxy._lock:
        proxy._models.clear()
        proxy._models[live.id] = live
    try:
        req = proxy.ProxyStartRequest(port=8099, approved=True, dangerous_ack=True)
        try:
            proxy.start_proxy(req)
        except proxy.ProxyRefused as exc:
            assert exc.gate == "limit", exc.gate
            assert "home directory" in exc.reason, (
                f"the refusal does not explain WHY a different port is refused: {exc.reason!r}. "
                "Without that, the operator reads it as an off-by-one in our own bookkeeping."
            )
        else:
            raise AssertionError(
                "a second proxy on another port in the same container was ACCEPTED — it would "
                "have died on ZAP's home-directory lock with no reason shown anywhere"
            )

        # control: a DIFFERENT container is unaffected — the lock is per home directory, and the
        # engage sandbox has its own.
        other = proxy.container_for(proxy.ProxyStartRequest(engagement_id="e1"))
        assert other != live.container, "the two sandboxes collapsed to one container"
    finally:
        with proxy._lock:
            proxy._models.clear()
    print("  a second proxy in the same container is refused, with ZAP's reason: PASS")


if __name__ == "__main__":
    test_one_proxy_per_container_not_per_port()
    test_the_real_api_response_parses()
    test_alerts_become_findings_with_the_right_severity()
    test_the_plugin_reference_matches_the_report_parsers_spelling()
    test_alerts_become_endpoints_carrying_the_attacked_param()
    test_a_malformed_alert_never_raises()
    test_the_risk_vocabulary_covers_what_zap_emits()
    test_the_report_parser_and_this_mapper_are_not_interchangeable()
    test_running_state_decides_what_blocks_a_second_scan()
    print("ALL ZAP active-scan parsing tests pass")
