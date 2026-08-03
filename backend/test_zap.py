"""ZAP report parser regression tests.  Run:  python test_zap.py

NOT named test_scans.py — that name belongs to the shared source scanner.
"""

from __future__ import annotations

from state import parsers

SESSION = "s-zap-test"

# A real ZAP traditional-JSON report, wrapped in the progress noise the scan scripts print
# around it. riskcode is a STRING in ZAP's output, not an int.
NOISY_REPORT = """\
Total of 3 URLs
PASS: Vulnerable JS Library [10003]
WARN-NEW: SQL Injection [40018] x 1
{
  "@programName": "ZAP",
  "@version": "2.14.0",
  "site": [
    {
      "@name": "http://lab.local",
      "@host": "lab.local",
      "@port": "80",
      "alerts": [
        {
          "pluginid": "40018",
          "name": "SQL Injection",
          "riskcode": "3",
          "desc": "<p>SQL injection may be possible.</p>",
          "instances": [
            {
              "uri": "http://lab.local/search",
              "method": "GET",
              "param": "q",
              "attack": "' OR '1'='1",
              "evidence": "syntax error"
            }
          ]
        },
        {
          "pluginid": "10038",
          "name": "Content Security Policy Header Not Set",
          "riskcode": "1",
          "instances": [
            {"uri": "http://lab.local/", "method": "GET", "param": ""}
          ]
        },
        {
          "pluginid": "10096",
          "name": "Timestamp Disclosure",
          "riskcode": "0",
          "instances": [{"uri": "http://lab.local/app.js", "method": "GET", "param": ""}]
        },
        {
          "pluginid": "40012",
          "name": "Cross Site Scripting (Reflected)",
          "riskcode": "2",
          "instances": [{"uri": "http://lab.local/x", "method": "POST", "param": "name"}]
        }
      ]
    }
  ]
}
FAIL-NEW: 1     FAIL-INPROG: 0
"""


def test_alerts_become_findings_with_mapped_severity() -> None:
    """Every alert becomes a Finding, and all four ZAP risk codes map correctly."""
    out = parsers.parse_zap(NOISY_REPORT, SESSION, "run-1")

    by_title = {f.title: f for f in out.findings}
    assert len(out.findings) == 4, f"expected 4 findings, got {len(out.findings)}"

    assert by_title["SQL Injection"].severity == "high", "riskcode 3 must map to high"
    assert by_title["Cross Site Scripting (Reflected)"].severity == "medium", "2 -> medium"
    assert by_title["Content Security Policy Header Not Set"].severity == "low", "1 -> low"
    assert by_title["Timestamp Disclosure"].severity == "info", "0 -> info"

    sqli = by_title["SQL Injection"]
    assert sqli.tool == "zap", f"tool must be 'zap', got {sqli.tool!r}"
    assert sqli.reference == "pluginid:40018", f"got {sqli.reference!r}"
    assert sqli.target == "http://lab.local/search", f"got {sqli.target!r}"
    assert "syntax error" in sqli.evidence, f"evidence lost: {sqli.evidence!r}"
    assert sqli.session_id == SESSION and sqli.source_run_id == "run-1"
    print("  4 alerts -> findings, all four risk codes mapped: PASS")


def test_instances_become_endpoints() -> None:
    """Each alert instance with an http(s) URI becomes an Endpoint carrying its param."""
    out = parsers.parse_zap(NOISY_REPORT, SESSION, "run-1")

    urls = {e.url for e in out.endpoints}
    assert "http://lab.local/search" in urls, f"missing the SQLi URL: {sorted(urls)}"
    assert "http://lab.local/x" in urls, f"missing the XSS URL: {sorted(urls)}"

    search = next(e for e in out.endpoints if e.url == "http://lab.local/search")
    assert search.method == "GET", f"got {search.method!r}"
    assert search.params == ["q"], f"param not carried: {search.params!r}"

    xss = next(e for e in out.endpoints if e.url == "http://lab.local/x")
    assert xss.method == "POST", f"method not carried: {xss.method!r}"

    blank = next(e for e in out.endpoints if e.url == "http://lab.local/")
    assert blank.params == [], f"an empty param must not become a param: {blank.params!r}"
    print("  instances -> endpoints with method and param: PASS")


def test_the_report_is_found_inside_progress_noise() -> None:
    """*** THE POINT OF THE CUSTOM EXTRACTOR. ***

    _json_objects() cannot do this: the whole document does not parse (progress lines), and no
    single line parses either (the report is pretty-printed). A positive control in the same
    test proves the assertion is live — a bare report with no noise must also work, so a
    parser that has broken into always-empty cannot pass this.
    """
    noisy = parsers.parse_zap(NOISY_REPORT, SESSION, None)
    assert noisy.findings, "the report was not found inside the progress noise"

    # positive control: the same report with the noise stripped
    bare = NOISY_REPORT[NOISY_REPORT.index("{"): NOISY_REPORT.rindex("}") + 1]
    clean = parsers.parse_zap(bare, SESSION, None)
    assert len(clean.findings) == len(noisy.findings), (
        f"noise changed the result: {len(noisy.findings)} vs {len(clean.findings)} clean"
    )

    # And _json_objects genuinely cannot reach the report — this is why the custom extractor
    # exists. Note what it DOES yield: its line-delimited fallback matches only the alert
    # INSTANCE fragments that happen to sit on a single line. That is worse than matching
    # nothing, because a parser resting on it would quietly emit rubbish rather than obviously
    # emit nothing. Assert on the report's absence, not on emptiness.
    fallback = list(parsers._json_objects(NOISY_REPORT))
    assert not any("site" in obj for obj in fallback), (
        "_json_objects now reaches the ZAP report object — re-check whether the custom "
        "extractor is still needed, and do not silently keep two code paths"
    )
    assert parsers._zap_report(NOISY_REPORT) is not None, (
        "the custom extractor no longer finds the report the fallback cannot reach"
    )
    print(f"  report extracted from progress noise; _json_objects saw only "
          f"{len(fallback)} fragment(s), none of them the report: PASS")


def test_garbage_never_raises_and_yields_nothing() -> None:
    """A parser must never break a completed run."""
    for junk in ("", "   ", "not json at all", "{", "{}", '{"site": "not-a-list"}',
                 '{"nope": 1}', "[1,2,3]", '{"site": [{"alerts": "no"}]}'):
        out = parsers.parse_zap(junk, SESSION, None)
        assert out.is_empty(), f"{junk!r} produced records: {out.counts()}"
    print("  9 malformed inputs yield empty and never raise: PASS")


def test_the_stdout_registry_is_keyed_the_way_program_name_spells_it() -> None:
    """THE BUILD #9 DEFECT CLASS. program_name() strips .exe but NOT .py, so the keys must
    carry the .py suffix. Keying them 'zap-full-scan' would silently ingest nothing — which is
    exactly how a live DCSync dumped krbtgt and ingested none of it."""
    from state.ingest import program_name

    for spelling in ("zap-baseline.py", "/usr/share/zaproxy/zap-baseline.py", "ZAP-BASELINE.PY"):
        key = program_name(spelling)
        assert key in parsers.STDOUT_PARSERS, (
            f"program_name({spelling!r}) -> {key!r}, which is NOT a STDOUT_PARSERS key. "
            f"Keys present: {sorted(parsers.STDOUT_PARSERS)}"
        )
        assert parsers.STDOUT_PARSERS[key] is parsers.parse_zap

    assert program_name("zap-full-scan.py") in parsers.STDOUT_PARSERS
    # positive control: the normaliser really does keep .py (if it ever starts stripping it,
    # this test must fail rather than quietly pass on a key that no longer matches)
    assert program_name("zap-full-scan.py") == "zap-full-scan.py", (
        f"program_name no longer preserves .py (got {program_name('zap-full-scan.py')!r}) — "
        "the registry keys above are now wrong"
    )
    print("  STDOUT_PARSERS keys match program_name's spelling: PASS")


def test_the_file_registry_does_not_claim_every_json_file() -> None:
    """FILE_PARSERS is registered on '-zap.json', not '.json'. A bare '.json' registration
    would claim every JSON loot file any tool ever writes."""
    assert "-zap.json" in parsers.FILE_PARSERS, "the ZAP suffix is not registered"
    assert ".json" not in parsers.FILE_PARSERS, (
        "'.json' is registered — this claims every JSON loot file in the tree"
    )

    claimed = parsers.parse_file("report-zap.json", NOISY_REPORT, SESSION, None)
    assert claimed.findings, "a -zap.json loot file was not parsed"

    not_claimed = parsers.parse_file("subfinder-output.json", NOISY_REPORT, SESSION, None)
    assert not_claimed.is_empty(), (
        "a non-ZAP .json loot file was claimed by the ZAP parser: "
        f"{not_claimed.counts()}"
    )
    print("  -zap.json is claimed, a plain .json file is not: PASS")


def test_detection_describes_the_names_that_actually_run() -> None:
    """ALIASES already maps 'zap'/'zaproxy', but runs are zap-baseline.py / zap-full-scan.py.
    Without these the detection panel goes silent on every ZAP run while looking healthy —
    a surface reporting nothing is indistinguishable from one with nothing to report."""
    from detection.catalog import ALIASES

    for name in ("zap-baseline.py", "zap-full-scan.py"):
        assert name in ALIASES, f"{name} is not in detection ALIASES — the panel will be blank"
        assert ALIASES[name] == "web_vuln_scan", f"{name} -> {ALIASES[name]!r}"

    # positive control: the pre-existing spellings are untouched
    assert ALIASES["zap"] == "web_vuln_scan" and ALIASES["zaproxy"] == "web_vuln_scan"
    print("  detection covers the program names that actually execute: PASS")


if __name__ == "__main__":
    test_alerts_become_findings_with_mapped_severity()
    test_instances_become_endpoints()
    test_the_report_is_found_inside_progress_noise()
    test_garbage_never_raises_and_yields_nothing()
    test_the_stdout_registry_is_keyed_the_way_program_name_spells_it()
    test_the_file_registry_does_not_claim_every_json_file()
    test_detection_describes_the_names_that_actually_run()
    print("ALL ZAP parser tests pass")
