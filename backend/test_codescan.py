"""Unit tests for the :code scan (static AppSec) feature — parsing, merging, reporting.

Scanner output is treated as UNTRUSTED INPUT here: the tests feed empty, malformed,
wrong-typed and truncated payloads and assert that a bad record drops itself rather than the
run. The scanner-dependent checks are skipped (loudly) when semgrep/bandit aren't installed,
so this file runs in the safety suite either way.

Run:  python test_codescan.py
"""

from __future__ import annotations

from pathlib import Path

from codescan import findings as F
from codescan import kb_link, report, runner

_ROOT = Path("C:/proj") if Path("C:/").exists() else Path("/proj")


# --------------------------------------------------------------------------- #
# 1. normalisation — each tool's real shape
# --------------------------------------------------------------------------- #
def test_semgrep_normalisation() -> None:
    raw = {"results": [{
        "check_id": "codescan.rules.hp-python-sql-string-build",
        "path": str(_ROOT / "app" / "db.py"),
        "start": {"line": 41},
        "extra": {
            "severity": "ERROR",
            "message": "SQL   statement built by\nstring formatting.",
            "metadata": {"cwe": "CWE-89: SQL Injection", "owasp": "A03:2021 - Injection",
                         "category": "injection"},
        },
    }]}
    got = F.from_semgrep(raw, _ROOT)
    assert len(got) == 1
    f = got[0]
    assert f.rule_id == "hp-python-sql-string-build", "the rule id is shortened, not mangled"
    assert f.severity == "high" and f.tool_severity == "ERROR", "mapped, original kept"
    assert f.file == "app/db.py" and f.line == 41
    assert f.message == "SQL statement built by string formatting.", "whitespace collapsed"
    assert f.cwe == "CWE-89" and f.owasp == "A03:2021 - Injection"
    assert f.category == "injection" and f.tools == ["semgrep"]
    print("  semgrep records normalise (id/severity/path/CWE/OWASP): PASS")


def test_bandit_normalisation() -> None:
    raw = {"results": [{
        "test_id": "B602",
        "test_name": "subprocess_popen_with_shell_equals_true",
        "filename": str(_ROOT / "run.py"),
        "line_number": 7,
        "issue_severity": "HIGH",
        "issue_confidence": "HIGH",
        "issue_cwe": {"id": 78, "link": "https://cwe.mitre.org/data/definitions/78.html"},
        "issue_text": "subprocess call with shell=True identified.",
    }]}
    got = F.from_bandit(raw, _ROOT)
    assert len(got) == 1
    f = got[0]
    assert f.rule_id == "B602:subprocess_popen_with_shell_equals_true"
    assert f.severity == "high" and f.tool_severity == "HIGH"
    assert f.confidence == "HIGH", "bandit confidence is carried, not folded into severity"
    assert f.cwe == "CWE-78" and f.category == "injection"
    print("  bandit records normalise (cwe dict, confidence kept): PASS")


# --------------------------------------------------------------------------- #
# 2. malformed / empty / hostile scanner output
# --------------------------------------------------------------------------- #
def test_malformed_output_never_fails_the_run() -> None:
    """A bad record drops itself. Anything else would make one weird finding lose a scan."""
    for junk in (
        {}, {"results": None}, {"results": "not a list"}, {"results": []},
        {"results": [None, 42, "nope", []]},
        {"results": [{}]},                                    # no check_id/test_id
        {"results": [{"check_id": "x"}]},                     # no extra/path/start
        {"results": [{"check_id": "x", "start": {"line": "NaN"}, "extra": {}}]},
        {"results": [{"check_id": "x", "extra": {"metadata": "not-a-dict"}}]},
        {"results": [{"test_id": "B1", "line_number": None, "issue_cwe": None}]},
    ):
        semgrep = F.from_semgrep(junk, _ROOT)
        bandit = F.from_bandit(junk, _ROOT)
        assert isinstance(semgrep, list) and isinstance(bandit, list)
        for f in semgrep + bandit:
            assert isinstance(f.line, int), "a non-numeric line must not survive as one"
            assert f.severity in F.SEVERITY_ORDER
    assert F.from_semgrep(None, _ROOT) == [] and F.from_bandit(None, _ROOT) == []
    assert F.summarize([])["total"] == 0
    print("  empty / malformed / wrong-typed scanner output degrades, never raises: PASS")


def test_large_output_is_handled() -> None:
    """A big result set normalises and summarises without special-casing."""
    raw = {"results": [
        {"check_id": f"r{i % 7}", "path": str(_ROOT / f"f{i % 50}.py"),
         "start": {"line": i}, "extra": {"severity": "WARNING", "message": "m",
                                         "metadata": {"cwe": f"CWE-{80 + (i % 5)}"}}}
        for i in range(5000)
    ]}
    got = F.from_semgrep(raw, _ROOT)
    assert len(got) == 5000
    merged = F.merge(got)
    assert 0 < len(merged) <= 5000
    assert F.summarize(merged)["total"] == len(merged)
    print(f"  5,000 findings normalise + merge cleanly ({len(merged)} after dedupe): PASS")


# --------------------------------------------------------------------------- #
# 3. merge = corroboration, not duplication
# --------------------------------------------------------------------------- #
def test_merge_collapses_agreement_and_keeps_worst_severity() -> None:
    sg = F.Finding(rule_id="hp-sqli", tool="semgrep", severity="high", file="a.py",
                   line=3, message="semgrep says", category="injection", cwe="CWE-89",
                   tools=["semgrep"])
    bd = F.Finding(rule_id="B608", tool="bandit", severity="medium", file="a.py",
                   line=3, message="bandit says", category="injection", cwe="CWE-89",
                   confidence="MEDIUM", tools=["bandit"])
    other = F.Finding(rule_id="B605", tool="bandit", severity="high", file="a.py",
                      line=9, message="elsewhere", category="injection", cwe="CWE-78",
                      tools=["bandit"])
    merged = F.merge([sg], [bd, other])
    assert len(merged) == 2, "same file+line+CWE from two tools is ONE defect"
    same = next(f for f in merged if f.line == 3)
    assert sorted(same.tools) == ["bandit", "semgrep"] and "+" in same.tool
    assert same.severity == "high", "the worst severity wins"
    assert same.confidence == "MEDIUM", "the other tool's extra detail is not lost"
    # different CWE at the same spot is NOT the same defect
    diff = F.merge([sg], [F.Finding(rule_id="x", tool="bandit", severity="low", file="a.py",
                                    line=3, message="different class", category="crypto",
                                    cwe="CWE-327", tools=["bandit"])])
    assert len(diff) == 2
    print("  merge collapses agreement, keeps worst severity, splits different classes: PASS")


def test_ordering_is_worst_first() -> None:
    mixed = [
        F.Finding("a", "semgrep", "low", "z.py", 1, "m", "other"),
        F.Finding("b", "semgrep", "critical", "b.py", 9, "m", "injection"),
        F.Finding("c", "semgrep", "medium", "a.py", 2, "m", "xss"),
    ]
    order = [f.severity for f in F.merge(mixed)]
    assert order == ["critical", "medium", "low"], order
    print("  findings sort worst-first (a review queue, not file order): PASS")


# --------------------------------------------------------------------------- #
# 4. the KB tie-in never fabricates
# --------------------------------------------------------------------------- #
def test_kb_link_never_fabricates() -> None:
    finding = F.Finding("hp-sqli", "semgrep", "high", "a.py", 3, "m", "injection")

    # no KB / no search -> no link at all
    assert kb_link.link([finding], {}, None) == 0
    assert finding.kb_entry_id is None

    # a search that returns something IRRELEVANT must not be cited
    unrelated = {"id": "e1", "title": "Wireless Evil Twin", "summary": "wifi attack"}
    assert kb_link.link([finding], {"e1": unrelated}, lambda q, k, m: [{"id": "e1"}]) == 0
    assert finding.kb_entry_id is None, "an off-topic entry must never be cited"

    # a genuinely matching entry IS linked
    real = {"id": "e2", "title": "SQL Injection", "summary": "sqli exploitation"}
    assert kb_link.link([finding], {"e2": real}, lambda q, k, m: [{"id": "e2"}]) == 1
    assert finding.kb_entry_id == "e2" and finding.kb_title == "SQL Injection"

    # an ineligible entry (writeup / grab-bag) is refused even when it matches
    other = F.Finding("hp-sqli", "semgrep", "high", "b.py", 4, "m", "injection")
    assert kb_link.link([other], {"e2": real}, lambda q, k, m: [{"id": "e2"}],
                        eligible=lambda e: False) == 0
    assert other.kb_entry_id is None

    # a search that BLOWS UP must not fail the scan
    def boom(q, k, m):
        raise RuntimeError("search is down")

    third = F.Finding("hp-sqli", "semgrep", "high", "c.py", 5, "m", "injection")
    assert kb_link.link([third], {"e2": real}, boom) == 0
    print("  KB links: none without a match, never off-topic, never ineligible, fail-soft: PASS")


# --------------------------------------------------------------------------- #
# 5. the report is faithful
# --------------------------------------------------------------------------- #
def test_report_is_faithful_and_caveated() -> None:
    result = {
        "path": "/proj", "files_scanned": 12, "duration_s": 1.5,
        "tools_run": ["semgrep", "bandit"], "ruleset": "bundled.yaml",
        "summary": {"total": 1, "files_affected": 1,
                    "by_severity": {"high": 1}, "by_category": {"injection": 1}},
        "findings": [{
            "rule_id": "hp-sqli", "tool": "bandit+semgrep", "severity": "high",
            "file": "a.py", "line": 3, "message": "SQL built by formatting",
            "category": "injection", "cwe": "CWE-89", "owasp": "A03:2021 - Injection",
            "confidence": "MEDIUM", "tool_severity": "ERROR",
            "tools": ["semgrep", "bandit"], "kb_entry_id": "kb1", "kb_title": "SQL Injection",
        }],
        "warnings": ["bandit skipped a file"],
    }
    md = report.render_markdown(result)
    for needed in ("# Code scan", "## Method", "no code from the scanned tree was executed",
                   "## Summary", "| HIGH | 1 |", "hp-sqli", "a.py:3", "CWE-89",
                   "SQL built by formatting", "SQL Injection", "bandit skipped a file",
                   "bandit + semgrep agree", "reported as: ERROR"):
        assert needed in md, f"report is missing {needed!r}"
    assert "not a confirmed vulnerability" in md, "the caveat must survive"
    assert md.count("bandit+semgrep") == 0, "attribution should read once, not twice"

    empty = report.render_markdown({"path": "/p", "summary": {}, "findings": []})
    assert "No findings were reported" in empty and "matched nothing" not in empty.split("---")[0]
    assert "not a confirmed vulnerability" in empty, "an empty report keeps the caveat"
    print("  report renders faithfully (tool words kept) + always caveated: PASS")


# --------------------------------------------------------------------------- #
# 6. live scanners (skipped cleanly when not installed)
# --------------------------------------------------------------------------- #
def test_live_scan_if_installed() -> None:
    have = runner.available()
    if not have.get("semgrep"):
        print("  live scan: SKIPPED (semgrep not installed — `uv pip install semgrep`)")
        return
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "vuln.py").write_text(
            "import os\n"
            "def run(u):\n"
            "    os.system('ls ' + u)\n",
            encoding="utf-8",
        )
        target = runner.resolve_target(str(root))
        got = F.from_semgrep(runner.run_semgrep(target), target)
        assert any(f.category == "injection" for f in got), (
            f"the bundled ruleset should flag os.system concatenation — got {got}"
        )
        assert all(f.file == "vuln.py" for f in got), "paths are relative to the scan root"
    print(f"  live semgrep scan flags a real defect with the bundled ruleset: PASS")


def test_semgrep_crash_degrades_not_502() -> None:
    """A semgrep CRASH (ScanError — e.g. it hits an OSError on a .php file on some Windows
    builds) must NOT sink the whole scan. It degrades to a warning and the scan still returns,
    exactly like a bandit failure. Regression for 'one unscannable file 502s everything'."""
    import tempfile

    from codescan import router as CR

    def _boom(*a, **k):
        raise runner.ScanError("boom: OSError [Errno 22] on v.php")

    orig = runner.run_semgrep
    runner.run_semgrep = _boom
    try:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "note.txt").write_text("nothing to scan", encoding="utf-8")
            out = CR.codescan_scan(CR.ScanIn(path=tmp, use_bandit=False))
        assert "semgrep" not in out["tools_run"], "a crashed semgrep must not be listed as run"
        assert any("semgrep did not complete" in w for w in out["warnings"]), out["warnings"]
        print("  a semgrep crash degrades to a warning; the scan still returns (no 502): PASS")
    finally:
        runner.run_semgrep = orig


if __name__ == "__main__":
    test_semgrep_normalisation()
    test_bandit_normalisation()
    test_malformed_output_never_fails_the_run()
    test_large_output_is_handled()
    test_merge_collapses_agreement_and_keeps_worst_severity()
    test_ordering_is_worst_first()
    test_kb_link_never_fabricates()
    test_report_is_faithful_and_caveated()
    test_live_scan_if_installed()
    test_semgrep_crash_degrades_not_502()
    print("ALL :code scan tests pass")
