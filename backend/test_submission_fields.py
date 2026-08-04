"""THE BUG-BOUNTY SUBMISSION FIELDS — VRT priority, and the known-issue check.

Two additions to the bug-bounty report, plus the plumbing that made the first one reachable.

**VRT PRIORITY.** Bugcrowd triages on the Vulnerability Rating Taxonomy: a P1–P5 priority
attached to a vulnerability TYPE. Reports carried CVSS 3.1 only, so the number a triager
acts on was absent. The invariant with teeth is that the priority is a LOOKUP and never a
function of the CVSS score — deriving one from the other would produce a plausible P-number
with no relationship to the taxonomy, which is a fabricated claim in the field read first.

**THE KNOWN-ISSUE CHECK.** Programs publish what they already know about and will not pay
for. The design rule is the whole feature: it FLAGS and never suppresses. A false match that
silently dropped a real finding costs a paid bug and nobody ever learns it happened; a false
flag costs one glance at the brief. So the tests below spend most of their weight proving
that no path removes a finding.

**AND THE FIELD NOTHING COULD SET.** `build_cvss_block` has read `session['cvss_vector']`
since the bug-bounty template shipped, and there was no column, no endpoint and no control —
the CVSS block this project verified against six reference vectors could never appear in a
real report. Fixed here alongside, since the VRT field would otherwise have been dead in the
same way.

Hermetic (no LLM, no network). Run:  python test_submission_fields.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import report as R  # noqa: E402

_KNOWN = """Known issues (will not be awarded):
- Missing SPF/DMARC records on non-mail domains
- Self-XSS in the profile bio field
- Clickjacking on marketing pages
- CVE-2021-44228 on the legacy jenkins host
"""


# --------------------------------------------------------------------------- #
# VRT — a lookup, never a calculation
# --------------------------------------------------------------------------- #
def test_vrt_priority_is_a_lookup_on_the_category() -> None:
    assert R.vrt_priority("rce")["priority"] == "P1"
    assert R.vrt_priority("xss-stored")["priority"] == "P2"
    assert R.vrt_priority("xss-reflected")["priority"] == "P3"
    assert R.vrt_priority("open-redirect")["priority"] == "P4"
    assert R.vrt_priority("xss-self")["priority"] == "P5"
    # case and whitespace are the operator's, not the taxonomy's
    assert R.vrt_priority("  XSS-Stored  ")["priority"] == "P2"
    # AN UNKNOWN CATEGORY YIELDS NOTHING. "P3 because it sounds middling" is the exact
    # fabrication this block exists to avoid.
    assert R.vrt_priority("some-category-we-do-not-know") is None
    assert R.vrt_priority("") is None
    print(f"  all {len(R._VRT)} VRT categories resolve; an unknown one yields None: PASS")


def test_the_priority_is_never_derived_from_the_cvss_score() -> None:
    """*** THE INVARIANT. *** VRT and CVSS genuinely disagree; a stored XSS is P2 whatever
    its vector works out to. If the priority ever became a function of the score, every
    report would carry a confident P-number that no program's taxonomy agrees with."""
    critical = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"   # 9.8
    trivial = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"    # low
    for vector in (critical, trivial, "", "garbage"):
        block = R.build_vrt_block({"vrt_category": "open-redirect", "cvss_vector": vector})
        assert "P4" in block, (
            f"the VRT priority moved with the CVSS vector {vector!r} — it is a taxonomy "
            f"lookup and must not be: {block}"
        )
    # and with NO category, no priority is claimed at all, whatever the score says
    assert R.build_vrt_block({"cvss_vector": critical}) == "", (
        "a P-number was produced from a CVSS vector alone"
    )
    print("  the priority is fixed by category across every CVSS input: PASS")


def test_a_cvss_vrt_disagreement_is_surfaced() -> None:
    """The useful part: a 9.8 on a class the program rates P3 is worth arguing explicitly."""
    block = R.build_vrt_block({
        "vrt_category": "xss-reflected",                              # P3
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 9.8 Critical
    })
    assert "P3" in block and "Critical" in block and "9.8" in block, block
    assert "argue it explicitly" in block, block

    # ...and agreement is NOT annotated, or the note appears on every report and stops
    # being read.
    agreed = R.build_vrt_block({
        "vrt_category": "rce",                                        # P1
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 9.8 Critical
    })
    assert "P1" in agreed and "Note:" not in agreed, agreed
    print("  a real CVSS/VRT disagreement is flagged; agreement is left silent: PASS")


def test_an_unknown_category_says_so_in_the_report() -> None:
    block = R.build_vrt_block({"vrt_category": "totally-made-up"})
    assert "not in HackPit's table" in block and "no priority is claimed" in block, block
    assert "P1" not in block and "P3" not in block, f"a priority leaked out: {block}"
    print("  an unrecognised category claims no priority and says why: PASS")


# --------------------------------------------------------------------------- #
# the known-issue check — FLAG, never suppress
# --------------------------------------------------------------------------- #
def test_a_published_known_issue_is_flagged() -> None:
    f = {"title": "Missing SPF record on mail.example.com", "severity": "low"}
    m = R.known_issue_matches(f, _KNOWN)
    assert m is not None and "SPF" in m["line"], m

    # a CVE named in both is the same issue, not a fuzzy match
    cve = {"title": "Log4Shell RCE", "severity": "critical", "reference": "CVE-2021-44228"}
    m2 = R.known_issue_matches(cve, _KNOWN)
    assert m2 is not None and m2["exact"] is True, m2
    print("  a published known issue is matched, by terms and by CVE: PASS")


def test_an_unrelated_finding_is_not_flagged() -> None:
    """The other direction. A check that flagged everything would be switched off in a week."""
    for title in (
        "SQL injection in /api/v1/search",
        "IDOR on /orders/{id} exposes other customers' addresses",
        "Server-side request forgery reaching the metadata endpoint",
    ):
        assert R.known_issue_matches({"title": title}, _KNOWN) is None, title

    # STORED XSS is not SELF-XSS, and the program only published the latter. Getting this
    # wrong would flag a P2 as unpayable.
    stored = {"title": "Stored XSS in the order comment field", "severity": "high"}
    assert R.known_issue_matches(stored, _KNOWN) is None, (
        "a stored XSS was matched against a published SELF-XSS — a real finding would be "
        "flagged as already-known"
    )
    print("  unrelated findings, and stored-vs-self XSS, are not flagged: PASS")


def test_nothing_is_ever_suppressed() -> None:
    """*** THE DESIGN RULE. *** Every finding survives, matched or not."""
    findings = [
        {"title": "Missing SPF record on mail.example.com", "severity": "low"},
        {"title": "Self-XSS in the profile bio field", "severity": "info"},
        {"title": "SQL injection in /api/v1/search", "severity": "critical"},
    ]
    session = {"known_issues": _KNOWN, "state_findings": findings}
    block = R.build_known_issues_block(session)

    # the block is a WARNING, and says so
    assert "NOTHING WAS REMOVED" in block, block
    assert "not a verdict" in block, block
    # the input list is untouched — no filtering, in place or otherwise
    assert len(session["state_findings"]) == 3, "the finding list was mutated"
    assert findings[0]["title"] == "Missing SPF record on mail.example.com"
    # and the unmatched critical is nowhere near the flagged table
    assert "SQL injection" not in block, (
        "an unmatched finding appeared in the known-issue table"
    )

    # POSITIVE CONTROL — the check can fire. Remove the known-issues text and it goes silent.
    assert R.build_known_issues_block({"state_findings": findings}) == ""
    print("  matched findings are flagged, none removed, list unmutated: PASS")


def test_a_check_that_found_nothing_still_reports_that_it_ran() -> None:
    """Silence is indistinguishable from a check that never happened."""
    clean = [{"title": "SQL injection in /api/v1/search", "severity": "critical"}]
    block = R.build_known_issues_block({"known_issues": _KNOWN, "state_findings": clean})
    assert "no matches" in block.lower(), block
    assert "every finding stands" in block, block

    # no findings at all -> say to check by hand, rather than imply a clean result
    none_block = R.build_known_issues_block({"known_issues": _KNOWN, "state_findings": []})
    assert "by hand" in none_block, none_block
    print("  a zero-match run and a no-findings run both report themselves: PASS")


def test_a_pipe_in_a_finding_cannot_break_the_table() -> None:
    f = {"title": "Missing SPF | DMARC record on mail.example.com", "severity": "low"}
    block = R.build_known_issues_block({
        "known_issues": "- Missing SPF | DMARC records on non-mail domains",
        "state_findings": [f],
    })
    assert "\\|" in block, f"an unescaped pipe would split the markdown row: {block}"
    print("  a pipe in a finding title is escaped, not table-breaking: PASS")


# --------------------------------------------------------------------------- #
# the plumbing — the field that nothing could set
# --------------------------------------------------------------------------- #
def test_the_submission_fields_round_trip_through_the_store() -> None:
    import sessions as S

    # Point the store at a THROWAWAY database. `_connect` reads the module global at call
    # time, so this redirects every write. The operator's real sessions.db is never opened —
    # a test that writes to it would be the D5 hazard in a second store.
    real_db = S.DB_PATH
    # ignore_cleanup_errors: sessions.py's `with _connect() as conn` COMMITS but does not
    # CLOSE — sqlite3's context manager is a transaction, not the connection — so the handle
    # survives until GC and Windows refuses to unlink the file. That is a tempdir teardown
    # problem, not a test result; failing the suite on it would be noise.
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
        S.DB_PATH = Path(td) / "sessions.db"
        try:
            S.init_db()
            sid = S.create_session("goal here", None, {"phases": []})

            assert S.set_submission(
                sid, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            )
            assert S.set_submission(sid, vrt_category="xss-stored")
            assert S.set_submission(sid, known_issues=_KNOWN)
            got = S.get_session(sid)
            assert got["cvss_vector"].startswith("CVSS:3.1/"), got["cvss_vector"]
            assert got["vrt_category"] == "xss-stored"
            assert "Self-XSS" in got["known_issues"]

            # ...and the stored vector is one build_cvss_block can actually use. That block
            # read this field for its whole existence with nothing ever writing it.
            assert "9.8" in R.build_cvss_block(got), R.build_cvss_block(got)

            # SETTING ONE MUST NOT CLEAR THE OTHERS
            S.set_submission(sid, vrt_category="rce")
            again = S.get_session(sid)
            assert again["cvss_vector"] and again["known_issues"], again
            assert again["vrt_category"] == "rce"

            # an empty string CLEARS, so a wrong vector can be taken back
            S.set_submission(sid, cvss_vector="")
            assert S.get_session(sid)["cvss_vector"] is None

            assert S.set_submission("no-such-session", vrt_category="rce") is False
        finally:
            S.DB_PATH = real_db
    assert S.DB_PATH == real_db, "the store was left pointing at a temp database"
    print("  submission fields round-trip; partial writes preserve the rest: PASS")


if __name__ == "__main__":
    test_vrt_priority_is_a_lookup_on_the_category()
    test_the_priority_is_never_derived_from_the_cvss_score()
    test_a_cvss_vrt_disagreement_is_surfaced()
    test_an_unknown_category_says_so_in_the_report()
    test_a_published_known_issue_is_flagged()
    test_an_unrelated_finding_is_not_flagged()
    test_nothing_is_ever_suppressed()
    test_a_check_that_found_nothing_still_reports_that_it_ran()
    test_a_pipe_in_a_finding_cannot_break_the_table()
    test_the_submission_fields_round_trip_through_the_store()
    print("ALL submission-field tests pass")
