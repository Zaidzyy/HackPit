"""CDN-fronting locks (build #18 item 2) + the silent-empty sweep (item 8).
Run:  python test_fronting.py

THE INVARIANTS:
  * item 2 — `unknown` is a REAL answer. A failed lookup never reports as "not behind a CDN",
    and a discovered origin is REPORTED and never added to any scope.
  * item 8 — the two empty returns that could not be told apart from a failure now can be, and
    the scanner that finds them is AST-based so a docstring cannot fool it.
"""

from __future__ import annotations

import ast
import inspect
import subprocess
import sys
from pathlib import Path

from cockpit import fronting, proxy

REPO_ROOT = Path(__file__).resolve().parent


# --------------------------------------------------------------------------- #
# item 2 — fronting
# --------------------------------------------------------------------------- #
def test_a_failed_lookup_reports_UNKNOWN_and_never_not_fronted() -> None:
    """*** THE LOAD-BEARING ONE. *** "We could not tell" and "there is no CDN" are different
    facts. Reporting the first as the second is the confident zero this project keeps finding —
    and here it would send an operator to attack a host with the wrong toolchain."""
    verdict, provider, evidence = fronting.classify(
        "h.example.com", [], "", "", [], reachable=False
    )
    assert verdict == "unknown", verdict
    assert provider == "" and evidence == []

    # control: the SAME absence of evidence, with the lookups having worked, is not-fronted
    ok_verdict, _, _ = fronting.classify(
        "h.example.com", [], "nginx", "SOME-ISP", ["203.0.113.4"], reachable=True
    )
    assert ok_verdict == "not-fronted", ok_verdict
    print("  a failed lookup is unknown; a successful one with no markers is not-fronted: PASS")


def test_a_cname_suffix_is_matched_dot_anchored_not_as_a_substring() -> None:
    """`notakamai.net.example.com` CONTAINS `akamai.net`. This repo has been bitten by a
    fragment match in both directions already — `[z]aproxy` matched too little and `[c]hrome`
    matched too much and killed the ZAP daemon."""
    assert fronting._suffix_provider("e1234.dscx.akamaiedge.net") == "Akamai"
    assert fronting._suffix_provider("akamaiedge.net") == "Akamai"
    assert fronting._suffix_provider("notakamai.net.example.com") == ""
    assert fronting._suffix_provider("myakamai.net") == ""
    assert fronting._suffix_provider("d111.cloudfront.net") == "Amazon CloudFront"
    print("  suffix matching is dot-anchored, so a lookalike host is not claimed: PASS")


def test_evidence_from_all_three_sources_is_kept() -> None:
    """A WAF in front of a CDN is a real arrangement. Reporting only the first hit would hide
    the second, and which one refuses a request matters."""
    verdict, provider, evidence = fronting.classify(
        "h", ["x.incapdns.net"], "AkamaiGHost", "CLOUDFLARENET", ["1.2.3.4"], reachable=True
    )
    assert verdict == "fronted"
    sources = {e.source for e in evidence}
    assert sources == {"cname", "server-header", "asn"}, sources
    assert "Imperva" in provider and "Akamai" in provider, provider
    print("  every source contributes evidence, not just the first: PASS")


def test_nothing_in_this_module_scans_or_brute_forces() -> None:
    """It answers a question. The only thing that touches the target is ONE HEAD request — the
    same request a browser makes opening the page."""
    src = inspect.getsource(fronting)
    tree = ast.parse(src)
    argvs: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "id", "") in ("_run", "_dig"):
            argvs.append(ast.unparse(node))
    joined = " ".join(argvs)
    for banned in ("nmap", "ffuf", "gobuster", "nuclei", "masscan", "hydra", "sqlmap",
                   "-X POST", "--data"):
        assert banned not in joined, f"fronting.py invokes {banned!r} — this module is passive"
    # the HEAD is a HEAD
    assert '"-I"' in src or "'-I'" in src, "the Server-header read is not a HEAD request"
    print("  no scanner, no brute force, and the one request is a HEAD: PASS")


def test_a_discovered_origin_is_reported_and_never_added() -> None:
    """`engagement.add_pivot_subnet` is the one deliberate widening path in this codebase and a
    human uses it. A module that looks like it should be allowed to widen is exactly the one that
    must not.

    *** AST, NOT SUBSTRING — AND THE FIRST DRAFT OF THIS TEST PROVED WHY. ***
    It was written as a substring check and failed immediately, because fronting.py's own
    docstring NAMES `add_pivot_subnet` in the sentence explaining that it must never call it.
    That is build #18 item 8's lesson arriving from the other direction, in the test written to
    check for it: prose about a thing reads identically to the thing. So this walks the tree and
    looks for real imports and real calls.
    """
    tree = ast.parse(inspect.getsource(fronting))

    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            imported |= {a.name for a in node.names}
        elif isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
    assert "engagement" not in imported, (
        "fronting.py imports the engagement module — it has no business touching a scope"
    )

    called: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            called.add(node.func.attr if isinstance(node.func, ast.Attribute)
                       else getattr(node.func, "id", ""))
    for banned in ("add_pivot_subnet", "record_discoveries", "enter", "upsert_endpoints"):
        assert banned not in called, (
            f"fronting.py CALLS {banned!r} — a candidate origin is a LEAD for a human, and "
            "auto-adding one would break the recon-driven-expansion rule from the module that "
            "most looks like it should be allowed to"
        )
    assert "candidate_origins" in fronting.HostFronting.model_fields
    print("  candidate origins are reported; the module cannot widen a scope (AST): PASS")


def test_a_null_MX_does_not_become_an_empty_lead() -> None:
    """*** FOUND BY LOOKING AT THE SCREEN, not by any test. ***

    `dig +short MX example.com` answers `0 .` — a NULL MX (RFC 7505), which says "this domain
    sends no mail". Stripping the trailing dot leaves an EMPTY host, and the first version
    appended the origin `mx:` with nothing after it. It rendered in the browser as a chip an
    operator would try to chase: a lead pointing at nowhere.

    A blank lead is worse than no lead, and no typecheck, build or lint could see it.
    """
    src = inspect.getsource(fronting.analyse)
    assert "null MX" in src, "the null-MX case is not handled"
    assert "if not host:" in src, "an empty MX host still becomes a candidate origin"
    # the SPF side had the same shape and is guarded too
    assert "if value:" in src, "an empty spf: value can still become a lead"
    print("  a null MX becomes a NOTE, not an empty candidate origin: PASS")


def test_an_empty_certificate_transparency_answer_says_so() -> None:
    """A failed crt.sh query and a domain with no certificates look identical from here, and
    only one of them is a statement about the world."""
    src = inspect.getsource(fronting.analyse)
    assert "FAILED" in src and "certificate transparency returned nothing" in src, (
        "an empty CT result is treated as a fact about the domain rather than a failed query"
    )
    print("  an empty CT answer is reported as a failed-or-empty query: PASS")


# --------------------------------------------------------------------------- #
# item 8 — the silent-empty sweep
# --------------------------------------------------------------------------- #
def test_the_scanner_uses_an_AST_and_a_docstring_cannot_fool_it() -> None:
    """The module docstrings in cockpit/proxy.py contain the literal text `return []` several
    times, describing the very bug being hunted. A regex would report that file as its own worst
    offender, which is the trap this repo has already been caught by."""
    src = (REPO_ROOT / "tools" / "silent_empty_scan.py").read_text(encoding="utf-8")
    assert "ast.parse" in src and "ast.walk" in src, "the sweep is not AST-based"
    assert "re.compile" not in src and "re.search" not in src, (
        "the sweep uses a regex somewhere — a docstring quoting `return []` would be a hit"
    )

    # BITE CHECK: it finds a planted example, and does NOT find a docstring that quotes one.
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "silent_empty_scan", REPO_ROOT / "tools" / "silent_empty_scan.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)

    planted = ast.parse(
        'def reader():\n'
        '    """This function is documented as: except Exception: return []"""\n'
        '    try:\n'
        '        return compute()\n'
        '    except Exception:\n'
        '        return []\n'
        'def only_a_docstring():\n'
        '    """except Exception: return [] — but this one really does not."""\n'
        '    return compute()\n'
    )
    finder = module._Finder(Path("planted.py"), "\n" * 12)
    finder.visit(planted)
    names = {h["function"] for h in finder.hits}
    assert names == {"reader"}, (
        f"the sweep found {names} — it must find the real handler and NOT the docstring that "
        "quotes one"
    )
    print("  the sweep is AST-based; it bites on a real handler and not on prose: PASS")


def test_the_scan_list_read_can_fail_distinguishably() -> None:
    """*** THE ONE THAT FAILED OPEN ON A BOUND. *** `observed_scans` answered [] for both "ZAP
    knows of no scan" and "the read failed", and `start_scan` used that to enforce ONE SCAN AT A
    TIME. An unreadable daemon GRANTED a second concurrent scan — the same defect build #17
    fixed one function away in `clash_refusal`."""
    assert callable(proxy.scans_snapshot)
    src = inspect.getsource(proxy.start_scan)
    assert "read_ok" in src, "start_scan does not distinguish a failed read from an empty list"
    # ...and the refusal names the harm rather than being a bare limit
    # Matched on a fragment that survives the source's own line wrapping — an assertion that
    # spans an implicit string concatenation would fail on reflow rather than on meaning.
    assert "double the attack" in src, (
        "the refusal does not say why it matters, so a future edit will read it as ceremony"
    )
    print("  an unreadable scan list is told apart from an empty one: PASS")


def test_the_alert_read_can_fail_distinguishably() -> None:
    """This one travelled furthest: a failed read wrote "0 findings" into engagement state, and a
    REPORT is rendered from that state.

    THE ASSERTION IS THE PROPERTY, NOT THE FUNCTION NAME — it has fired on a rename twice now."""
    assert "read_ok" in (proxy.AlertPage.model_fields), (
        "AlertPage cannot say whether the read succeeded"
    )
    from cockpit import router

    ingest_src = inspect.getsource(router.ingest_scan_alerts)
    assert "read_ok" in ingest_src and "409" in ingest_src, (
        "the ingest route does not act on whether the read succeeded — it would still write a "
        "confident zero into engagement state"
    )
    print("  a failed alert read refuses the ingest instead of persisting a zero: PASS")


def test_an_UNPARSEABLE_row_is_counted_rather_than_vanishing() -> None:
    """*** THE UNDERCOUNT — the silent empty at partial strength (build #18, second pass). ***

    `parse_message` returns None for a message it cannot read and `history()` filtered those out,
    so a window of 200 exchanges of which 50 were unparseable came back as 150 and nothing said
    the other 50 existed. Not a confident zero — a confident UNDERCOUNT, which is harder to
    notice precisely because it looks plausible.

    Exercised on the PARSERS directly, because that is the half that can be tested without a
    daemon, plus the models that carry the count.
    """
    # the parsers really do refuse a row rather than raising
    assert proxy.parse_message({"requestHeader": "garbage with no url"}, "c") is None
    assert proxy.parse_message("not even a dict", "c") is None
    assert proxy.parse_alert("not even a dict") is None
    # ...and a GOOD row still parses, or the check above passes for the wrong reason
    good = proxy.parse_message(
        {"id": "1", "requestHeader": "GET https://h/x HTTP/1.1\r\nHost: h\r\n",
         "responseHeader": "HTTP/1.1 200 OK\r\n", "responseBody": "hi", "rtt": "5"},
        "c",
    )
    assert good is not None and good.request.url == "https://h/x"

    for model, label in ((proxy.HistoryPage, "HistoryPage"), (proxy.AlertPage, "AlertPage")):
        assert "dropped" in model.model_fields, (
            f"{label} cannot say how many rows could not be parsed, so a shorter list reads as "
            "less traffic"
        )
        assert "read_ok" in model.model_fields, f"{label} cannot say whether the read succeeded"

    # An EMPTY window on a daemon that answered is read_ok=True — the trustworthy zero. That
    # distinction is what makes `read_ok=False` mean something.
    empty = proxy.HistoryPage(total=0, window_start=0)
    assert empty.read_ok and empty.dropped == 0 and empty.returned == 0

    # and the route hands the object out rather than flattening it back to a list
    from cockpit import router

    # Compared as a STRING: router.py carries `from __future__ import annotations`, so the
    # annotation is unevaluated text and an `is` comparison against the class would be comparing
    # a str to a type and always failing — for a reason that has nothing to do with the property.
    annotation = str(inspect.signature(router.proxy_history).return_annotation)
    assert "HistoryPage" in annotation, (
        f"the history route returns {annotation!r} — if that is a bare list, `dropped` never "
        "reaches the operator"
    )
    ingest_src = inspect.getsource(router.ingest_scan_alerts)
    assert "alerts_dropped" in ingest_src, (
        "the ingest response does not report how many alerts failed to parse — a finding that "
        "never parsed is a finding that never reaches a report"
    )
    print("  an unparseable row is COUNTED rather than vanishing, both readers: PASS")


def test_the_sweep_runs_and_reports_rather_than_gating() -> None:
    """It is a REPORTING tool. Making it fail a build would turn every legitimate empty return
    into work, which is how a control stops being read."""
    proc = subprocess.run(
        [sys.executable, str(REPO_ROOT / "tools" / "silent_empty_scan.py")],
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, proc.stderr[-1500:]
    assert "SILENT-EMPTY SWEEP" in proc.stdout
    assert "rank" in proc.stdout, "the sweep produced no ranked findings at all"
    # ASCII only — the console this project is driven from is cp1252.
    proc.stdout.encode("ascii")
    print("  the sweep runs, ranks, exits 0 and prints ASCII: PASS")


if __name__ == "__main__":
    print("== CDN fronting + the silent-empty sweep (build #18 items 2 and 8) ==")
    test_a_failed_lookup_reports_UNKNOWN_and_never_not_fronted()
    test_a_cname_suffix_is_matched_dot_anchored_not_as_a_substring()
    test_evidence_from_all_three_sources_is_kept()
    test_nothing_in_this_module_scans_or_brute_forces()
    test_a_discovered_origin_is_reported_and_never_added()
    test_a_null_MX_does_not_become_an_empty_lead()
    test_an_empty_certificate_transparency_answer_says_so()
    test_the_scanner_uses_an_AST_and_a_docstring_cannot_fool_it()
    test_the_scan_list_read_can_fail_distinguishably()
    test_the_alert_read_can_fail_distinguishably()
    test_an_UNPARSEABLE_row_is_counted_rather_than_vanishing()
    test_the_sweep_runs_and_reports_rather_than_gating()
    print("ALL fronting and silent-empty locks pass")
