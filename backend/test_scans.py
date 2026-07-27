"""The shared source scanner's OWN regression tests.

Ten safety locks now depend on `test_support/scans.py`. Every one of them reports "no
offenders" when it is working AND when it is broken, so the scanner has to be independently
demonstrated to fail on a real violation before any lock is allowed to rest on it. That is the
whole lesson of the gate audit: a guard test with no proof it can fail is not evidence.

Each test below plants a violation of a shape the OLD scans missed, and asserts this one finds
it. Run:  python test_scans.py
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from test_support import scans

BACKEND = Path(__file__).parent


def _tree(files: dict[str, str]) -> tempfile.TemporaryDirectory:
    tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
    for name, body in files.items():
        p = Path(tmp.name) / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    return tmp


def test_it_reaches_the_directories_the_old_globs_never_opened() -> None:
    """`backend/*.py + backend/cockpit/*.py` covered 30 of 69 modules. Every package the old
    selection skipped — adgraph, arsenal, codescan, detection, evasion, exploits, state — is a
    place a violation could sit forever."""
    checked = {scans.rel(p) for p in scans.source_files()}
    for pkg in ("adgraph", "arsenal", "codescan", "detection", "evasion", "exploits", "state"):
        assert any(n.startswith(f"{pkg}/") for n in checked), (
            f"the sweep never reaches {pkg}/ — this is the C3 coverage gap returning"
        )
    assert not any(".venv/" in n for n in checked), "the venv leaked into the sweep"
    assert len(checked) >= 60, f"only {len(checked)} modules in the tree sweep"
    print(f"  the sweep reaches all 7 previously-unscanned packages ({len(checked)} modules): PASS")


def test_a_planted_import_in_an_unscanned_package_is_caught() -> None:
    """The exact demonstration from the audit: adgraph/orchestrator.py imports the shell."""
    scans.assert_catches_a_planted_violation(
        plant="from cockpit.kali import run_kali",
        patterns=[r"run_kali", r"cockpit\.kali"],
        ast_targets=["cockpit.kali", "run_kali"],
    )
    print("  a planted run_kali import in adgraph/orchestrator.py is CAUGHT: PASS")


def test_the_allow_list_is_keyed_on_paths_not_basenames() -> None:
    """`allowed = {"router.py"}` matched `f.name in allowed`, so adgraph/router.py,
    detection/router.py and arsenal/router.py were all exempt by accident."""
    tmp = _tree({
        "cockpit/router.py": "from cockpit.kali import run_kali\n",
        "adgraph/router.py": "from cockpit.kali import run_kali\n",
    })
    with tmp:
        res = scans.scan_source_tree(
            patterns=[r"run_kali"], allowed={"cockpit/router.py"}, root=Path(tmp.name),
        )
        assert any("adgraph/router.py" in o for o in res.offenders), (
            f"a basename allow-list exempted adgraph/router.py again: {res.offenders}"
        )
        assert "cockpit/router.py" not in res.checked, "the allow-listed path was not exempted"
        assert res.controls.get("cockpit/router.py"), (
            "the allow-listed file must still be recorded as MATCHING — that is the control "
            "that catches a rename emptying the patterns"
        )
    print("  allow-lists are repo-relative paths; a same-named file elsewhere is NOT exempt: PASS")


def test_indirection_is_caught_by_the_ast_pass() -> None:
    """Four literal substrings cannot see an alias, an in-function import, or a name built by
    concatenation. The audit planted all three and every one was missed."""
    cases = {
        "alias": "import cockpit.kali as _k\n",
        "in_function": "def go():\n    from cockpit.kali import run_kali\n    return run_kali\n",
        "concat": (
            "import importlib\n"
            "def go():\n"
            "    m = importlib.import_module('cockpit.' + 'kali')\n"
            "    return getattr(m, 'run_' + 'kali')\n"
        ),
        "fstring": (
            "import importlib\n"
            "def go(n):\n"
            "    return importlib.import_module(f'cockpit.kali{n}')\n"
        ),
    }
    for label, body in cases.items():
        tmp = _tree({"adgraph/orchestrator.py": body})
        with tmp:
            res = scans.scan_source_tree(
                patterns=[r"\brun_kali\b"],           # the OLD-style substring pass alone
                ast_targets=["cockpit.kali", "run_kali"],
                root=Path(tmp.name),
            )
            assert res.offenders, f"[{label}] indirection was MISSED: {body!r}"
    print(f"  all {len(cases)} indirection shapes (alias / in-function / concat / f-string) "
          "are caught: PASS")


def test_prose_does_not_trip_a_lock_but_a_string_literal_still_does() -> None:
    """Both halves, and the second is the one that is easy to get wrong.

    Blanking prose is required — a module that DOCUMENTS a rule must not violate it. But a
    scanner that blanked every string would go blind to `import_module("cockpit.kali")`, which
    is precisely the indirection these locks exist to catch. So docstrings are found
    structurally, not by blanking the whole STRING token class.
    """
    tmp = _tree({
        "adgraph/prose.py": '"""This module must never call run_kali."""\nx = 1  # not run_kali\n',
        "adgraph/real.py": "import importlib\nm = importlib.import_module('cockpit.kali')\n",
    })
    with tmp:
        res = scans.scan_source_tree(
            patterns=[r"run_kali", r"cockpit\.kali"],
            ast_targets=["cockpit.kali"],
            root=Path(tmp.name),
        )
        assert not any("prose.py" in o for o in res.offenders), (
            f"a docstring/comment mentioning the rule tripped it: {res.offenders}"
        )
        assert any("real.py" in o for o in res.offenders), (
            f"a real string-literal reference was blanked away and MISSED: {res.offenders}"
        )
    print("  prose is stripped; a genuine string-literal reference still fires: PASS")


def test_checked_counts_content_not_files_opened() -> None:
    """Build #4's `scanned > 40` incremented BEFORE the filter that decided whether to read the
    file: of 99 counted, 5 were inspected. `checked` and `skipped` are separate for that reason."""
    tmp = _tree({
        "a.py": "x = 1\n",
        "test_b.py": "x = 1\n",
        "cockpit/c.py": "x = 1\n",
        "adgraph/d.py": "x = 1\n",
    })
    with tmp:
        res = scans.scan_source_tree(patterns=[r"zzz"], allowed={"a.py"}, root=Path(tmp.name))
        assert set(res.checked) == {"cockpit/c.py", "adgraph/d.py"}, res.checked
        assert set(res.skipped) == {"a.py", "test_b.py"}, res.skipped
        assert len(res) == 2, "len(result) must be the CHECKED count"
    print("  `checked` counts files whose content was matched, never files opened: PASS")


def test_assert_clean_fails_on_each_of_its_four_claims() -> None:
    """The helper every lock will call must itself be demonstrated to fail — otherwise ten
    suites inherit one vacuous assertion instead of writing ten."""
    ok = scans.ScanResult(checked=[f"m{i}.py" for i in range(50)], controls={"x.py": ["hit"]})

    def fails(res, **kw) -> bool:
        try:
            scans.assert_clean(res, what="probe", **kw)
        except AssertionError:
            return True
        return False

    scans.assert_clean(ok, what="probe", min_checked=10)          # the passing case
    assert fails(scans.ScanResult(checked=ok.checked, offenders=["bad.py (x)"],
                                  controls=ok.controls), min_checked=10), "offenders ignored"
    assert fails(ok, min_checked=10, must_have_scanned=["never.py"]), "must_have_scanned ignored"
    assert fails(ok, min_checked=500), "min_checked ignored"
    assert fails(scans.ScanResult(checked=ok.checked, controls={"x.py": []}),
                 min_checked=10), "the rotted-pattern control is ignored"
    print("  assert_clean() demonstrably fails on all 4 of its claims: PASS")


if __name__ == "__main__":
    test_it_reaches_the_directories_the_old_globs_never_opened()
    test_a_planted_import_in_an_unscanned_package_is_caught()
    test_the_allow_list_is_keyed_on_paths_not_basenames()
    test_indirection_is_caught_by_the_ast_pass()
    test_prose_does_not_trip_a_lock_but_a_string_literal_still_does()
    test_checked_counts_content_not_files_opened()
    test_assert_clean_fails_on_each_of_its_four_claims()
    print("ALL shared-scanner regression tests pass")
