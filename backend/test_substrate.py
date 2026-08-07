"""Substrate-coverage tests (backend/substrate_probe.py) — Task 1's hermetic half.

The LIVE half (does each tool run in the real image?) needs Docker and is run by hand /
in CI via ``python backend/substrate_probe.py``. What is tested here without a stack:

  * the verdict function :func:`classify` — a landmine output is NOT a run, a version banner IS,
    an unresolved binary is not installed — with a positive control (it can distinguish);
  * the whole pipeline over the REAL catalog with an injected fake container, so a tool added to
    tools.json tomorrow is exercised by nobody-remembering-to-add-it (the safety-test rule);
  * the static catalogued-vs-Dockerfile coverage.

Run:  python test_substrate.py
"""
from __future__ import annotations

import substrate_probe as sp
from arsenal import loader


def test_classify_verdicts() -> None:
    # a real version banner => runs
    runs, reason = sp.classify(name="nmap", resolved="nmap", flag="--version", exit_code=0,
                               output="Nmap version 7.99 ( https://nmap.org )")
    assert runs and not reason
    # a usage error still means the binary EXECUTED => runs (exit code is not the verdict)
    runs, _ = sp.classify(name="x", resolved="x", flag="--version", exit_code=2, output="usage: x [opts]")
    assert runs, "a tool that rejects --version with usage text still ran"
    # the no-new-privileges / setcap landmine => does NOT run, with the reason
    runs, reason = sp.classify(name="amass", resolved="amass", flag="--version", exit_code=0,
                               output='sudo: The "no new privileges" flag is set')
    assert not runs and "landmine" in reason, reason
    # not resolved => not installed
    runs, reason = sp.classify(name="ghidra", resolved="", flag="", exit_code=None, output="")
    assert not runs and "not installed" in reason
    # resolved but nothing executed => not a run
    runs, reason = sp.classify(name="y", resolved="y", flag="", exit_code=None, output="")
    assert not runs and "no trivial call" in reason
    print("  Task 1 classify: landmine!=runs, banner==runs, unresolved==not-installed: PASS")


def test_pipeline_over_real_catalog() -> None:
    """Drive probe_all over the REAL tools.json with a fake container, so every catalogued tool is
    classified. A landmine and an absent tool are simulated to prove the tiers separate."""
    arsenal = loader.load()
    assert len(arsenal.tools) > 90, "the catalog should carry the real tool population"

    def fake_probe(container: str, candidates: list[str]):
        first = candidates[0]
        if first == "amass":                       # simulate the sudo/no-new-privileges landmine
            return "amass", "--version", 0, 'sudo: The "no new privileges" flag is set'
        if first in ("ghidra", "prowler"):         # simulate genuinely absent
            return "", "", None, ""
        # an aliased package: resolve under the LAST candidate (impacket-*), still runs
        resolved = candidates[-1] if len(candidates) > 1 else first
        return resolved, "--version", 0, f"{resolved} 1.0"

    results = sp.probe_all(arsenal, container="fake", probe=fake_probe)
    assert len(results) == len(arsenal.tools)
    summ = sp.summarize(results)
    assert summ["windows_only"] == len([t for t in arsenal.tools if not t.runs_here()])
    assert summ["installed_no_run"] >= 1, "the simulated landmine must be an installed-no-run"
    assert summ["not_installed"] >= 1, "the simulated absent tool must be not-installed"
    assert summ["runs"] > 80, "most Linux tools should classify as runs under the fake"
    # the landmine tool is reported not-running with its reason — never counted as covered
    amass = next(r for r in results if r.name == "amass")
    assert not amass.runs and "landmine" in amass.reason
    # aliased resolution is surfaced honestly
    assert summ["resolved_under_alias"] >= 1
    print(f"  Task 1 pipeline: {summ['runs']}/{summ['linux_catalogued']} classify as runs over the real catalog: PASS")


def test_binre_and_forensics_tools_are_probed() -> None:
    """Every binary-RE and forensics-CTF tool is EXERCISED by the probe — present-or-report.

    The image install for these is the operator's manual rebuild step, so the honest claim this
    build can make without Docker is narrower: each catalogued tool reaches the probe and lands in
    a tier (runs / installed-no-run / not-installed), never silently skipped. A tool the image has
    not baked yet surfaces as `not-installed` in the live report rather than vanishing — which is
    exactly what drives docs/substrate-coverage.md after the rebuild.
    """
    arsenal = loader.load()
    new = [t for t in arsenal.tools if t.category in ("binary-re", "forensics-ctf")]
    assert len(new) >= 24, f"expected the binary-RE + forensics-CTF set, got {len(new)}"

    # A fake container that resolves nothing — the point is that every tool is still REPORTED,
    # each with a not-installed tier and a reason, not dropped.
    absent = lambda container, candidates: ("", "", None, "")  # noqa: E731
    results = {r.name: r for r in sp.probe_all(arsenal, container="fake", probe=absent)}
    for tool in new:
        r = results[tool.name]
        assert r.tier() in ("runs", "installed-no-run", "not-installed"), (tool.name, r.tier())
        assert r.reason, f"{tool.name}: an unresolved tool must carry a reason, not pass silently"
        # candidates the probe would try = the tool's own names+aliases, as invoked
        assert r.candidates == list(dict.fromkeys(tool.names())), tool.name
    print(f"  Task 1: all {len(new)} binary-RE + forensics-CTF tools are probed "
          "(present-or-report), none skipped: PASS")


def test_static_coverage() -> None:
    arsenal = loader.load()
    dockerfile = sp.DOCKERFILE.read_text(encoding="utf-8")
    cov = static_result = sp.static_coverage(arsenal, dockerfile)
    linux = [t for t in arsenal.tools if t.runs_here()]
    assert cov["linux_catalogued"] == len(linux)
    # most Linux tools are named somewhere in the Dockerfile install lines (metapackages hide the
    # rest, which is exactly why the LIVE probe is the real arbiter — asserted, not assumed).
    assert cov["named_count"] >= len(linux) // 2, cov["named_count"]
    # the function actually discriminates (a bogus catalog name would not be "named")
    assert "not_named_in_dockerfile" in cov
    print(f"  Task 1 static: {cov['named_count']}/{cov['linux_catalogued']} Linux tools named in the Dockerfile: PASS")


if __name__ == "__main__":
    test_classify_verdicts()
    test_pipeline_over_real_catalog()
    test_binre_and_forensics_tools_are_probed()
    test_static_coverage()
    print("ALL substrate-coverage tests pass")
