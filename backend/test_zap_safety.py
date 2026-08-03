"""ZAP gating locks.  Run:  python test_zap_safety.py

Two invariants:
  1. an ACTIVE ZAP scan demands the red-confirm; a PASSIVE one does not
  2. the danger verdict is driven by the name the executor actually classifies
"""

from __future__ import annotations

from arsenal import loader
from cockpit import allowlist

# Kali's zaproxy package ships ONE launcher and no scan scripts, so the binary is identical
# for a crawl and for an attack — the whole distinction lives in the arguments. Verified
# against the built image (`dpkg -L zaproxy`), not upstream's documentation.
BIN = "zaproxy"
ACTIVE_ARGS = ["-cmd", "-quickurl", "http://target", "-quickout", "/loot/x-zap.json"]
RECON_ARGS = ["-cmd", "-zapit", "http://target"]


def _fires(command: str, args: list[str] | None = None) -> bool:
    return bool(allowlist.dangerous_command_heuristic(command, args or []))


def test_active_fires_passive_does_not_with_a_live_control() -> None:
    """*** THE INVARIANT. *** An active scan sends live injection payloads at every discovered
    parameter; a baseline crawl observes. They must get different verdicts.

    The controls are in THIS test on purpose: a heuristic broken into always-True or
    always-False would otherwise satisfy half of it and look fine.
    """
    assert _fires(BIN, ACTIVE_ARGS), "-quickurl does NOT demand the red-confirm"
    assert not _fires(BIN, RECON_ARGS), "-zapit demands the red-confirm — a crawl must not"
    assert not _fires(BIN, ["-cmd", "-version"]), "the bare launcher demands a confirm"

    # positive control: a known-dangerous command still fires
    assert _fires("msfvenom"), "control failed — the heuristic fires on nothing"
    # negative control: a known-benign command still does not
    assert not _fires("nmap", ["-sV", "10.0.0.1"]), "control failed — the heuristic fires on all"
    print("  active fires, passive does not, both controls hold: PASS")


def test_the_verdict_survives_every_spelling_the_executor_may_see() -> None:
    """_tool_name() normalises path, case and the .py suffix. The verdict must not depend on
    which spelling a template or an operator used."""
    for spelling in (BIN, f"/usr/bin/{BIN}", BIN.upper(), "owasp-zap", "/usr/bin/owasp-zap"):
        assert _fires(spelling, ACTIVE_ARGS), f"{spelling!r} lost its attack verdict"
        assert not _fires(spelling, RECON_ARGS), f"{spelling!r} gained a verdict on a crawl"
    print("  the verdict holds across path, case and .py spellings: PASS")


def test_a_wrapped_active_scan_still_fires() -> None:
    """D22: proxychains laundered a red-confirm once. The wrapper is not what runs."""
    assert _fires("proxychains", [BIN, *ACTIVE_ARGS]), (
        "proxychains launders the ZAP active-scan confirm — D22 returning"
    )
    assert not _fires("proxychains", [BIN, *RECON_ARGS]), (
        "a proxied CRAWL gained a confirm — over-firing through the wrapper"
    )
    print("  proxychains does not launder the active-scan confirm: PASS")


def test_both_heuristics_agree_the_shared_predicate_lock() -> None:
    """*** THE SHARED-PREDICATE LOCK. *** The command heuristic and the SCRIPT heuristic (the
    WinRM path) must reach the same verdict about the same tool.

    This codebase has produced this defect three times — the WinRM argv[0] classification
    (Critical 2), the proxychains-laundered confirm (D22), and the collector FQDN classifier
    (D24) — and dangerous_script_heuristic's own docstring says the groups are shared with
    dangerous_command_heuristic ON PURPOSE, because "two lists would drift, and drift is what
    produced this bug". Adding a tool to one and not the other is how a 4th arrives.
    """
    active_script = allowlist.dangerous_script_heuristic(
        f"{BIN} {' '.join(ACTIVE_ARGS)}")
    assert active_script, (
        "the SCRIPT heuristic does not flag an active ZAP scan while the COMMAND heuristic "
        "does — the two predicates have drifted, which is the Critical 2 / D22 / D24 shape"
    )

    passive_script = allowlist.dangerous_script_heuristic(
        f"{BIN} {' '.join(RECON_ARGS)}")
    assert not passive_script, (
        f"the SCRIPT heuristic flags a PASSIVE baseline crawl: {passive_script}"
    )

    # positive control: the script heuristic is live and can still fail
    assert allowlist.dangerous_script_heuristic("msfvenom -p windows/x64/meterpreter"), (
        "control failed — the script heuristic flags nothing at all"
    )
    print("  the command and script heuristics agree on both ZAP verdicts: PASS")


def test_the_catalog_really_contains_both_invocations() -> None:
    """Draw from the real source of truth: if the catalog stops shipping these templates the
    tests above are asserting about nothing, and this fails instead of quietly passing."""
    import shlex

    argv0s: set[str] = set()
    for tool in loader.load().tools:
        for tpl in tool.templates:
            try:
                parts = shlex.split(tpl.template, posix=True)
            except ValueError:
                parts = tpl.template.split()
            if parts:
                argv0s.add(parts[0].rsplit("/", 1)[-1])

    assert BIN in argv0s, f"the catalog ships no {BIN} template; found: {sorted(argv0s)}"

    # and the templates really do carry BOTH argument shapes, or the split above is theory
    tpls = [t.template for tool in loader.load().tools if tool.name == BIN for t in tool.templates]
    assert any("-quickurl" in t for t in tpls), f"no ACTIVE template in the catalog: {tpls}"
    assert any("-zapit" in t for t in tpls), f"no RECON template in the catalog: {tpls}"
    assert not any("-autorun" in t for t in tpls), (
        "an -autorun template entered the catalog: a plan file decides its own aggression, so "
        "the gate would classify a string that does not describe what runs (design spec §4)"
    )
    print(f"  the catalog ships both ZAP invocations ({len(argv0s)} argv[0]s total): PASS")


if __name__ == "__main__":
    test_active_fires_passive_does_not_with_a_live_control()
    test_the_verdict_survives_every_spelling_the_executor_may_see()
    test_a_wrapped_active_scan_still_fires()
    test_both_heuristics_agree_the_shared_predicate_lock()
    test_the_catalog_really_contains_both_invocations()
    print("ALL ZAP gating locks pass")
