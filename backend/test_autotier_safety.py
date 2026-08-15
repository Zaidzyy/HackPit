"""SAFETY invariants for AUTO-RUNNER TIER CLASSIFICATION.

The auto-runner may fire the ``passive`` tier without a human; it must NEVER auto-fire an
``exploitation`` or ``human_only`` action in assisted mode, and never a ``human_only`` action in
any mode. That guarantee is only as good as the classifier, so this locks it:

  1. THE PASSIVE SET IS CLOSED. Every invokable surface that is NOT explicitly passive classifies
     as exploitation (or human_only for the repeater). A surface added to the invokable set later
     without being added to the passive allowlist is therefore exploitation by default — it can
     never silently become auto-fireable.
  2. DETECT vs CONFIRM. smuggle/cache are passive at their read-only 'detect' stage and
     exploitation at 'confirm' (which plants/poisons). Only the exact string 'detect' is passive.
  3. THE REPEATER AND 'ask' ARE human_only, always.
  4. FAIL SAFE. A malformed / unknown / empty proposal is exploitation, not passive.

Hermetic. Run:  python test_autotier_safety.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cockpit import autotier  # noqa: E402
from mcp_tools import _MCP_SURFACES  # noqa: E402  (the real invokable surface set)

P, X, H = autotier.PASSIVE, autotier.EXPLOITATION, autotier.HUMAN_ONLY


def _surf(name: str, **params) -> dict:
    return {"kind": "surface", "surface": name, "surface_params": params}


# --------------------------------------------------------------------------- #
# 1. the passive set is closed — cross-checked against the REAL invokable surfaces
# --------------------------------------------------------------------------- #
def test_every_invokable_surface_classifies_and_only_the_allowlist_is_passive() -> None:
    # These are the ONLY surfaces that may ever be auto-fired without a human (recon only when
    # its mode is passive; smuggle/cache only at detect — checked separately below).
    expected_passive = {"discover", "jsrecon", "nuclei", "recon", "smuggle", "cache"}
    for name in _MCP_SURFACES:
        active = autotier.classify(_surf(name))  # bare params: no passive mode/stage
        if name in ("discover", "jsrecon", "nuclei"):
            assert active == P, f"{name} should be passive, got {active}"
        elif name == "repeater":
            assert active == H, f"repeater must be human_only, got {active}"
        elif name in ("recon", "smuggle", "cache"):
            # passive ONLY with the right mode/stage; bare form is exploitation (fail-safe)
            assert active == X, f"{name} with bare params must be exploitation, got {active}"
        else:
            assert active == X, f"{name} must be exploitation, got {active}"

    # and no surface OUTSIDE that reviewed set is ever passive — a new invokable surface defaults
    # to needing a human.
    for name in _MCP_SURFACES:
        if name not in expected_passive and name != "repeater":
            assert autotier.classify(_surf(name)) == X, f"{name} leaked into a non-exploitation tier"
    print("  every invokable surface classifies; only the reviewed allowlist is passive: PASS")


def test_a_fabricated_unknown_surface_is_exploitation() -> None:
    assert autotier.classify(_surf("totally-new-surface")) == X
    assert autotier.classify(_surf("")) == X
    print("  an unknown / new surface fails safe to exploitation: PASS")


# --------------------------------------------------------------------------- #
# 2. detect vs confirm; passive recon
# --------------------------------------------------------------------------- #
def test_detect_is_passive_and_confirm_is_exploitation() -> None:
    for surf in ("smuggle", "cache"):
        assert autotier.classify(_surf(surf, stage="detect")) == P, f"{surf} detect not passive"
        assert autotier.classify(_surf(surf, stage="confirm")) == X, f"{surf} confirm not exploitation"
        # anything that is not exactly 'detect' is NOT treated as passive
        assert autotier.classify(_surf(surf, stage="")) == X, f"{surf} empty stage leaked to passive"
        assert autotier.classify(_surf(surf, stage="poison")) == X

    assert autotier.classify(_surf("recon", mode="passive")) == P
    assert autotier.classify(_surf("recon", mode="active")) == X
    assert autotier.classify(_surf("recon")) == X, "bare recon (active by default) must be exploitation"
    print("  detect/passive-recon are passive; confirm/active-recon are exploitation: PASS")


def test_the_named_active_surfaces_are_exploitation() -> None:
    for name in ("intruder", "race", "credentials", "tokens", "c2", "tunnels", "capture"):
        assert autotier.classify(_surf(name)) == X, f"{name} was not exploitation"
    print("  intruder/race/credentials/tokens/c2/tunnels/capture are exploitation: PASS")


# --------------------------------------------------------------------------- #
# 3. human_only: repeater + ask
# --------------------------------------------------------------------------- #
def test_repeater_and_ask_are_human_only() -> None:
    assert autotier.classify(_surf("repeater")) == H
    assert autotier.classify(_surf("repeater", stage="detect")) == H, "repeater never downgrades"
    assert autotier.classify({"kind": "ask", "ask_label": "session cookie"}) == H
    print("  the repeater and an 'ask' are human_only, always: PASS")


# --------------------------------------------------------------------------- #
# 4. commands + fail-safe
# --------------------------------------------------------------------------- #
def test_commands_split_on_the_danger_heuristic() -> None:
    assert autotier.classify({"kind": "command", "command": "httpx", "dangerous_flags": []}) == P
    assert autotier.classify(
        {"kind": "command", "command": "sqlmap", "dangerous_flags": ["--os-shell"]}
    ) == X
    print("  a flagged command is exploitation; an unflagged one is passive: PASS")


def test_malformed_proposals_fail_safe() -> None:
    for bad in (None, {}, [], "surface", {"kind": "weird"}, {"surface": "nuclei"}):
        assert autotier.classify(bad) == X, f"{bad!r} did not fail safe to exploitation"
    print("  None / empty / malformed proposals fail safe to exploitation: PASS")


if __name__ == "__main__":
    test_every_invokable_surface_classifies_and_only_the_allowlist_is_passive()
    test_a_fabricated_unknown_surface_is_exploitation()
    test_detect_is_passive_and_confirm_is_exploitation()
    test_the_named_active_surfaces_are_exploitation()
    test_repeater_and_ask_are_human_only()
    test_commands_split_on_the_danger_heuristic()
    test_malformed_proposals_fail_safe()
    print("ALL auto-tier safety invariants hold")
