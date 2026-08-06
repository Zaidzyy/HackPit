"""nuclei surface SAFETY invariants.  Run:  python test_nuclei_safety.py

*** THE LINE THIS FILE HOLDS. ***
The nuclei surface adds NO new gate. A scan is ONE approved job — the intruder / ZAP-active-scan
shape — gated by the SAME executor gates every command clears, with an UNGATED stop. So this file
asserts, in both directions where it can:

  * THE PURE HALF BUILDS ARGV + PARSES JSON ONLY. `resolve_targets`, `nuclei_argv`, `parse_records`,
    `parse_findings`, `parse_ui_findings`, `parse_template_list` reach no subprocess / eval / exec —
    checked per-function against the AST (a docstring is not proof).
  * THE SCAN GOES THROUGH `executor.validate_request`. `start` reaches the gate via `_gate` BEFORE
    it resolves a sandbox or spawns anything; `validate` does too — the gate cannot be skipped.
  * THE SCOPE HANDRAIL APPLIES. Every target rides as `-u <target>`, so `check_target_lock` sees
    the exact hosts. In LAB mode a non-lab target is refused at the target gate (control: the lab
    target passes) — the INHERITED handrail, not a stronger gate this build invented.
  * AN OMITTED APPROVAL IS REFUSED, not granted (both gate flags default False), and STOP IS UNGATED.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

from cockpit import config, nuclei

_HERE = Path(__file__).parent

# Functions that MUST execute nothing — the pure, inspectable half.
_PURE_FUNCS = (
    nuclei.resolve_targets, nuclei.nuclei_argv, nuclei.parse_records,
    nuclei.parse_findings, nuclei.parse_ui_findings, nuclei.parse_template_list,
    nuclei._exec_request,
)
_BANNED_CALLS = {
    "Popen", "run", "call", "check_output", "system", "popen", "spawn",
    "eval", "exec", "compile", "__import__",
}


def _calls_in(fn) -> set[str]:
    tree = ast.parse(inspect.getsource(fn))
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Name):
                out.add(f.id)
            elif isinstance(f, ast.Attribute):
                out.add(f.attr)
    return out


# --------------------------------------------------------------------------- #
# 1. the pure half builds argv + parses JSON only
# --------------------------------------------------------------------------- #
def test_pure_functions_execute_nothing() -> None:
    """Per-function AST walk: none of the argv-building / JSON-parsing functions call a subprocess
    or eval. They are the half a UI inspects before anything spawns, so they must stay inert."""
    for fn in _PURE_FUNCS:
        calls = _calls_in(fn)
        offenders = calls & _BANNED_CALLS
        assert not offenders, f"{fn.__name__} calls {offenders}"
    print("  resolve_targets/nuclei_argv/parse_* build argv + parse JSON only — no exec: PASS")


# --------------------------------------------------------------------------- #
# 2. the scan goes through the gate before spawning
# --------------------------------------------------------------------------- #
def test_start_and_validate_reach_validate_request() -> None:
    """Structurally: `start` calls `_gate` and `validate` calls `_gate`, and `_gate` calls
    `validate_request`. The gate cannot be skipped by a caller of the worker."""
    assert "_gate" in _calls_in(nuclei.start), "start must call the gate"
    assert "_gate" in _calls_in(nuclei.validate), "validate must call the gate"
    assert "validate_request" in _calls_in(nuclei._gate), "_gate must call validate_request"
    # And it gates BEFORE it resolves a sandbox / spawns: _gate precedes resolve_mode / Popen.
    src = inspect.getsource(nuclei.start)
    assert src.index("_gate(") < src.index("resolve_mode"), "gate must run before sandbox resolution"
    print("  start + validate reach executor.validate_request via _gate, before any spawn: PASS")


# --------------------------------------------------------------------------- #
# 3. the target handrail — inherited, with a control
# --------------------------------------------------------------------------- #
def test_every_target_rides_as_dash_u() -> None:
    """The handrail can only see a target that is on the argv. Every target must be a `-u <target>`
    token so `check_target_lock` reads the exact hosts that get hit."""
    argv = nuclei.nuclei_argv(["http://a.example", "b.example"], nuclei.NucleiRequest())
    idxs = [i for i, tok in enumerate(argv) if tok == "-u"]
    assert len(idxs) == 2, argv
    assert {argv[i + 1] for i in idxs} == {"http://a.example", "b.example"}, argv
    print("  every target rides as -u <target> where the handrail reads it: PASS")


def test_lab_refuses_a_non_lab_target_with_a_control() -> None:
    """In LAB mode a scan of a non-lab host is refused at the target gate; the LAB target is NOT —
    that control proves the handrail actually fires and is not always-refusing."""
    off = nuclei.validate(nuclei.NucleiRequest(targets=["evil.example.com"], approved=True))
    assert off is not None and off.gate == "target", off
    lab = nuclei.validate(nuclei.NucleiRequest(targets=[config.LAB_TARGET_HOST], approved=True))
    assert lab is None or lab.gate != "target", lab
    print("  lab refuses a non-lab target at the target gate; the lab target passes: PASS")


def test_unapproved_scan_refused_at_approval_gate_with_a_control() -> None:
    """Against the LAB target (so the target-lock passes) an UNAPPROVED scan is refused at the
    approval gate; an approved one is not."""
    unapproved = nuclei.validate(nuclei.NucleiRequest(targets=[config.LAB_TARGET_HOST]))
    assert unapproved is not None and unapproved.gate == "approval", unapproved
    approved = nuclei.validate(nuclei.NucleiRequest(targets=[config.LAB_TARGET_HOST], approved=True))
    assert approved is None or approved.gate != "approval", approved
    print("  an unapproved scan is refused at the approval gate; an approved one is not: PASS")


# --------------------------------------------------------------------------- #
# 4. defaults refuse; stop is ungated
# --------------------------------------------------------------------------- #
def test_gate_flags_default_false() -> None:
    req = nuclei.NucleiRequest()
    assert req.approved is False, "approval must never default true"
    assert req.dangerous_ack is False, "the red-confirm must never default true"
    print("  approval + red-confirm both default FALSE — an omitted field is refused: PASS")


def test_stop_is_ungated() -> None:
    calls = _calls_in(nuclei.stop)
    assert "validate_request" not in calls and "validate" not in calls, "stop must be ungated"
    print("  stop() reaches no gate — it is the ungated panic button: PASS")


if __name__ == "__main__":
    test_pure_functions_execute_nothing()
    test_start_and_validate_reach_validate_request()
    test_every_target_rides_as_dash_u()
    test_lab_refuses_a_non_lab_target_with_a_control()
    test_unapproved_scan_refused_at_approval_gate_with_a_control()
    test_gate_flags_default_false()
    test_stop_is_ungated()
    print("\nnuclei safety: all invariants hold.")
