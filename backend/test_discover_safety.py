"""discover surface SAFETY invariants.  Run:  python test_discover_safety.py

*** THE LINE THIS FILE HOLDS. ***
:discover adds NO new gate. A discovery job is ONE approved job — the :recon/:nuclei/intruder shape
— gated by the SAME executor gates every command clears, with an UNGATED stop. AND it holds the
correctness property the spec insists on: A DISCOVERY JOB CAN NEVER BE POINTED OFF-SCOPE, and
nothing it surfaces enters state unless the scope already covered it. So this file asserts:

  * THE PURE HALF BUILDS ARGV / SORTS BY SCOPE / LABELS ROWS ONLY — the `*_argv` builders,
    `filter_endpoints_in_scope`, `gate_argv`, `_exec_request`, `_mark_param`, `_findings_from`,
    `_resolve_domain` reach no subprocess / eval / exec, per-function against the AST.
  * THE JOB GOES THROUGH `executor.validate_request`. `start` reaches the gate via `_gate` BEFORE
    it spawns; `validate` does too — the gate cannot be skipped.
  * DISCOVERY IS ENGAGEMENT-BOUND. No active engagement -> refused (availability, never a bypass).
  * TARGET SCOPE-LOCK BY CONSTRUCTION: an out-of-scope target url is refused BEFORE the gate/spawn,
    and `filter_endpoints_in_scope` drops an out-of-scope discovery (with a control).
  * AN OMITTED APPROVAL IS REFUSED, not granted (both gate flags default False), and STOP IS UNGATED.
"""
from __future__ import annotations

import ast
import inspect
import tempfile
from pathlib import Path

from cockpit import discover
from cockpit import engagement as ENG
from cockpit import runstore
from cockpit import scope as SC
from state.models import Endpoint

# Functions that MUST execute nothing — the pure, inspectable half.
_PURE_FUNCS = (
    discover.arjun_argv, discover.arjun_gate_argv, discover.ffuf_argv, discover.feroxbuster_argv,
    discover.paramspider_argv, discover.content_gate_argv, discover.gate_argv, discover._fuzz_url,
    discover.filter_endpoints_in_scope, discover._mark_param, discover._to_discovered_param,
    discover._to_discovered_endpoint, discover._findings_from, discover._resolve_domain,
    discover._exec_request, discover._interesting_params, discover._interesting_url,
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
# 1. the pure half executes nothing
# --------------------------------------------------------------------------- #
def test_pure_functions_execute_nothing() -> None:
    for fn in _PURE_FUNCS:
        offenders = _calls_in(fn) & _BANNED_CALLS
        assert not offenders, f"{fn.__name__} calls {offenders}"
    print("  argv builders / filter_endpoints_in_scope / gate_argv / findings build+sort+label only — no exec: PASS")


# --------------------------------------------------------------------------- #
# 2. the job reaches the gate before spawning
# --------------------------------------------------------------------------- #
def test_start_gates_before_spawn() -> None:
    src = inspect.getsource(discover.start)
    assert "_gate" in _calls_in(discover.start), "start must call the gate"
    assert src.index("_gate(") < src.index("threading.Thread"), "start must gate before it spawns"
    assert "_gate" in _calls_in(discover.validate)
    assert "validate_request" in _calls_in(discover._gate), "_gate must call validate_request"
    print("  start + validate reach validate_request via _gate before any spawn: PASS")


# --------------------------------------------------------------------------- #
# 3. engagement-bound: no engagement -> refused, nothing runs
# --------------------------------------------------------------------------- #
def test_discover_requires_an_engagement() -> None:
    orig = ENG.get_active
    ENG.get_active = lambda _id: None  # type: ignore[assignment]
    try:
        try:
            discover.start(discover.DiscoverRequest(
                mode="params", url="https://api.example.com/x", engagement_id="nope", approved=True))
            assert False, "a job with no active engagement must be refused"
        except discover.DiscoverRefused as exc:
            assert exc.gate == "engagement", exc.gate
    finally:
        ENG.get_active = orig
    print("  a discovery job with no active engagement is refused at the engagement precondition: PASS")


# --------------------------------------------------------------------------- #
# 4. SCOPE — the target is scope-locked by construction (with a control)
# --------------------------------------------------------------------------- #
def test_target_scope_locked_by_construction() -> None:
    tmp = Path(tempfile.mkdtemp()) / "eng.db"
    orig_rs, orig_eng = runstore.DB_PATH, ENG.DB_PATH
    orig_running = discover.repeater_mod._container_running
    orig_ensure = discover.loot.ensure
    runstore.DB_PATH = ENG.DB_PATH = tmp
    discover.repeater_mod._container_running = lambda _c: True  # type: ignore[assignment]
    discover.loot.ensure = lambda _n: "/loot/eng"              # type: ignore[assignment]
    try:
        ENG.init_db()
        rec = ENG.enter("example.com", "authorized", scope_spec="example.com, *.example.com")
        eid = rec.engagement_id
        # an OUT-OF-SCOPE target url is refused BEFORE the gate/spawn.
        try:
            discover.start(discover.DiscoverRequest(
                mode="params", url="https://evil.com/x", engagement_id=eid,
                approved=True, dangerous_ack=True))
            assert False, "an out-of-scope target must be refused by construction"
        except discover.DiscoverRefused as exc:
            assert exc.gate == "scope", exc.gate
        # CONTROL: an in-scope host is NOT refused by the scope check.
        live = ENG.get_active(eid)
        assert discover._target_in_scope(live, "api.example.com") is True, "in-scope host passes (control)"
        assert discover._target_in_scope(live, "evil.com") is False
        print("  an out-of-scope target url is refused by construction; an in-scope one passes (control): PASS")
    finally:
        discover.repeater_mod._container_running = orig_running
        discover.loot.ensure = orig_ensure
        runstore.DB_PATH, ENG.DB_PATH = orig_rs, orig_eng


def test_filter_drops_out_of_scope_with_control() -> None:
    matcher = SC.parse_scope("example.com, *.example.com", resolve=False)
    eps = [
        Endpoint(session_id="s", url="https://api.example.com/x?id=1", params=["id"]),
        Endpoint(session_id="s", url="https://evil.com/x", params=[]),
    ]
    kept, out_hosts = discover.filter_endpoints_in_scope(eps, matcher)
    assert [e.url for e in kept] == ["https://api.example.com/x?id=1"], "in-scope endpoint survives (control)"
    assert "evil.com" in out_hosts, "the out-of-scope host is surfaced read-only"
    assert "api.example.com" not in out_hosts
    print("  filter_endpoints_in_scope: out-of-scope dropped, in-scope kept (control): PASS")


# --------------------------------------------------------------------------- #
# 5. defaults refuse; stop is ungated
# --------------------------------------------------------------------------- #
def test_gate_flags_default_false() -> None:
    req = discover.DiscoverRequest()
    assert req.approved is False, "approval must never default true"
    assert req.dangerous_ack is False, "the red-confirm must never default true"
    print("  approval + red-confirm both default FALSE — an omitted field is refused: PASS")


def test_stop_is_ungated() -> None:
    calls = _calls_in(discover.stop)
    assert "validate_request" not in calls and "validate" not in calls, "stop must be ungated"
    print("  stop() reaches no gate — it is the ungated panic button: PASS")


if __name__ == "__main__":
    test_pure_functions_execute_nothing()
    test_start_gates_before_spawn()
    test_discover_requires_an_engagement()
    test_target_scope_locked_by_construction()
    test_filter_drops_out_of_scope_with_control()
    test_gate_flags_default_false()
    test_stop_is_ungated()
    print("\ndiscover safety: all invariants hold.")
