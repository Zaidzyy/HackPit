"""jsrecon surface SAFETY invariants.  Run:  python test_jsrecon_safety.py

*** THE LINE THIS FILE HOLDS. ***
:jsrecon adds NO new gate. A JS-recon job is ONE approved job — the :recon/:discover shape — gated by
the SAME executor gates every command clears, with an UNGATED stop. AND it holds two correctness
properties the spec insists on: A JOB CAN NEVER BE POINTED OFF-SCOPE and nothing it mines enters
state unless the scope already covered it; and A SECRET'S VALUE NEVER REACHES A FINDING (it goes to a
loot file, mirror :credentials). So this file asserts:

  * THE PURE HALF BUILDS ARGV / SORTS BY SCOPE / LABELS ROWS ONLY — the `*_argv`/`*_job_spec`
    builders, `filter_urls_in_scope`, `filter_endpoints_in_scope`, `parse_mine_output`,
    `_secret_finding`, `_mask`, `_to_mined_*`, `_exec_request` reach no subprocess/eval/exec.
  * THE JOB GOES THROUGH `executor.validate_request`. `start` reaches the gate via `_gate` BEFORE it
    spawns; `validate` does too.
  * JS RECON IS ENGAGEMENT-BOUND. No active engagement -> refused (availability, never a bypass).
  * TARGET + NAMED JS URL SCOPE-LOCKED BY CONSTRUCTION: an out-of-scope one is refused BEFORE the
    gate/spawn, and both scope filters drop an out-of-scope URL (with controls).
  * A SECRET VALUE NEVER REACHES A FINDING (with a planted control), and the value IS written to loot.
  * AN OMITTED APPROVAL IS REFUSED, not granted, and STOP IS UNGATED.
"""
from __future__ import annotations

import ast
import inspect
import json
import tempfile
from pathlib import Path

from cockpit import engagement as ENG
from cockpit import jsrecon
from cockpit import runstore
from cockpit import scope as SC
from state.models import Endpoint

# Functions that MUST execute nothing — the pure, inspectable half.
_PURE_FUNCS = (
    jsrecon.gate_argv, jsrecon.collect_job_spec, jsrecon.mine_job_spec,
    jsrecon.filter_urls_in_scope, jsrecon.filter_endpoints_in_scope, jsrecon.parse_mine_output,
    jsrecon._secret_finding, jsrecon._mask, jsrecon._to_mined_secret, jsrecon._to_mined_endpoint,
    jsrecon._endpoint_host, jsrecon._exec_request, jsrecon.validate,
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
    print("  argv/job-spec builders / scope filters / parse_mine_output / secret-finding build+sort+label only — no exec: PASS")


# --------------------------------------------------------------------------- #
# 2. the job reaches the gate before spawning
# --------------------------------------------------------------------------- #
def test_start_gates_before_spawn() -> None:
    src = inspect.getsource(jsrecon.start)
    assert "_gate" in _calls_in(jsrecon.start), "start must call the gate"
    assert src.index("_gate(") < src.index("threading.Thread"), "start must gate before it spawns"
    assert "_gate" in _calls_in(jsrecon.validate)
    assert "validate_request" in _calls_in(jsrecon._gate), "_gate must call validate_request"
    print("  start + validate reach validate_request via _gate before any spawn: PASS")


# --------------------------------------------------------------------------- #
# 3. engagement-bound: no engagement -> refused, nothing runs
# --------------------------------------------------------------------------- #
def test_jsrecon_requires_an_engagement() -> None:
    orig = ENG.get_active
    ENG.get_active = lambda _id: None  # type: ignore[assignment]
    try:
        try:
            jsrecon.start(jsrecon.JsReconRequest(
                target="https://app.example.com", engagement_id="nope", approved=True))
            assert False, "a job with no active engagement must be refused"
        except jsrecon.JsReconRefused as exc:
            assert exc.gate == "engagement", exc.gate
    finally:
        ENG.get_active = orig
    print("  a JS-recon job with no active engagement is refused at the engagement precondition: PASS")


# --------------------------------------------------------------------------- #
# 4. SCOPE — target + named JS url scope-locked by construction (with controls)
# --------------------------------------------------------------------------- #
def test_target_scope_locked_by_construction() -> None:
    tmp = Path(tempfile.mkdtemp()) / "eng.db"
    orig_rs, orig_eng = runstore.DB_PATH, ENG.DB_PATH
    orig_running = jsrecon.repeater_mod._container_running
    orig_ensure = jsrecon.loot.ensure
    runstore.DB_PATH = ENG.DB_PATH = tmp
    jsrecon.repeater_mod._container_running = lambda _c: True  # type: ignore[assignment]
    jsrecon.loot.ensure = lambda _n: "/loot/eng"              # type: ignore[assignment]
    try:
        ENG.init_db()
        rec = ENG.enter("example.com", "authorized", scope_spec="example.com, *.example.com")
        eid = rec.engagement_id
        # an OUT-OF-SCOPE collection target is refused BEFORE the gate/spawn.
        try:
            jsrecon.start(jsrecon.JsReconRequest(
                target="https://evil.com/", engagement_id=eid, approved=True, dangerous_ack=True))
            assert False, "an out-of-scope target must be refused by construction"
        except jsrecon.JsReconRefused as exc:
            assert exc.gate == "scope", exc.gate
        # an OUT-OF-SCOPE explicitly-named JS URL is refused too.
        try:
            jsrecon.start(jsrecon.JsReconRequest(
                js_urls=["https://cdn.evil.com/x.js"], engagement_id=eid,
                approved=True, dangerous_ack=True))
            assert False, "an out-of-scope JS url must be refused by construction"
        except jsrecon.JsReconRefused as exc:
            assert exc.gate == "scope", exc.gate
        # CONTROL: an in-scope host is NOT refused by the scope check.
        live = ENG.get_active(eid)
        assert jsrecon._target_in_scope(live, "app.example.com") is True, "in-scope host passes (control)"
        assert jsrecon._target_in_scope(live, "evil.com") is False
        print("  an out-of-scope target/JS url is refused by construction; an in-scope one passes (control): PASS")
    finally:
        jsrecon.repeater_mod._container_running = orig_running
        jsrecon.loot.ensure = orig_ensure
        runstore.DB_PATH, ENG.DB_PATH = orig_rs, orig_eng


def test_both_scope_filters_drop_out_of_scope_with_control() -> None:
    matcher = SC.parse_scope("example.com, *.example.com", resolve=False)
    kept_u, out_u = jsrecon.filter_urls_in_scope(
        ["https://app.example.com/a.js", "https://cdn.evil.com/b.js"], matcher)
    assert kept_u == ["https://app.example.com/a.js"], kept_u
    assert "cdn.evil.com" in out_u and "app.example.com" not in out_u
    eps = [Endpoint(session_id="s", url="https://api.example.com/x", params=[]),
           Endpoint(session_id="s", url="https://evil.com/y", params=[])]
    kept_e, out_e = jsrecon.filter_endpoints_in_scope(eps, matcher)
    assert [e.url for e in kept_e] == ["https://api.example.com/x"]
    assert "evil.com" in out_e and "api.example.com" not in out_e
    print("  filter_urls_in_scope + filter_endpoints_in_scope both drop out-of-scope, keep in-scope (controls): PASS")


# --------------------------------------------------------------------------- #
# 5. A SECRET VALUE NEVER REACHES A FINDING; the value IS written to loot
# --------------------------------------------------------------------------- #
def test_secret_value_never_in_finding_but_is_in_loot() -> None:
    planted = "AKIAIOSFODNN7EXAMPLE"
    secret = {"type": "aws-access-key-id", "value": planted, "verified": True,
              "source_url": "https://app.example.com/static/app.js"}
    finding = jsrecon._secret_finding(secret, "/loot/eng/s.txt", "s1", "r1")
    blob = json.dumps(vars(finding))
    assert planted not in blob, "PLANTED CONTROL: the secret value leaked into the finding"
    assert finding.severity == "high"  # verified -> High
    # and it DOES reach the loot file (the one place it lives).
    tmp = Path(tempfile.mkdtemp())
    orig_host, orig_container = jsrecon.loot.host_dir, jsrecon.loot.container_dir
    jsrecon.loot.host_dir = lambda _e: tmp                        # type: ignore[assignment]
    jsrecon.loot.container_dir = lambda _e: "/loot/eng"           # type: ignore[assignment]
    try:
        jsrecon._write_secret_loot("eng", "j", [secret])
        assert planted in (tmp / "jsrecon-j-secrets.txt").read_text(encoding="utf-8")
    finally:
        jsrecon.loot.host_dir = orig_host
        jsrecon.loot.container_dir = orig_container
    print("  a secret value never reaches the finding (planted control) but IS written to loot: PASS")


# --------------------------------------------------------------------------- #
# 6. defaults refuse; stop is ungated
# --------------------------------------------------------------------------- #
def test_gate_flags_default_false() -> None:
    req = jsrecon.JsReconRequest()
    assert req.approved is False, "approval must never default true"
    assert req.dangerous_ack is False, "the red-confirm must never default true"
    print("  approval + red-confirm both default FALSE — an omitted field is refused: PASS")


def test_stop_is_ungated() -> None:
    calls = _calls_in(jsrecon.stop)
    assert "validate_request" not in calls and "validate" not in calls, "stop must be ungated"
    print("  stop() reaches no gate — it is the ungated panic button: PASS")


if __name__ == "__main__":
    test_pure_functions_execute_nothing()
    test_start_gates_before_spawn()
    test_jsrecon_requires_an_engagement()
    test_target_scope_locked_by_construction()
    test_both_scope_filters_drop_out_of_scope_with_control()
    test_secret_value_never_in_finding_but_is_in_loot()
    test_gate_flags_default_false()
    test_stop_is_ungated()
    print("\njsrecon safety: all invariants hold.")
