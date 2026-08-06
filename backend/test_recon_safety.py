"""recon surface SAFETY invariants.  Run:  python test_recon_safety.py

*** THE LINE THIS FILE HOLDS. ***
The :recon surface adds NO new gate. A sweep is ONE approved job — the nuclei/credattack shape —
gated by the SAME executor gates every command clears, with an UNGATED stop. AND it holds the one
correctness property the spec insists on: RECON CAN NEVER WIDEN BEYOND THE DECLARED SCOPE. So this
file asserts, in both directions where it can:

  * THE PURE HALF BUILDS ARGV / SORTS BY SCOPE / SCORES STATE ONLY — the `*_argv` builders,
    `filter_in_scope`, `rank_surface`, `_exec_request`, `_resolve_domain` reach no subprocess /
    eval / exec, checked per-function against the AST (a docstring is not proof).
  * THE SWEEP GOES THROUGH `executor.validate_request`. `start_passive`/`start_active` reach the
    gate via `_gate` BEFORE they spawn anything; `validate` does too — the gate cannot be skipped.
  * RECON IS ENGAGEMENT-BOUND. No active engagement -> refused (availability, never a bypass).
  * SCOPE DISCIPLINE: `filter_in_scope` drops an out-of-scope record (with a control), and a host
    an out-of-scope subfinder line surfaced does NOT enter the engagement's allowed set — proven
    end to end against a throwaway engagement DB.
  * AN OMITTED APPROVAL IS REFUSED, not granted (both gate flags default False), and STOP IS UNGATED.
"""
from __future__ import annotations

import ast
import inspect
import tempfile
from pathlib import Path

from cockpit import engagement as ENG
from cockpit import recon
from cockpit import runstore
from cockpit import scope as SC
from state.parsers import Parsed
from state.models import Endpoint, Host, Service

# Functions that MUST execute nothing — the pure, inspectable half.
_PURE_FUNCS = (
    recon.subfinder_argv, recon.dnsx_argv, recon.httpx_argv, recon.url_argv,
    recon.naabu_argv, recon.nmap_argv, recon.filter_in_scope, recon.rank_surface,
    recon._exec_request, recon._resolve_domain, recon._active_host_set,
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
    print("  argv builders / filter_in_scope / rank_surface build+sort+score only — no exec: PASS")


# --------------------------------------------------------------------------- #
# 2. the sweep reaches the gate before spawning
# --------------------------------------------------------------------------- #
def test_start_paths_gate_before_spawn() -> None:
    for start in (recon.start_passive, recon.start_active):
        src = inspect.getsource(start)
        assert "_gate" in _calls_in(start), f"{start.__name__} must call the gate"
        # the gate must precede the thread that spawns the worker
        assert src.index("_gate(") < src.index("threading.Thread"), \
            f"{start.__name__} must gate before it spawns the worker"
    assert "_gate" in _calls_in(recon.validate)
    assert "validate_request" in _calls_in(recon._gate), "_gate must call validate_request"
    print("  start_passive/start_active + validate reach validate_request via _gate before any spawn: PASS")


# --------------------------------------------------------------------------- #
# 3. engagement-bound: no engagement -> refused, nothing runs
# --------------------------------------------------------------------------- #
def test_recon_requires_an_engagement() -> None:
    orig = ENG.get_active
    ENG.get_active = lambda _id: None  # type: ignore[assignment]
    try:
        for start in (recon.start_passive, recon.start_active):
            try:
                start(recon.ReconRequest(domain="example.com", engagement_id="nope", approved=True))
                assert False, f"{start.__name__} must refuse with no active engagement"
            except recon.ReconRefused as exc:
                assert exc.gate == "engagement", exc.gate
    finally:
        ENG.get_active = orig
    print("  a sweep with no active engagement is refused at the engagement precondition: PASS")


# --------------------------------------------------------------------------- #
# 4. SCOPE — filter drops out-of-scope (with a control)
# --------------------------------------------------------------------------- #
def test_filter_in_scope_drops_out_of_scope_with_control() -> None:
    matcher = SC.parse_scope("example.com, *.example.com", resolve=False)
    p = Parsed()
    p.hosts = [Host(session_id="s", address="api.example.com"), Host(session_id="s", address="evil.com")]
    p.services = [Service(session_id="s", address="evil.com", port=80)]
    p.endpoints = [Endpoint(session_id="s", url="https://evil.com/x")]
    kept, out_hosts = recon.filter_in_scope(p, matcher)
    assert [h.address for h in kept.hosts] == ["api.example.com"], "in-scope host survives (control)"
    assert not kept.services and not kept.endpoints, "out-of-scope records are dropped"
    assert "evil.com" in out_hosts, "the out-of-scope host is surfaced read-only"
    print("  filter_in_scope: out-of-scope records dropped, in-scope host kept (control): PASS")


# --------------------------------------------------------------------------- #
# 4b. SCOPE — an out-of-scope discovery never enters the allowed set (end to end)
# --------------------------------------------------------------------------- #
def test_recon_never_widens_beyond_scope() -> None:
    """The whole point: a host recon surfaces that is OUTSIDE the declared scope must never join
    the engagement's live allowed set — the set the probing tools are pointed at. Proven against a
    real (throwaway) engagement DB via the same expansion the passive worker calls."""
    tmp = Path(tempfile.mkdtemp()) / "eng.db"
    orig_rs, orig_eng = runstore.DB_PATH, ENG.DB_PATH
    runstore.DB_PATH = ENG.DB_PATH = tmp
    try:
        ENG.init_db()
        rec = ENG.enter("example.com", "authorized", scope_spec="example.com, *.example.com")
        # subfinder-shaped output carrying one in-scope and two out-of-scope names.
        out = "api.example.com\nevil.com\nexample.com.attacker.net\n"
        disc = ENG.record_discoveries(rec, out, run_id="r-1")
        assert "api.example.com" in disc["added"], disc
        assert set(disc["out_of_scope"]) == {"evil.com", "example.com.attacker.net"}, disc

        live = ENG.get_active(rec.engagement_id)
        assert live is not None
        assert "api.example.com" in live.allowed_hosts, "the in-scope discovery joined the set"
        for host in ("evil.com", "example.com.attacker.net"):
            assert host not in live.allowed_hosts, f"{host} must NEVER enter the allowed set"

        # …and recon's own downstream host-set builder agrees: it only ever hands the scanner
        # in-scope hosts, never the out-of-scope discoveries.
        matcher = ENG.resolved_scope(live)
        active_hosts = recon._active_host_set(live, rec.engagement_id, matcher)
        for host in ("evil.com", "example.com.attacker.net"):
            assert host not in active_hosts, f"{host} must never reach the scanner's host file"
        assert "example.com" in active_hosts, "the declared target is scannable (control)"
        print("  an out-of-scope discovery never enters the allowed set OR the scanner's host file: PASS")
    finally:
        runstore.DB_PATH, ENG.DB_PATH = orig_rs, orig_eng


# --------------------------------------------------------------------------- #
# 5. defaults refuse; stop is ungated
# --------------------------------------------------------------------------- #
def test_gate_flags_default_false() -> None:
    req = recon.ReconRequest()
    assert req.approved is False, "approval must never default true"
    assert req.dangerous_ack is False, "the red-confirm must never default true"
    print("  approval + red-confirm both default FALSE — an omitted field is refused: PASS")


def test_stop_is_ungated() -> None:
    calls = _calls_in(recon.stop)
    assert "validate_request" not in calls and "validate" not in calls, "stop must be ungated"
    print("  stop() reaches no gate — it is the ungated panic button: PASS")


if __name__ == "__main__":
    test_pure_functions_execute_nothing()
    test_start_paths_gate_before_spawn()
    test_recon_requires_an_engagement()
    test_filter_in_scope_drops_out_of_scope_with_control()
    test_recon_never_widens_beyond_scope()
    test_gate_flags_default_false()
    test_stop_is_ungated()
    print("\nrecon safety: all invariants hold.")
