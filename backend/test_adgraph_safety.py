"""SAFETY INVARIANTS for the AD attack-path graph (G6).

The AD graph is a VISUALIZATION + a path engine; it must not add any new way to run a command.
Every AD command — the collector AND every abuse step — must go through the SAME gated executor
as the rest of the cockpit. These tests fail loudly if any invariant weakens:

  1. NO EXECUTION IN adgraph: no module in the adgraph package imports subprocess / Popen /
     os.system / docker, calls the executor's run path, or touches the :kali shell. It BUILDS
     requests + parses data only.
  2. ZERO :kali PATH: no adgraph module references run_kali / the :kali open container.
  3. COLLECTOR IS GATED: the collector request is argv-only, unapproved, engagement-scoped —
     an out-of-scope DC is refused at the target gate (proven in test_adgraph_collector.py; a
     smoke re-check here).
  4. ABUSE STEPS ARE GATED: a walked abuse command routed through the executor in engagement
     mode is refused unless approved (never-auto-run) and refused when its host is out of scope.
  5. LAB MODE BYTE-FOR-BYTE UNCHANGED: importing + exercising adgraph does not alter the lab
     target-lock wording or the lab gate order.
  6. THE GRAPH RUNS NOTHING ON ITS OWN: the technique resolver returns a command as DATA; it
     never executes it. (Structural: proven by invariant 1 + a call check.)

Hermetic: no Docker, no LLM, no network. Run:  python test_adgraph_safety.py
"""
from __future__ import annotations

from pathlib import Path

from adgraph import collector as C
from adgraph import orchestrator as ORCH
from adgraph import parser as P
from adgraph import paths as PA
from adgraph import persistence as PER
from adgraph import router as R
from adgraph import sample_data as S
from adgraph import schema as SC
from adgraph import store as ST
from adgraph import techniques as T
from cockpit import executor as E
from cockpit.models import EngagementRecord, ExecRequest

# ORCH (the AD reasoning layer) is scanned here too: it is the one module in the package an
# LLM drives, so it is the one that most needs to be provably unable to run anything. PER (the
# golden/silver forging catalog) is data + string-fill only — it is scanned here as well so a
# new adgraph module cannot quietly gain an execution path.
_ADGRAPH_MODULES = [C, ORCH, P, PA, PER, R, S, SC, ST, T]

# Tokens that would indicate a module can execute something itself.
_EXEC_TOKENS = ["subprocess", "Popen", "os.system", "docker exec", "pty.spawn", "os.exec"]
_KALI_TOKENS = ["run_kali", "KALI_OPEN", "cockpit.kali", "from .kali", "/cockpit/kali"]
# The executor's run entrypoints — adgraph must never call them (it builds requests only).
_RUN_TOKENS = ["iter_run(", "run_command(", ".Popen("]


def test_no_execution_in_adgraph() -> None:
    for mod in _ADGRAPH_MODULES:
        src = Path(mod.__file__).read_text(encoding="utf-8")
        for tok in _EXEC_TOKENS:
            assert tok not in src, f"{mod.__name__} must not execute anything (found {tok!r})"
        for tok in _RUN_TOKENS:
            assert tok not in src, f"{mod.__name__} must not call the executor run path ({tok!r})"
    print("  no adgraph module executes anything / calls the executor run path: PASS")


def test_zero_kali_path() -> None:
    for mod in _ADGRAPH_MODULES:
        src = Path(mod.__file__).read_text(encoding="utf-8")
        for tok in _KALI_TOKENS:
            assert tok not in src, f"{mod.__name__} must have ZERO :kali path (found {tok!r})"
    # and the modules don't even import the kali module object
    for mod in _ADGRAPH_MODULES:
        assert not hasattr(mod, "run_kali") and not hasattr(mod, "kali"), \
            f"{mod.__name__} must not reference :kali"
    print("  adgraph has ZERO :kali path: PASS")


def _eng(scope: str, target: str) -> EngagementRecord:
    include = [p.strip() for p in scope.split(",") if not p.strip().startswith("!")]
    return EngagementRecord(
        engagement_id="eng-adsafe00000", target=target, authorization="ok", active=True,
        entered_at="2026-07-25T00:00:00+00:00", scope=scope, scope_include=include,
        allowed_hosts=[target],
    )


def _patch(rec):
    orig = E.engagement.get_active
    E.engagement.get_active = lambda _id: rec  # type: ignore[assignment]
    return orig


def test_collector_is_gated() -> None:
    eng = _eng("sevenkingdoms.local, dc01.sevenkingdoms.local, 10.10.10.0/24",
               "dc01.sevenkingdoms.local")
    orig = _patch(eng)
    try:
        p = C.CollectorParams(domain="sevenkingdoms.local", username="tywin",
                              dc="dc01.sevenkingdoms.local", password="pw", nameserver="10.10.10.10")
        req = C.build_collector_request(p, eng.engagement_id)
        assert req.approved is False
        # out-of-scope DC -> refused at target gate
        off = C.build_collector_request(
            C.CollectorParams(domain="evil.corp", username="u", dc="dc.evil.corp", password="p"),
            eng.engagement_id)
        off.approved = True
        rej = E.validate_request(off)
        assert rej is not None and rej.gate == "target", rej
        print("  the collector is argv-only, unapproved + engagement scope-locked: PASS")
    finally:
        E.engagement.get_active = orig


def test_abuse_step_is_gated() -> None:
    """A walked abuse command is just an ExecRequest — the same gates apply. Unapproved is
    refused; an out-of-scope host is refused."""
    eng = _eng("sevenkingdoms.local, dc01.sevenkingdoms.local", "dc01.sevenkingdoms.local")
    orig = _patch(eng)
    try:
        # a plausible abuse step (DCSync against the DC) — unapproved => refused at approval
        step = ExecRequest(command="impacket-secretsdump",
                           args=["-just-dc", "sevenkingdoms.local/tywin:pw@dc01.sevenkingdoms.local"],
                           approved=False, engagement_id=eng.engagement_id)
        rej = E.validate_request(step)
        assert rej is not None and rej.gate == "approval", rej
        # an abuse step against an OUT-OF-SCOPE host => refused at target, even if approved
        off = ExecRequest(command="nxc", args=["smb", "fileserver.other.corp", "-u", "a", "-p", "b"],
                          approved=True, engagement_id=eng.engagement_id)
        rej2 = E.validate_request(off)
        assert rej2 is not None and rej2.gate == "target", rej2
        print("  a walked abuse step is gated (never-auto-run + scope-lock) like any command: PASS")
    finally:
        E.engagement.get_active = orig


def test_lab_mode_unchanged() -> None:
    # importing/exercising adgraph must not perturb the lab target-lock or gate order
    ok, _ = E.check_target_lock(["-sV", "hackpit-lab-target"], "nmap")
    assert ok
    ok, reason = E.check_target_lock(["-sV", "dc01.sevenkingdoms.local"], "nmap")
    assert not ok and reason == "target 'dc01.sevenkingdoms.local' is not the lab — only the lab is allowed"
    lab = ExecRequest(command="nmap", args=["-sV", "hackpit-lab-target"], approved=False)
    rej = E.validate_request(lab)
    assert rej is not None and rej.gate == "approval", "lab gate order unchanged (target->approval)"
    print("  LAB target-lock wording + gate order byte-for-byte unchanged: PASS")


def test_technique_returns_data_not_execution() -> None:
    g = P.parse_collection(S.sample_collection())
    edge = next(e for e in g.edges if e.kind == "DCSync")
    # a grounder that would "run" if called incorrectly — prove it's only used for data
    calls = {"n": 0}

    def grounder(seeds):
        calls["n"] += 1
        return None

    tech = T.technique_for_edge(edge, g, grounder)
    assert isinstance(tech, dict) and tech["commands"], "technique must return command DATA"
    assert "cmd" in tech["commands"][0], tech
    assert calls["n"] >= 1, "the grounder is consulted (for data), not an executor"
    print("  the technique resolver returns command DATA, never executes it: PASS")


if __name__ == "__main__":
    test_no_execution_in_adgraph()
    test_zero_kali_path()
    test_collector_is_gated()
    test_abuse_step_is_gated()
    test_lab_mode_unchanged()
    test_technique_returns_data_not_execution()
    print("ALL adgraph safety-invariant tests pass")
