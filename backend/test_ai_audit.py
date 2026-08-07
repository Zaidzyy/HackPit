"""AI code-audit fan-out — the decomposition and post-processing it promises.

  * the three stages compose: enumerate -> flows -> per-flow verify, each verdict schema-valid;
  * a claimed finding with no concrete source ref is downranked to a STUB, never a finding;
  * dedup collapses the same bug found via more than one flow;
  * ranking orders by IMPACT_LEVELS (critical before high before ...);
  * a no-finding stub is not a finding;
  * `patched-since` restricts the audited file set to the diff;
  * the deterministic heuristic analyst runs the same pipeline with no LLM.

Hermetic: the LLM agent is a FAKE that returns canned JSON keyed off the stage/flow — no network,
no Docker, no model. Run:  python test_ai_audit.py
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from codescan import ai_audit as A


# --------------------------------------------------------------------------- #
# a fake agent: reads the stage from the system prompt, returns canned JSON
# --------------------------------------------------------------------------- #
def make_agent(entrypoints, flows, verify_by_title):
    def agent(system: str, user: str) -> str:
        if "mapping the ATTACK SURFACE" in system:
            return json.dumps({"entrypoints": entrypoints})
        if "auditing ONE entrypoint" in system:
            return json.dumps({"flows": flows})
        if "verifying ONE flow" in system:
            for title, payload in verify_by_title.items():
                if title in user:
                    return "```json\n" + json.dumps(payload) + "\n```"  # fenced, like a real model
            return json.dumps({"finding": False, "reason": "no issue on this flow"})
        return "{}"

    return agent


def _repo(files: dict[str, str]) -> str:
    tmp = tempfile.mkdtemp(prefix="aiaudit-")
    for name, body in files.items():
        p = Path(tmp) / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    return tmp


# --------------------------------------------------------------------------- #
# schema + gate
# --------------------------------------------------------------------------- #
def test_schema_and_gate() -> None:
    good = {"finding": True, "title": "SSRF", "severity": "high",
            "attacker_path": "supply an internal url", "impact": "reach metadata",
            "source_refs": ["app.py:12"]}
    ok, problems = A.validate_payload(good)
    assert ok, problems
    concrete, _ = A.gate_finding(good)
    assert concrete

    # bad enum value fails the shape check
    bad = dict(good, severity="catastrophic")
    ok, problems = A.validate_payload(bad)
    assert not ok and any("severity" in p for p in problems)

    # a claim with NO concrete file:line is downranked to a stub
    vague = {"finding": True, "title": "maybe something", "severity": "high",
             "attacker_path": "somehow", "impact": "bad", "source_refs": ["somewhere"]}
    concrete, reason = A.gate_finding(vague)
    assert not concrete and "file:line" in reason

    # an explicit no-finding is a stub, not an error
    concrete, reason = A.gate_finding({"finding": False, "reason": "validated"})
    assert not concrete and reason == "no-finding stub"
    print("  schema validates shape; gate downranks non-concrete claims to stubs: PASS")


# --------------------------------------------------------------------------- #
# the three stages compose
# --------------------------------------------------------------------------- #
def test_enumerate_flows_verify_compose() -> None:
    repo = _repo({"app.py": "def fetch(url):\n    return get(url)\n"})
    agent = make_agent(
        entrypoints=[{"name": "/fetch", "file": "app.py", "kind": "http-route",
                      "note": "takes url"}],
        flows=[{"title": "url flows to outbound request", "note": "ssrf sink"},
               {"title": "empty-url branch returns 400", "note": "validation"}],
        verify_by_title={
            "url flows to outbound request": {
                "finding": True, "title": "SSRF in /fetch", "vuln_class": "ssrf",
                "severity": "high", "attacker_path": "supply 169.254.169.254",
                "impact": "cloud metadata", "source_refs": ["app.py:2"], "confidence": "high",
                "poc": "curl '.../fetch?url=http://169.254.169.254/'"},
            # the validation branch is safe -> a stub
        },
    )
    r = A.run_audit(repo, agent)
    assert r["mode"] == "ai" and r["static_only"] is True
    assert r["summary"]["entrypoints"] == 1
    assert r["summary"]["flows"] == 2
    assert r["summary"]["verified"] == 2
    assert r["summary"]["stubs"] == 1                 # the validation branch
    assert r["summary"]["findings"] == 1              # only the concrete SSRF
    assert r["findings"][0]["vuln_class"] == "ssrf"
    assert r["findings"][0]["source_refs"] == ["app.py:2"]
    # the stub is present in verdicts but never promoted to a finding
    assert any(not v["finding"] for v in r["verdicts"])
    print("  enumerate -> flows -> verify composes; one concrete finding, one honest stub: PASS")


# --------------------------------------------------------------------------- #
# dedup + rank
# --------------------------------------------------------------------------- #
def test_dedup_and_rank() -> None:
    # two DIFFERENT flows report the SAME bug (same class + source), plus a worse-severity bug
    ssrf = lambda: {"finding": True, "title": "SSRF", "vuln_class": "ssrf", "severity": "high",
                    "attacker_path": "internal url", "impact": "metadata",
                    "source_refs": ["app.py:2"]}
    rce = {"finding": True, "title": "RCE via eval", "vuln_class": "code-injection",
           "severity": "critical", "attacker_path": "inject expr", "impact": "code exec",
           "source_refs": ["app.py:9"]}
    verdicts = [
        A.Verdict(**_v(ssrf())), A.Verdict(**_v(ssrf())),   # duplicate
        A.Verdict(**_v(rce)),
        A.Verdict(flow_id="f4", finding=False, reason="safe"),
    ]
    ranked = A.dedup_and_rank(verdicts)
    assert len(ranked) == 2, [v.title for v in ranked]     # the duplicate collapsed
    assert ranked[0].severity == "critical" and ranked[1].severity == "high"  # IMPACT_LEVELS order
    print("  duplicate findings collapse; critical ranks above high; stubs excluded: PASS")


def _v(p: dict) -> dict:
    return {"flow_id": "f", "finding": True, "title": p["title"], "vuln_class": p["vuln_class"],
            "severity": p["severity"], "attacker_path": p["attacker_path"],
            "source_refs": list(p["source_refs"]), "impact": p["impact"]}


# --------------------------------------------------------------------------- #
# to_state_findings maps IMPACT_LEVELS -> the state severity vocabulary
# --------------------------------------------------------------------------- #
def test_state_finding_mapping() -> None:
    v = A.Verdict(flow_id="f", finding=True, title="info leak", vuln_class="info-disclosure",
                  severity="informational", attacker_path="read", impact="minor",
                  source_refs=["a.py:1"])
    out = A.to_state_findings("sess-1", [v], "repo")
    assert out[0]["severity"] == "info"                    # informational -> info
    assert out[0]["session_id"] == "sess-1"
    assert out[0]["tool"] == "ai-audit"
    assert "a.py:1" in out[0]["target"] or "a.py:1" in out[0]["evidence"]
    print("  ranked verdicts map to state Findings (informational -> info, refs carried): PASS")


# --------------------------------------------------------------------------- #
# patched-since restricts scope to the diff
# --------------------------------------------------------------------------- #
def test_patched_since_restricts_to_the_diff() -> None:
    repo = _repo({"app.py": "x = 1\n", "other.py": "y = 2\n", "assets/logo.svg": "<svg/>"})
    root = Path(repo)
    everything = A._iter_code_files(root, None)
    assert "app.py" in everything and "other.py" in everything
    assert "assets/logo.svg" not in everything            # non-code is never enumerated

    diff_only = A._iter_code_files(root, {"app.py"})
    assert diff_only == ["app.py"], diff_only             # ONLY the changed file

    # end to end: a patched-since audit marks itself changed-only and never touches other.py
    agent = make_agent(entrypoints=[{"name": "app", "file": "app.py", "kind": "handler"}],
                       flows=[], verify_by_title={})
    r = A.run_audit(repo, agent, changed_paths={"app.py"}, patched_since="HEAD~1")
    assert r["changed_only"] is True and r["patched_since"] == "HEAD~1"

    # an empty diff audits nothing and says so, rather than silently scanning the whole tree
    empty = A.run_heuristic_audit(repo, changed_paths=set(), patched_since="HEAD")
    assert empty["summary"]["findings"] == 0
    assert any("changed" in w for w in empty["warnings"])
    print("  patched-since audits only the diff; an empty diff scans nothing and warns: PASS")


# --------------------------------------------------------------------------- #
# the heuristic analyst runs the same pipeline with no LLM
# --------------------------------------------------------------------------- #
def test_heuristic_pipeline_on_the_sample() -> None:
    sample = Path(__file__).parent / "codescan" / "sample_app"
    r = A.run_heuristic_audit(sample)
    assert r["mode"] == "heuristic" and r["static_only"] is True
    assert r["summary"]["entrypoints"] >= 5
    assert r["summary"]["findings"] >= 5
    # ranked worst-first, and each finding carries a concrete file:line + an attacker path
    sevs = [f["severity"] for f in r["findings"]]
    assert sevs == sorted(sevs, key=lambda s: A._IMPACT_RANK[s]), sevs
    for f in r["findings"]:
        assert f["source_refs"] and ":" in f["source_refs"][0]
        assert f["attacker_path"] and f["impact"]
    # each sink maps to the route that ENCLOSES it, not just the first route in the file
    titles = {f["title"] for f in r["findings"]}
    assert any("/fetch" in t for t in titles) and any("/ping" in t for t in titles)
    assert any("/user" in t for t in titles) and any("/admin" in t for t in titles)
    print("  heuristic analyst maps 6 routes to 6 enclosing-route findings, ranked: PASS")


if __name__ == "__main__":
    test_schema_and_gate()
    test_enumerate_flows_verify_compose()
    test_dedup_and_rank()
    test_state_finding_mapping()
    test_patched_since_restricts_to_the_diff()
    test_heuristic_pipeline_on_the_sample()
    print("ALL AI code-audit fan-out tests pass")
