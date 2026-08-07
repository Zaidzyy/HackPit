"""Finding pipeline — dynamic schema, de-duplication, pluggable rankers, post-scripts.

The behavioural contract (spec §3):

  * the dynamic schema VALIDATES a well-formed finding and REJECTS a malformed one;
  * de-dup is IDEMPOTENT — the same finding twice collapses to one ("merged 1"), and re-running
    the pipeline over its own output is a fixed point;
  * a RANKER re-scored a fixture finding set into the right order;
  * a DATA post-script (validate / report) runs IN-PROCESS;
  * a COMMAND post-script (PoC) is APPROVE-EACH — it returns a proposal and never fires.

Run:  python test_finding_pipeline.py
"""

from __future__ import annotations

from findings import pipeline, postscripts, rankers, schema


# --------------------------------------------------------------------------- #
# 1. dynamic / structured schema
# --------------------------------------------------------------------------- #
def test_schema_validates_and_rejects() -> None:
    ok, problems = schema.validate_payload(
        {"title": "SSRF in the image proxy", "severity": "high",
         "source_refs": ["proxy/fetch.py:34"]})
    assert ok and not problems, problems

    # malformed: missing required title + an out-of-enum severity + wrong-typed refs
    bad, probs = schema.validate_payload(
        {"severity": "spicy", "source_refs": "not-a-list"})
    assert not bad
    joined = " ".join(probs)
    assert "title" in joined and "one of" in joined and "array" in joined, probs
    print("  schema validates a well-formed finding and rejects a malformed one: PASS")


def test_schema_is_dynamic_with_custom_fields() -> None:
    """An engagement can DEFINE custom fields (the dynamic part); unknown keys land in extra."""
    fields = schema.normalize_output_format(["bounty_tier:string", "confirmed:bool!"])
    names = {f["name"] for f in fields}
    assert "bounty_tier" in names and "confirmed" in names
    assert any(f["name"] == "confirmed" and f["required"] for f in fields)
    # base fields are still present and first
    assert fields[0]["name"] == "title"

    coerced = schema.coerce_finding(
        {"title": "x", "severity": "informational", "bounty_tier": "P1",
         "note_only_here": "kept"}, fields)
    assert coerced["severity"] == "info", "informational must normalize to info"
    assert coerced["extra"]["note_only_here"] == "kept", "unknown key must survive in extra"
    assert coerced["bounty_tier"] == "P1"
    print("  schema is dynamic: custom fields declared, unknown keys preserved in extra: PASS")


# --------------------------------------------------------------------------- #
# 2. de-duplication (idempotent, "merged N")
# --------------------------------------------------------------------------- #
def test_dedup_is_idempotent() -> None:
    one = {"title": "SQL injection in ?id=1", "severity": "high", "vuln_class": "sqli",
           "source_refs": ["app/db.py:42"]}
    # the SAME finding twice -> ONE, merged 1
    res = pipeline.run_pipeline([one, dict(one)], "default")
    assert len(res["findings"]) == 1, res["findings"]
    assert res["merged"] == 1 and res["merged_note"] == "merged 1 duplicate", res
    assert res["findings"][0]["merged_count"] == 1

    # re-running the pipeline over its OWN output is a fixed point (no re-inflation)
    again = pipeline.run_pipeline(res["findings"], "default")
    assert len(again["findings"]) == 1
    assert again["merged"] == 0, "a de-duplicated set must not merge again"
    assert again["findings"][0]["merged_count"] == 1, "the merged badge must persist, not grow"
    print("  same finding twice -> one (merged 1); re-run is a fixed point: PASS")


def test_dedup_collapses_different_wordings_same_place() -> None:
    """Two producers, same defect at the same location, worded differently -> one finding,
    worst severity wins, source refs unioned."""
    a = {"title": "SQL injection in /orders?id=1", "severity": "high", "vuln_class": "sqli",
         "source_refs": ["api/orders.py:88"]}
    b = {"title": "SQLi via the sort parameter", "severity": "critical", "vuln_class": "sqli",
         "source_refs": ["api/orders.py:88", "api/orders.py:90"]}
    res = pipeline.run_pipeline([a, b], "default")
    assert len(res["findings"]) == 1, res["findings"]
    f = res["findings"][0]
    assert f["severity"] == "critical", "the worse severity must win the merge"
    assert set(f["source_refs"]) == {"api/orders.py:88", "api/orders.py:90"}
    # two DIFFERENT hosts with no location must NOT over-merge
    h1 = {"title": "Missing HSTS", "severity": "low", "vuln_class": "missing-header",
          "target": "https://a.example/"}
    h2 = {"title": "Missing HSTS", "severity": "low", "vuln_class": "missing-header",
          "target": "https://b.example/"}
    res2 = pipeline.run_pipeline([h1, h2], "default")
    assert len(res2["findings"]) == 2, "distinct hosts must stay distinct"
    print("  different wordings at the same place collapse; distinct hosts do not: PASS")


# --------------------------------------------------------------------------- #
# 3. pluggable rankers re-score a fixture set
# --------------------------------------------------------------------------- #
def test_rankers_rescore_into_the_right_order() -> None:
    fixture = [
        {"title": "SQL injection", "severity": "critical", "vuln_class": "sqli",
         "source_refs": ["a:1"]},
        {"title": "SSRF to metadata", "severity": "medium", "vuln_class": "ssrf",
         "source_refs": ["b:2"]},
        {"title": "Missing security header", "severity": "high", "vuln_class": "missing-header",
         "target": "https://x/"},
    ]
    # the producer set a missing-header=high (wrong for a payout view) and SSRF=medium (low).
    payout = pipeline.run_pipeline(fixture, "bug-bounty-payout")
    sev = {f["vuln_class"]: f["severity"] for f in payout["findings"]}
    assert sev["sqli"] == "critical", sev
    assert sev["ssrf"] == "high", sev
    assert sev["missing-header"] == "info", "best-practice noise must drop to info"
    # worst-first ordering after re-score
    order = [f["vuln_class"] for f in payout["findings"]]
    assert order[0] == "sqli" and order[-1] == "missing-header", order

    # the compliance ranker is a DIFFERENT lens: it caps exploitation criticals and lifts
    # control gaps. Same findings, different order.
    comp = pipeline.run_pipeline(fixture, "compliance")
    csev = {f["vuln_class"]: f["severity"] for f in comp["findings"]}
    assert csev["missing-header"] == "medium", "a control gap rises under compliance"
    assert csev["sqli"] == "high", "compliance caps a raw exploitation critical at high"
    assert payout["ranker"] == "bug-bounty-payout" and comp["ranker"] == "compliance"
    print("  bug-bounty and compliance rankers re-score the SAME set differently + in order: PASS")


def test_rankers_registry_has_defaults() -> None:
    ids = {r["id"] for r in rankers.list_rankers()}
    assert {"default", "bug-bounty-payout", "compliance"} <= ids, ids
    assert rankers.get_ranker("nonexistent").id == "default", "unknown ranker -> default"
    assert rankers.list_rankers()[0]["id"] == "default", "default must be listed first"
    print("  ranker registry ships the defaults; unknown id resolves to default: PASS")


# --------------------------------------------------------------------------- #
# 4. post-scripts — data in-process, command approve-each
# --------------------------------------------------------------------------- #
def test_data_postscript_runs_in_process() -> None:
    finding = {"title": "SSRF", "severity": "high", "vuln_class": "ssrf",
               "attacker_path": "url=http://169.254.169.254/ reaches IMDS",
               "source_refs": ["proxy.py:34"], "evidence": "200 OK, creds returned"}
    validate = postscripts.run(postscripts.get_postscript("validate-concrete"), finding)
    assert validate["mode"] == "data" and validate["ok"] is True, validate

    # a finding with no attacker path is flagged (composes with the validation gates), not run
    thin = {"title": "maybe something", "severity": "info"}
    flagged = postscripts.run(postscripts.get_postscript("validate-concrete"), thin)
    assert flagged["ok"] is False and flagged["problems"], flagged

    report = postscripts.run(postscripts.get_postscript("render-report"), finding)
    assert report["mode"] == "data" and report["markdown"].startswith("## SSRF"), report
    assert "169.254.169.254" in report["markdown"]
    print("  validate + report post-scripts run in-process and return data: PASS")


def test_command_postscript_is_approve_each_and_never_fires() -> None:
    finding = {"title": "SQLi", "severity": "critical", "target": "https://x/api?id=1",
               "reference": "CWE-89", "source_refs": ["api/db.py:42"]}
    out = postscripts.run(postscripts.get_postscript("poc-curl"), finding)
    assert out["mode"] == "command"
    assert out["needs_approval"] is True, "a command post-script must require approval"
    assert out["executed"] is False, "a command post-script must NEVER execute here"
    assert "https://x/api?id=1" in out["command"], out
    # the template placeholders are filled, none left dangling for a well-specified finding
    nuclei = postscripts.run(postscripts.get_postscript("poc-nuclei-retest"), finding)
    assert nuclei["executed"] is False and "CWE-89" in nuclei["command"], nuclei
    print("  the PoC post-script is approve-each: proposal only, executed:false: PASS")


def test_postscript_lock_refuses_a_concurrent_double_run() -> None:
    locks = postscripts.PostScriptLocks()
    with locks.guard("s1", "fp1", "poc-curl"):
        assert locks.is_held("s1", "fp1", "poc-curl")
        try:
            with locks.guard("s1", "fp1", "poc-curl"):
                raise AssertionError("a second concurrent run must be refused")
        except postscripts.PostScriptLocked:
            pass
    # released after the block — a fresh run is allowed again
    assert not locks.is_held("s1", "fp1", "poc-curl")
    with locks.guard("s1", "fp1", "poc-curl"):
        pass
    print("  a concurrent double-run of the same post-script on a finding is refused: PASS")


if __name__ == "__main__":
    test_schema_validates_and_rejects()
    test_schema_is_dynamic_with_custom_fields()
    test_dedup_is_idempotent()
    test_dedup_collapses_different_wordings_same_place()
    test_rankers_rescore_into_the_right_order()
    test_rankers_registry_has_defaults()
    test_data_postscript_runs_in_process()
    test_command_postscript_is_approve_each_and_never_fires()
    test_postscript_lock_refuses_a_concurrent_double_run()
    print("ALL finding-pipeline tests pass")
