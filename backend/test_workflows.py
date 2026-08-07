"""Functional tests for the reusable prompt-workflow builder (codescan/workflows.py).

Covers the semantics ported from open·kritt (spec §3):
  - variable resolution: {{repo}}, dotted {{steps.<id>.output...}}, per-run extra vars
  - a batch step fans out ONE task per item; siblings multiply branches
  - depth re-expands a step's list output into the right child-step shape
  - import -> export round-trips a workflow, and an import is flagged inspect-before-run
  - a step's output validates against its schema (default finding-or-stub AND a custom schema)
  - the runner threads a step's output into a downstream step, and command steps are proposal-only

Run:  python test_workflows.py
"""

from __future__ import annotations

import json

from codescan import workflows as W


class _FakeAgent:
    """A deterministic, network-free agent. It keys its reply off a ``STEP:<id>`` marker the test
    puts in each prompt, and records every (system, user) call so the test can assert threading."""

    def __init__(self, replies: dict[str, object]) -> None:
        self.replies = replies
        self.calls: list[tuple[str, str]] = []

    def __call__(self, system: str, user: str) -> str:
        self.calls.append((system, user))
        for marker, reply in self.replies.items():
            if f"STEP:{marker}" in user:
                return reply if isinstance(reply, str) else json.dumps(reply)
        return json.dumps({"finding": False, "reason": "no marker matched"})


# --------------------------------------------------------------------------- #
# 1. variable resolution — {{repo}}, dotted refs, extra vars
# --------------------------------------------------------------------------- #
def test_variable_resolution() -> None:
    ctx = {
        "repo": "acme/app",
        "steps": {"enum": {"output": [{"routes": [{"id": "r0"}, {"id": "r1"}]}]}},
        "extra": {"customer": "ACME"},
        "customer": "ACME",
    }
    # a built-in
    assert W.render_prompt("audit {{repo}}", ctx) == "audit acme/app"
    # an extra variable, flat and via the extra.* namespace
    assert W.render_prompt("for {{customer}} / {{extra.customer}}", ctx) == "for ACME / ACME"
    # a dotted ref into a prior step's output (list index + key)
    assert W.resolve_ref(ctx, "steps.enum.output.0.routes.1.id") == "r1"
    assert W.render_prompt("route {{steps.enum.output.0.routes.1.id}}", ctx) == "route r1"
    # an unresolved ref renders empty, never a literal {{x}}
    assert W.render_prompt("x={{nope.nope}}!", ctx) == "x=!"
    # referenced_vars feeds the editor linter
    assert W.referenced_vars("{{repo}} and {{flow}} and {{repo}}") == ["repo", "flow"]
    print("  {{repo}}, dotted step-output refs and extra vars resolve; misses render empty: PASS")


# --------------------------------------------------------------------------- #
# 2. a batch step fans out one task per item; siblings multiply
# --------------------------------------------------------------------------- #
def test_batch_fans_out_one_task_per_item() -> None:
    agent = _FakeAgent({
        "enum": {"items": [{"id": "a"}, {"id": "b"}, {"id": "c"}]},
        "work": {"finding": False, "reason": "checked"},
    })
    wf = W.Workflow(id="w", name="W", steps=[
        W.Step(id="enum", title="enum", prompt="STEP:enum map {{repo}}",
               output_format=[W.OutputField("items", "list", True)]),
        W.Step(id="work", title="work", kind="batch",
               batch_over="steps.enum.output.0.items", item_var="it", siblings=2,
               prompt="STEP:work look at {{it}}"),
    ])
    res = W.run_workflow(wf, repo="acme/app", agent=agent)
    by_id = {s["step_id"]: s for s in res["steps"]}
    assert by_id["enum"]["tasks"] == 1
    # 3 items x 2 siblings = 6 tasks
    assert by_id["work"]["tasks"] == 6, by_id["work"]["tasks"]
    assert res["tasks_run"] == 7
    print("  a batch step runs one task per item (3) x siblings (2) = 6, enumerate stays 1: PASS")


def test_batch_over_empty_list_no_ops() -> None:
    agent = _FakeAgent({"enum": {"items": []}, "work": {"finding": False}})
    wf = W.Workflow(id="w", name="W", steps=[
        W.Step(id="enum", title="e", prompt="STEP:enum",
               output_format=[W.OutputField("items", "list", True)]),
        W.Step(id="work", title="w", kind="batch",
               batch_over="steps.enum.output.0.items", prompt="STEP:work {{item}}"),
    ])
    res = W.run_workflow(wf, repo="r", agent=agent)
    assert {s["step_id"]: s["tasks"] for s in res["steps"]}["work"] == 0
    print("  a batch step over an empty list fans out to zero tasks (no-op), never a crash: PASS")


# --------------------------------------------------------------------------- #
# 3. depth re-expands a list output into the right child-step shape
# --------------------------------------------------------------------------- #
def test_depth_and_siblings_child_shape() -> None:
    # 'grow' batches over a 2-item extra list, depth=2, and each task yields a 2-child list, so:
    #   gen0 (the step itself): 2 items x 1 branch = 2 tasks
    #   gen1: flatten 2*2 children = 4 items      = 4 tasks
    #   gen2: flatten 4*2 children = 8 items       = 8 tasks
    agent = _FakeAgent({"grow": {"children": [{"n": 1}, {"n": 2}]}})
    wf = W.Workflow(id="w", name="W", steps=[
        W.Step(id="grow", title="grow", kind="batch", batch_over="seeds", item_var="s",
               depth=2, prompt="STEP:grow expand {{s}}"),
    ])
    res = W.run_workflow(wf, repo="r", agent=agent, extra_vars={"seeds": ["x", "y"]})
    tasks = {s["step_id"]: s["tasks"] for s in res["steps"]}
    assert tasks["grow"] == 2, tasks
    assert tasks["grow~gen1"] == 4, tasks
    assert tasks["grow~gen2"] == 8, tasks
    assert res["tasks_run"] == 14
    # and there are exactly two child generations (depth=2)
    gens = [s for s in res["steps"] if s["step_id"].startswith("grow~gen")]
    assert len(gens) == 2
    print("  depth=2 over a 2->2 expansion produces the 2/4/8 child-step shape (14 tasks): PASS")


def test_siblings_are_clamped() -> None:
    agent = _FakeAgent({"s": {"finding": False}})
    wf = W.Workflow(id="w", name="W", steps=[
        W.Step(id="s", title="s", prompt="STEP:s", siblings=999),
    ])
    # from_dict clamps to MAX_SIBLINGS; a single analyze step then runs that many branches
    parsed = W.Workflow.from_dict(wf.to_dict())
    assert parsed.steps[0].siblings == W.MAX_SIBLINGS
    res = W.run_workflow(parsed, repo="r", agent=agent)
    assert res["steps"][0]["tasks"] == W.MAX_SIBLINGS
    print(f"  siblings clamp to MAX_SIBLINGS ({W.MAX_SIBLINGS}); the fan-out is bounded: PASS")


# --------------------------------------------------------------------------- #
# 4. import -> export round-trips; an import is inspect-before-run
# --------------------------------------------------------------------------- #
def test_import_export_round_trip() -> None:
    wf = W._external_flow_builtin()
    portable = W.to_portable(wf)
    assert portable["kritt_workflow_schema"] == W.SCHEMA_VERSION
    back = W.from_portable(portable)
    # the definition (identity + every step) survives a round trip byte-for-byte
    rt = W.to_portable(back)["workflow"]
    for key in ("id", "name", "description", "playbook", "steps"):
        assert rt[key] == portable["workflow"][key], key
    # only the provenance flag flips: an imported workflow is inspect-before-run, not a built-in
    assert back.imported is True and back.builtin is False
    assert portable["workflow"]["imported"] is False and rt["imported"] is True
    # a wrong/absent schema version is refused loudly
    for bad in ({}, {"kritt_workflow_schema": 999, "workflow": {}}):
        try:
            W.from_portable(bad)
        except W.WorkflowError:
            continue
        raise AssertionError(f"from_portable accepted a bad export: {bad}")
    print("  a workflow round-trips export->import byte-for-byte, flagged inspect-before-run: PASS")


# --------------------------------------------------------------------------- #
# 5. a step's output validates against its schema
# --------------------------------------------------------------------------- #
def test_step_output_validates_against_schema() -> None:
    # default (no declared schema) -> the finding-or-stub shape the audit uses
    default_step = W.Step(id="v", title="v", prompt="p")
    ok, _ = W.validate_step_output({"finding": True, "title": "t", "severity": "high",
                                    "attacker_path": "a", "source_refs": ["f.py:1"],
                                    "impact": "i"}, default_step)
    assert ok
    ok, problems = W.validate_step_output({"title": "t"}, default_step)  # no `finding` key
    assert not ok and problems
    # a declared schema is checked field-by-field: required present, types right
    custom = W.Step(id="c", title="c", prompt="p", output_format=[
        W.OutputField("name", "string", required=True),
        W.OutputField("count", "number"),
        W.OutputField("sev", "severity"),
    ])
    ok, _ = W.validate_step_output({"name": "x", "count": 3, "sev": "low"}, custom)
    assert ok
    ok, problems = W.validate_step_output({"count": "not-a-number"}, custom)
    assert not ok and any("name" in p for p in problems) and any("count" in p for p in problems)
    ok, problems = W.validate_step_output({"name": "x", "sev": "not-a-severity"}, custom)
    assert not ok and any("sev" in p for p in problems)
    print("  step output validates against BOTH the default finding schema and a custom schema: PASS")


# --------------------------------------------------------------------------- #
# 6. the runner threads outputs downstream, dedups+ranks, and command steps propose only
# --------------------------------------------------------------------------- #
def test_runner_threads_outputs_and_dedups() -> None:
    agent = _FakeAgent({
        "enum": {"items": [{"id": "login"}]},
        # two different flows report the SAME bug at the same file:line -> dedup to one
        "verify": {"finding": True, "title": "SQLi", "vuln_class": "sqli", "severity": "high",
                   "attacker_path": "POST /login u", "source_refs": ["auth.py:42"],
                   "impact": "db read"},
    })
    wf = W.Workflow(id="w", name="W", steps=[
        W.Step(id="enum", title="e", prompt="STEP:enum {{repo}}",
               output_format=[W.OutputField("items", "list", True)]),
        W.Step(id="verify", title="v", kind="batch",
               batch_over="steps.enum.output.0.items", item_var="ep", siblings=3,
               prompt="STEP:verify flow for {{ep}}"),
    ])
    res = W.run_workflow(wf, repo="acme/app", agent=agent)
    # the downstream step SAW the upstream item value threaded into its prompt
    verify_prompts = [u for (_s, u) in agent.calls if "STEP:verify" in u]
    # a dict item renders as JSON into the downstream prompt
    assert verify_prompts and all('"id": "login"' in p for p in verify_prompts)
    # 3 sibling verdicts of the SAME bug collapse to ONE ranked finding
    assert len(res["findings"]) == 1, res["findings"]
    assert res["findings"][0]["title"] == "SQLi" and res["findings"][0]["severity"] == "high"
    print("  a step's output threads into the downstream prompt; same-bug siblings dedup to one: PASS")


def test_command_step_is_proposal_only() -> None:
    agent = _FakeAgent({})  # a command step must NOT call the agent
    wf = W.Workflow(id="w", name="W", steps=[
        W.Step(id="cmd", title="tool pass", kind="command",
               prompt="slither {{repo}} --json -"),
    ])
    res = W.run_workflow(wf, repo="acme/contracts", agent=agent)
    assert agent.calls == [], "a command step must not call the agent"
    assert res["proposals"] == [{"step": "cmd", "command": "slither acme/contracts --json -",
                                 "approve_each": True, "executed": False}]
    assert res["findings"] == []
    print("  a command step PROPOSES a rendered string (approve-each, executed:false), never runs: PASS")


# --------------------------------------------------------------------------- #
# 7. the plan preview computes the static fan-out shape without running
# --------------------------------------------------------------------------- #
def test_plan_preview_static_shape() -> None:
    wf = W.Workflow(id="w", name="W", steps=[
        W.Step(id="a", title="a", prompt="p {{repo}}", siblings=2),
        W.Step(id="b", title="b", kind="batch", batch_over="seeds", siblings=1, prompt="p {{item}}"),
        W.Step(id="c", title="c", kind="batch", batch_over="steps.b.output", siblings=1,
               prompt="p {{item}}"),
    ])
    p = W.plan(wf, extra_vars={"seeds": [1, 2, 3, 4]})
    rows = {r["step_id"]: r for r in p["steps"]}
    assert rows["a"]["tasks"] == 2                 # analyze x 2 siblings
    assert rows["b"]["items"] == 4 and rows["b"]["tasks"] == 4  # batch over a 4-item extra list
    assert rows["c"]["items"] == "dynamic"         # batch over a prior step -> unknown until run
    print("  plan() computes the static fan-out shape (a=2, b=4, c=dynamic) without running: PASS")


def test_build_rejects_forward_batch_ref() -> None:
    # a batch step may not reference a step that runs AFTER it
    try:
        W.Workflow.from_dict({"id": "w", "name": "W", "steps": [
            {"id": "first", "title": "f", "prompt": "p", "kind": "batch",
             "batch_over": "steps.later.output"},
            {"id": "later", "title": "l", "prompt": "p"},
        ]})
    except W.WorkflowError:
        print("  a batch step referencing a LATER step is refused at build time: PASS")
        return
    raise AssertionError("a forward batch reference was accepted")


if __name__ == "__main__":
    test_variable_resolution()
    test_batch_fans_out_one_task_per_item()
    test_batch_over_empty_list_no_ops()
    test_depth_and_siblings_child_shape()
    test_siblings_are_clamped()
    test_import_export_round_trip()
    test_step_output_validates_against_schema()
    test_runner_threads_outputs_and_dedups()
    test_command_step_is_proposal_only()
    test_plan_preview_static_shape()
    test_build_rejects_forward_batch_ref()
    print("ALL workflow-builder tests pass")
