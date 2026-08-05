"""GraphQL containment and disclosure invariants.  Run:  python test_graphql_safety.py

Build #20 adds no gate, no confirm, no blocklist and no allow-list narrowing. These tests guard
the OTHER direction — that nothing it added weakens what was already there, and that the two
places it declines to do something are honest about being disclosure decisions rather than
prohibitions.

  1. NO NEW GATE. The GraphQL scan is the ORDINARY active scanner: `scan_plan_for` computes a
     target and reaches no execution path, and `proxy.validate_scan` still runs the same four.
  2. NO VALUES ANYWHERE. `GraphQLArgument`, `SchemaArgument` and the Endpoint records this build
     writes carry argument NAMES and never argument VALUES — a GraphQL argument is routinely a
     token (report #61's is called `token`).
  3. THE REPEATER STAYS HUMAN-ONLY. The new modules must not reference `repeater.send`.
  4. THE PURE MODULE IS PURE. `cockpit/graphql.py` executes nothing: no subprocess, no socket, no
     docker. Checked by AST, not substring — `sorted(a_dict)` yields keys, so a shape change in a
     substring scan fails silently.
  5. NOTHING REFUSES. The probe WARNS on an out-of-scope host and sends; a nonsense bound WARNS
     and is applied. Both are asserted, because "warn and continue" is a requirement of this
     build and a later "tightening" would be a regression.
"""

from __future__ import annotations

import ast
import inspect
import json
from pathlib import Path

from cockpit import graphql, graphql_zap, proxy

BACKEND = Path(__file__).parent


# --------------------------------------------------------------------------- #
# 1. no new gate
# --------------------------------------------------------------------------- #
def test_the_graphql_scan_is_the_ordinary_scanner_behind_the_same_four_gates() -> None:
    """A GraphQL scan is an `ascan`. It adds nothing to the gate path and removes nothing."""
    # AST, and ONLY AST. The first draft of this test also asserted `"start_scan" not in src`,
    # which failed instantly — because the DOCSTRING tells the operator to hand `target_url` to
    # `proxy.start_scan`. A substring scan cannot tell a call from the prose explaining the call,
    # which is the same reason this repo scans source by AST everywhere else.
    tree = ast.parse(inspect.getsource(graphql_zap))
    seen = False
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "scan_plan_for":
            seen = True
            called = {getattr(n.func, "attr", None) or getattr(n.func, "id", None)
                      for n in ast.walk(node) if isinstance(n, ast.Call)}
            forbidden = {"start_scan", "run", "Popen", "check_output", "_api_post", "_api_get",
                         "system", "urlopen"}
            assert not (called & forbidden), f"scan_plan_for reaches {sorted(called & forbidden)}"
    assert seen, "scan_plan_for was not found — this test stopped checking anything"

    # And the four gates are still what a scan of a GraphQL endpoint goes through, unchanged.
    #
    # *** EACH CONTROL NAMES THE GATE IT WAS REFUSED AT, NEVER A BARE "REFUSED". ***
    # The gates run target -> approval -> danger, so a non-lab target is refused at `target`
    # BEFORE approval is ever consulted — which means "an unapproved scan is refused" would pass
    # vacuously for the wrong reason if it used an off-lab URL. That is the gate-ORDER trap the
    # 2026-08-04 audit recorded; this test walks the lab target through both gates in turn.
    from cockpit import config, executor

    lab = f"http://{config.LAB_TARGET_HOST}:3000/graphql"
    steps = [
        (dict(target_url=lab, approved=False, dangerous_ack=False), "approval"),
        (dict(target_url=lab, approved=True, dangerous_ack=False), "danger"),
        (dict(target_url="http://example.com/graphql", approved=True, dangerous_ack=True),
         "target"),
    ]
    for kwargs, gate in steps:
        verdict = executor.validate_request(proxy._gate_scan_request(
            proxy.ScanStartRequest(container="c", engagement_id=None, **kwargs)))
        assert getattr(verdict, "rejected", False), \
            f"a GraphQL scan was NOT refused at the {gate} gate: {verdict}"
        assert verdict.gate == gate, \
            f"expected refusal at {gate}, got {verdict.gate} ({verdict.reason})"
    print("  scan_plan_for starts nothing; a GraphQL scan is refused at the approval, danger "
          "and target gates in turn: PASS")


def test_no_route_this_build_added_can_execute_anything() -> None:
    """The five new routes are reads, transforms and one ZAP action. None reaches the executor."""
    from cockpit import router as router_mod

    tree = ast.parse(Path(router_mod.__file__).read_text(encoding="utf-8"))
    wanted = {"graphql_split", "graphql_compose", "graphql_detect",
              "graphql_probe", "graphql_bounds", "graphql_scan_plan",
              # build #21
              "graphql_fingerprint", "graphql_enumerate", "graphql_compose_recovered"}
    seen = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef) or node.name not in wanted:
            continue
        seen.add(node.name)
        called = {n.func.attr for n in ast.walk(node)
                  if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
        for bad in ("run_kali", "execute", "start_scan", "send", "run"):
            assert bad not in called, f"{node.name} calls {bad}()"
    assert seen == wanted, f"routes not found in router.py: {sorted(wanted - seen)}"
    print(f"  {len(seen)} new read/transform routes reach no execution path (AST): PASS")


# --------------------------------------------------------------------------- #
# 2. names, never values
# --------------------------------------------------------------------------- #
def test_no_model_this_build_added_can_carry_an_argument_VALUE() -> None:
    """*** BUILD #19'S COOKIE-JAR RULE, APPLIED TO A THIRD SECRET. ***
    Never handing a value over cannot regress; redacting it afterwards depends on a redactor
    being correct forever. `report.py::redact_captured_body` still has no production caller."""
    for model in (graphql.GraphQLArgument, graphql_zap.SchemaArgument):
        fields = set(model.model_fields)
        assert "value" not in fields, f"{model.__name__} grew a value field: {sorted(fields)}"
        assert "default" not in fields, f"{model.__name__} grew a default field"

    found = graphql.detect("POST", "https://x/graphql",
                           [("Content-Type", "application/json")],
                           json.dumps({"query": 'query { userById(token: "SECRET-TOKEN-123") '
                                                '{ id } }',
                                       "variables": {"token": "SECRET-IN-VARIABLES"}}))
    blob = found.model_dump_json()
    assert "SECRET-TOKEN-123" not in blob, "an inline argument value reached the detection model"
    assert "SECRET-IN-VARIABLES" not in blob, "a variable value reached the detection model"
    assert "userById.token" in blob, "the argument NAME should be reported"
    print("  argument values never reach GraphQLArgument/SchemaArgument/detection: PASS")


def test_a_graphql_endpoint_record_carries_names_not_values() -> None:
    from cockpit.proxy import CapturedExchange, CapturedHeader, CapturedRequest, CapturedResponse

    ex = CapturedExchange(
        id="zap-1",
        request=CapturedRequest(
            method="POST", url="https://api.example.com/v2/data",
            headers=[CapturedHeader(name="Content-Type", value="application/json")],
            body=json.dumps({"query": "query { userById(id: 1, token: \"SEKRIT\") { name } }"}),
        ),
        response=CapturedResponse(status=200, headers=[], body="{}", size_bytes=2, time_ms=1),
        sent_at="", container="c",
    )
    [endpoint] = proxy.endpoints_from([ex], session_id="s1")
    assert endpoint.tech == "graphql", f"a GraphQL endpoint was not flagged: {endpoint.tech!r}"
    assert "userById.id" in endpoint.params and "userById.token" in endpoint.params, \
        endpoint.params
    assert "SEKRIT" not in json.dumps(endpoint.__dict__), "an argument value reached the record"

    plain = CapturedExchange(
        id="zap-2",
        request=CapturedRequest(method="POST", url="https://api.example.com/login",
                                headers=[], body='{"user":"bob"}'),
        response=CapturedResponse(status=200, headers=[], body="{}", size_bytes=2, time_ms=1),
        sent_at="", container="c",
    )
    [other] = proxy.endpoints_from([plain], session_id="s1")
    assert other.tech == "", f"a non-GraphQL endpoint was flagged: {other.tech!r}"
    print("  endpoint records: flagged, argument NAMES in params, no values: PASS")


# --------------------------------------------------------------------------- #
# 3. the repeater stays human-only
# --------------------------------------------------------------------------- #
def test_the_new_modules_never_reach_repeater_send() -> None:
    """The structured editor is a pair of transforms over a body. It composes; it does not send.
    `test_repeater.py`'s whole-tree lock is the real guard — this is the local restatement, so a
    regression here names this build rather than pointing at that one."""
    for module in (graphql, graphql_zap):
        tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and (node.module or "").endswith("repeater"):
                raise AssertionError(f"{module.__name__} imports from repeater")
            if isinstance(node, ast.Attribute) and node.attr == "send":
                raise AssertionError(f"{module.__name__} references .send")
    print("  neither GraphQL module imports the repeater or references .send: PASS")


# --------------------------------------------------------------------------- #
# 4. the pure module is pure
# --------------------------------------------------------------------------- #
def test_the_detection_module_executes_nothing() -> None:
    """*** BY AST, NOT SUBSTRING. *** A substring scan for "subprocess" passes the moment somebody
    writes `getattr(__import__("sub" + "process"), "run")`, and — the reason this repo insists —
    `sorted(a_dict)` yields KEYS, so a shape change in a substring-based scan fails SILENTLY."""
    tree = ast.parse(Path(graphql.__file__).read_text(encoding="utf-8"))
    banned_modules = {"subprocess", "socket", "os", "shutil", "requests", "urllib.request",
                      "http.client", "docker"}
    banned_calls = {"run", "Popen", "system", "popen", "call", "check_output", "exec", "eval",
                    "__import__", "urlopen"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name not in banned_modules, f"imports {alias.name}"
        if isinstance(node, ast.ImportFrom):
            assert (node.module or "") not in banned_modules, f"imports from {node.module}"
        if isinstance(node, ast.Call):
            name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
            assert name not in banned_calls, f"calls {name}()"
    print("  cockpit/graphql.py imports nothing that executes and calls nothing that does: PASS")


# --------------------------------------------------------------------------- #
# 5. nothing refuses — warn and continue
# --------------------------------------------------------------------------- #
def test_an_out_of_scope_probe_WARNS_AND_IS_STILL_SENT() -> None:
    """*** THIS BUILD ADDS NO REFUSAL, AND THAT IS A REQUIREMENT, NOT AN OVERSIGHT. ***
    Human approval is the only bound. A scope warning on a probe the operator typed and pressed
    is a handrail; refusing would be a prohibition invented by the tooling. `filter_history` took
    the same position on an ended engagement in build #19."""
    from cockpit import scope as scope_mod

    class _Eng:
        pass

    resolved = scope_mod.parse_scope("target.com, *.target.com", resolve=False)
    orig_active = graphql_zap.__dict__.get("_scope_warning")
    from cockpit import engagement as engagement_mod
    saved = (engagement_mod.get_active, engagement_mod.resolved_scope)
    try:
        engagement_mod.get_active = lambda eid: _Eng() if eid == "e1" else None
        engagement_mod.resolved_scope = lambda eng: resolved

        outside = graphql_zap._scope_warning("https://evil.example.com/graphql", "e1")
        assert "OUTSIDE" in outside, outside
        assert "sent" in outside.lower(), f"the warning does not say it was sent: {outside}"
        inside = graphql_zap._scope_warning("https://api.target.com/graphql", "e1")
        assert "OUTSIDE" not in inside, inside
        gone = graphql_zap._scope_warning("https://anything.com/graphql", "nosuch")
        assert "not active" in gone and "sent" in gone.lower(), gone
    finally:
        engagement_mod.get_active, engagement_mod.resolved_scope = saved
        assert orig_active is graphql_zap.__dict__.get("_scope_warning")

    # The function returns a STRING. It cannot refuse: it raises nothing and returns no verdict.
    tree = ast.parse(Path(graphql_zap.__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "_scope_warning":
            for inner in ast.walk(node):
                assert not isinstance(inner, ast.Raise), "_scope_warning raises — it must warn"
    print("  out-of-scope probe warns and is sent; the warner cannot raise: PASS")


def test_a_nonsense_BOUND_warns_and_is_still_applied() -> None:
    """*** ZAP VALIDATES ITS OWN BOUND NOT AT ALL *** — `maxQueryDepth=-1` answers OK and reads
    back -1 (measured). HackPit says so and sends it: the bound is the operator's."""
    warned = graphql_zap._bound_warning("max_query_depth", -1)
    assert warned and "Sent as asked" in warned, warned
    assert graphql_zap._bound_warning("args_type", "NOPE"), "an unknown enum was not flagged"
    assert not graphql_zap._bound_warning("max_query_depth", 5), "a sane bound warned"

    tree = ast.parse(Path(graphql_zap.__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name in ("_bound_warning", "apply_bounds"):
            for inner in ast.walk(node):
                assert not isinstance(inner, ast.Raise), f"{node.name} raises rather than warns"
    print("  a negative depth and an unknown enum warn, apply_bounds cannot raise: PASS")


def test_the_import_result_admits_it_is_not_scannable() -> None:
    """*** MEASURED FOUR WAYS: THE GENERATED OPERATIONS NEVER ENTER THE SITES TREE. ***
    `scannable` is a field that is always False rather than a silence, because a panel that said
    nothing would let an operator believe a schema import gave the scanner something to attack."""
    result = graphql_zap.SchemaImport(ok=True, endpoint_url="https://x/graphql")
    assert result.scannable is False, "scannable defaulted true"
    field = graphql_zap.SchemaImport.model_fields["scannable"]
    assert "NEVER ADDED TO THE SITES TREE" in (field.description or ""), \
        "the field does not carry the measured reason it is always false"
    print("  SchemaImport.scannable is always False and documents why: PASS")


def test_the_graphql_history_filter_refuses_nothing() -> None:
    """An unset filter matches everything, and the GraphQL filter is a THREE-state field: True,
    False, and None meaning both. A two-state boolean would have made "everything" unsayable."""
    field = proxy.HistoryFilter.model_fields["is_graphql"]
    assert field.default is None, f"the GraphQL filter defaults to {field.default!r}, not None"
    wide = proxy.HistoryFilter()
    assert wide.is_graphql is None, "the widest filter is not the default"
    counts = proxy.FilteredHistory.model_fields
    assert "graphql_seen" in counts and "graphql_argument_names" in counts, sorted(counts)
    print("  the GraphQL filter is three-state and defaults to matching everything: PASS")


def test_enumeration_adds_NO_GATE_and_its_bounds_cannot_become_one() -> None:
    """*** BUILD #21'S OWN REQUIREMENT, GUARDED IN THE DIRECTION IT WOULD BE BROKEN. ***

    Enumeration is thousands of requests, which is precisely the shape somebody later "hardens"
    by adding a confirm or a ceiling. The bounds are a DESCRIPTION the operator sets: when one is
    reached the run stops, names the bound, and returns what it found. It never refuses to start,
    never refuses a size, and `stop` stays ungated.

    This is NOT the scanner-wide request cap that was declined -- that would be a limit the tool
    imposes across every feature. This is one feature stating its own size.
    """
    from cockpit import graphql_enum

    src = Path(inspect.getfile(graphql_enum)).read_text(encoding="utf-8")
    tree = ast.parse(src)
    assert not [n for n in ast.walk(tree) if isinstance(n, ast.Raise)], \
        "graphql_enum raises -- it must warn and continue"

    # The runner must not refuse either: no raise on the enumeration path.
    zap_src = Path(inspect.getfile(graphql_zap)).read_text(encoding="utf-8")
    for fn in ("enumerate_schema", "fingerprint_engine"):
        node = next(n for n in ast.walk(ast.parse(zap_src))
                    if isinstance(n, ast.FunctionDef) and n.name == fn)
        assert not [x for x in ast.walk(node) if isinstance(x, ast.Raise)], f"{fn} raises"
        called = {c.func.attr for c in ast.walk(node)
                  if isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute)}
        for bad in ("run_kali", "start_scan", "send", "validate_scan"):
            assert bad not in called, f"{fn} reaches {bad}()"

    # A bound of zero means UNBOUNDED, not "refuse" -- the default must not be a limit.
    b = graphql_enum.EnumerationBounds()
    assert b.max_requests == 0 and b.max_seconds == 0
    assert "unbounded" in b.describe()

    # A run stopped by a bound still RETURNS its results.
    r = graphql_enum.EnumerationResult(
        stopped_early=True, stop_reason="max_requests=10 reached", requests_sent=10,
        fields=[graphql_enum.Suggestion(name="user")], status="productive")
    assert r.fields, "a bounded run discarded what it found"
    print("  enumeration refuses nothing; bounds describe and never gate: PASS")


def test_an_out_of_scope_FINGERPRINT_warns_and_is_still_sent() -> None:
    """Same position as the probe. Recorded here because a later 'tightening' is the regression.

    The check is on the SOURCE rather than a live call: `fingerprint_engine` sends its probes
    BEFORE it asks about scope, and then attaches the warning. An implementation that consulted
    scope first would be one `if` away from refusing.
    """
    src = inspect.getsource(graphql_zap.fingerprint_engine)
    assert "_scope_warning" in src, "the fingerprint does not warn about scope at all"
    assert "raise" not in src, "the fingerprint refuses on scope"
    probes_at = src.index("FINGERPRINT_PROBES")
    scope_at = src.index("_scope_warning(")
    assert probes_at < scope_at, "scope is consulted BEFORE the probes are sent -- one `if` away "\
                                 "from a refusal this build is not allowed to add"
    print("  an out-of-scope fingerprint WARNS after sending, and cannot refuse: PASS")


def test_enumeration_records_carry_NAMES_and_never_VALUES() -> None:
    """A recovered argument is routinely called `token`. Nothing may carry its value."""
    from cockpit import graphql_enum

    for model in (graphql_enum.Suggestion, graphql_enum.EnumerationResult,
                  graphql_enum.ComposedOperation, graphql_enum.EngineFingerprint):
        fields = set(model.model_fields)
        assert "value" not in fields, f"{model.__name__} grew a value field"
        assert "default" not in fields, f"{model.__name__} grew a default field"

    result = graphql_enum.EnumerationResult(
        url="https://api.example.com/graphql", status="productive",
        fingerprint=graphql_enum.EngineFingerprint(core="graphql-js", dialect="graphql-js",
                                                   suggests=True),
        fields=[graphql_enum.Suggestion(name="userById")],
        arguments=[graphql_enum.Suggestion(name="token", kind="argument",
                                           on_type="Query.userById")])
    rec = graphql_enum.recovered_state_records(result, "sess")
    blob = json.dumps(rec) + graphql_enum.compose_from_recovered(result, "userById").variables
    assert "SUPERSECRET" not in blob and "Bearer " not in blob
    assert rec["endpoint"]["params"] == ["userById.token"]
    # The composed variables are EMPTY placeholders -- there is nowhere a value could enter.
    assert '"token": ""' in graphql_enum.compose_from_recovered(result, "userById").variables
    print("  recovered records carry field.argument names and no values: PASS")


if __name__ == "__main__":
    test_the_graphql_scan_is_the_ordinary_scanner_behind_the_same_four_gates()
    test_no_route_this_build_added_can_execute_anything()
    test_no_model_this_build_added_can_carry_an_argument_VALUE()
    test_a_graphql_endpoint_record_carries_names_not_values()
    test_the_new_modules_never_reach_repeater_send()
    test_the_detection_module_executes_nothing()
    test_an_out_of_scope_probe_WARNS_AND_IS_STILL_SENT()
    test_a_nonsense_BOUND_warns_and_is_still_applied()
    test_the_import_result_admits_it_is_not_scannable()
    test_the_graphql_history_filter_refuses_nothing()
    test_enumeration_adds_NO_GATE_and_its_bounds_cannot_become_one()
    test_an_out_of_scope_FINGERPRINT_warns_and_is_still_sent()
    test_enumeration_records_carry_NAMES_and_never_VALUES()
    print("ALL GraphQL safety tests pass")
