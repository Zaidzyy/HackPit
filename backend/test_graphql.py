"""GraphQL detection, parsing and the repeater round trip.  Run:  python test_graphql.py

Everything here is hermetic: `cockpit/graphql.py` is pure and `graphql_zap.parse_introspection`
is the pure half of the probe, so the five non-`ok` answers — the part actually worth testing —
need no daemon and no network.

The two live-measured facts these tests encode, both from `docs/proof/build20_graphql_api.py`
(55 passed, 0 failed against ZAP 2.17.0 + graphql-alpha-0.33.0):

  * an argument is named `field.argument` — ZAP raised a High SQL Injection on `search.limit`
    while the JSON variable key was `search_limit`. A dot where the JSON has an underscore, so
    the name comes from ZAP's own GraphQL variant, not a JSON path. HackPit matches that spelling
    so what the operator is shown BEFORE a scan is what they read in the findings AFTER it.
  * a schema import does NOT make anything scannable — hence `SchemaImport.scannable` is a field
    that is always False rather than a silence.
"""

from __future__ import annotations

import json

from cockpit import graphql, graphql_zap

JSON_CT = [("Content-Type", "application/json")]


def _detect(body: str, url: str = "https://api.example.com/v2/data",
            method: str = "POST", headers=JSON_CT):
    return graphql.detect(method, url, headers, body)


def test_it_is_recognised_by_body_shape_not_by_path() -> None:
    """*** THE HEADLINE PROPERTY. *** /graphql is a convention, not a rule."""
    off_path = _detect('{"query":"{ me { id } }"}', "https://api.example.com/v2/data")
    assert off_path.is_graphql, "GraphQL on a non-graphql path was missed"
    assert off_path.where == "json_body", off_path.where
    assert not off_path.path_hint, "the path hint fired on a path that is not conventional"

    on_path = _detect('{"user":"bob","password":"hunter2"}', "https://api.example.com/graphql")
    assert not on_path.is_graphql, "plain JSON on /graphql was called GraphQL"
    assert on_path.path_hint, "the hint should still REPORT that the path looks conventional"
    print("  off-path GraphQL found, on-path JSON not mistaken for it, hint reported: PASS")


def test_every_envelope_shape_is_found() -> None:
    cases = {
        "json_body": ('{"query":"{ me { id } }"}', "POST", JSON_CT,
                      "https://x.example.com/api"),
        "json_batch": ('[{"query":"{a}"},{"query":"{b}"}]', "POST", JSON_CT,
                       "https://x.example.com/api"),
        "raw_document": ("mutation M { setEmail(id: 1, email: \"a\") { id } }", "POST",
                         [("Content-Type", "application/graphql")], "https://x.example.com/api"),
        "query_param": ("", "GET", [],
                        "https://x.example.com/api?query=%7B__schema%7Btypes%7Bname%7D%7D%7D"),
    }
    for expected, (body, method, headers, url) in cases.items():
        found = graphql.detect(method, url, headers, body)
        assert found.is_graphql, f"{expected} envelope was not detected"
        assert found.where == expected, f"{expected}: got where={found.where!r}"
    print(f"  all {len(cases)} envelope shapes detected by name: PASS")


def test_batching_and_introspection_are_reported_separately() -> None:
    """Both are facts an operator acts on: batching walks around per-operation limits, and an
    introspection query in the capture says the endpoint answered one for somebody."""
    batch = _detect('[{"query":"{a}"},{"query":"{b}"},{"query":"{c}"}]')
    assert batch.batched and batch.where == "json_batch"
    assert len(batch.operations) == 3, f"{len(batch.operations)} operations parsed from a batch"

    intro = _detect('{"query":"query IntrospectionQuery { __schema { types { name } } }"}')
    assert intro.introspection, "an introspection query was not flagged"
    assert not _detect('{"query":"{ me { id } }"}').introspection, "false introspection flag"
    print("  batching (3 operations) and introspection reported as their own facts: PASS")


def test_arguments_are_named_field_dot_argument() -> None:
    """MEASURED against ZAP: `search.limit`, where the JSON variable key is `search_limit`."""
    found = _detect(json.dumps({
        "query": ("query GetUser($id: ID!, $token: String) "
                  "{ userById(id: $id, token: $token, locale: \"en\") { name } "
                  "  search(term: \"x\", limit: 5) { id } }"),
        "variables": {"id": "1", "token": "t"},
    }))
    assert found.argument_names == [
        "userById.id", "userById.token", "userById.locale", "search.term", "search.limit",
    ], found.argument_names
    op = found.operations[0]
    assert op.operation_name == "GetUser", op.operation_name
    assert op.variable_names == ["id", "token"], op.variable_names
    assert op.root_fields == ["userById", "search"], op.root_fields
    by_var = {a.argument: a.from_variable for a in op.arguments}
    assert by_var["id"] and by_var["token"], "a $variable argument was not marked as one"
    assert not by_var["locale"], "an inline argument was marked as coming from a variable"
    print(f"  {len(found.argument_names)} arguments named field.argument, "
          f"$variables told apart from inline: PASS")


def test_an_alias_reports_the_real_field() -> None:
    """`a: userById(...)` — the SERVER sees `userById` and so does ZAP, so an alias must not
    become the parameter name or the plan will not match the finding."""
    found = _detect('{"query":"query { a: userById(id: 1) { x } }"}')
    assert found.argument_names == ["userById.id"], found.argument_names
    print("  an aliased field reports the real field name: PASS")


def test_strings_and_comments_cannot_be_mistaken_for_syntax() -> None:
    """A `{` or a `#` inside a string literal is not structure. Without masking, a query
    carrying a JSON blob as an argument value parses into nonsense."""
    found = _detect(json.dumps({
        "query": '# a comment with { braces } and query mutation\n'
                 'query { note(text: "a } b { c # d", tag: "x") { id } }',
    }))
    assert found.argument_names == ["note.text", "note.tag"], found.argument_names
    assert found.operations[0].root_fields == ["note"], found.operations[0].root_fields
    print("  braces and comment markers inside strings do not become syntax: PASS")


def test_an_unparseable_operation_is_still_graphql() -> None:
    """*** THE PARSE FAILING IS NOT EVIDENCE THE REQUEST IS SOMETHING ELSE. ***
    The envelope decides. A request HackPit cannot parse is exactly the one worth looking at, and
    dropping it from a GraphQL filter would hide it."""
    found = _detect('{"query":"this is not { balanced"}')
    assert found.is_graphql, "a malformed operation was dropped from the GraphQL answer"
    assert not found.operations, "nonsense parsed into operations"
    assert found.note, "no note explaining why it would not parse"
    print(f"  malformed operation still GraphQL, with a reason: {found.note!r}: PASS")


def test_nothing_in_the_detector_ever_raises() -> None:
    for body in ("", "   ", "null", "[]", "[1,2,3]", '{"query":null}', '{"query":123}',
                 "\x00\x01binary", '{"query":"' + "{" * 500 + '"}', "{" * 4000):
        for method in ("GET", "POST"):
            graphql.detect(method, "https://x/graphql?query=" + "%7B" * 50, JSON_CT, body)
    graphql.detect_exchange(None)
    graphql.detect_exchange(object())
    print("  10 hostile bodies x 2 methods and two broken exchanges: no exception: PASS")


# --------------------------------------------------------------------------- #
# the repeater's round trip — item 3
# --------------------------------------------------------------------------- #
def test_a_captured_body_splits_and_rebuilds() -> None:
    captured = ('{"query":"query Q($id: ID!) { userById(id: $id) { name } }",'
                '"variables":{"id":"1"},"operationName":"Q"}')
    state = graphql.split_body(captured)
    assert state.parsed, state.note
    assert state.operation_name == "Q"
    assert json.loads(state.variables) == {"id": "1"}
    assert "\n" in state.variables, "variables were not pretty-printed for a human to edit"

    body, error = graphql.build_body(state.query, state.variables, state.operation_name)
    assert not error, error
    assert json.loads(body) == json.loads(captured), f"round trip changed the request: {body}"
    print("  captured -> query + variables -> captured, byte-equal as JSON: PASS")


def test_a_body_that_will_not_split_is_returned_RAW_and_says_so() -> None:
    """*** NEVER SILENTLY DISCARDED, NEVER SILENTLY REWRITTEN. *** Build #19's cookie-jar rule."""
    for body, why in (
        ("not json at all", "not JSON"),
        ('{"user":"bob"}', "no string query"),
        ('[{"query":"{a}"},{"query":"{b}"}]', "batched"),
        ("", "empty"),
    ):
        state = graphql.split_body(body)
        assert not state.parsed, f"{why}: split when it should not have"
        assert state.raw_body == body, f"{why}: the captured body was not preserved"
        assert state.note, f"{why}: no reason given"
    batched = graphql.split_body('[{"query":"{a}"},{"query":"{b}"}]')
    assert "2 operations" in batched.note, batched.note
    print("  4 unsplittable bodies: raw kept, reason given, none dropped: PASS")


def test_bad_variables_build_NOTHING_rather_than_something_plausible() -> None:
    """A composer that quietly repaired a body would put a request on the wire nobody wrote."""
    for variables in ("{oops", "[1,2]", '"a string"', "42"):
        body, error = graphql.build_body("{a}", variables)
        assert body == "", f"{variables!r} produced a body anyway: {body!r}"
        assert error, f"{variables!r} failed silently"
    body, error = graphql.build_body("{a}", "")
    assert not error and json.loads(body)["variables"] == {}, "an empty variables box should mean {}"
    assert "operationName" not in json.loads(body), "a blank operationName was sent as null"
    print("  4 invalid variable documents build nothing and say why; blank name omitted: PASS")


# --------------------------------------------------------------------------- #
# the schema probe — the pure half
# --------------------------------------------------------------------------- #
def test_disabled_empty_and_broken_are_THREE_DIFFERENT_ANSWERS() -> None:
    """*** THE ITEM-4 REQUIREMENT, AND ZAP CANNOT MEET IT. ***
    `graphql/action/importUrl` answers `illegal_parameter`, with the same message, for
    introspection-disabled AND for a host that is not listening (measured). Four of these five
    would be an empty list from a naive implementation."""
    cases = {
        "disabled": {"errors": [{"message": "GraphQL introspection is not allowed, but the "
                                            "query contained __schema or __type"}]},
        "http_error": {"errors": [{"message": "Unauthorized"}]},
        "empty": {"data": {"__schema": {"queryType": {"name": "Query"},
                                        "types": [{"name": "Query", "fields": []}]}}},
        "unparseable": {"data": {"something": "else"}},
    }
    for expected, payload in cases.items():
        got = graphql_zap.parse_introspection(payload)
        assert got.status == expected, f"expected {expected}, got {got.status}: {got.note}"
        assert got.note, f"{expected} came back with no explanation"
    disabled = graphql_zap.parse_introspection(cases["disabled"])
    assert disabled.server_errors, "the server's own wording was thrown away"
    assert graphql_zap.parse_introspection(["not a dict"]).status == "unparseable"
    print("  disabled / http_error / empty / unparseable are four distinct answers: PASS")


def test_a_real_schema_yields_fields_and_argument_names() -> None:
    payload = {"data": {"__schema": {
        "queryType": {"name": "Query"}, "mutationType": {"name": "Mutation"},
        "types": [
            {"name": "Query", "fields": [{
                "name": "userById",
                "type": {"kind": "OBJECT", "name": "User"},
                "args": [
                    {"name": "id", "type": {"kind": "NON_NULL",
                                            "ofType": {"kind": "SCALAR", "name": "ID"}}},
                    {"name": "token", "type": {"kind": "SCALAR", "name": "String"}},
                ]}]},
            {"name": "Mutation", "fields": [{
                "name": "setEmail", "type": {"kind": "OBJECT", "name": "User"},
                "args": [{"name": "email", "type": {"kind": "NON_NULL",
                                                    "ofType": {"kind": "SCALAR",
                                                               "name": "String"}}}]}]},
        ]}}}
    probe = graphql_zap.parse_introspection(payload)
    assert probe.status == "ok", probe.note
    assert probe.argument_names == ["userById.id", "userById.token", "setEmail.email"], \
        probe.argument_names
    assert probe.queries[0].args[0].type == "ID!", probe.queries[0].args[0].type
    assert probe.queries[0].args[0].required, "a NON_NULL argument was not marked required"
    assert not probe.queries[0].args[1].required, "a nullable argument was marked required"
    print("  a real schema -> 3 field.argument names, NON_NULL read as required: PASS")


def test_the_scan_plan_names_the_arguments_and_demands_recursion() -> None:
    """*** `recurse` IS NOT A PREFERENCE. *** ZAP files captured GraphQL under a SYNTHETIC
    `<endpoint>/query` child node, so a scan of the endpoint alone runs the path-based rules and
    touches no argument. The first live measurement of that sent 114 requests and reached none."""
    class _Req:
        method, url = "POST", "https://api.example.com/graphql?trace=1"
        headers = [type("H", (), {"name": "Content-Type", "value": "application/json"})()]
        body = json.dumps({
            "query": "query Q($id: ID!, $token: String) "
                     "{ userById(id: $id, token: $token) { name } }",
            "variables": {"id": "1", "token": "abc"},
        })

    plan = graphql_zap.scan_plan_for(type("E", (), {"request": _Req()})())
    assert plan.ok, plan.note
    assert plan.recurse_required is True, "the plan did not require recursion"
    assert plan.target_url == "https://api.example.com/graphql", plan.target_url
    assert plan.argument_names == ["userById.id", "userById.token"], plan.argument_names
    assert plan.operation_names == ["Q"], plan.operation_names

    class _Plain:
        method, url, headers, body = "POST", "https://x/login", [], '{"user":"bob"}'
    nope = graphql_zap.scan_plan_for(type("E", (), {"request": _Plain()})())
    assert not nope.ok and nope.note, "a non-GraphQL exchange produced a GraphQL plan"
    print("  plan names 2 arguments, strips the query string, requires recurse: PASS")


def test_impersonate_swaps_the_fetch_binary_to_curl_chrome116() -> None:
    """The WAF fix: _curl_json fetches through curl_chrome116 (browser JA3) when impersonate is
    set, so a Cloudflare-fronted /graph serves the request instead of 403-ing plain curl. Default
    stays plain curl. Hermetic — subprocess is mocked, no docker/network."""
    seen: dict = {}

    class _P:
        stdout = b'{"data":{}}\n__HACKPIT_GQL_STATUS__200'
        stderr = b""
        returncode = 0

    orig = graphql_zap.subprocess.run
    graphql_zap.subprocess.run = lambda argv, **k: (seen.__setitem__("argv", argv), _P())[1]
    try:
        graphql_zap._curl_json("c", "https://cf/graph", "{}", [], impersonate=False)
        assert "curl" in seen["argv"] and "curl_chrome116" not in seen["argv"], seen["argv"]
        graphql_zap._curl_json("c", "https://cf/graph", "{}", [], impersonate=True)
        assert "curl_chrome116" in seen["argv"] and "curl" not in seen["argv"], seen["argv"]
    finally:
        graphql_zap.subprocess.run = orig
    print("  _curl_json: impersonate -> curl_chrome116, default -> plain curl: PASS")


if __name__ == "__main__":
    test_it_is_recognised_by_body_shape_not_by_path()
    test_every_envelope_shape_is_found()
    test_batching_and_introspection_are_reported_separately()
    test_arguments_are_named_field_dot_argument()
    test_an_alias_reports_the_real_field()
    test_strings_and_comments_cannot_be_mistaken_for_syntax()
    test_an_unparseable_operation_is_still_graphql()
    test_nothing_in_the_detector_ever_raises()
    test_a_captured_body_splits_and_rebuilds()
    test_a_body_that_will_not_split_is_returned_RAW_and_says_so()
    test_bad_variables_build_NOTHING_rather_than_something_plausible()
    test_disabled_empty_and_broken_are_THREE_DIFFERENT_ANSWERS()
    test_a_real_schema_yields_fields_and_argument_names()
    test_the_scan_plan_names_the_arguments_and_demands_recursion()
    test_impersonate_swaps_the_fetch_binary_to_curl_chrome116()
    print("ALL GraphQL tests pass")
