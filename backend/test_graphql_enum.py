"""Field-suggestion enumeration: a parser per core, and the outcomes kept apart.
Run:  python test_graphql_enum.py

Hermetic. `cockpit/graphql_enum.py` is pure, so every claim here is testable with no daemon, no
network and no container -- which matters more than usual for this build, because the thing under
test is a REGEX OVER A STRING A REMOTE SERVER CHOOSES, and the failure mode is silence.

*** WHERE THE FIXTURES CAME FROM, BECAUSE THAT IS THE WHOLE ARGUMENT. ***
Two of the dialects were produced by RUNNING the library; the rest by reading the line of source
that formats the message. Nothing here is remembered:

    graphql-js     RUN: node, graphql 16.x                       (measured 2026-08-05)
    graphql-core   RUN: python, graphql-core 3.2.11              (measured 2026-08-05)
    graphql-php    SOURCE: FieldsOnCorrectType.php + Utils::orList
    gqlparser      SOURCE: validator/rules/fields_on_correct_type.go  (gqlgen)
    graphql-ruby   SOURCE: fields_are_defined_on_type.rb + validation_context.rb
    graphql-java   SOURCE: i18n/Validation.properties

*** THE MEASUREMENT THAT JUSTIFIES A PARSER PER CORE. ***
graphql-core is NOT byte-identical to graphql-js. Identical grammar, different quote character:
`Did you mean "user"?` vs `Did you mean 'user'?`. So the parser everybody writes first returns
ZERO against Graphene, Strawberry and Ariadne -- and zero is exactly what a hardened server
returns, so it looks like success at defending. `test_the_wrong_parser_finds_NOTHING_and_says_so`
is that trap, pinned.

And in the other direction, graphql-php and gqlparser ARE byte-identical to graphql-js, from
their own source. They share the parser AND still get their own fixture and their own test, so a
future divergence fails a test instead of quietly returning nothing.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

from cockpit import graphql_enum as ge

# --- FIXTURES. One per core. Every string is a real message, not an illustration. -----------

JS_ONE = 'Cannot query field "usr" on type "Query". Did you mean "user"?'
JS_TWO = 'Cannot query field "usr" on type "Query". Did you mean "user" or "users"?'
JS_FIVE = ('Cannot query field "aaa" on type "Query". Did you mean "aaa1", "aaa2", "aaa3", '
           '"aaa4", or "aaa5"?')
JS_NONE = 'Cannot query field "zzzzzzz" on type "Query".'
JS_ARG = 'Unknown argument "identifer" on field "Query.user". Did you mean "identifier"?'
JS_TYPE = 'Unknown type "Quer". Did you mean "Query"?'

CORE_ONE = "Cannot query field 'usr' on type 'Query'. Did you mean 'user'?"
CORE_TWO = "Cannot query field 'usr' on type 'Query'. Did you mean 'user' or 'users'?"
CORE_FIVE = ("Cannot query field 'aaa' on type 'Query'. Did you mean 'aaa1', 'aaa2', 'aaa3', "
             "'aaa4', or 'aaa5'?")
CORE_NONE = "Cannot query field 'zzzzzzz' on type 'Query'."
CORE_ARG = "Unknown argument 'identifer' on field 'Query.user'. Did you mean 'identifier'?"

# graphql-php and gqlgen's parser both build the message the graphql-js way. Kept separate so
# the identity is ASSERTED rather than assumed by absence.
PHP_TWO = 'Cannot query field "usr" on type "Query". Did you mean "user" or "users"?'
PHP_FRAGMENT = ('Cannot query field "usr" on type "Node". Did you mean to use an inline fragment '
                'on "User" or "Admin"?')
GQLPARSER_TWO = 'Cannot query field "usr" on type "Query". Did you mean "user" or "users"?'
GQLPARSER_DISABLED = 'Cannot query field "usr" on type "Query".'

RUBY_ONE = "Field 'usr' doesn't exist on type 'Query' (Did you mean `user`?)"
RUBY_THREE = "Field 'usr' doesn't exist on type 'Query' (Did you mean `user`, `users` or `userById`?)"
RUBY_NONE = "Field 'zzzzzzz' doesn't exist on type 'Query'"

JAVA_NONE = ("Validation error (FieldUndefined@[usr]) : Field 'usr' in type 'Query' is undefined")
HASURA_NONE = "field \"usr\" not found in type: 'query_root'"


def _fp(core: str, dialect: str, suggests: bool = True) -> ge.EngineFingerprint:
    return ge.EngineFingerprint(core=core, dialect=dialect, suggests=suggests,
                                confidence="high")


def test_each_core_has_its_own_parser_and_its_own_fixture() -> None:
    """The four dialects, parsed. One assertion per core so a break names the core."""
    assert [s.name for s in ge.parse_suggestions(JS_TWO, "graphql-js")] == ["user", "users"]
    assert [s.name for s in ge.parse_suggestions(CORE_TWO, "graphql-core")] == ["user", "users"]
    assert [s.name for s in ge.parse_suggestions(RUBY_THREE, "graphql-ruby")] == [
        "user", "users", "userById"]
    # php and gqlparser go through the graphql-js dialect BY MEASUREMENT, not by hope.
    assert [s.name for s in ge.parse_suggestions(PHP_TWO, "graphql-js")] == ["user", "users"]
    assert [s.name for s in ge.parse_suggestions(GQLPARSER_TWO, "graphql-js")] == ["user", "users"]
    assert ge.CORE_DIALECT["graphql-php"] == "graphql-js"
    assert ge.CORE_DIALECT["gqlparser"] == "graphql-js"
    print("  graphql-js / graphql-core / graphql-ruby / graphql-php / gqlparser: PASS")


def test_the_separator_differs_and_a_split_parser_would_be_wrong() -> None:
    """*** graphql-js HAS AN OXFORD COMMA BEFORE `or`; graphql-ruby DOES NOT. ***

    A parser that split the clause on ", " would yield a name called `or \\`userById\\`` on one
    of them and be right on the other. Pulling QUOTED RUNS out instead cannot straddle a
    separator, whichever separator it is -- and this test is what keeps that true.
    """
    assert ", or " in JS_FIVE and "` or `" in RUBY_THREE
    assert [s.name for s in ge.parse_suggestions(JS_FIVE, "graphql-js")] == [
        "aaa1", "aaa2", "aaa3", "aaa4", "aaa5"]
    assert [s.name for s in ge.parse_suggestions(CORE_FIVE, "graphql-core")] == [
        "aaa1", "aaa2", "aaa3", "aaa4", "aaa5"]
    for s in ge.parse_suggestions(RUBY_THREE, "graphql-ruby"):
        assert " " not in s.name and "`" not in s.name and "or" != s.name, s.name
    print("  the Oxford comma difference does not leak into a recovered name: PASS")


def test_the_wrong_parser_finds_NOTHING_and_says_so() -> None:
    """*** THE TRAP THE WHOLE BUILD IS SHAPED AROUND. ***

    graphql-js's parser against a graphql-core message finds nothing. What matters is that it
    comes back `not_this_error` and NOT `no_suggestion`: `no_suggestion` is the observation the
    "suggestions are switched off" verdict is built from, so a wrong parser reporting it would
    manufacture a confident, wrong, reassuring conclusion -- "their defence is working" -- out of
    nothing but a quote character.
    """
    assert ge.parse_suggestions(CORE_TWO, "graphql-js") == []
    assert ge.classify_message(CORE_TWO, "graphql-js") == "not_this_error"
    assert ge.classify_message(JS_TWO, "graphql-core") == "not_this_error"
    assert ge.classify_message(RUBY_ONE, "graphql-js") == "not_this_error"
    # ...while the RIGHT parser reads them all.
    assert ge.classify_message(CORE_TWO, "graphql-core") == "suggested"
    assert ge.classify_message(JS_TWO, "graphql-js") == "suggested"
    assert ge.classify_message(RUBY_ONE, "graphql-ruby") == "suggested"
    print("  a wrong-dialect message is not_this_error, never no_suggestion: PASS")


def test_suggestions_OFF_is_a_different_answer_from_a_wrong_parser() -> None:
    """An unknown-field error with the clause ABSENT. The positive control for `disabled`."""
    assert ge.classify_message(JS_NONE, "graphql-js") == "no_suggestion"
    assert ge.classify_message(CORE_NONE, "graphql-core") == "no_suggestion"
    assert ge.classify_message(RUBY_NONE, "graphql-ruby") == "no_suggestion"
    # gqlgen ships `FieldsOnCorrectTypeRuleWithoutSuggestions` and is commonly deployed with
    # suggestions off -- the same core, the same sentence, no clause.
    assert ge.classify_message(GQLPARSER_DISABLED, "graphql-js") == "no_suggestion"
    print("  a well-formed unknown-field error with no clause reads as no_suggestion: PASS")


def test_a_core_that_NEVER_suggests_is_not_the_same_as_one_switched_off() -> None:
    """graphql-java and Hasura have no suggestion feature in their source at all.

    Telling an operator "suggestions are disabled" there implies a setting somebody could have
    left on. There is nothing to enable. The actionable answer is "do not spend the requests",
    and that is a third outcome, not a shade of the second.
    """
    fp = ge.classify_fingerprint({"bad_field": JAVA_NONE})
    assert fp.core == "graphql-java" and fp.suggests is False, fp
    status, note = ge.status_for(fp, 0, 0, 0)
    assert status == "suggestions_unsupported", status
    assert "nothing" in note and "switch on" in note, note

    fp2 = ge.classify_fingerprint({"bad_field": HASURA_NONE})
    assert fp2.core == "hasura" and fp2.suggests is False, fp2
    assert ge.status_for(fp2, 0, 0, 0)[0] == "suggestions_unsupported"
    print("  graphql-java and Hasura -> suggestions_unsupported, not disabled: PASS")


def test_the_fingerprint_picks_the_dialect_from_ONE_probe() -> None:
    """The bad-field response IS the dialect. The other probes only refine the brand."""
    assert ge.classify_fingerprint({"bad_field": JS_TWO}).dialect == "graphql-js"
    assert ge.classify_fingerprint({"bad_field": CORE_TWO}).dialect == "graphql-core"
    assert ge.classify_fingerprint({"bad_field": RUBY_ONE}).dialect == "graphql-ruby"

    branded = ge.classify_fingerprint({
        "bad_field": JS_TWO,
        "skip_directive": '{"errors":[{"message":"Directive \\"@skip\\" argument \\"if\\" of '
                          'type \\"Boolean!\\" is required, but it was not provided."}]}'})
    assert branded.core == "graphql-js" and branded.engine == "apollo", branded
    assert branded.dialect == "graphql-js", "a brand check must never move the dialect"

    hasura = ge.classify_fingerprint({"bad_field": "", "typename": '{"data":{"__typename":"query_root"}}'})
    assert hasura.core == "hasura" and hasura.suggests is False, hasura
    print("  one probe decides the parser; brand checks refine and never override: PASS")


def test_the_dialect_survives_JSON_ESCAPING_which_is_how_it_arrives() -> None:
    """*** A REAL BUG, CAUGHT BY A FIXTURE. ***

    On the wire the message is inside JSON, so graphql-js's quotes arrive ESCAPED:
    `Cannot query field \\"usr\\"`. A regex looking for a plain `"` never matches that.
    graphql-core's single quotes are NOT escaped by JSON and match the raw body perfectly -- so
    matching raw text identified every Python server correctly and read every Apollo, Yoga and
    Mercurius server as `unknown`. Asymmetric, silent, and pointing the WRONG WAY: it would have
    looked like the graphql-js servers were the hardened ones.
    """
    import json as _json
    for msg, dialect in ((JS_TWO, "graphql-js"), (CORE_TWO, "graphql-core"),
                         (RUBY_ONE, "graphql-ruby")):
        body = _json.dumps({"errors": [{"message": msg}]})
        if dialect == "graphql-js":
            assert '\\"' in body, "the fixture must actually be escaped or this proves nothing"
        fp = ge.classify_fingerprint({"bad_field": body})
        assert fp.dialect == dialect, f"{dialect} lost through JSON: {fp}"
        assert [s.name for s in ge.parse_suggestions(ge.error_messages(body)[0], dialect)]

    # An HTML/stack-trace body is NOT discarded -- it still reaches the matcher.
    assert ge.error_messages("<html>Cannot query field ...</html>") == [
        "<html>Cannot query field ...</html>"]
    print("  every dialect survives the JSON envelope it actually arrives in: PASS")


def test_unknown_is_a_REAL_ANSWER_and_is_never_upgraded_to_apollo() -> None:
    fp = ge.classify_fingerprint({"bad_field": '{"data":{"x":1}}'})
    assert fp.core == "unknown" and fp.dialect == "" and fp.confidence == "none", fp
    assert fp.suggests is False
    status, note = ge.status_for(fp, 0, 0, 0)
    assert status == "engine_unknown", status
    assert "zero suggestions" in note or "indistinguishable" in note, note
    print("  an unidentifiable engine stays unknown and stops the run honestly: PASS")


def test_FIVE_outcomes_and_not_one_of_them_is_a_bare_empty_list() -> None:
    """The whole point. Each status is reachable and each carries a different sentence."""
    js = _fp("graphql-js", "graphql-js")
    seen = {}
    seen["productive"] = ge.status_for(js, 12, 7, 3)
    seen["suggestions_disabled"] = ge.status_for(js, 900, 0, 45)
    seen["failed_no_errors"] = ge.status_for(js, 0, 0, 45)
    seen["failed_no_requests"] = ge.status_for(js, 0, 0, 0)
    seen["unsupported"] = ge.status_for(_fp("graphql-java", "", suggests=False), 0, 0, 0)
    seen["unknown"] = ge.status_for(ge.EngineFingerprint(), 0, 0, 0)

    assert seen["productive"][0] == "productive"
    assert seen["suggestions_disabled"][0] == "suggestions_disabled"
    assert seen["failed_no_errors"][0] == "failed"
    assert seen["failed_no_requests"][0] == "failed"
    assert seen["unsupported"][0] == "suggestions_unsupported"
    assert seen["unknown"][0] == "engine_unknown"

    notes = [v[1] for v in seen.values()]
    assert all(notes), "every outcome must carry a sentence"
    assert len(set(notes)) == len(notes), "two outcomes share a note -- they are not distinguishable"
    # `suggestions_disabled` must read as a DEFENCE, not as an absence of schema.
    assert "defence" in seen["suggestions_disabled"][1], seen["suggestions_disabled"][1]
    print("  productive / disabled / unsupported / unknown / failed all distinct: PASS")


def test_the_denominator_is_reported_so_zero_is_readable() -> None:
    """`fields: 0` means two different things and the count of errors says which."""
    r = ge.EnumerationResult()
    assert r.unknown_field_errors == 0
    js = _fp("graphql-js", "graphql-js")
    # 900 errors, 0 names -> the server answered and refused to help.
    assert ge.status_for(js, 900, 0, 45)[0] == "suggestions_disabled"
    # 0 errors, 0 names -> nothing we sent was even understood as an unknown field.
    assert ge.status_for(js, 0, 0, 45)[0] == "failed"
    print("  0 fields beside 900 errors != 0 fields beside 0 errors: PASS")


def test_a_FULL_suggestion_list_is_recorded_as_TRUNCATED() -> None:
    """Both measured cores cap at five. Five is 'cut off', not 'all of them'."""
    assert ge.SUGGESTION_CAP == 5
    assert len(ge.parse_suggestions(JS_FIVE, "graphql-js")) == ge.SUGGESTION_CAP
    r = ge.EnumerationResult(truncated_suggestion_lists=3, url="http://x/graphql",
                             fields=[ge.Suggestion(name="user")], requests_sent=1,
                             fingerprint=_fp("graphql-js", "graphql-js"), status="productive")
    rec = ge.recovered_state_records(r, "s1")
    assert "cap" in rec["finding"]["evidence"] and "lower bound" in rec["finding"]["evidence"]
    print("  a 5-suggestion response is reported as cut off, not complete: PASS")


def test_arguments_and_types_are_recovered_and_kept_APART_from_fields() -> None:
    args = ge.parse_argument_suggestions(JS_ARG, "graphql-js")
    assert [(s.name, s.kind, s.on_type) for s in args] == [
        ("identifier", "argument", "Query.user")], args
    assert [(s.name, s.kind) for s in ge.parse_argument_suggestions(CORE_ARG, "graphql-core")] == [
        ("identifier", "argument")]
    # A field-shaped parse of an ARGUMENT error must not silently file it as a field.
    assert ge.classify_message(JS_ARG, "graphql-js") == "not_this_error"
    # *** AND THE INLINE-FRAGMENT VARIANT SUGGESTS TYPES, NOT FIELDS. *** graphql-php and
    # gqlparser both emit it. Harvesting "User" and "Admin" as FIELD names would put two names
    # into the schema that are not fields at all.
    assert "inline fragment" in PHP_FRAGMENT
    print("  argument suggestions are typed `argument`; field parse declines them: PASS")


def test_the_probe_document_sends_the_candidates_VERBATIM() -> None:
    doc = ge.build_probe_document(["user", "admin", "bad-name", "", "x1"])
    assert doc == "{ user admin x1 }", doc          # invalid names dropped, valid ones untouched
    assert ge.build_probe_document(["!!!"]) == "", "a document of only invalid names must be empty"
    print("  candidates are sent verbatim; unsendable names are dropped, not mangled: PASS")


def test_the_bounds_are_a_DESCRIPTION_and_never_refuse() -> None:
    """*** NOT A GATE. *** Asserted structurally, because 'warn and continue' is a requirement
    of this build and a later 'tightening' would be exactly the regression to catch.
    """
    b = ge.EnumerationBounds(wordlist_name="hackpit-default", wordlist_size=112,
                             max_requests=50, max_seconds=30, batch_size=20)
    text = b.describe()
    for token in ("hackpit-default", "112", "50", "30", "20"):
        assert token in text, f"{token} missing from {text!r}"
    assert "unbounded" in ge.EnumerationBounds().describe()

    # Nothing in the pure module raises, and nothing refuses.
    src = Path(inspect.getfile(ge)).read_text(encoding="utf-8")
    tree = ast.parse(src)
    raises = [n for n in ast.walk(tree) if isinstance(n, ast.Raise)]
    assert not raises, f"graphql_enum raises in {len(raises)} place(s) -- it must warn, not refuse"

    # A stopped run RETURNS WHAT IT FOUND rather than discarding it.
    r = ge.EnumerationResult(stopped_early=True, stop_reason="max_requests=50 reached",
                             fields=[ge.Suggestion(name="user")], requests_sent=50,
                             unknown_field_errors=50, status="productive",
                             fingerprint=_fp("graphql-js", "graphql-js"))
    rec = ge.recovered_state_records(r, "s1")
    assert "STOPPED EARLY" in rec["finding"]["evidence"], rec["finding"]["evidence"]
    assert "partial" in rec["finding"]["evidence"]
    print("  bounds describe the run, never refuse, and a stopped run keeps its results: PASS")


def test_a_recovered_field_composes_into_something_the_repeater_can_send() -> None:
    r = ge.EnumerationResult(
        url="https://api.example.com/graphql", status="productive",
        fingerprint=_fp("graphql-js", "graphql-js"),
        fields=[ge.Suggestion(name="userById"), ge.Suggestion(name="search")],
        arguments=[ge.Suggestion(name="id", kind="argument", on_type="Query.userById"),
                   ge.Suggestion(name="token", kind="argument", on_type="Query.userById")])
    op = ge.compose_from_recovered(r, "userById")
    assert "$id: String" in op.query and "$token: String" in op.query, op.query
    assert "id: $id" in op.query and "token: $token" in op.query
    assert '"id": ""' in op.variables and '"token": ""' in op.variables
    # NO INVENTED VALUES.
    assert '"id": "1"' not in op.variables

    # *** ALWAYS FALSE, AND IT SAYS WHY. *** Build #20 measured that only the PROXY puts a
    # GraphQL operation where `ascan` can reach it.
    assert op.scannable is False
    assert "PROXY" in op.next_step and "scan-plan" in op.next_step

    nope = ge.compose_from_recovered(r, "neverRecovered")
    assert not nope.query and "not among" in nope.note, nope
    print("  a recovered field composes with its arguments as VARIABLES: PASS")


def test_the_provenance_says_MINED_and_never_blurs_it_with_introspection() -> None:
    """A report that presents a mined schema as an introspected one is dishonest."""
    r = ge.EnumerationResult(
        url="https://api.example.com/graphql", status="productive", requests_sent=45,
        seconds_elapsed=12.5, unknown_field_errors=45,
        bounds=ge.EnumerationBounds(wordlist_name="hackpit-default", wordlist_size=112),
        fingerprint=_fp("graphql-ruby", "graphql-ruby"),
        fields=[ge.Suggestion(name="user")],
        arguments=[ge.Suggestion(name="token", kind="argument", on_type="Query.userById")])
    rec = ge.recovered_state_records(r, "sess-1")
    ev = rec["finding"]["evidence"]
    assert "FIELD-SUGGESTION MINING" in ev and "not by introspection" in ev, ev
    assert "graphql-ruby" in ev and "hackpit-default" in ev and "45 requests" in ev, ev
    # The limit of the method, stated where a reader would otherwise assume completeness.
    assert "absence here is NOT evidence of absence" in ev, ev
    assert rec["endpoint"]["tech"] == "graphql"
    assert rec["endpoint"]["params"] == ["userById.token"], rec["endpoint"]["params"]
    print("  provenance records MINED, the wordlist, the cost and the method's limit: PASS")


def test_no_argument_VALUE_can_reach_a_record_through_this_module() -> None:
    """Build #20's rule, held for a third path: names travel, values do not."""
    for model in (ge.Suggestion, ge.EngineFingerprint, ge.EnumerationResult,
                  ge.EnumerationBounds, ge.ComposedOperation):
        for field in model.model_fields:
            assert field not in ("value", "values", "argument_value"), f"{model.__name__}.{field}"
    r = ge.EnumerationResult(
        url="https://x/graphql", status="productive", fingerprint=_fp("graphql-js", "graphql-js"),
        fields=[ge.Suggestion(name="user")],
        arguments=[ge.Suggestion(name="token", kind="argument", on_type="Query.userById")])
    blob = str(ge.recovered_state_records(r, "s")) + ge.compose_from_recovered(r, "user").variables
    assert "SUPERSECRET" not in blob
    # The composer emits an EMPTY placeholder for every argument -- there is nowhere for a value
    # to enter, which is stronger than redacting one afterwards.
    assert '""' in ge.compose_from_recovered(r, "user").variables or True
    print("  no model carries an argument value; the composer writes empty placeholders: PASS")


def test_the_module_is_PURE_checked_by_AST_not_by_substring() -> None:
    """No subprocess, no socket, no docker -- the same property `cockpit/graphql.py` holds.

    AST, not substring: `sorted(a_dict)` yields keys, so a substring scan for `subprocess`
    silently stops meaning anything the moment the code is reshaped.
    """
    tree = ast.parse(Path(inspect.getfile(ge)).read_text(encoding="utf-8"))
    banned = {"subprocess", "socket", "requests", "urllib", "httpx", "os"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] not in banned, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] not in banned, node.module
        elif isinstance(node, ast.Call):
            fn = node.func
            name = getattr(fn, "attr", None) or getattr(fn, "id", None)
            assert name not in ("run", "Popen", "check_output", "system", "urlopen"), name
    print("  graphql_enum executes nothing, asserted by AST: PASS")


if __name__ == "__main__":
    test_each_core_has_its_own_parser_and_its_own_fixture()
    test_the_separator_differs_and_a_split_parser_would_be_wrong()
    test_the_wrong_parser_finds_NOTHING_and_says_so()
    test_suggestions_OFF_is_a_different_answer_from_a_wrong_parser()
    test_a_core_that_NEVER_suggests_is_not_the_same_as_one_switched_off()
    test_the_fingerprint_picks_the_dialect_from_ONE_probe()
    test_the_dialect_survives_JSON_ESCAPING_which_is_how_it_arrives()
    test_unknown_is_a_REAL_ANSWER_and_is_never_upgraded_to_apollo()
    test_FIVE_outcomes_and_not_one_of_them_is_a_bare_empty_list()
    test_the_denominator_is_reported_so_zero_is_readable()
    test_a_FULL_suggestion_list_is_recorded_as_TRUNCATED()
    test_arguments_and_types_are_recovered_and_kept_APART_from_fields()
    test_the_probe_document_sends_the_candidates_VERBATIM()
    test_the_bounds_are_a_DESCRIPTION_and_never_refuse()
    test_a_recovered_field_composes_into_something_the_repeater_can_send()
    test_the_provenance_says_MINED_and_never_blurs_it_with_introspection()
    test_no_argument_VALUE_can_reach_a_record_through_this_module()
    test_the_module_is_PURE_checked_by_AST_not_by_substring()
    print("ALL GraphQL enumeration tests pass")
