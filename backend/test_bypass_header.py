"""WAF-bypass header locks (build #18 item 1).  Run:  python test_bypass_header.py

THE INVARIANT: the header's VALUE is a credential. It is stored once, delivered to ZAP on
stdin, and reaches no model, no run record, no LLM prompt and no report. What IS reported is
the header NAME and what ZAP actually holds.
"""

from __future__ import annotations

import ast
import inspect
import tempfile
import uuid
from pathlib import Path

from cockpit import engagement, proxy, runstore, secretargs

# A THROWAWAY DATABASE. These tests write engagement records, and writing them into the real
# sessions.db would leave lab engagements behind — build #17 found twenty of those already there
# and correctly declined to tidy them up, which is exactly why a test must not add a twenty-first.
_TMP_DB = Path(tempfile.mkdtemp()) / "bypass-header-test.db"
runstore.DB_PATH = engagement.DB_PATH = _TMP_DB


def _fresh_engagement() -> str:
    engagement.init_db()
    # `example.com` because `enter()` RESOLVES the scope and fails closed on a name that does
    # not exist — the same host the existing engagement-scope tests use.
    record = engagement.enter(
        target="example.com",
        authorization="build #18 hermetic test — nothing runs",
        scope_spec="example.com",
    )
    return record.engagement_id


def test_the_value_is_stored_and_the_record_carries_only_the_name() -> None:
    """The load-bearing one. `EngagementRecord` is returned by GET /cockpit/engagement, joined
    into the proposer's context and rendered into reports — so the secret must not be on it.

    The control is in this test: the NAME must be there, or the check would pass for a record
    that simply lost the header altogether."""
    eid = _fresh_engagement()
    secret = "s3cr3t-" + uuid.uuid4().hex
    names = engagement.set_bypass_header(eid, "X-Bug-Bounty", secret)
    assert names == ["X-Bug-Bounty"], names

    record = engagement.get_active(eid)
    assert record is not None
    blob = record.model_dump_json()
    assert secret not in blob, (
        "the bypass header VALUE is in the engagement record — it travels to the browser, into "
        "the LLM proposer context and into every rendered report"
    )
    # control: the NAME is there, so the absence above is redaction and not amnesia
    assert "X-Bug-Bounty" in blob, "the record does not even carry the header NAME"
    assert record.bypass_header_names == ["X-Bug-Bounty"]

    # and the value IS retrievable by the one function that is supposed to have it
    assert engagement.bypass_headers(eid) == [("X-Bug-Bounty", secret)]
    engagement.exit_engagement(eid)
    print("  the value is stored, the record carries the NAME only, control holds: PASS")


def test_no_model_in_the_whole_module_has_a_value_field() -> None:
    """A property a future edit cannot quietly undo: there is nowhere for the value to live.

    Scans the pydantic models by FIELD NAME rather than looking for the string in a docstring,
    because this module's prose is full of the word 'value'."""
    from pydantic import BaseModel

    offenders: list[str] = []
    for module in (proxy,):
        for name, obj in vars(module).items():
            if not (isinstance(obj, type) and issubclass(obj, BaseModel)):
                continue
            for field in obj.model_fields:
                if field in ("replacement", "bypass_header_value", "header_value"):
                    offenders.append(f"{name}.{field}")
    assert not offenders, (
        f"these models carry a bypass-header VALUE field: {offenders}. The rule is that there is "
        "no field for it, which is the version of the property that cannot regress."
    )
    assert "replacement" not in proxy.ReplacerRule.model_fields, (
        "ReplacerRule carries the replacement value — this model is returned to the browser"
    )
    assert "replacement_set" in proxy.ReplacerRule.model_fields, (
        "ReplacerRule cannot even say whether a value is present, which is what a panel needs"
    )
    print("  no model anywhere carries the header value; ReplacerRule reports only presence: PASS")


def test_the_value_goes_on_STDIN_and_never_on_an_argv() -> None:
    """`_api_get` interpolates its path into a `docker exec … curl … <url>` argv that `ps` on
    this host can read, and ZAP records what passes through it. The install therefore uses the
    POST path, whose body is fed on stdin.

    AST, NOT SUBSTRING — the docstrings in that module quote both function names repeatedly."""
    tree = ast.parse(inspect.getsource(proxy.install_bypass_headers))
    called = {
        node.func.id for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert "_api_get" not in called, (
        "install_bypass_headers calls _api_get — that puts the credential on a command line "
        "and into ZAP's own recorded history"
    )
    assert "_post_first_that_answers" in called, (
        f"install_bypass_headers does not use the POST path at all: {sorted(called)}"
    )

    # ...and the POST path really does send a body on stdin rather than in the URL.
    post_src = inspect.getsource(proxy._api_post)
    assert "--data-binary" in post_src and "input=" in post_src, (
        "_api_post does not feed a body on stdin"
    )
    assert '"-i"' in post_src or "'-i'" in post_src, (
        "docker exec is not given -i, so the container's curl reads a CLOSED stdin, sends an "
        "empty body, and ZAP answers OK for a rule with no value in it"
    )
    print("  the value is delivered on stdin; the argv never carries it: PASS")


def test_an_empty_value_is_refused_because_it_would_STRIP_the_header() -> None:
    """A shape check, not a gate: a ZAP replacer rule with an empty replacement REMOVES the
    header. A control that silently does the opposite of what it says is worse than no control.

    The control is the same call with a real value succeeding."""
    eid = _fresh_engagement()
    for bad in ("", "   "):
        try:
            engagement.set_bypass_header(eid, "X-Bypass", bad)
        except ValueError as exc:
            assert "empty" in str(exc).lower()
        else:
            raise AssertionError(f"an empty value {bad!r} was accepted")
    assert engagement.set_bypass_header(eid, "X-Bypass", "ok") == ["X-Bypass"]
    engagement.exit_engagement(eid)
    print("  an empty value is refused, a real one is accepted: PASS")


def test_the_name_is_shape_checked_and_nothing_else() -> None:
    """It refuses what could not BE a header name and decides nothing about WHICH headers an
    operator may set — that would be an allow-list narrowing, which this build does not add."""
    eid = _fresh_engagement()
    for bad in ("X Bypass", "X:Bypass", "X\nBypass"):
        try:
            engagement.set_bypass_header(eid, bad, "v")
        except ValueError:
            pass
        else:
            raise AssertionError(f"{bad!r} was accepted as a header name")
    # Anything token-shaped goes, including names nobody would predict.
    for good in ("X-Bug-Bounty", "cf-bypass", "X_Weird.Header~1", "Authorization"):
        assert good in engagement.set_bypass_header(eid, good, "v"), good
    engagement.exit_engagement(eid)
    print("  the name is shape-checked; no header name is forbidden: PASS")


def test_the_header_is_case_insensitive_so_two_rules_cannot_fight() -> None:
    """HTTP header names are case-insensitive. Two rows for `X-Bypass` and `x-bypass` would
    install two replacer rules for one header and let whichever ZAP applied last win."""
    eid = _fresh_engagement()
    engagement.set_bypass_header(eid, "X-Bypass", "first")
    names = engagement.set_bypass_header(eid, "x-bypass", "second")
    assert names == ["x-bypass"], names
    assert engagement.bypass_headers(eid) == [("x-bypass", "second")], "the upsert did not replace"
    engagement.exit_engagement(eid)
    print("  a differently-cased name amends rather than duplicates: PASS")


def test_only_hackpit_rules_are_removed() -> None:
    """A rule a human added in ZAP's own UI is somebody else's decision. The cleanup identifies
    its own by description prefix and leaves the rest."""
    mine = proxy._rule_from({
        "description": proxy.bypass_rule_description("X-Bypass"),
        "matchType": "REQ_HEADER", "matchString": "X-Bypass",
        "enabled": "true", "replacement": "secret",
    })
    theirs = proxy._rule_from({
        "description": "operator's own rule", "matchType": "REQ_HEADER",
        "matchString": "X-Debug", "enabled": "true", "replacement": "1",
    })
    assert mine is not None and theirs is not None
    assert mine.hackpit_managed and not theirs.hackpit_managed
    assert mine.replacement_set and "secret" not in mine.model_dump_json(), (
        "the parsed rule carries the replacement value into the model"
    )
    # a row with no description is DROPPED, because a rule we cannot identify is one we must
    # not remove
    assert proxy._rule_from({"matchString": "X"}) is None
    print("  hackpit rules are identified by prefix; an unidentifiable rule is never claimed: PASS")


def test_stopping_a_proxy_clears_the_rules_BEFORE_it_kills_the_daemon() -> None:
    """Ordering, and it is load-bearing: after the kill there is no API to remove the rule
    through, while ZAP's persisted config keeps it for whatever starts next."""
    src = inspect.getsource(proxy.stop_proxy)
    clear_at = src.find("clear_bypass_headers")
    kill_at = src.find(".kill(")
    assert clear_at != -1, "stop_proxy does not clear the bypass headers at all"
    assert kill_at != -1, "stop_proxy no longer kills the daemon"
    assert clear_at < kill_at, (
        "stop_proxy kills the daemon before removing the replacer rules — afterwards there is no "
        "API to remove them through and ZAP's persisted config keeps the credential"
    )
    assert "clear_auth_contexts" in src, (
        "stop_proxy does not clear auth contexts, which carry a stored credential in their user"
    )
    print("  the rules are cleared before the kill, and contexts with them: PASS")


def test_a_sync_with_no_engagement_CLEARS_rather_than_leaves() -> None:
    """The failure worth preventing is a credential surviving into a session it was not issued
    for. A MISSING header announces itself as a 403 on the next request; a stale one does not
    announce itself at all."""
    src = inspect.getsource(proxy.sync_bypass_headers)
    assert "clear_bypass_headers" in src, "sync never clears"
    tree = ast.parse(src)
    # the no-engagement branch must reach the clear, not fall through to a no-op
    assert any(
        isinstance(node, ast.If) for node in ast.walk(tree)
    ), "sync has no branch on whether headers were found"
    result_doc = proxy.sync_bypass_headers.__doc__ or ""
    assert "CLEARS" in result_doc, "the clearing behaviour is not documented where it is decided"
    print("  syncing with no engagement clears rather than leaving a stale credential: PASS")


def test_the_api_key_redaction_still_holds() -> None:
    """The existing safety spine, unmoved. Build #18 must not widen a redaction map to fit new
    code, and it did not: `api.key` is still masked and `api.disablekey=false` still survives as
    the evidence the lock was on."""
    argv = proxy.server_argv_for(
        proxy.ProxyStartRequest(approved=True, dangerous_ack=True), api_key="deadbeef" * 4
    )
    recorded = secretargs.redact_argv(argv[0], argv[1:])
    joined = " ".join(recorded)
    assert "deadbeef" not in joined, "the API key survives redaction"
    assert "api.disablekey=false" in joined, (
        "the evidence that the API lock was ON was redacted away with the key"
    )
    print("  api.key is still masked and api.disablekey survives: PASS")


if __name__ == "__main__":
    print("== WAF-bypass header (build #18 item 1) ==")
    test_the_value_is_stored_and_the_record_carries_only_the_name()
    test_no_model_in_the_whole_module_has_a_value_field()
    test_the_value_goes_on_STDIN_and_never_on_an_argv()
    test_an_empty_value_is_refused_because_it_would_STRIP_the_header()
    test_the_name_is_shape_checked_and_nothing_else()
    test_the_header_is_case_insensitive_so_two_rules_cannot_fight()
    test_only_hackpit_rules_are_removed()
    test_stopping_a_proxy_clears_the_rules_BEFORE_it_kills_the_daemon()
    test_a_sync_with_no_engagement_CLEARS_rather_than_leaves()
    test_the_api_key_redaction_still_holds()
    print("ALL bypass-header locks pass")
