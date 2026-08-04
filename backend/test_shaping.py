"""Payload-shaping locks (build #18 item 4).  Run:  python test_shaping.py

THE INVARIANT: shaping changes the BYTES of a request a human already composed, and the thing
that goes on the wire is the thing that was scope-checked, previewed and recorded.

IT IS AN OPTION, NOT A GATE. There is no confirm, no acknowledgement and no refusal — the
repeater is human-only by construction and a human clicking Send is the approval. A test that
demanded one would be a harness inventing a prohibition the product does not have, which is the
single thing build #17 had to strip three of.
"""

from __future__ import annotations

import ast
import inspect

from cockpit import repeater, shaping


def _req(**kw):
    base = dict(url="https://lab.example.com/search?q=x")
    base.update(kw)
    return repeater.RepeaterRequest(**base)


def test_with_no_shapes_the_markers_are_STILL_stripped() -> None:
    """The control half of every measurement. Shaped-vs-unshaped has to differ in the shaping and
    in nothing else, so an unshaped send must transmit the payload rather than the annotation."""
    url, body, applied, warnings = repeater.shape_request(
        _req(url="https://h/x?a=[[1 OR 1=1]]", shapes=[])
    )
    assert url == "https://h/x?a=1 OR 1=1", url
    assert applied == [] and warnings == []
    assert "[[" not in url and "]]" not in url, "the markers reached the wire"
    print("  markers are stripped with no shapes selected — the control is honest: PASS")


def test_shapes_compose_in_the_order_given() -> None:
    """`['sql-comment', 'url-encode']` comments first and then encodes the comment. The order is
    the operator's choice and is never re-ordered here — guessing it would silently produce a
    payload they did not ask for."""
    commented, _ = shaping.apply_shapes("[[1 OR 1=1]]", ["sql-comment"])
    assert commented == "1/**/OR/**/1=1", commented
    both, _ = shaping.apply_shapes("[[1 OR 1=1]]", ["sql-comment", "url-encode"])
    assert both == "1%2F%2A%2A%2FOR%2F%2A%2A%2F1%3D1", both
    reversed_order, _ = shaping.apply_shapes("[[1 OR 1=1]]", ["url-encode", "sql-comment"])
    assert reversed_order != both, "the order made no difference — the transforms are not composing"
    print("  transforms compose in the order given, and the order matters: PASS")


def test_only_the_marked_span_is_transformed() -> None:
    """A transform applied to a whole URL would encode the scheme, the host and the parameter
    names and produce a request that goes nowhere."""
    url, _, _, _ = repeater.shape_request(
        _req(url="https://lab.example.com/a/b?q=[[1 2]]&keep=me", shapes=["url-encode"])
    )
    assert url.startswith("https://lab.example.com/a/b?q="), url
    assert url.endswith("&keep=me"), url
    assert "%201%202" not in url and "1%202" in url, url
    print("  only the [[...]] span is transformed; scheme, host and other params survive: PASS")


def test_an_unclosed_marker_is_left_alone() -> None:
    """An opening marker with no close is not a span. Shaping to the end of the string would
    silently encode the rest of the request."""
    url, _, _, _ = repeater.shape_request(
        _req(url="https://h/x?a=[[unclosed&b=2", shapes=["url-encode"])
    )
    assert url == "https://h/x?a=[[unclosed&b=2", url
    print("  an unclosed marker shapes nothing rather than swallowing the request: PASS")


def test_an_unknown_shape_WARNS_and_the_request_still_goes() -> None:
    """WARN AND CONTINUE. A typo in one transform name must not throw away a request the
    operator composed, and it must not pretend the transform ran either."""
    url, _, applied, warnings = repeater.shape_request(
        _req(url="https://h/x?a=[[v]]", shapes=["not-a-shape", "case-vary"])
    )
    assert url == "https://h/x?a=v", url          # case-vary on 'v' is 'v'
    assert applied == ["case-vary"], applied
    assert any("not-a-shape" in w for w in warnings), warnings
    assert any("Known:" in w for w in warnings), "the warning does not say what IS known"
    print("  an unknown shape warns, names the alternatives, and sends anyway: PASS")


def test_a_request_level_shape_with_nothing_to_act_on_says_so() -> None:
    """`param-pollution` on a URL with no query string and `chunked` on a request with no body
    both do nothing. Reporting that beats a UI that claims a transform ran."""
    _, _, applied, warnings = repeater.shape_request(
        _req(url="https://h/nopath", shapes=["param-pollution"])
    )
    assert "param-pollution" not in applied
    assert any("no query string" in w for w in warnings), warnings

    _, _, applied2, warnings2 = repeater.shape_request(
        _req(url="https://h/x", body="", shapes=["chunked"])
    )
    assert "chunked" not in applied2
    assert any("no body" in w for w in warnings2), warnings2

    # control: with something to act on, they DO apply
    _, _, applied3, _ = repeater.shape_request(
        _req(url="https://h/x?a=1", shapes=["param-pollution"])
    )
    assert "param-pollution" in applied3
    print("  a no-op request shape reports itself; the control still applies: PASS")


def test_parameter_pollution_duplicates_and_preserves_a_valueless_parameter() -> None:
    """`?debug` has no `=`. `parse_qsl` would drop it, and dropping a parameter changes the
    request the operator asked to send."""
    out = shaping.pollute_query("https://h/x?a=1&debug&b=2")
    assert out.count("a=1") == 2 and out.count("b=2") == 2, out
    assert "debug=" in out, out
    print("  pollution duplicates every parameter, valueless ones included: PASS")


def test_the_scope_check_runs_on_the_SHAPED_url() -> None:
    """*** THE LOAD-BEARING ONE. *** Nothing stops an operator marking a span inside the HOST.
    Checking the composed URL and sending a different one is 'the gated argv is not the spawned
    argv' wearing a new hat — a scope check on bytes that never went on the wire."""
    src = inspect.getsource(repeater.send)
    shape_at = src.find("shape_request(")
    scope_at = src.find("_scope_check(")
    assert shape_at != -1 and scope_at != -1
    assert shape_at < scope_at, (
        "send() scope-checks before it shapes — the URL that was checked is not the URL that "
        "gets sent"
    )
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == "_scope_check"):
            assert len(node.args) == 2, (
                "_scope_check is called with one argument — it is reading req.url, which is the "
                "COMPOSED url and not the one that goes on the wire"
            )
            assert any(getattr(a, "id", "") == "sent_url" for a in node.args), (
                "the scope check is not given the shaped URL"
            )
            break
    else:
        raise AssertionError("send() no longer scope-checks at all")

    # ...and the check itself reads its argument rather than the request.
    check_src = inspect.getsource(repeater._scope_check)
    assert "bare_host(url)" in check_src, (
        "_scope_check still derives the host from req.url instead of the URL it was handed"
    )
    print("  the scope check reads the SHAPED url, and shaping happens first: PASS")


def test_the_run_record_states_what_was_SENT_not_what_was_typed() -> None:
    """An audit trail showing the unshaped request would misdescribe every shaped send."""
    src = inspect.getsource(repeater.send)
    record_at = src.find("RunRecord(")
    assert record_at != -1
    tail = src[record_at:record_at + 500]
    assert "sent_url" in tail, "the run record stores req.url, not the URL that was transmitted"
    assert "req.url" not in tail, "the run record still carries the composed URL"
    print("  the run record states the URL that was sent: PASS")


def test_shaping_adds_no_gate_field_anywhere() -> None:
    """*** THE UNRESTRICTIVE REQUIREMENT, ASSERTED. ***
    Build #18 adds no gate, confirm, acknowledgement or refusal. The repeater is human-only and
    a human clicking Send is the approval; a second confirm for changing the bytes of that same
    request would teach the operator that a confirm means 'a form has fields'."""
    for name in ("dangerous_ack", "approved", "shaping_ack", "confirm"):
        assert name not in repeater.RepeaterRequest.model_fields, (
            f"RepeaterRequest grew a {name!r} field — the repeater is human-only and gates none "
            "of its sends; build #18 explicitly adds no confirm"
        )
    shaping_src = inspect.getsource(shaping)
    tree = ast.parse(shaping_src)
    raises = [
        n for n in ast.walk(tree)
        if isinstance(n, ast.Raise)
    ]
    assert not raises, (
        f"cockpit/shaping.py raises ({len(raises)} sites) — an unknown shape is RETURNED and "
        "warned about, never refused. A pure transform module has nothing to refuse."
    )
    print("  no gate field, no confirm, and shaping refuses nothing: PASS")


def test_chunked_suppresses_content_length() -> None:
    """`-H 'Transfer-Encoding: chunked'` alone makes some curl versions send BOTH framings, which
    is request smuggling by accident rather than a shaped payload."""
    argv = repeater._build_curl(
        _req(body="x=1"), "SENT", url="https://h/x", has_body=True, chunked=True
    )
    joined = " ".join(argv)
    assert "Transfer-Encoding: chunked" in joined, joined
    assert "Content-Length:" in joined, (
        "Content-Length is not suppressed, so curl may send two framings at once"
    )
    # control: without the shape, neither header is added
    plain = " ".join(repeater._build_curl(
        _req(body="x=1"), "SENT", url="https://h/x", has_body=True, chunked=False
    ))
    assert "Transfer-Encoding" not in plain
    print("  chunked sets one framing, not two; the control stays clean: PASS")


def test_the_preview_and_the_send_use_ONE_derivation() -> None:
    """What is previewed has to be what is transmitted, or the preview is a second implementation
    that can drift — the trap the credential vault's docstring names."""
    from cockpit import router

    preview_src = inspect.getsource(router.repeater_preview)
    assert "shape_request" in preview_src, "the preview re-implements shaping"
    send_src = inspect.getsource(repeater.send)
    assert "shape_request" in send_src, "send() does not use the shared derivation"
    print("  preview and send call the same function: PASS")


if __name__ == "__main__":
    print("== payload shaping (build #18 item 4) ==")
    test_with_no_shapes_the_markers_are_STILL_stripped()
    test_shapes_compose_in_the_order_given()
    test_only_the_marked_span_is_transformed()
    test_an_unclosed_marker_is_left_alone()
    test_an_unknown_shape_WARNS_and_the_request_still_goes()
    test_a_request_level_shape_with_nothing_to_act_on_says_so()
    test_parameter_pollution_duplicates_and_preserves_a_valueless_parameter()
    test_the_scope_check_runs_on_the_SHAPED_url()
    test_the_run_record_states_what_was_SENT_not_what_was_typed()
    test_shaping_adds_no_gate_field_anywhere()
    test_chunked_suppresses_content_length()
    test_the_preview_and_the_send_use_ONE_derivation()
    print("ALL payload-shaping locks pass")
