"""Interception + history-filter locks (build #19 items 3 and 4).
Run:  python test_intercept.py

*** INTERCEPTION ADDS NO GATE, AND THAT IS ASSERTED HERE RATHER THAN ASSUMED. ***
A request is held, a HUMAN reads it, a HUMAN edits it, a HUMAN forwards it. There is no approval
to bypass because the press IS the approval, and interception only ever REDUCES what reaches the
target. Every route is ungated in BOTH directions, which matters most for "off": while breaking
is on the operator's own browser is frozen, so a gate that could refuse to stop it would be
indistinguishable from the target having gone down.

The measured traps this file locks — every one of them found by `docs/proof/build19_break_api.py`
against a live ZAP 2.17.0, several of them AFTER a first draft had written the opposite down:

  * `http-all` is the ONLY accepted break type
  * `continue` turns breaking OFF; `step` and `drop` leave it on
  * `isBreakRequest` is a SETTING, so `held` must come from the message
  * A DROP WITH NOTHING HELD PERMANENTLY WEDGES THE DAEMON
"""

from __future__ import annotations

import ast
import inspect

from cockpit import intercept, proxy


# --------------------------------------------------------------------------- #
# INTERCEPTION (item 4)
# --------------------------------------------------------------------------- #
def test_http_all_is_the_only_break_type_and_it_is_a_CONSTANT() -> None:
    """`http-request`, `http-response` and `http-sender` all answer `illegal_parameter`. Exposing
    the type as a request field would offer a choice that does not exist."""
    assert intercept.BREAK_TYPE == "http-all"
    src = inspect.getsource(intercept)
    assert "type={BREAK_TYPE}" in src, "the break action no longer uses the constant"
    for model in (intercept.InterceptState,):
        assert "type" not in model.model_fields, "a break TYPE became a request field"
    print("  http-all is the only type, and it is a constant not a parameter: PASS")


def test_held_is_derived_from_the_MESSAGE_never_from_isBreakRequest() -> None:
    """*** `isBreakRequest` IS A SETTING. *** It reads true whenever breaking is switched on,
    with nothing held. A panel wired to it says "a request is waiting" forever."""
    src = inspect.getsource(intercept.observed)
    assert "state.held = bool(state.message)" in src, (
        "`held` is no longer derived from the held message"
    )
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if (isinstance(node, ast.Assign)
                and any(getattr(t, "attr", "") == "held" for t in node.targets)):
            assigned = ast.dump(node.value)
            assert "break_on_request" not in assigned and "isBreakRequest" not in assigned, (
                "`held` is being derived from isBreakRequest, which is a SETTING and not a state"
            )
    print("  `held` comes from the message, never from the isBreakRequest setting: PASS")


def test_a_DROP_WITH_NOTHING_HELD_IS_NEVER_SENT() -> None:
    """*** THE ONE THAT COST A DAY. ***
    One stray `break/action/drop/` against a daemon holding nothing wedges its break manager for
    good: requests keep being held, `httpMessage` returns "" forever, `setHttpMessage` never
    applies. Measured single-variable on FRESH daemons — 23/4 with the stray drop, 27/0 without.

    So both drop sites read the state first. This is NOT a prohibition on the operator: dropping
    nothing was never an action. It is refusing to send an API call that breaks the daemon.
    """
    rel = inspect.getsource(intercept.release)
    assert 'if name == "drop":' in rel, "release() no longer special-cases drop"
    guard_at = rel.find('if name == "drop":')
    send_at = rel.find("_api_get(container, port, path)")
    assert guard_at != -1 and send_at != -1 and guard_at < send_at, (
        "the drop guard runs after the API call — it is not a guard"
    )
    assert "current.held" in rel, "the guard does not consult the observed held state"

    panic = inspect.getsource(intercept.panic)
    tree = ast.parse(panic)
    drops = [n for n in ast.walk(tree)
             if isinstance(n, ast.Call) and "_ACTION_DROP" in ast.dump(n)]
    assert drops, "panic() no longer drops at all"
    # every drop in panic() must sit under `if before.held`
    guarded = [n for n in ast.walk(tree)
               if isinstance(n, ast.If) and "held" in ast.dump(n.test)
               and any("_ACTION_DROP" in ast.dump(c) for c in ast.walk(n))]
    assert guarded, "panic() drops unconditionally — that wedges the daemon it is meant to rescue"
    print("  neither release() nor panic() can send a drop with nothing held: PASS")


def test_panic_DROPS_FIRST_then_turns_breaking_off() -> None:
    """Switching off first leaves the held request held with nothing left to release it through —
    measured as a control request timing out at 15s with breaking already reported off."""
    src = inspect.getsource(intercept.panic)
    drop_at = src.find("_ACTION_DROP")
    off_at = src.find("set_breaking(container, port, False)")
    assert drop_at != -1 and off_at != -1 and drop_at < off_at, (
        "panic() turns breaking off before dropping — that does not restore traffic"
    )
    print("  panic drops first and switches off second: PASS")


def test_continue_turns_breaking_OFF_and_the_product_says_so() -> None:
    """ZAP's break-panel semantics: Continue means "let everything go". An operator forwarding a
    request expecting to catch the next one catches nothing."""
    assert intercept.RELEASE_LEAVES_BREAKING_ON == {
        "continue": False, "step": True, "drop": True}
    src = inspect.getsource(intercept.release)
    assert 'name == "continue"' in src and "TURNED BREAKING OFF" in src, (
        "release() no longer explains that continue also stops breaking"
    )
    print("  continue stops breaking, step and drop do not, and the detail says so: PASS")


def test_every_verb_reads_the_state_BACK_and_never_trusts_the_OK() -> None:
    """An `{\"Result\":\"OK\"}` from this API has already been measured meaning nothing — the
    same endpoint answers OK for a break type that is not real."""
    for fn in (intercept.set_breaking, intercept.replace_held, intercept.release):
        src = inspect.getsource(fn)
        assert "observed(container, port)" in src, (
            f"{fn.__name__} returns without reading the state back"
        )
    print("  set/replace/release all answer with a read-back: PASS")


def test_an_unreadable_daemon_is_NOT_reported_as_not_breaking() -> None:
    """Build #18 item 8's rule. `read_ok` False and `breaking` False must be different facts, or
    the panel draws a dead daemon as a quiet one."""
    # ASSERT THE BEHAVIOUR, NOT A SENTENCE. Build #18 had two locks break on a rename while the
    # property they were written for still held; pinning a literal makes a test that only ever
    # says "you edited a string", which teaches people to update it without reading it.
    real_get = proxy._api_get
    try:
        proxy._api_get = lambda *a, **k: "not json at all"        # the daemon is gone
        dead = intercept.observed("c", 1)
        assert dead.read_ok is False, "an unreadable daemon reported read_ok True"
        assert dead.held is False
        assert dead.detail, "an unreadable daemon said nothing about why"

        proxy._api_get = lambda c, p, path, **k: (
            '{"httpMessage":""}' if "httpMessage" in path
            else '{"isBreakAll":"false"}' if "isBreakAll" in path
            else '{"isBreakRequest":"false"}' if "isBreakRequest" in path
            else '{"isBreakResponse":"false"}'
        )
        quiet = intercept.observed("c", 1)
        assert quiet.read_ok is True, "a healthy daemon holding nothing reported read_ok False"
        assert quiet.held is False and quiet.breaking is False
    finally:
        proxy._api_get = real_get
    print("  an unreadable daemon and a quiet one are different answers, with a control: PASS")


def test_the_replacement_goes_over_POST_never_in_a_URL() -> None:
    """A held request routinely carries a session cookie and an Authorization header. `_api_get`
    would put those in ZAP's own history AND on a `docker exec ... curl ...` argv `ps` can read."""
    src = inspect.getsource(intercept.replace_held)
    assert "_api_post(" in src, "replace_held no longer POSTs"
    assert "_api_get(" not in src, "replace_held sends the edited request through a URL"
    print("  the replaced request travels as a POST body, never a URL: PASS")


def test_INTERCEPTION_ADDS_NO_GATE_ANYWHERE() -> None:
    """*** THE UNRESTRICTIVE REQUIREMENT. ***"""
    src = inspect.getsource(intercept)
    for token in ("approved", "dangerous_ack", "validate_request", "executor"):
        assert token not in src, (
            f"cockpit/intercept.py references {token!r} — interception is human-in-the-loop by "
            "construction and gates nothing"
        )
    assert "InterceptState" in src
    for field in ("approved", "dangerous_ack"):
        assert field not in intercept.InterceptState.model_fields

    from cockpit import router

    for fn in (router.get_intercept, router.set_intercept, router.replace_intercepted,
               router.release_intercepted, router.panic_intercept):
        rsrc = inspect.getsource(fn)
        assert "validate" not in rsrc and "approved" not in rsrc, (
            f"{fn.__name__} grew a gate — every intercept route is ungated in BOTH directions"
        )
    print("  no gate, no confirm and no approval field on any intercept route: PASS")


def test_intercept_reaches_ZAP_through_the_proxy_modules_own_channel() -> None:
    """No new egress path: every call goes through `proxy._api_get` / `_api_post`, which are
    `docker exec` argv-only and already carry the key-off-the-URL discipline."""
    tree = ast.parse(inspect.getsource(intercept))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in ("run", "Popen", "urlopen", "request"):
                raise AssertionError(
                    f"intercept.py calls {node.func.attr} directly — it must reach ZAP only "
                    "through proxy._api_get / _api_post"
                )
    print("  intercept.py spawns nothing and opens no socket of its own: PASS")


# --------------------------------------------------------------------------- #
# HISTORY FILTERING (item 3)
# --------------------------------------------------------------------------- #
def _ex(method="GET", url="https://api.example.com/v1/items?id=1", status=200,
        ctype="application/json", body=""):
    return proxy.CapturedExchange(
        id="x",
        request=proxy.CapturedRequest(method=method, url=url, body=body),
        response=proxy.CapturedResponse(
            status=status,
            headers=[proxy.CapturedHeader(name="Content-Type", value=ctype)]),
    )


def test_an_unset_filter_matches_everything() -> None:
    """The widest possible filter is the default. A filter nobody set is `history` with counting."""
    assert proxy.exchange_matches(_ex(), proxy.HistoryFilter())
    assert proxy.exchange_matches(_ex(status=None, ctype=""), proxy.HistoryFilter())
    print("  an unset filter matches everything, including a response that never arrived: PASS")


def test_a_single_digit_status_means_the_whole_CLASS() -> None:
    assert proxy._status_matches(404, [4]) and proxy._status_matches(499, [4])
    assert not proxy._status_matches(200, [4])
    assert proxy._status_matches(404, [404]) and not proxy._status_matches(403, [404])
    # No HTTP status is one digit, so the two spellings share a field with no mode flag.
    assert not proxy._status_matches(None, [4]), "a response that never arrived matched a class"
    print("  4 means 4xx, 404 means 404, and a missing status matches neither: PASS")


def test_the_host_filter_uses_THE_SCOPE_PARSER_not_a_second_matcher() -> None:
    """A host filter that meant something different here than in a scope field is how
    `notexample.com` gets to match `example.com`."""
    src = inspect.getsource(proxy.exchange_matches)
    assert "scope_mod.parse_scope(" in src, "the host filter re-implements host matching"
    ex = _ex(url="https://api.example.com/x")
    assert proxy.exchange_matches(ex, proxy.HistoryFilter(host="*.example.com"))
    assert proxy.exchange_matches(ex, proxy.HistoryFilter(host="api.example.com"))
    assert not proxy.exchange_matches(ex, proxy.HistoryFilter(host="*.notexample.com"))
    print("  the host filter is the engagement scope vocabulary, dot-anchored: PASS")


def test_has_param_None_is_BOTH_and_False_is_a_real_filter() -> None:
    """An unchecked box must not silently become a filter."""
    withp, without = _ex(url="https://h/x?a=1"), _ex(url="https://h/x")
    assert proxy.exchange_matches(withp, proxy.HistoryFilter(has_param=None))
    assert proxy.exchange_matches(without, proxy.HistoryFilter(has_param=None))
    assert proxy.exchange_matches(withp, proxy.HistoryFilter(has_param=True))
    assert not proxy.exchange_matches(without, proxy.HistoryFilter(has_param=True))
    assert proxy.exchange_matches(without, proxy.HistoryFilter(has_param=False))
    print("  has_param None is both; True and False are each a real filter: PASS")


def test_the_result_reports_scanned_matched_dropped_and_truncated() -> None:
    """*** THE COUNTS ARE THE FEATURE. *** An empty `exchanges` is four different facts and the
    operator must be able to tell which."""
    for field in ("total", "scanned", "matched", "returned", "dropped", "read_ok", "truncated"):
        assert field in proxy.FilteredHistory.model_fields, f"{field} is not reported"
    src = inspect.getsource(proxy.filter_history)
    assert "out.truncated = out.read_ok and offset < out.total" in src, (
        "truncated is not derived from how far the scan actually got"
    )
    print("  every count is reported and truncated is never silently false: PASS")


def test_an_inactive_engagement_IGNORES_the_scope_filter_rather_than_refusing() -> None:
    """This is a read of traffic that already happened. Refusing to show an operator their own
    capture because an engagement ended would be a prohibition invented by the tooling."""
    src = inspect.getsource(proxy.filter_history)
    assert "scope_note" in src and "was IGNORED" in src
    tree = ast.parse(src)
    assert not [n for n in ast.walk(tree) if isinstance(n, ast.Raise)], (
        "filter_history raises — a read must not refuse"
    )
    print("  an inactive engagement drops the filter and says so, refusing nothing: PASS")


def test_the_filter_route_is_UNGATED_and_executes_nothing() -> None:
    from cockpit import router

    src = inspect.getsource(router.proxy_history_filter)
    for token in ("approved", "dangerous_ack", "validate"):
        assert token not in src, f"the history filter route grew {token!r} — it is a READ"
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert node.func.attr not in ("run", "Popen", "start_scan", "start_proxy"), (
                f"the filter route reaches {node.func.attr}"
            )
    print("  the filter route is ungated and reaches no execution path: PASS")


def test_the_scan_walks_the_WHOLE_capture_not_one_window() -> None:
    """A filter that silently searched only the newest window would be `history`'s own build #17
    defect in a new place, with a scarier failure: "there are no 500s on this target" is a
    conclusion someone acts on."""
    src = inspect.getsource(proxy.filter_history)
    assert "while offset < out.total and remaining_scan > 0:" in src, (
        "filter_history no longer loops over the whole capture"
    )
    assert proxy.HISTORY_SCAN_CAP >= 5000, "the default scan reach no longer covers a real capture"
    print("  the scan pages through the whole capture, bounded and reported: PASS")


if __name__ == "__main__":
    print("== interception (item 4) ==")
    test_http_all_is_the_only_break_type_and_it_is_a_CONSTANT()
    test_held_is_derived_from_the_MESSAGE_never_from_isBreakRequest()
    test_a_DROP_WITH_NOTHING_HELD_IS_NEVER_SENT()
    test_panic_DROPS_FIRST_then_turns_breaking_off()
    test_continue_turns_breaking_OFF_and_the_product_says_so()
    test_every_verb_reads_the_state_BACK_and_never_trusts_the_OK()
    test_an_unreadable_daemon_is_NOT_reported_as_not_breaking()
    test_the_replacement_goes_over_POST_never_in_a_URL()
    test_INTERCEPTION_ADDS_NO_GATE_ANYWHERE()
    test_intercept_reaches_ZAP_through_the_proxy_modules_own_channel()
    print("== history filtering (item 3) ==")
    test_an_unset_filter_matches_everything()
    test_a_single_digit_status_means_the_whole_CLASS()
    test_the_host_filter_uses_THE_SCOPE_PARSER_not_a_second_matcher()
    test_has_param_None_is_BOTH_and_False_is_a_real_filter()
    test_the_result_reports_scanned_matched_dropped_and_truncated()
    test_an_inactive_engagement_IGNORES_the_scope_filter_rather_than_refusing()
    test_the_filter_route_is_UNGATED_and_executes_nothing()
    test_the_scan_walks_the_WHOLE_capture_not_one_window()
    print("ALL interception + history-filter locks pass")
