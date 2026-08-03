"""ZAP active-scan gating locks.  Run:  python test_zap_scan_safety.py

THE INVARIANT: a scan start passes the real executor gates, and THE HOST THE GATE SCOPED IS THE
HOST THE API ATTACKS.

That second half is deliberately NOT phrased as build #14 part 2's lock ("the gated argv is the
spawned argv"). It cannot be: the gate classifies an ARGV and what executes is a URL, so string
equality between them would be theatre. The property underneath part 2's lock is what actually
matters, and it is what these tests assert.
"""

from __future__ import annotations

from cockpit import config, proxy

LAB_URL = f"http://{config.LAB_TARGET_HOST}:3000/rest/products/search?q=measure"


def _req(**kw):
    base = dict(target_url=LAB_URL, approved=True, dangerous_ack=True, engagement_id=None)
    base.update(kw)
    return proxy.ScanStartRequest(**base)


def test_an_unapproved_scan_is_refused_with_a_control() -> None:
    """approved=False must refuse. The control is in THIS test: the same request WITH approval
    must not be refused at the approval gate, or the check passes for the wrong reason."""
    rejected = proxy.validate_scan(_req(approved=False))
    assert rejected is not None, "an unapproved active scan was NOT refused"
    assert rejected.gate == "approval", f"refused at {rejected.gate!r}, expected 'approval'"

    other = proxy.validate_scan(_req(approved=True))
    assert other is None or other.gate != "approval", (
        "the approval gate still fires with approved=True — it is not reading the field"
    )
    print("  an unapproved scan is refused at the approval gate, control holds: PASS")


def test_the_red_confirm_is_required() -> None:
    """An active scan sends real SQLi/XSS/command-injection payloads at every parameter —
    MEASURED at 376 requests against ONE endpoint, finding a live High SQL injection. If this
    ever says 'approval' instead of 'danger', the danger heuristic stopped seeing `-quickurl`
    and the red-confirm has become decorative (gate-audit finding I2's shape)."""
    rejected = proxy.validate_scan(_req(dangerous_ack=False))
    assert rejected is not None, "an active scan with no red-confirm was NOT refused"
    assert rejected.gate == "danger", (
        f"refused at {rejected.gate!r}, expected 'danger' — the danger heuristic is not flagging "
        "the equivalent argv as an attack"
    )

    other = proxy.validate_scan(_req(dangerous_ack=True))
    assert other is None or other.gate != "danger", (
        "the danger gate still fires with dangerous_ack=True — it is not reading the field"
    )
    print("  a scan without the red-confirm is refused at the danger gate, control holds: PASS")


def test_an_off_lab_target_is_refused_by_the_real_scope_gate() -> None:
    """*** THE REASON THE FULL URL GOES IN THE SURFACE. ***

    The scan target is the one part of this request that names somewhere in the world. It is put
    in the gate surface precisely so the EXISTING scope extractor reads it — no new gate, no new
    scope logic. The control proves the gate is reading the target rather than refusing
    everything: the lab URL, same request otherwise, is allowed.
    """
    rejected = proxy.validate_scan(_req(target_url="http://example.com/x?a=1"))
    assert rejected is not None, "a scan against example.com was NOT refused in lab mode"
    assert rejected.gate == "target", (
        f"refused at {rejected.gate!r}, expected 'target' — if this is not the target gate then "
        "the scope extractor is not seeing the host inside the URL, and an out-of-scope scan "
        "would only be stopped by luck"
    )
    # CONTROL, written to stay HERMETIC. The lab target must not be refused at the TARGET gate —
    # it may still be refused at `sandbox`, because the isolation gate asks whether Docker is up
    # and CI has no Docker. Asserting `is None` here passed locally and would fail in CI, which
    # is a test quietly depending on the developer's stack being up; part 2's locks phrase every
    # control this way for the same reason.
    other = proxy.validate_scan(_req())
    assert other is None or other.gate != "target", (
        "the lab target is refused at the target gate too — the gate is refusing every host, so "
        "the check above proves nothing"
    )
    print("  an off-lab scan target is refused at the target gate, control holds: PASS")


def test_the_scoped_host_is_the_attacked_host() -> None:
    """*** THE CRITICAL 2 PROPERTY, IN THE ONLY FORM IT CAN TAKE HERE. ***

    One derivation (scan_target_for) feeds BOTH the gate surface and the API url= parameter. If
    they ever drift, the operator approves a scan of one host while another is attacked — which
    is Critical 2 exactly, just not expressed in an argv.

    Asserted for a target carrying a port, a path AND a query string, because those are the parts
    a naive split or a re-parse would lose.
    """
    from urllib.parse import parse_qs, unquote, urlparse

    from cockpit import executor

    req = _req()
    target = proxy.scan_target_for(req)

    # the gate side — read the host out with the SAME helpers check_target_lock uses, so this
    # asserts what the gate actually sees rather than what a second parser would have seen.
    surface = proxy._gate_scan_request(req)
    assert target in surface.args, (
        f"the gate surface {surface.args!r} does not contain the derived target {target!r}"
    )
    gated_hosts = [executor._host_of(a) for a in surface.args if executor._looks_like_host(a)]
    assert gated_hosts == [config.LAB_TARGET_HOST], (
        f"the target gate reads hosts {gated_hosts!r} out of the surface — it must be exactly "
        "the scanned host. Anything else means the gate is scoping something other than what "
        "gets attacked."
    )

    # the API side — decode url= back out and confirm it is the SAME host
    query = parse_qs(proxy.scan_url_for(req).split("?", 1)[1])
    attacked = unquote(query["url"][0])
    assert attacked == target, f"the API attacks {attacked!r} but the gate scoped {target!r}"
    assert urlparse(attacked).hostname == config.LAB_TARGET_HOST, (
        f"the attacked host is {urlparse(attacked).hostname!r}, not the scoped lab host"
    )
    print("  the host the gate scoped is the host the API attacks: PASS")


def test_the_target_cannot_inject_zap_api_parameters() -> None:
    """*** A DEFECT CLASS THAT DID NOT EXIST BEFORE THIS BUILD. ***

    The target is interpolated into a URL that carries THE SCAN'S OWN PARAMETERS:

        /JSON/ascan/action/scan/?url=<TARGET>&recurse=false

    A target containing `&recurse=true` would append to ZAP's parameter list and broaden the scan
    the human approved. Nothing about a URL text field stops an `&`. quote(safe="") is what does.

    The CONTROL matters as much as the check: `recurse=true` must still be settable the legitimate
    way, or this test would also pass on a build where recursion silently never worked.
    """
    from urllib.parse import parse_qs

    evil = "http://" + config.LAB_TARGET_HOST + ":3000/x&recurse=true&inScopeOnly=true"
    query = parse_qs(proxy.scan_url_for(_req(target_url=evil, recurse=False)).split("?", 1)[1])

    assert query["recurse"] == ["false"], (
        f"a target containing '&recurse=true' turned recursion ON: recurse={query['recurse']!r}. "
        "The target is not being percent-encoded, so it can rewrite the scan the operator approved."
    )
    assert query["inScopeOnly"] == ["false"], (
        f"the target injected inScopeOnly={query['inScopeOnly']!r}"
    )
    assert len(query["url"]) == 1 and evil in query["url"][0], (
        f"the target did not survive intact as a single url parameter: {query['url']!r}"
    )

    # control: the legitimate route to recursion still works
    legit = parse_qs(proxy.scan_url_for(_req(recurse=True)).split("?", 1)[1])
    assert legit["recurse"] == ["true"], (
        f"recurse=True does not set recurse=true ({legit['recurse']!r}) — the check above would "
        "pass on a build where recursion never worked at all"
    )
    print("  a target carrying '&recurse=true' cannot broaden the scan, control holds: PASS")


def test_a_non_http_target_is_refused_before_any_gate() -> None:
    """A target with no host would reach the target gate as a target-less command — refused for a
    confusing reason in lab mode, and in engagement mode (where target-less IS permitted) not
    refused here at all. Refusing the shape up front means the surface always carries a real host.
    """
    for bad in ("file:///etc/passwd", "hackpit-lab-target:3000", "", "ftp://x/y"):
        try:
            proxy.ScanStartRequest(target_url=bad, approved=True, dangerous_ack=True)
        except Exception:
            continue
        raise AssertionError(f"a non-http target was accepted: {bad!r}")

    # control: a real URL is still accepted
    proxy.ScanStartRequest(target_url=LAB_URL, approved=True, dangerous_ack=True)
    print("  non-http targets are refused at construction, control holds: PASS")


def test_nothing_is_attacked_on_a_refusal() -> None:
    """*** THE GATE RUNS BEFORE ZAP IS CONTACTED AT ALL. *** Source-level, because the
    alternative is launching a real active scan from a unit test."""
    import inspect

    src = inspect.getsource(proxy.start_scan)
    gate_at = src.find("validate_scan")
    call_at = src.find("_api_get")
    assert gate_at != -1, "start_scan never calls validate_scan"
    assert call_at != -1, "start_scan never calls the API"
    assert gate_at < call_at, (
        "start_scan contacts ZAP before it gates — a refused scan would already have launched"
    )
    print("  the gate is checked before ZAP is contacted: PASS")


def test_the_concurrency_bound_is_observed_not_remembered() -> None:
    """A second concurrent scan doubles attack traffic against a target approved once. The refusal
    reads ZAP's own scan list rather than a backend dict, so a restart cannot lose the fact — the
    same 'observed, never assigned' rule lifecycle.observe follows."""
    import inspect

    src = inspect.getsource(proxy.start_scan)
    assert "observed_scans" in src and "is_running" in src, (
        "start_scan does not check ZAP's observed scan list — if it tracks concurrency in local "
        "state instead, a backend restart silently permits a second concurrent scan"
    )
    print("  the one-scan-at-a-time bound is read from ZAP, not from local state: PASS")


def test_stopping_a_scan_is_not_gated() -> None:
    """Stopping an in-flight scan REMOVES attack traffic — hundreds of requests per endpoint are
    live when this is called. It is the strongest case in the codebase for an ungated stop, and
    it is restated here so a later 'for consistency' edit has to argue with it."""
    import inspect

    src = inspect.getsource(proxy.stop_scan)
    assert "validate_scan" not in src and "validate_request" not in src, (
        "stop_scan runs a gate — a gate that can refuse to stop a live active scan makes the "
        "system less safe"
    )
    print("  stopping a scan is not gated: PASS")


def test_the_action_urls_are_only_reachable_from_the_gated_path() -> None:
    """*** THE ONE-MODULE DECISION, WRITTEN AS A CHECK RATHER THAN A HOPE (spec §6). ***

    Zaid declined the module split and declined a guard, so nothing STRUCTURAL stops the ungated
    reader from gaining an action URL. This does not add the declined guard — it asserts the far
    weaker, factual thing the decision left true today: the scan action URL appears in exactly
    one function, and that function gates. If a second function ever issues it, this fails and
    the reviewer gets to make the decision consciously instead of by accident.
    """
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(proxy))
    funcs = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]

    def reads_name(fn: ast.FunctionDef, wanted: str) -> bool:
        """Does this function REFERENCE the name — as a load or a call, not in prose?

        AST, not a substring search over the source. A substring scan reports every function
        whose DOCSTRING mentions the name, which it did on the first run of this very test:
        `scan_target_for` documents its relationship to `scan_url_for` and was flagged as a
        caller. Same lesson build #8 recorded for payload strings.
        """
        return any(isinstance(n, ast.Name) and n.id == wanted for n in ast.walk(fn))

    issuers = sorted(f.name for f in funcs if reads_name(f, "_ACTION_SCAN"))
    assert issuers == ["scan_url_for"], (
        f"the scan action URL is built in {issuers!r}. It must be built in exactly one place "
        "(scan_url_for), whose only caller is the gated start_scan — see the URL constant block."
    )
    callers = sorted(
        f.name for f in funcs if f.name != "scan_url_for" and reads_name(f, "scan_url_for")
    )
    assert callers == ["start_scan"], (
        f"scan_url_for is called from {callers!r}. Only start_scan may call it, because only "
        "start_scan runs executor.validate_request first. A caller on the ungated read path is "
        "the exact risk the one-module decision accepted as residual — it is not meant to arrive."
    )
    print("  the scan action URL is built once and reached only from the gated start: PASS")


def test_the_container_follows_the_mode() -> None:
    """A scan drives the daemon a start put in a particular container. If the two disagreed, a lab
    scan would talk to a port in the fully-open box — reach the gate never scoped."""
    assert proxy.container_for(_req(engagement_id=None)) == config.SANDBOX_CONTAINER
    assert proxy.container_for(_req(engagement_id="e1")) == config.ENGAGE_SANDBOX_CONTAINER
    print("  lab -> isolated sandbox, engagement -> engage sandbox: PASS")


if __name__ == "__main__":
    test_an_unapproved_scan_is_refused_with_a_control()
    test_the_red_confirm_is_required()
    test_an_off_lab_target_is_refused_by_the_real_scope_gate()
    test_the_scoped_host_is_the_attacked_host()
    test_the_target_cannot_inject_zap_api_parameters()
    test_a_non_http_target_is_refused_before_any_gate()
    test_nothing_is_attacked_on_a_refusal()
    test_the_concurrency_bound_is_observed_not_remembered()
    test_stopping_a_scan_is_not_gated()
    test_the_action_urls_are_only_reachable_from_the_gated_path()
    test_the_container_follows_the_mode()
    print("ALL ZAP active-scan gating locks pass")
