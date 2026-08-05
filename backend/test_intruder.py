"""Intruder locks (build #19 item 5).  Run:  python test_intruder.py

*** THE ARGUMENT THIS FILE ENFORCES. ***
HackPit refuses BATCHING ACROSS APPROVALS — an agent queueing five commands behind one human
click. It has never refused ONE approval that produces many requests, and could not: `ffuf`,
`nuclei` and the ZAP active scanner are each a single approval buying thousands, and the
scanner's own measurement was 376 requests from one press. An intruder is that same shape.

So this file asserts THE FOUR GATES AND NO NEW ONES, in both directions, and it asserts the two
properties that make a single approval honest:

  * the payload set is IN the approved surface, complete and untruncated
  * the per-request scope check runs on the SUBSTITUTED url, not the marked one

THE RED-CONFIRM IS THE GATE'S TO DEMAND, NOT THIS MODULE'S. A payload set of ordinary injection
strings does not trip the danger gate; one carrying `| sh` does. Requiring the ack unconditionally
would be this build adding a confirm, which it may not.
"""

from __future__ import annotations

import ast
import inspect

from cockpit import config, executor, intruder, shaping


def _req(**kw):
    base = dict(url=f"http://{config.LAB_TARGET_HOST}/x?id=[[1]]", payloads=["a"], approved=True)
    base.update(kw)
    return intruder.IntruderRequest(**base)


# --------------------------------------------------------------------------- #
# positions + substitution
# --------------------------------------------------------------------------- #
def test_positions_reuse_the_SHAPING_marker_and_not_a_second_vocabulary() -> None:
    """`[[...]]` already means "the interesting span of this request" everywhere in the product.
    A second marker would make a marked request mean different things in two panels."""
    assert intruder.POSITION_OPEN == shaping.SHAPE_OPEN
    assert intruder.POSITION_CLOSE == shaping.SHAPE_CLOSE
    print("  positions use the shaping marker, one vocabulary: PASS")


def test_an_unclosed_marker_is_NOT_a_position() -> None:
    """Treating it as one would swallow the rest of the request into a payload slot."""
    assert intruder.find_positions("https://h/x?a=[[unclosed&b=2") == []
    assert len(intruder.find_positions("https://h/x?a=[[1]]&b=[[2]]")) == 2
    print("  an unclosed marker is not a position; two closed ones are: PASS")


def test_SNIPER_leaves_the_other_positions_at_their_BASELINE() -> None:
    """*** NOT AT AN EMPTY STRING. *** A sniper run that blanked the other parameters would change
    two things at once and make every result uninterpretable."""
    out = intruder.substitute("https://h/x?id=[[1]]&q=[[apple]]", "PAY", 0)
    assert out == "https://h/x?id=PAY&q=apple", out
    out2 = intruder.substitute("https://h/x?id=[[1]]&q=[[apple]]", "PAY", 1)
    assert out2 == "https://h/x?id=1&q=PAY", out2
    print("  sniper changes one position and keeps the others' baseline values: PASS")


def test_BATTERING_RAM_fills_every_position() -> None:
    out = intruder.substitute("https://h/x?id=[[1]]&q=[[apple]]", "PAY")
    assert out == "https://h/x?id=PAY&q=PAY", out
    print("  battering-ram fills every position: PASS")


def test_the_baseline_request_is_the_MARKERS_STRIPPED_request() -> None:
    """The control half of every measurement, and the same function build #18 established for it.
    Without it "this response is different" has nothing to be different from."""
    src = inspect.getsource(intruder._run)
    assert "shaping.strip_markers(req.url)" in src, "the baseline is not the unmarked request"
    assert "baseline = record(" in src
    assert src.find("baseline = record(") < src.find("for i, (position, payload)"), (
        "the baseline is sent AFTER the payloads — every row would be compared against nothing"
    )
    print("  the baseline is the marker-stripped request and it is sent FIRST: PASS")


def test_payload_shaping_REUSES_build_18s_transforms() -> None:
    """"Do not grow a second encoder" — the transforms are shared; only the call site differs."""
    src = inspect.getsource(intruder.shape_payload)
    assert "shaping.VALUE_TRANSFORMS" in src
    out, unknown = intruder.shape_payload("1 OR 1=1", ["sql-comment"])
    assert out == "1/**/OR/**/1=1", out
    assert unknown == []
    out2, unknown2 = intruder.shape_payload("x", ["not-a-shape"])
    assert out2 == "x" and unknown2 == ["not-a-shape"], (out2, unknown2)
    print("  payloads go through the shared transforms; an unknown name is returned: PASS")


# --------------------------------------------------------------------------- #
# THE GATE — the scanner's four, unchanged
# --------------------------------------------------------------------------- #
def _not_refused_at(verdict, gate: str) -> bool:
    """*** "NOT REFUSED AT **THIS** GATE", NEVER A BARE "NOT REFUSED". ***

    A fully approved in-lab job legitimately ends at ``gate='sandbox'`` when Docker is absent —
    which is CI, and which is also the docker-stripped local run this repo requires. Asserting
    `verdict is None` made this file depend on Docker, and the strip caught it: that is the THIRD
    time a test in this repo has quietly required a running stack, after two CI catches in
    build #14 part 3 and build #15. The isolation gate firing is not evidence that the approval,
    target or danger gate failed.
    """
    return verdict is None or verdict.gate != gate


def test_all_four_gates_fire_EACH_WITH_A_CONTROL() -> None:
    """Each gate is shown firing, and each control is phrased "not refused at THIS gate"."""
    ok = intruder.validate(_req())
    for gate in ("approval", "target", "danger"):
        assert _not_refused_at(ok, gate), f"an approved in-lab job was refused at {gate}: {ok}"

    unapproved = intruder.validate(_req(approved=False))
    assert unapproved is not None and unapproved.gate == "approval", unapproved

    offlab = intruder.validate(_req(url="http://example.com/x?id=[[1]]"))
    assert offlab is not None and offlab.gate == "target", offlab

    shelly = intruder.validate(_req(payloads=["x| sh"]))
    assert shelly is not None and shelly.gate == "danger", shelly
    assert any("| sh" in f for f in shelly.dangerous_flags), shelly.dangerous_flags
    # ...and the ack clears THAT gate, which is what makes it a confirm rather than a blocklist.
    acked = intruder.validate(_req(payloads=["x| sh"], dangerous_ack=True))
    assert _not_refused_at(acked, "danger"), (
        f"the red-confirm did not clear the danger gate: {acked}"
    )
    print("  approval / target / danger each fire, and the ack clears danger "
          "(controls phrased per-gate, so this runs without Docker): PASS")


def test_THE_PAYLOAD_SET_IS_IN_THE_APPROVED_SURFACE_AND_IS_NOT_TRUNCATED() -> None:
    """*** CRITICAL 2 IN A PAYLOAD LIST. ***
    Rendering "…and 4,993 more" would let a payload carrying `| sh` sit at position 5,000 where
    the danger heuristic cannot see it, while the human approves a summary."""
    payloads = [f"p{i}" for i in range(200)] + ["evil| sh"]
    argv = intruder.intruder_argv_for(_req(payloads=payloads))
    joined = " ".join(argv)
    for p in payloads:
        assert p in joined, f"payload {p!r} is missing from the approved surface"
    assert "more" not in joined.lower() or "evil| sh" in joined
    # ...and the gate SEES it, which is the whole reason completeness matters.
    verdict = intruder.validate(_req(payloads=payloads))
    assert verdict is not None and verdict.gate == "danger", (
        "a shell payload at position 200 did not reach the danger gate"
    )
    print("  every payload is in the surface, and one at position 200 still trips danger: PASS")


def test_the_positions_are_visible_in_the_surface() -> None:
    """A human approving must be able to see WHERE the payloads land, not only what they are."""
    argv = intruder.intruder_argv_for(_req(url=f"http://{config.LAB_TARGET_HOST}/x?id=[[1]]"))
    assert any("[[1]]" in a for a in argv), argv
    print("  the marked URL is in the approved surface: PASS")


def test_the_gate_surface_and_the_validated_request_are_ONE_DERIVATION() -> None:
    """The scanner's rule: the thing the gate scoped is the thing that gets attacked."""
    src = inspect.getsource(intruder._gate_request)
    assert "intruder_argv_for(req)" in src, "_gate_request builds its own argv"
    vsrc = inspect.getsource(intruder.validate)
    assert "_gate_request(req)" in vsrc
    ssrc = inspect.getsource(intruder.start)
    assert "validate(req)" in ssrc, "start() does not run the shared validator"
    print("  gate surface, validate and start all come through one derivation: PASS")


def test_the_gate_runs_BEFORE_anything_is_sent() -> None:
    src = inspect.getsource(intruder.start)
    gate_at = src.find("validate(req)")
    thread_at = src.find("threading.Thread")
    assert gate_at != -1 and thread_at != -1 and gate_at < thread_at, (
        "start() spawns the worker before validating — an unapproved job would send traffic"
    )
    print("  validation happens before the worker thread exists: PASS")


def test_the_scope_check_runs_PER_REQUEST_on_the_SUBSTITUTED_url() -> None:
    """Not once at the start. A payload can contain a '.' and a '/', and a marked span inside the
    HOST would otherwise send the substituted request somewhere the gate never saw."""
    src = inspect.getsource(intruder._run)
    assert "_scope_ok(req, url)" in inspect.getsource(intruder._run) or "_scope_ok" in src
    rec = src[src.find("def record("):src.find("# THE BASELINE FIRST")]
    assert "_scope_ok(req, url)" in rec, "the scope check does not read the substituted url"
    assert rec.find("_scope_ok") < rec.find("_send_one"), (
        "the request is sent before the scope check"
    )
    print("  every substituted URL is scope-checked before that request is sent: PASS")


def test_an_off_scope_payload_COUNTS_and_the_job_CONTINUES() -> None:
    """WARN AND CONTINUE. One payload that walks off-scope must not throw away the other 4,999."""
    src = inspect.getsource(intruder._run)
    assert "j.scope_refusals += 1" in src
    assert "return IntruderResult(" in src, "an off-scope payload aborts instead of being counted"
    assert "scope_refusals" in intruder.IntruderJob.model_fields
    print("  an off-scope substitution is counted and the job carries on: PASS")


# --------------------------------------------------------------------------- #
# planning, bounds, stop
# --------------------------------------------------------------------------- #
def test_no_positions_marked_WARNS_and_expands_nothing() -> None:
    """Every request would be identical. Saying so beats sending 5,000 copies of one request."""
    work, warnings, capped = intruder.plan(_req(url=f"http://{config.LAB_TARGET_HOST}/x?id=1"))
    assert work == [] and not capped
    assert any("no [[" in w for w in warnings), warnings
    print("  an unmarked request expands to nothing and says why: PASS")


def test_an_unknown_mode_falls_back_and_SAYS_SO_rather_than_refusing() -> None:
    work, warnings, _ = intruder.plan(_req(mode="clusterbomb", payloads=["a", "b"]))
    assert len(work) == 2, work
    assert any("unknown mode" in w for w in warnings), warnings
    print("  an unknown mode runs as sniper and warns; it does not refuse: PASS")


def test_the_ceiling_CAPS_AND_REPORTS_rather_than_refusing() -> None:
    """A silent truncation would tell the operator the payload set had been exhausted when it
    had not."""
    big = [f"p{i}" for i in range(intruder.INTRUDER_MAX_REQUESTS + 50)]
    work, warnings, capped = intruder.plan(_req(payloads=big))
    assert capped is True
    assert len(work) == intruder.INTRUDER_MAX_REQUESTS
    assert any("ceiling" in w for w in warnings), warnings
    assert any("NOT refused" in w for w in warnings), warnings
    print("  the ceiling caps, reports and does not refuse: PASS")


def test_sniper_multiplies_by_POSITIONS_and_battering_ram_does_not() -> None:
    two = f"http://{config.LAB_TARGET_HOST}/x?a=[[1]]&b=[[2]]"
    sniper, _, _ = intruder.plan(_req(url=two, payloads=["x", "y"], mode="sniper"))
    ram, _, _ = intruder.plan(_req(url=two, payloads=["x", "y"], mode="battering-ram"))
    assert len(sniper) == 4, len(sniper)
    assert len(ram) == 2, len(ram)
    print("  sniper is payloads x positions; battering-ram is payloads: PASS")


def test_STOP_IS_UNGATED() -> None:
    """Thousands of requests may be queued. A gate that could refuse to stop them would make the
    system less safe — the position every other stop in this codebase takes."""
    src = inspect.getsource(intruder.stop)
    for token in ("approved", "dangerous_ack", "validate", "executor"):
        assert token not in src, f"stop() consults {token!r}"
    from cockpit import router

    rsrc = inspect.getsource(router.stop_intruder_job)
    for token in ("approved", "dangerous_ack", "validate"):
        assert token not in rsrc, f"the stop route consults {token!r}"
    print("  stop is ungated in the module and on the route: PASS")


def test_the_preview_SENDS_NOTHING_and_uses_the_same_functions() -> None:
    from cockpit import router

    src = inspect.getsource(router.intruder_preview)
    assert "intruder_mod.plan(" in src and "intruder_mod.validate(" in src
    assert "intruder_mod.start(" not in src, "the preview route can start a job"
    tree = ast.parse(inspect.getsource(intruder.plan))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert node.func.attr not in ("run", "Popen"), "plan() spawns a process"
    print("  the preview reuses plan+validate and spawns nothing: PASS")


def test_the_container_is_a_CONSTANT_never_a_request_field() -> None:
    """No new egress path, and nothing in a request can redirect where traffic leaves from."""
    for field in ("container", "target", "host", "sandbox"):
        assert field not in intruder.IntruderRequest.model_fields, (
            f"IntruderRequest grew a {field!r} field — the box must be a code constant"
        )
    src = inspect.getsource(intruder._send_one)
    assert "config.KALI_OPEN_CONTAINER" in src
    print("  the sandbox is a code constant, not a request field: PASS")


def test_the_run_record_does_NOT_carry_the_payload_set() -> None:
    """report.py renders a run record's command line verbatim into a report, and a payload set is
    both enormous and occasionally a credential list."""
    src = inspect.getsource(intruder._run)
    rec = src[src.find("RunRecord("):]
    assert "req.payloads" not in rec, "the run record carries every payload into the report"
    assert "strip_markers(req.url)" in rec
    print("  the run record carries counts and the URL, never the payload set: PASS")


def test_the_declared_command_is_HONEST_because_there_is_no_allowlist_to_hide_behind() -> None:
    """*** A CORRECTION THIS FILE MADE TO ITS OWN FIRST DRAFT. ***
    The first version asserted "ffuf is in the allowlist". THERE IS NO TOOL ALLOWLIST — the
    module that sounds like one says so in its own comment: `SUGGESTED_COMMANDS` is
    "Informational only ... NOT an allowlist; anything may run". The gates are approval, target,
    danger and isolation, and none of them consults a list of permitted binaries.

    So membership proves nothing and the real property is different: the declared command must
    DESCRIBE what runs, because that string is what a human approves and what the danger
    heuristic reads. `ffuf` is a marked request plus a wordlist, which is exactly this feature.
    """
    argv = intruder.intruder_argv_for(_req())
    assert argv[0] == "ffuf", argv
    from cockpit import allowlist

    assert not hasattr(allowlist, "ALLOWED_TOOLS"), (
        "an ALLOWED_TOOLS list appeared — if HackPit has grown a binary allowlist, this test's "
        "argument changes and the intruder's declared command has to be re-checked against it"
    )
    assert any(name == "ffuf" for name, _ in allowlist.SUGGESTED_COMMANDS), (
        "ffuf is no longer even a suggested command — check the declared surface still names "
        "something an operator would recognise"
    )
    print("  the declared command is honest, and there is no allowlist to be in: PASS")


def test_the_intruder_adds_NO_NEW_GATE_to_the_executor() -> None:
    """*** THE FOUR GATES, NO NEW ONES. *** The module must run the executor's validator and not
    grow a check of its own."""
    src = inspect.getsource(intruder)
    assert "executor.validate_request" in src
    tree = ast.parse(src)
    # No refusal may be raised outside start()'s own availability/gate relay.
    raisers = {
        node.lineno for node in ast.walk(tree)
        if isinstance(node, ast.Raise) and "IntruderRefused" in ast.dump(node)
    }
    start_src = inspect.getsource(intruder.start)
    assert start_src.count("raise IntruderRefused") == 2, (
        f"IntruderRefused is raised {start_src.count('raise IntruderRefused')} times in start() — "
        "there should be exactly two: the gate verdict relay and the sandbox availability check"
    )
    assert len(raisers) == 2, f"IntruderRefused raised at {len(raisers)} sites across the module"
    print("  the module relays the executor's verdict and invents no gate of its own: PASS")


def test_ffufs_own_gating_is_UNCHANGED_by_this_build() -> None:
    """*** THE ONE THIS BUILD MUST NOT HAVE DONE. ***
    Making the intruder feel dangerous by declaring `ffuf` an attack tool would have added a
    red-confirm to every existing ffuf run in the product — a confirm this build is not allowed
    to add. The gate's verdict on a plain ffuf must be exactly what it was."""
    from cockpit.models import ExecRequest

    plain = executor.validate_request(ExecRequest(
        command="ffuf", args=["-u", f"http://{config.LAB_TARGET_HOST}/FUZZ", "-w", "/list"],
        approved=True, dangerous_ack=False))
    assert _not_refused_at(plain, "danger"), (
        f"a plain in-lab ffuf now needs a red-confirm ({plain}) — build #19 added a confirm to an "
        "existing tool, which it may not"
    )
    print("  a plain ffuf still needs no red-confirm — no confirm was added: PASS")


if __name__ == "__main__":
    print("== intruder (build #19 item 5) ==")
    test_positions_reuse_the_SHAPING_marker_and_not_a_second_vocabulary()
    test_an_unclosed_marker_is_NOT_a_position()
    test_SNIPER_leaves_the_other_positions_at_their_BASELINE()
    test_BATTERING_RAM_fills_every_position()
    test_the_baseline_request_is_the_MARKERS_STRIPPED_request()
    test_payload_shaping_REUSES_build_18s_transforms()
    test_all_four_gates_fire_EACH_WITH_A_CONTROL()
    test_THE_PAYLOAD_SET_IS_IN_THE_APPROVED_SURFACE_AND_IS_NOT_TRUNCATED()
    test_the_positions_are_visible_in_the_surface()
    test_the_gate_surface_and_the_validated_request_are_ONE_DERIVATION()
    test_the_gate_runs_BEFORE_anything_is_sent()
    test_the_scope_check_runs_PER_REQUEST_on_the_SUBSTITUTED_url()
    test_an_off_scope_payload_COUNTS_and_the_job_CONTINUES()
    test_no_positions_marked_WARNS_and_expands_nothing()
    test_an_unknown_mode_falls_back_and_SAYS_SO_rather_than_refusing()
    test_the_ceiling_CAPS_AND_REPORTS_rather_than_refusing()
    test_sniper_multiplies_by_POSITIONS_and_battering_ram_does_not()
    test_STOP_IS_UNGATED()
    test_the_preview_SENDS_NOTHING_and_uses_the_same_functions()
    test_the_container_is_a_CONSTANT_never_a_request_field()
    test_the_run_record_does_NOT_carry_the_payload_set()
    test_the_declared_command_is_HONEST_because_there_is_no_allowlist_to_hide_behind()
    test_the_intruder_adds_NO_NEW_GATE_to_the_executor()
    test_ffufs_own_gating_is_UNCHANGED_by_this_build()
    print("ALL intruder locks pass")
