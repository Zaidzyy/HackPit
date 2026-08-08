"""Race-tester locks (race-singlepacket build).  Run:  python test_race.py

*** THE ARGUMENT THIS FILE ENFORCES — THE INTRUDER'S, WITH A SYNCHRONIZED TRANSPORT. ***
HackPit refuses BATCHING ACROSS APPROVALS — an agent queueing five commands behind one human
click. It has never refused ONE approval that produces many requests, and could not: ffuf, nuclei,
the ZAP active scanner and the intruder are each a single approval buying many requests. The race
tester is that same shape: ONE gated job, the SAME four gates, NO new ones — it just fires the
identical request N times so the copies land in one instant.

So this file asserts THE FOUR GATES AND NO NEW ONES, in both directions, and the two properties
that make a single approval honest:

  * the whole request template (method, URL, body, every header) AND N are IN the approved
    surface, complete and untruncated — a body carrying `| sh` must reach the danger gate
  * the scope check runs on the URL that goes ON THE WIRE, before anything is fired

THE RED-CONFIRM IS THE GATE'S TO DEMAND, NOT THIS MODULE'S. An ordinary coupon body does not trip
the danger gate; one carrying `| sh` does. Requiring the ack unconditionally would be this build
adding a confirm, which it may not.
"""

from __future__ import annotations

import ast
import inspect

from cockpit import config, executor, race


def _req(**kw):
    base = dict(url=f"http://{config.LAB_TARGET_HOST}/redeem", method="POST",
                body="code=SAVE10", count=20, approved=True)
    base.update(kw)
    return race.RaceRequest(**base)


# --------------------------------------------------------------------------- #
# the gate — the scanner's four, unchanged
# --------------------------------------------------------------------------- #
def _not_refused_at(verdict, gate: str) -> bool:
    """*** "NOT REFUSED AT **THIS** GATE", NEVER A BARE "NOT REFUSED". ***

    A fully approved in-lab job legitimately ends at ``gate='sandbox'``/``'isolation'`` when Docker
    is absent — which is CI, and the docker-stripped local run this repo requires. Asserting
    `verdict is None` made this file depend on Docker; the isolation gate firing is not evidence
    that the approval, target or danger gate failed.
    """
    return verdict is None or verdict.gate != gate


def test_all_four_gates_fire_EACH_WITH_A_CONTROL() -> None:
    """Each gate is shown firing, and each control is phrased "not refused at THIS gate"."""
    ok = race.validate(_req())
    for gate in ("approval", "target", "danger"):
        assert _not_refused_at(ok, gate), f"an approved in-lab job was refused at {gate}: {ok}"

    unapproved = race.validate(_req(approved=False))
    assert unapproved is not None and unapproved.gate == "approval", unapproved

    offlab = race.validate(_req(url="http://example.com/redeem"))
    assert offlab is not None and offlab.gate == "target", offlab

    shelly = race.validate(_req(body="x| sh"))
    assert shelly is not None and shelly.gate == "danger", shelly
    assert any("| sh" in f for f in shelly.dangerous_flags), shelly.dangerous_flags
    # ...and the ack clears THAT gate, which is what makes it a confirm rather than a blocklist.
    acked = race.validate(_req(body="x| sh", dangerous_ack=True))
    assert _not_refused_at(acked, "danger"), f"the red-confirm did not clear the danger gate: {acked}"
    print("  approval / target / danger each fire, and the ack clears danger "
          "(controls phrased per-gate, so this runs without Docker): PASS")


def test_THE_WHOLE_REQUEST_AND_N_ARE_IN_THE_SURFACE_AND_NOT_TRUNCATED() -> None:
    """*** CRITICAL 2, CARRIED FROM THE INTRUDER. *** A summarised body would let a shell pattern
    ride unseen while a human approves "20 requests to /redeem"."""
    from cockpit.repeater import RepeaterHeader

    headers = [RepeaterHeader(name=f"X-H{i}", value=f"v{i}") for i in range(12)]
    req = _req(headers=headers, body="amount=1&note=evil| sh", count=37)
    argv = race.race_argv_for(req)
    joined = " ".join(argv)
    assert req.url in joined, "the URL is missing from the approved surface"
    assert "-n 37" in joined, "the concurrency count N is missing from the surface"
    for i in range(12):
        assert f"X-H{i}: v{i}" in joined, f"header X-H{i} is missing from the surface"
    assert "evil| sh" in joined and "more" not in joined.lower(), joined
    # ...and the gate SEES it, which is the whole reason completeness matters.
    verdict = race.validate(req)
    assert verdict is not None and verdict.gate == "danger", (
        "a shell pattern in the body did not reach the danger gate"
    )
    print("  the whole request + N are in the surface, and a shell body still trips danger: PASS")


def test_BOTH_MODES_BUILD_A_COMPLETE_SURFACE() -> None:
    """h2-single-packet and h1-last-byte each carry the mode + N + request into the argv."""
    for mode in ("h2-single-packet", "h1-last-byte"):
        argv = race.race_argv_for(_req(mode=mode, count=15))
        joined = " ".join(argv)
        assert f"--mode {mode}" in joined, (mode, joined)
        assert "-n 15" in joined, joined
        assert "-X POST" in joined and "/redeem" in joined, joined
    print("  both transports build a complete, honest approved surface: PASS")


def test_the_gate_surface_and_the_validated_request_are_ONE_DERIVATION() -> None:
    """The scanner's rule: the thing the gate scoped is the thing that gets fired."""
    src = inspect.getsource(race._gate_request)
    assert "race_argv_for(req)" in src, "_gate_request builds its own argv"
    assert "_gate_request(req)" in inspect.getsource(race.validate)
    assert "validate(req)" in inspect.getsource(race.start), "start() does not run the shared validator"
    print("  gate surface, validate and start all come through one derivation: PASS")


def test_the_gate_runs_BEFORE_anything_is_fired() -> None:
    src = inspect.getsource(race.start)
    gate_at = src.find("validate(req)")
    thread_at = src.find("threading.Thread")
    assert gate_at != -1 and thread_at != -1 and gate_at < thread_at, (
        "start() spawns the worker before validating — an unapproved job would fire traffic"
    )
    print("  validation happens before the worker thread exists: PASS")


# --------------------------------------------------------------------------- #
# containment: the box, the wire, the argv, the record
# --------------------------------------------------------------------------- #
def test_the_container_is_a_CONSTANT_never_a_request_field() -> None:
    """No new egress path, and nothing in a request can redirect where traffic leaves from."""
    for field in ("container", "target", "host", "sandbox"):
        assert field not in race.RaceRequest.model_fields, (
            f"RaceRequest grew a {field!r} field — the box must be a code constant"
        )
    assert "config.KALI_OPEN_CONTAINER" in inspect.getsource(race._engine_argv)
    print("  the sandbox is a code constant, not a request field: PASS")


def test_the_engine_is_argv_only_with_the_request_on_STDIN() -> None:
    """No shell parses a request byte: the argv is fixed, the request rides stdin as JSON."""
    argv = race._engine_argv()
    assert argv[:3] == ["docker", "exec", "-i"], argv
    assert "race-singlepacket" in argv and "--job-stdin" in argv, argv
    assert config.KALI_OPEN_CONTAINER in argv, argv
    # the request is delivered on stdin, not on the argv
    runsrc = inspect.getsource(race._run)
    assert "input=json.dumps(spec)" in runsrc, "the request does not travel on stdin"
    print("  the engine runs argv-only with the whole request on stdin: PASS")


def test_the_scope_check_runs_ON_THE_WIRE_URL_BEFORE_ANYTHING_IS_FIRED() -> None:
    """Not a composed URL — the bytes that go out. And BEFORE the engine subprocess, so an
    off-scope host fires nothing."""
    src = inspect.getsource(race._run)
    assert "_scope_ok(req, req.url)" in src, "the scope check does not read the wire URL"
    assert src.find("_scope_ok(req, req.url)") < src.find("subprocess.run"), (
        "the batch is fired before the scope check"
    )
    # an off-scope host refuses the WHOLE batch (all N share one URL) and sends nothing
    assert "j.scope_refusals = n" in src
    refuse = src[src.find("if not ok:"):src.find("cookie_header = ")]
    assert "return" in refuse, "an off-scope URL does not stop before the engine runs"
    assert "scope_refusals" in race.RaceJob.model_fields
    print("  the wire URL is scope-checked before the batch fires; off-scope refuses all N: PASS")


def test_the_run_record_does_NOT_carry_the_body_or_headers() -> None:
    """report.py renders a run record's command line verbatim into a report, and a race body is
    occasionally a coupon code or a session-bound token."""
    src = inspect.getsource(race._run)
    rec = src[src.find("RunRecord("):]
    assert "req.body" not in rec, "the run record carries the request body into the report"
    assert "req.headers" not in rec, "the run record carries the request headers into the report"
    assert "req.url" in rec and "mode=" in rec
    print("  the run record carries the URL, mode and counts, never the body/headers: PASS")


# --------------------------------------------------------------------------- #
# planning + bounds + the verdict
# --------------------------------------------------------------------------- #
def test_an_unknown_mode_FALLS_BACK_and_SAYS_SO_rather_than_refusing() -> None:
    n, warnings, capped = race.plan(_req(mode="turbo-intruder", count=10))
    assert n == 10 and not capped
    assert any("unknown mode" in w for w in warnings), warnings
    print("  an unknown mode runs as the default and warns; it does not refuse: PASS")


def test_the_ceiling_CAPS_AND_REPORTS_rather_than_refusing() -> None:
    n, warnings, capped = race.plan(_req(count=race.RACE_MAX_REQUESTS + 25))
    assert capped is True
    assert n == race.RACE_MAX_REQUESTS
    assert any("ceiling" in w for w in warnings), warnings
    assert any("NOT refused" in w for w in warnings), warnings
    print("  the ceiling caps, reports and does not refuse: PASS")


def test_the_verdict_FLAGS_a_multi_winner_cluster() -> None:
    """*** THE RACE SIGNAL. *** The rare single-success outcome appearing more than once is the
    whole point — 'K of N requests won the race'."""
    def R(status, size, err=""):
        return race.RaceResult(index=0, status=status, size_bytes=size, error=err)

    # 2 requests landed the rare 200 that a serial baseline returns once; 8 got the 409.
    hit = [R(200, 120)] * 2 + [R(409, 80)] * 8
    v = race.race_verdict(hit)
    assert v.race_detected is True, v
    assert v.won == 2 and v.winning_status == 200, v
    assert v.of == 10, v

    # control: exactly one 200 — the serial baseline's normal outcome, NOT a race.
    one = [R(200, 120)] + [R(409, 80)] * 9
    v2 = race.race_verdict(one)
    assert v2.race_detected is False and v2.won == 1, v2

    # uniform: every response identical — no distinguishable single-success outcome, no signal.
    uniform = [R(200, 120)] * 10
    v3 = race.race_verdict(uniform)
    assert v3.race_detected is False, v3
    assert len(v3.clusters) == 1, v3

    # error rows are excluded from the count entirely.
    mixed = [R(200, 120)] * 2 + [R(None, 0, err="connect failed")] * 3 + [R(409, 80)] * 5
    v4 = race.race_verdict(mixed)
    assert v4.of == 7 and v4.won == 2 and v4.race_detected is True, v4
    print("  the verdict flags a >1-winner cluster, ignores a lone winner and error rows: PASS")


def test_a_confirmed_race_BECOMES_a_finding() -> None:
    """A confirmed race writes a high Finding to engagement state — but only with a session."""
    src = inspect.getsource(race._write_finding)
    assert "Finding(" in src and 'severity="high"' in src
    assert "verdict.race_detected" in src and "req.session_id" in src, (
        "a race is written regardless of detection or session — it must gate on both"
    )
    print("  a confirmed race becomes a high Finding in engagement state: PASS")


# --------------------------------------------------------------------------- #
# stop + no-new-gate
# --------------------------------------------------------------------------- #
def test_STOP_IS_UNGATED() -> None:
    """N synchronized requests may be in flight. A gate that could refuse to stop them would make
    the system less safe — the position every other stop in this codebase takes."""
    src = inspect.getsource(race.stop)
    for token in ("approved", "dangerous_ack", "validate", "executor"):
        assert token not in src, f"stop() consults {token!r}"
    from cockpit import router

    rsrc = inspect.getsource(router.stop_race_job)
    for token in ("approved", "dangerous_ack", "validate"):
        assert token not in rsrc, f"the stop route consults {token!r}"
    print("  stop is ungated in the module and on the route: PASS")


def test_the_preview_FIRES_NOTHING_and_uses_the_same_functions() -> None:
    from cockpit import router

    src = inspect.getsource(router.race_preview)
    assert "race_mod.plan(" in src and "race_mod.validate(" in src
    assert "race_mod.start(" not in src, "the preview route can start a job"
    tree = ast.parse(inspect.getsource(race.plan))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert node.func.attr not in ("run", "Popen"), "plan() spawns a process"
    print("  the preview reuses plan+validate and fires nothing: PASS")


def test_the_race_adds_NO_NEW_GATE_to_the_executor() -> None:
    """*** THE FOUR GATES, NO NEW ONES. *** The module runs the executor's validator and grows no
    check of its own. start() raises RaceRefused exactly three times: the URL-shape input guard
    (like the repeater's absolute-URL check — not a safety gate), the gate-verdict relay, and the
    sandbox-availability check. None invents a policy."""
    src = inspect.getsource(race)
    assert "executor.validate_request" in src
    tree = ast.parse(src)
    raisers = {
        node.lineno for node in ast.walk(tree)
        if isinstance(node, ast.Raise) and "RaceRefused" in ast.dump(node)
    }
    start_src = inspect.getsource(race.start)
    assert start_src.count("raise RaceRefused") == 3, (
        f"RaceRefused is raised {start_src.count('raise RaceRefused')} times in start() — there "
        "should be exactly three: the URL-input guard, the gate relay and the availability check"
    )
    assert len(raisers) == 3, f"RaceRefused raised at {len(raisers)} sites across the module"
    print("  the module relays the executor's verdict and invents no gate of its own: PASS")


def test_race_singlepackets_own_gating_is_UNCHANGED_by_this_build() -> None:
    """The declared command must be CLEAN by binary identity — firing benign duplicated requests is
    not code execution — so a plain race adds no red-confirm, exactly like a plain ffuf."""
    plain = race.validate(_req(body="code=SAVE10"))
    assert _not_refused_at(plain, "danger"), (
        f"a plain in-lab race now needs a red-confirm ({plain}) — this build added a confirm, which "
        "it may not"
    )
    print("  a plain race still needs no red-confirm — no confirm was added: PASS")


if __name__ == "__main__":
    print("== race-singlepacket ==")
    test_all_four_gates_fire_EACH_WITH_A_CONTROL()
    test_THE_WHOLE_REQUEST_AND_N_ARE_IN_THE_SURFACE_AND_NOT_TRUNCATED()
    test_BOTH_MODES_BUILD_A_COMPLETE_SURFACE()
    test_the_gate_surface_and_the_validated_request_are_ONE_DERIVATION()
    test_the_gate_runs_BEFORE_anything_is_fired()
    test_the_container_is_a_CONSTANT_never_a_request_field()
    test_the_engine_is_argv_only_with_the_request_on_STDIN()
    test_the_scope_check_runs_ON_THE_WIRE_URL_BEFORE_ANYTHING_IS_FIRED()
    test_the_run_record_does_NOT_carry_the_body_or_headers()
    test_an_unknown_mode_FALLS_BACK_and_SAYS_SO_rather_than_refusing()
    test_the_ceiling_CAPS_AND_REPORTS_rather_than_refusing()
    test_the_verdict_FLAGS_a_multi_winner_cluster()
    test_a_confirmed_race_BECOMES_a_finding()
    test_STOP_IS_UNGATED()
    test_the_preview_FIRES_NOTHING_and_uses_the_same_functions()
    test_the_race_adds_NO_NEW_GATE_to_the_executor()
    test_race_singlepackets_own_gating_is_UNCHANGED_by_this_build()
    print("ALL race locks pass")
